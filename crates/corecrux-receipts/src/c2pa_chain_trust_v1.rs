// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Private-anchor X.509 chain validation for CueCrux C2PA envelopes.
//!
//! This is the shared, cryptographic chain validator behind both the offline
//! `corecruxctl c2pa-verify` private-anchor path and the hosted BYOK
//! provenance verify path's operator-pinned-root trust mode. Semantics follow
//! the M9j offline verifier hardening (`verifiable-record-products-2026-07-17`):
//! per-link cryptographic signature verification, current validity at the
//! supplied time, leaf/CA BasicConstraints + KeyUsage + the CueCrux C2PA
//! emailProtection EKU leaf profile, path-length enforcement, and fail-closed
//! rejection of unparseable, unsupported-critical, or path-constraint
//! extensions this verifier does not implement.
//!
//! Deliberate non-claims: revocation (CRL/OCSP) and public C2PA trust-list
//! membership are NOT evaluated. Callers own anchor selection; this function
//! only proves the presented chain terminates at the exact supplied anchor.

/// Validate a presented DER certificate chain (leaf first) against one exact,
/// caller-trusted anchor certificate at the supplied Unix time.
///
/// The presented chain may include the anchor as its terminal certificate;
/// it is then stripped before link validation so the anchor never doubles as
/// its own intermediate. Any validation failure returns `Err` with a bounded,
/// key-material-free reason. `Ok(())` means: every presented certificate
/// parsed completely, is currently valid, carries only understood critical
/// extensions and no unimplemented path constraints, the leaf satisfies the
/// CueCrux C2PA leaf profile (CA=false, digitalSignature, emailProtection
/// EKU), every intermediate is a CA with keyCertSign and a satisfied path
/// length, every link signature verifies cryptographically, and the terminal
/// presented certificate is signed by the self-issued, self-signature-valid
/// anchor.
pub fn validate_c2pa_chain_to_anchor_v1(
    chain_der: &[Vec<u8>],
    anchor_der: &[u8],
    now_unix_seconds: u64,
) -> Result<(), String> {
    use x509_parser::time::ASN1Time;

    let now_signed =
        i64::try_from(now_unix_seconds).map_err(|_| "current time is outside the supported range".to_string())?;
    let now = ASN1Time::from_timestamp(now_signed).map_err(|_| "current time is not a valid X.509 time".to_string())?;

    if chain_der.is_empty() {
        return Err("presented chain contains no leaf certificate".to_string());
    }
    let mut presented = chain_der;
    if presented.last().is_some_and(|cert| cert.as_slice() == anchor_der) {
        presented = &presented[..presented.len() - 1];
    }
    if presented.is_empty() {
        return Err("presented chain contains an anchor but no leaf certificate".to_string());
    }
    if presented.iter().any(|cert| cert.as_slice() == anchor_der) {
        return Err("trusted anchor appears out of order in the presented chain".to_string());
    }
    for (index, cert) in presented.iter().enumerate() {
        if presented[..index].contains(cert) {
            return Err("presented chain contains a duplicate certificate".to_string());
        }
    }

    let leaf = parse_x509_certificate(&presented[0], "leaf")?;
    validate_certificate_common(&leaf, now, "leaf")?;
    validate_c2pa_leaf_profile(&leaf)?;

    for (index, der) in presented.iter().enumerate().skip(1) {
        let label = format!("intermediate {index}");
        let cert = parse_x509_certificate(der, &label)?;
        validate_certificate_common(&cert, now, &label)?;
        let ca_below = u32::try_from(index - 1).map_err(|_| "certificate path is too deep".to_string())?;
        validate_ca_profile(&cert, ca_below, &label)?;
    }

    for index in 0..presented.len().saturating_sub(1) {
        let child = parse_x509_certificate(&presented[index], "chain child")?;
        let issuer = parse_x509_certificate(&presented[index + 1], "chain issuer")?;
        verify_certificate_link(&child, &issuer, &format!("presented chain link {index}"))?;
    }

    let anchor = parse_x509_certificate(anchor_der, "trusted anchor")?;
    validate_certificate_common(&anchor, now, "trusted anchor")?;
    let ca_below =
        u32::try_from(presented.len().saturating_sub(1)).map_err(|_| "certificate path is too deep".to_string())?;
    validate_ca_profile(&anchor, ca_below, "trusted anchor")?;
    if anchor.subject() != anchor.issuer() {
        return Err("trusted anchor is not self-issued".to_string());
    }
    anchor
        .verify_signature(None)
        .map_err(|_| "trusted anchor self-signature verification failed".to_string())?;

    let terminal = parse_x509_certificate(
        presented.last().ok_or_else(|| "presented chain is empty".to_string())?,
        "terminal presented certificate",
    )?;
    verify_certificate_link(&terminal, &anchor, "terminal-to-anchor link")?;
    Ok(())
}

fn parse_x509_certificate<'a>(
    der: &'a [u8],
    label: &str,
) -> Result<x509_parser::certificate::X509Certificate<'a>, String> {
    use x509_parser::prelude::{FromDer as _, X509Certificate};

    let (remaining, certificate) =
        X509Certificate::from_der(der).map_err(|error| format!("{label} certificate parse failed: {error}"))?;
    if !remaining.is_empty() {
        return Err(format!("{label} certificate has trailing DER bytes"));
    }
    Ok(certificate)
}

fn validate_certificate_common(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    now: x509_parser::time::ASN1Time,
    label: &str,
) -> Result<(), String> {
    use x509_parser::extensions::ParsedExtension;

    certificate
        .extensions_map()
        .map_err(|error| format!("{label} certificate extensions are invalid: {error}"))?;
    if !certificate.validity().is_valid_at(now) {
        return Err(format!("{label} certificate is not currently valid"));
    }
    for extension in certificate.extensions() {
        if extension.parsed_extension().error().is_some() {
            return Err(format!("{label} certificate contains an unparseable extension"));
        }
        if extension.critical
            && !matches!(
                extension.parsed_extension(),
                ParsedExtension::BasicConstraints(_)
                    | ParsedExtension::KeyUsage(_)
                    | ParsedExtension::ExtendedKeyUsage(_)
                    | ParsedExtension::SubjectAlternativeName(_)
            )
        {
            return Err(format!(
                "{label} certificate contains an unsupported critical extension ({})",
                extension.oid
            ));
        }
        if matches!(
            extension.parsed_extension(),
            ParsedExtension::NameConstraints(_)
                | ParsedExtension::PolicyMappings(_)
                | ParsedExtension::PolicyConstraints(_)
                | ParsedExtension::InhibitAnyPolicy(_)
        ) {
            return Err(format!(
                "{label} certificate uses path constraints this verifier does not implement"
            ));
        }
    }
    Ok(())
}

fn validate_c2pa_leaf_profile(certificate: &x509_parser::certificate::X509Certificate<'_>) -> Result<(), String> {
    let basic_constraints = certificate
        .basic_constraints()
        .map_err(|error| format!("leaf BasicConstraints parse failed: {error}"))?
        .ok_or_else(|| "leaf certificate is missing BasicConstraints".to_string())?;
    if basic_constraints.value.ca {
        return Err("leaf certificate asserts CA=true".to_string());
    }
    let key_usage = certificate
        .key_usage()
        .map_err(|error| format!("leaf KeyUsage parse failed: {error}"))?
        .ok_or_else(|| "leaf certificate is missing KeyUsage".to_string())?;
    if !key_usage.value.digital_signature() || key_usage.value.key_cert_sign() {
        return Err("leaf KeyUsage must allow digitalSignature and forbid keyCertSign".to_string());
    }
    let extended_key_usage = certificate
        .extended_key_usage()
        .map_err(|error| format!("leaf ExtendedKeyUsage parse failed: {error}"))?
        .ok_or_else(|| "leaf certificate is missing ExtendedKeyUsage".to_string())?;
    if !extended_key_usage.value.email_protection {
        return Err("leaf ExtendedKeyUsage must include emailProtection for the CueCrux C2PA profile".to_string());
    }
    Ok(())
}

fn validate_ca_profile(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    ca_certificates_below: u32,
    label: &str,
) -> Result<(), String> {
    let basic_constraints = certificate
        .basic_constraints()
        .map_err(|error| format!("{label} BasicConstraints parse failed: {error}"))?
        .ok_or_else(|| format!("{label} is missing BasicConstraints"))?;
    if !basic_constraints.value.ca {
        return Err(format!("{label} does not assert CA=true"));
    }
    if basic_constraints
        .value
        .path_len_constraint
        .is_some_and(|maximum| ca_certificates_below > maximum)
    {
        return Err(format!("{label} BasicConstraints path length is exceeded"));
    }
    let key_usage = certificate
        .key_usage()
        .map_err(|error| format!("{label} KeyUsage parse failed: {error}"))?
        .ok_or_else(|| format!("{label} is missing KeyUsage"))?;
    if !key_usage.value.key_cert_sign() {
        return Err(format!("{label} KeyUsage does not allow keyCertSign"));
    }
    Ok(())
}

fn verify_certificate_link(
    child: &x509_parser::certificate::X509Certificate<'_>,
    issuer: &x509_parser::certificate::X509Certificate<'_>,
    label: &str,
) -> Result<(), String> {
    if child.issuer() != issuer.subject() {
        return Err(format!("{label} issuer/subject names do not match"));
    }
    child
        .verify_signature(Some(issuer.public_key()))
        .map_err(|_| format!("{label} certificate signature verification failed"))
}
