// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! v1 receipt verifier — checks Ed25519 signatures, recomputes candidate digests, returns `VerificationReportV1`.

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use crate::candidate_digest_v1::{parse_stored_candidate_digest_bytes_v1, recompute_candidate_digest_bytes_v1};
use crate::keyring_v1::Ed25519KeyRingV1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyErrorCodeV1 {
    Ok,
    BodyHashMismatch,
    BodyCborParseError,
    SigMissing,
    SigParseError,
    SigAlgUnsupported,
    SigReceiptIdMismatch,
    SigTenantMismatch,
    SigPayloadHashMismatch,
    KeyRingMissing,
    KeyNotFound,
    PubKeyInvalid,
    SigInvalid,
}

impl VerifyErrorCodeV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::BodyHashMismatch => "BODY_HASH_MISMATCH",
            Self::BodyCborParseError => "BODY_CBOR_PARSE_ERROR",
            Self::SigMissing => "SIG_MISSING",
            Self::SigParseError => "SIG_PARSE_ERROR",
            Self::SigAlgUnsupported => "SIG_ALG_UNSUPPORTED",
            Self::SigReceiptIdMismatch => "SIG_RECEIPT_ID_MISMATCH",
            Self::SigTenantMismatch => "SIG_TENANT_MISMATCH",
            Self::SigPayloadHashMismatch => "SIG_PAYLOAD_HASH_MISMATCH",
            Self::KeyRingMissing => "KEYRING_MISSING",
            Self::KeyNotFound => "KEY_NOT_FOUND",
            Self::PubKeyInvalid => "PUBKEY_INVALID",
            Self::SigInvalid => "SIG_INVALID",
        }
    }
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("cbor: {0}")]
    Cbor(String),
}

/// ReceiptSignatureV1: logical fields stored as canonical CBOR bytes.
///
/// We decode it using serde to a typed struct, but we never re-encode it to produce "canonical"
/// bytes. Canonicalization is producer responsibility.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReceiptSigV1 {
    pub schema: String,
    #[serde(rename = "receipt_id")]
    pub receipt_id: String,
    pub alg: String,
    #[serde(rename = "key_id")]
    pub key_id: String,
    #[serde(rename = "signed_at")]
    pub signed_at: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signed_payload_hash: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationReportV1 {
    pub schema: String,
    #[serde(rename = "receipt_id")]
    pub receipt_id: String,
    #[serde(rename = "tenant_id")]
    pub tenant_id: String,

    #[serde(rename = "payload_hash")]
    pub payload_hash_hex: String,

    pub signature: VerificationSigInfoV1,
    pub integrity: VerificationIntegrityV1,
    /// What this receipt could be bound to beyond its own bytes.
    ///
    /// Defaulted on deserialize so reports written before the binding
    /// existed still load; they read as "nothing bound", which is the truth
    /// about them.
    #[serde(default)]
    pub binding: VerificationBindingV1,
    #[serde(rename = "trace_checks", default)]
    pub trace_checks: VerificationTraceChecksV1,
    /// Best-effort extracted trace values from the receipt body (for drift tools).
    ///
    /// This is additive metadata; the canonical truth is always the stored receipt body bytes.
    #[serde(rename = "trace_summary", skip_serializing_if = "Option::is_none", default)]
    pub trace_summary: Option<VerificationTraceSummaryV1>,

    #[serde(rename = "signature_valid")]
    pub signature_valid: bool,
    #[serde(rename = "pubkey_fingerprint", skip_serializing_if = "Option::is_none")]
    pub pubkey_fingerprint: Option<String>,

    #[serde(rename = "error_code")]
    pub error_code: String,
    #[serde(rename = "error_message", skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    #[serde(rename = "verified_at")]
    pub verified_at: String,
    #[serde(rename = "verifier_build")]
    pub verifier_build: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationSigInfoV1 {
    pub alg: String,
    #[serde(rename = "key_id", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationIntegrityV1 {
    #[serde(rename = "payload_hash_matches")]
    pub payload_hash_matches: bool,
    #[serde(rename = "canonical_bytes_parse_ok")]
    pub canonical_bytes_parse_ok: bool,
}

/// Which of a receipt's *contextual* claims the verifier could actually check.
///
/// A valid Ed25519 signature proves the body bytes are authentic. It does not
/// prove the body belongs to the tenant you asked about, at the chain position
/// you asked about — and until this struct existed the report said `OK` either
/// way, which is what made a genuine receipt replayable under another tenant
/// label (defect D3).
///
/// The signature covers `body_bytes` alone; the `ReceiptSigV1` envelope is not
/// signed. So the only trustworthy source for these claims is the body itself,
/// and that is where [`verify_receipt_v1`] reads them from.
///
/// `false` is not automatically a failure: a body that carries no `tenant_id`
/// predates the binding and still verifies, but it reports `tenant_bound:
/// false` so an auditor can tell an unbound receipt from a bound one instead
/// of reading the same bare `OK` for both.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, Default, PartialEq, Eq)]
pub struct VerificationBindingV1 {
    /// The signed body declared a top-level `tenant_id` and it equals the
    /// tenant the caller asked about. A *mismatch* is a hard failure
    /// (`SIG_TENANT_MISMATCH`), so `false` here means "the body declared no
    /// tenant", never "the tenant was wrong".
    #[serde(rename = "tenant_bound")]
    pub tenant_bound: bool,
    /// The signed body declared a top-level `receipt_id` and it equals the
    /// receipt the caller asked about.
    ///
    /// Reported, not enforced. The `sig.receipt_id` envelope check below
    /// already rejects the careless case, and hard-failing on the body field
    /// would change the verdict for receipts whose producers never treated it
    /// as a contract. A `false` here on a receipt whose body *does* carry a
    /// `receipt_id` means the envelope agreed with the query and the signed
    /// body did not — worth an operator's attention.
    #[serde(rename = "receipt_id_bound")]
    pub receipt_id_bound: bool,
    /// The caller resolved this receipt's position in a tamper-evident chain
    /// before asking for verification.
    ///
    /// [`verify_receipt_v1`] never sets this: it is handed one receipt and
    /// cannot see its neighbours, so only the store that resolved it can
    /// assert the position. It stays `false` unless that store sets it, which
    /// is the honest answer for every caller that does no chain resolution.
    #[serde(rename = "chain_position_checked")]
    pub chain_position_checked: bool,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, Default)]
pub struct VerificationTraceChecksV1 {
    #[serde(rename = "retrieval_trace_present")]
    pub retrieval_trace_present: bool,
    #[serde(rename = "lanes_used_present")]
    pub lanes_used_present: bool,
    #[serde(rename = "candidate_generation_present")]
    pub candidate_generation_present: bool,
    #[serde(rename = "filters_present")]
    pub filters_present: bool,
    #[serde(rename = "normalisation_present")]
    pub normalisation_present: bool,
    #[serde(rename = "fusion_present")]
    pub fusion_present: bool,
    #[serde(rename = "priors_applied_present")]
    pub priors_applied_present: bool,
    #[serde(rename = "anchors_present")]
    pub anchors_present: bool,
    #[serde(rename = "anchors_ids_present")]
    pub anchors_ids_present: bool,
    #[serde(rename = "anchors_derivation_method_present")]
    pub anchors_derivation_method_present: bool,
    #[serde(rename = "rerank_present")]
    pub rerank_present: bool,
    #[serde(rename = "candidates_present")]
    pub candidates_present: bool,

    #[serde(rename = "candidate_digest_present")]
    pub candidate_digest_present: bool,
    #[serde(
        rename = "candidate_digest_matches_recompute",
        skip_serializing_if = "Option::is_none"
    )]
    pub candidate_digest_matches_recompute: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct VerificationTraceSummaryV1 {
    /// Stored candidate_digest value as extracted from the receipt body bytes.
    ///
    /// We never reserialize receipt bytes; this is a convenience field for drift tools.
    #[serde(rename = "candidate_digest", skip_serializing_if = "Option::is_none", default)]
    pub candidate_digest: Option<String>,
}

pub struct VerifyReceiptInput<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub body_bytes: &'a [u8],
    /// Payload hash stored in the v3 event header for the body event.
    pub stored_body_payload_hash: [u8; 32],
    pub sig_bytes: Option<&'a [u8]>,
    pub keyring: Option<&'a Ed25519KeyRingV1>,
    /// Stable timestamp for determinism; prefer the signature event's ingested_at.
    pub verified_at: &'a str,
    pub verifier_build: &'a corecrux_types::BuildInfo,
    /// Phase 8 Tier 2 (optional): recompute candidate_digest from receipt trace and compare.
    pub recompute_candidate_digest: bool,
}

/// Verify one receipt in isolation: body hash, Ed25519 signature over the body
/// bytes, keyring membership of the signing key, and — since D3 — that the
/// signed body's own `tenant_id` is the tenant the caller asked about.
///
/// What it deliberately does **not** check: chain position. This function is
/// handed a single receipt and never its neighbours, so it cannot tell a chain
/// head from a spliced-in replay. Callers that resolve receipts out of a
/// hash-chained store must run that check themselves and record it in
/// [`VerificationBindingV1::chain_position_checked`]; callers that cannot must
/// leave it `false` rather than let the report imply a check nobody ran.
pub fn verify_receipt_v1(input: VerifyReceiptInput<'_>) -> Result<VerificationReportV1, VerifyError> {
    let computed = blake3::hash(input.body_bytes);
    let payload_hash_matches = computed.as_bytes() == &input.stored_body_payload_hash;

    // Optional parseability check: we only care that it's valid CBOR; canonical-form checks are
    // explicitly producer-side in Phase 8.
    let mut parsed_body: Option<ciborium::value::Value> = None;
    let canonical_bytes_parse_ok =
        match ciborium::de::from_reader::<ciborium::value::Value, _>(std::io::Cursor::new(input.body_bytes)) {
            Ok(v) => {
                parsed_body = Some(v);
                true
            }
            Err(_) => false,
        };

    let (trace_checks, trace_summary) = compute_trace_checks(parsed_body.as_ref(), input.recompute_candidate_digest);

    // Report the stored header payloadHash; this is the anchor value exported and indexed by CoreCrux.
    let payload_hash_hex = hex32(&input.stored_body_payload_hash);
    let verifier_build = format!("{}@{}", input.verifier_build.version, input.verifier_build.commit);

    // Contextual binding (D3). Read from the BODY, never the sig envelope: the
    // ed25519 signature covers `body_bytes` only, so a field in the envelope
    // can be rewritten without invalidating it. That makes the pre-existing
    // `sig.receipt_id` check below a consistency check rather than a binding
    // — the body is the only source that costs a re-signing to change.
    let body_tenant_id = body_top_level_text(parsed_body.as_ref(), "tenant_id");
    let body_receipt_id = body_top_level_text(parsed_body.as_ref(), "receipt_id");
    let binding = VerificationBindingV1 {
        tenant_bound: body_tenant_id.as_deref() == Some(input.tenant_id),
        receipt_id_bound: body_receipt_id.as_deref() == Some(input.receipt_id),
        chain_position_checked: false,
    };

    // If body hash doesn't match, we still attempt to verify the signature over the stored bytes
    // so operators can distinguish "corrupt storage" from "bad signature".

    let mut signature_valid = false;
    let mut pubkey_fingerprint: Option<String> = None;
    let err: VerifyErrorCodeV1;
    let mut err_msg: Option<String> = None;
    let mut sig_info = VerificationSigInfoV1 {
        alg: "ed25519".to_string(),
        key_id: None,
    };

    // Fail closed on a tenant mismatch BEFORE anything else about the
    // signature is considered. A receipt whose signed body names another
    // tenant is not this tenant's receipt, whether or not it also happens to
    // carry a valid signature — that is exactly the replay D3 describes, and
    // deciding it here means no later branch can return `OK` for it.
    let binding_failure = body_tenant_id
        .as_deref()
        .filter(|t| *t != input.tenant_id)
        .map(|found| {
            (
                VerifyErrorCodeV1::SigTenantMismatch,
                format!(
                    "signed body tenant_id mismatch: expected {} got {found}",
                    input.tenant_id
                ),
            )
        });
    if let Some((binding_err, binding_msg)) = binding_failure {
        // Storage corruption still outranks it, same as every other check
        // here: an operator must be able to tell a mangled body from a
        // deliberately relabelled one.
        err = if payload_hash_matches {
            binding_err
        } else {
            VerifyErrorCodeV1::BodyHashMismatch
        };
        err_msg = Some(binding_msg);
        return Ok(VerificationReportV1 {
            schema: "cuecrux.receipt.verify.v1".to_string(),
            receipt_id: input.receipt_id.to_string(),
            tenant_id: input.tenant_id.to_string(),
            payload_hash_hex,
            signature: sig_info,
            integrity: VerificationIntegrityV1 {
                payload_hash_matches,
                canonical_bytes_parse_ok,
            },
            binding,
            trace_checks,
            trace_summary,
            signature_valid,
            pubkey_fingerprint,
            error_code: err.as_str().to_string(),
            error_message: err_msg,
            verified_at: input.verified_at.to_string(),
            verifier_build,
        });
    }

    let Some(sig_bytes) = input.sig_bytes else {
        err = if !payload_hash_matches {
            VerifyErrorCodeV1::BodyHashMismatch
        } else {
            VerifyErrorCodeV1::SigMissing
        };
        if !payload_hash_matches {
            err_msg = Some(format!(
                "payload_hash mismatch: stored={} computed={}",
                hex32(&input.stored_body_payload_hash),
                computed.to_hex()
            ));
        }
        sig_info.alg = "ed25519".to_string();
        return Ok(VerificationReportV1 {
            schema: "cuecrux.receipt.verify.v1".to_string(),
            receipt_id: input.receipt_id.to_string(),
            tenant_id: input.tenant_id.to_string(),
            payload_hash_hex,
            signature: sig_info,
            integrity: VerificationIntegrityV1 {
                payload_hash_matches,
                canonical_bytes_parse_ok,
            },
            binding,
            trace_checks,
            trace_summary,
            signature_valid,
            pubkey_fingerprint,
            error_code: err.as_str().to_string(),
            error_message: err_msg,
            verified_at: input.verified_at.to_string(),
            verifier_build,
        });
    };

    let sig: ReceiptSigV1 = match ciborium::de::from_reader(std::io::Cursor::new(sig_bytes)) {
        Ok(v) => v,
        Err(e) => {
            err = if !payload_hash_matches {
                VerifyErrorCodeV1::BodyHashMismatch
            } else {
                VerifyErrorCodeV1::SigParseError
            };
            err_msg = Some(e.to_string());
            return Ok(VerificationReportV1 {
                schema: "cuecrux.receipt.verify.v1".to_string(),
                receipt_id: input.receipt_id.to_string(),
                tenant_id: input.tenant_id.to_string(),
                payload_hash_hex,
                signature: sig_info,
                integrity: VerificationIntegrityV1 {
                    payload_hash_matches,
                    canonical_bytes_parse_ok,
                },
                binding,
                trace_checks,
                trace_summary,
                signature_valid,
                pubkey_fingerprint,
                error_code: err.as_str().to_string(),
                error_message: err_msg,
                verified_at: input.verified_at.to_string(),
                verifier_build,
            });
        }
    };

    sig_info.alg.clone_from(&sig.alg);
    sig_info.key_id = Some(sig.key_id.clone());

    if sig.alg != "ed25519" {
        err = if !payload_hash_matches {
            VerifyErrorCodeV1::BodyHashMismatch
        } else {
            VerifyErrorCodeV1::SigAlgUnsupported
        };
        err_msg = Some(format!("unsupported alg {}", sig.alg));
        return Ok(VerificationReportV1 {
            schema: "cuecrux.receipt.verify.v1".to_string(),
            receipt_id: input.receipt_id.to_string(),
            tenant_id: input.tenant_id.to_string(),
            payload_hash_hex,
            signature: sig_info,
            integrity: VerificationIntegrityV1 {
                payload_hash_matches,
                canonical_bytes_parse_ok,
            },
            binding,
            trace_checks,
            trace_summary,
            signature_valid,
            pubkey_fingerprint,
            error_code: err.as_str().to_string(),
            error_message: err_msg,
            verified_at: input.verified_at.to_string(),
            verifier_build,
        });
    }

    if sig.receipt_id != input.receipt_id {
        err = if !payload_hash_matches {
            VerifyErrorCodeV1::BodyHashMismatch
        } else {
            VerifyErrorCodeV1::SigReceiptIdMismatch
        };
        err_msg = Some(format!(
            "sig receipt_id mismatch: expected {} got {}",
            input.receipt_id, sig.receipt_id
        ));
        return Ok(VerificationReportV1 {
            schema: "cuecrux.receipt.verify.v1".to_string(),
            receipt_id: input.receipt_id.to_string(),
            tenant_id: input.tenant_id.to_string(),
            payload_hash_hex,
            signature: sig_info,
            integrity: VerificationIntegrityV1 {
                payload_hash_matches,
                canonical_bytes_parse_ok,
            },
            binding,
            trace_checks,
            trace_summary,
            signature_valid,
            pubkey_fingerprint,
            error_code: err.as_str().to_string(),
            error_message: err_msg,
            verified_at: input.verified_at.to_string(),
            verifier_build,
        });
    }

    if sig.signed_payload_hash.len() != 32 || sig.signed_payload_hash.as_slice() != input.stored_body_payload_hash {
        err = if !payload_hash_matches {
            VerifyErrorCodeV1::BodyHashMismatch
        } else {
            VerifyErrorCodeV1::SigPayloadHashMismatch
        };
        err_msg = Some(format!(
            "signed_payload_hash mismatch: expected {} got {}",
            hex32(&input.stored_body_payload_hash),
            match <&[u8; 32]>::try_from(sig.signed_payload_hash.as_slice()) {
                Ok(hash) => hex32(hash),
                Err(_) => format!("len({})", sig.signed_payload_hash.len()),
            }
        ));
        return Ok(VerificationReportV1 {
            schema: "cuecrux.receipt.verify.v1".to_string(),
            receipt_id: input.receipt_id.to_string(),
            tenant_id: input.tenant_id.to_string(),
            payload_hash_hex,
            signature: sig_info,
            integrity: VerificationIntegrityV1 {
                payload_hash_matches,
                canonical_bytes_parse_ok,
            },
            binding,
            trace_checks,
            trace_summary,
            signature_valid,
            pubkey_fingerprint,
            error_code: err.as_str().to_string(),
            error_message: err_msg,
            verified_at: input.verified_at.to_string(),
            verifier_build,
        });
    }

    let Some(keyring) = input.keyring else {
        err = if !payload_hash_matches {
            VerifyErrorCodeV1::BodyHashMismatch
        } else {
            VerifyErrorCodeV1::KeyRingMissing
        };
        err_msg = Some("no keyring configured".to_string());
        return Ok(VerificationReportV1 {
            schema: "cuecrux.receipt.verify.v1".to_string(),
            receipt_id: input.receipt_id.to_string(),
            tenant_id: input.tenant_id.to_string(),
            payload_hash_hex,
            signature: sig_info,
            integrity: VerificationIntegrityV1 {
                payload_hash_matches,
                canonical_bytes_parse_ok,
            },
            binding,
            trace_checks,
            trace_summary,
            signature_valid,
            pubkey_fingerprint,
            error_code: err.as_str().to_string(),
            error_message: err_msg,
            verified_at: input.verified_at.to_string(),
            verifier_build,
        });
    };

    let key_map = match keyring.to_index_map() {
        Ok(m) => m,
        Err(e) => {
            err = if !payload_hash_matches {
                VerifyErrorCodeV1::BodyHashMismatch
            } else {
                VerifyErrorCodeV1::PubKeyInvalid
            };
            err_msg = Some(e.to_string());
            return Ok(VerificationReportV1 {
                schema: "cuecrux.receipt.verify.v1".to_string(),
                receipt_id: input.receipt_id.to_string(),
                tenant_id: input.tenant_id.to_string(),
                payload_hash_hex,
                signature: sig_info,
                integrity: VerificationIntegrityV1 {
                    payload_hash_matches,
                    canonical_bytes_parse_ok,
                },
                binding,
                trace_checks,
                trace_summary,
                signature_valid,
                pubkey_fingerprint,
                error_code: err.as_str().to_string(),
                error_message: err_msg,
                verified_at: input.verified_at.to_string(),
                verifier_build,
            });
        }
    };

    let Some(pk_bytes) = key_map.get(&sig.key_id) else {
        err = if !payload_hash_matches {
            VerifyErrorCodeV1::BodyHashMismatch
        } else {
            VerifyErrorCodeV1::KeyNotFound
        };
        err_msg = Some(format!("key_id {} not found", sig.key_id));
        return Ok(VerificationReportV1 {
            schema: "cuecrux.receipt.verify.v1".to_string(),
            receipt_id: input.receipt_id.to_string(),
            tenant_id: input.tenant_id.to_string(),
            payload_hash_hex,
            signature: sig_info,
            integrity: VerificationIntegrityV1 {
                payload_hash_matches,
                canonical_bytes_parse_ok,
            },
            binding,
            trace_checks,
            trace_summary,
            signature_valid,
            pubkey_fingerprint,
            error_code: err.as_str().to_string(),
            error_message: err_msg,
            verified_at: input.verified_at.to_string(),
            verifier_build,
        });
    };

    let vk = match VerifyingKey::from_bytes(pk_bytes) {
        Ok(v) => v,
        Err(e) => {
            err = if !payload_hash_matches {
                VerifyErrorCodeV1::BodyHashMismatch
            } else {
                VerifyErrorCodeV1::PubKeyInvalid
            };
            err_msg = Some(e.to_string());
            return Ok(VerificationReportV1 {
                schema: "cuecrux.receipt.verify.v1".to_string(),
                receipt_id: input.receipt_id.to_string(),
                tenant_id: input.tenant_id.to_string(),
                payload_hash_hex,
                signature: sig_info,
                integrity: VerificationIntegrityV1 {
                    payload_hash_matches,
                    canonical_bytes_parse_ok,
                },
                binding,
                trace_checks,
                trace_summary,
                signature_valid,
                pubkey_fingerprint,
                error_code: err.as_str().to_string(),
                error_message: err_msg,
                verified_at: input.verified_at.to_string(),
                verifier_build,
            });
        }
    };

    pubkey_fingerprint = Some(blake3::hash(pk_bytes).to_hex().to_string());

    if sig.signature.len() != 64 {
        err = if !payload_hash_matches {
            VerifyErrorCodeV1::BodyHashMismatch
        } else {
            VerifyErrorCodeV1::SigInvalid
        };
        err_msg = Some(format!("signature length {} != 64", sig.signature.len()));
        return Ok(VerificationReportV1 {
            schema: "cuecrux.receipt.verify.v1".to_string(),
            receipt_id: input.receipt_id.to_string(),
            tenant_id: input.tenant_id.to_string(),
            payload_hash_hex,
            signature: sig_info,
            integrity: VerificationIntegrityV1 {
                payload_hash_matches,
                canonical_bytes_parse_ok,
            },
            binding,
            trace_checks,
            trace_summary,
            signature_valid,
            pubkey_fingerprint,
            error_code: err.as_str().to_string(),
            error_message: err_msg,
            verified_at: input.verified_at.to_string(),
            verifier_build,
        });
    }

    let mut sig64 = [0u8; 64];
    sig64.copy_from_slice(&sig.signature);
    let signature = Signature::from_bytes(&sig64);

    match vk.verify_strict(input.body_bytes, &signature) {
        Ok(_) => {
            signature_valid = true;
            err = if !payload_hash_matches {
                VerifyErrorCodeV1::BodyHashMismatch
            } else if !canonical_bytes_parse_ok {
                VerifyErrorCodeV1::BodyCborParseError
            } else {
                VerifyErrorCodeV1::Ok
            };
            if err == VerifyErrorCodeV1::BodyCborParseError {
                err_msg = Some("receipt body payload is not valid CBOR".to_string());
            }
        }
        Err(e) => {
            signature_valid = false;
            err = if !payload_hash_matches {
                VerifyErrorCodeV1::BodyHashMismatch
            } else {
                VerifyErrorCodeV1::SigInvalid
            };
            if !payload_hash_matches {
                err_msg = Some(format!(
                    "payload_hash mismatch: stored={} computed={}; sig_error={}",
                    hex32(&input.stored_body_payload_hash),
                    computed.to_hex(),
                    e
                ));
            } else {
                err_msg = Some(e.to_string());
            }
        }
    }

    Ok(VerificationReportV1 {
        schema: "cuecrux.receipt.verify.v1".to_string(),
        receipt_id: input.receipt_id.to_string(),
        tenant_id: input.tenant_id.to_string(),
        payload_hash_hex,
        signature: sig_info,
        integrity: VerificationIntegrityV1 {
            payload_hash_matches,
            canonical_bytes_parse_ok,
        },
        binding,
        trace_checks,
        trace_summary,
        signature_valid,
        pubkey_fingerprint,
        error_code: err.as_str().to_string(),
        error_message: err_msg,
        verified_at: input.verified_at.to_string(),
        verifier_build,
    })
}

/// Read a top-level text field out of an already-parsed receipt body.
///
/// Deliberately top-level and text-only: a nested or non-text `tenant_id` is
/// treated as absent rather than coerced, so a producer cannot smuggle a
/// binding claim past the check by changing its shape.
fn body_top_level_text(parsed_body: Option<&ciborium::value::Value>, field: &str) -> Option<String> {
    let ciborium::value::Value::Map(map) = parsed_body? else {
        return None;
    };
    for (k, v) in map {
        if let (ciborium::value::Value::Text(k), ciborium::value::Value::Text(v)) = (k, v) {
            if k == field {
                return Some(v.clone());
            }
        }
    }
    None
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8_lossy(&out).to_string()
}

fn compute_trace_checks(
    parsed_body: Option<&ciborium::value::Value>,
    recompute_candidate_digest: bool,
) -> (VerificationTraceChecksV1, Option<VerificationTraceSummaryV1>) {
    use ciborium::value::Value;

    let Some(parsed_body) = parsed_body else {
        return (
            VerificationTraceChecksV1 {
                candidate_digest_matches_recompute: if recompute_candidate_digest { Some(false) } else { None },
                ..Default::default()
            },
            None,
        );
    };

    let Value::Map(map) = parsed_body else {
        return (
            VerificationTraceChecksV1 {
                candidate_digest_matches_recompute: if recompute_candidate_digest { Some(false) } else { None },
                ..Default::default()
            },
            None,
        );
    };

    // Spec name is `retrieval_trace`; tolerate `retrieval` for transitional producers.
    let retrieval = get_val(map, "retrieval_trace").or_else(|| get_val(map, "retrieval"));
    let Some(Value::Map(rt)) = retrieval else {
        return (
            VerificationTraceChecksV1 {
                candidate_digest_matches_recompute: if recompute_candidate_digest { Some(false) } else { None },
                ..Default::default()
            },
            None,
        );
    };

    let digest_val = get_val(rt, "candidate_digest").or_else(|| get_val(rt, "candidateDigest"));
    let candidate_digest = digest_val.and_then(val_to_candidate_digest_string);
    let candidate_digest_present = candidate_digest.is_some();

    let lanes_used_present = matches!(
        get_val(rt, "lanes_used").or_else(|| get_val(rt, "lanesUsed")),
        Some(Value::Array(_))
    );
    let candidate_generation_present = get_val(rt, "candidate_generation")
        .or_else(|| get_val(rt, "candidateGeneration"))
        .is_some();
    let filters_present = get_val(rt, "filters").is_some();
    let normalisation_present = get_val(rt, "normalisation")
        .or_else(|| get_val(rt, "normalization"))
        .is_some();
    let fusion_present = get_val(rt, "fusion")
        .or_else(|| get_val(rt, "fusion_weights"))
        .or_else(|| get_val(rt, "fusionWeights"))
        .is_some();
    let priors_applied_present = get_val(rt, "priors_applied")
        .or_else(|| get_val(rt, "priorsApplied"))
        .is_some();
    let rerank_present = get_val(rt, "rerank").or_else(|| get_val(rt, "reranker")).is_some();
    let candidates_present = matches!(get_val(rt, "candidates"), Some(Value::Array(_)));

    let anchors = get_val(rt, "anchors").or_else(|| get_val(rt, "anchoring"));
    let (anchors_present, anchors_ids_present, anchors_derivation_method_present) = match anchors {
        Some(Value::Map(am)) => {
            let ids_ok = matches!(
                get_val(am, "anchor_set_ids")
                    .or_else(|| get_val(am, "anchorSetIds"))
                    .or_else(|| get_val(am, "anchor_ids"))
                    .or_else(|| get_val(am, "anchorIds")),
                Some(Value::Array(_))
            );
            let method_ok = matches!(
                get_val(am, "derivation_method")
                    .or_else(|| get_val(am, "derivationMethod"))
                    .or_else(|| get_val(am, "method")),
                Some(Value::Text(_))
            );
            (true, ids_ok, method_ok)
        }
        _ => (false, false, false),
    };

    if !recompute_candidate_digest {
        return (
            VerificationTraceChecksV1 {
                retrieval_trace_present: true,
                lanes_used_present,
                candidate_generation_present,
                filters_present,
                normalisation_present,
                fusion_present,
                priors_applied_present,
                anchors_present,
                anchors_ids_present,
                anchors_derivation_method_present,
                rerank_present,
                candidates_present,
                candidate_digest_present,
                candidate_digest_matches_recompute: None,
            },
            candidate_digest.clone().map(|v| VerificationTraceSummaryV1 {
                candidate_digest: Some(v),
            }),
        );
    }

    let stored = parse_stored_candidate_digest_bytes_v1(rt);
    let recomputed = recompute_candidate_digest_bytes_v1(rt).ok();
    let matches = match (stored, recomputed) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };
    (
        VerificationTraceChecksV1 {
            retrieval_trace_present: true,
            lanes_used_present,
            candidate_generation_present,
            filters_present,
            normalisation_present,
            fusion_present,
            priors_applied_present,
            anchors_present,
            anchors_ids_present,
            anchors_derivation_method_present,
            rerank_present,
            candidates_present,
            candidate_digest_present,
            candidate_digest_matches_recompute: Some(matches),
        },
        candidate_digest.clone().map(|v| VerificationTraceSummaryV1 {
            candidate_digest: Some(v),
        }),
    )
}

fn get_val<'a>(
    map: &'a [(ciborium::value::Value, ciborium::value::Value)],
    key: &str,
) -> Option<&'a ciborium::value::Value> {
    use ciborium::value::Value;
    for (k, v) in map {
        if let Value::Text(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}

fn val_to_candidate_digest_string(v: &ciborium::value::Value) -> Option<String> {
    use ciborium::value::Value;
    match v {
        Value::Text(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Value::Bytes(b) => {
            if b.len() != 32 {
                return None;
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(b);
            Some(format!("blake3:hex:{}", hex32(&out)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring_v1::{Ed25519KeyEntryV1, Ed25519KeyRingV1};
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn test_build_info() -> corecrux_types::BuildInfo {
        corecrux_types::BuildInfo {
            version: "0.0.1-test".to_string(),
            commit: "test123".to_string(),
        }
    }

    fn make_body_and_hash() -> (Vec<u8>, [u8; 32]) {
        let body_val = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("schema".to_string()),
                ciborium::value::Value::Text("cuecrux.receipt.body.v1".to_string()),
            ),
            (
                ciborium::value::Value::Text("receipt_id".to_string()),
                ciborium::value::Value::Text("r-1".to_string()),
            ),
            (
                ciborium::value::Value::Text("tenant_id".to_string()),
                ciborium::value::Value::Text("t-1".to_string()),
            ),
        ]);
        let mut body_bytes = Vec::new();
        ciborium::ser::into_writer(&body_val, &mut body_bytes).unwrap();
        let hash = blake3::hash(&body_bytes);
        (body_bytes, *hash.as_bytes())
    }

    // ── VerifyErrorCodeV1 ───────────────────────────────────────────

    #[test]
    fn error_code_as_str_exhaustive() {
        assert_eq!(VerifyErrorCodeV1::Ok.as_str(), "OK");
        assert_eq!(VerifyErrorCodeV1::BodyHashMismatch.as_str(), "BODY_HASH_MISMATCH");
        assert_eq!(VerifyErrorCodeV1::BodyCborParseError.as_str(), "BODY_CBOR_PARSE_ERROR");
        assert_eq!(VerifyErrorCodeV1::SigMissing.as_str(), "SIG_MISSING");
        assert_eq!(VerifyErrorCodeV1::SigParseError.as_str(), "SIG_PARSE_ERROR");
        assert_eq!(VerifyErrorCodeV1::SigAlgUnsupported.as_str(), "SIG_ALG_UNSUPPORTED");
        assert_eq!(
            VerifyErrorCodeV1::SigReceiptIdMismatch.as_str(),
            "SIG_RECEIPT_ID_MISMATCH"
        );
        assert_eq!(
            VerifyErrorCodeV1::SigPayloadHashMismatch.as_str(),
            "SIG_PAYLOAD_HASH_MISMATCH"
        );
        assert_eq!(VerifyErrorCodeV1::KeyRingMissing.as_str(), "KEYRING_MISSING");
        assert_eq!(VerifyErrorCodeV1::KeyNotFound.as_str(), "KEY_NOT_FOUND");
        assert_eq!(VerifyErrorCodeV1::PubKeyInvalid.as_str(), "PUBKEY_INVALID");
        assert_eq!(VerifyErrorCodeV1::SigInvalid.as_str(), "SIG_INVALID");
    }

    // ── verify_receipt_v1: no sig ────────────────────────────────────

    #[test]
    fn verify_receipt_no_sig_returns_sig_missing() {
        let (body_bytes, hash) = make_body_and_hash();
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: None,
            keyring: None,
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "SIG_MISSING");
        assert!(!report.signature_valid);
        assert!(report.integrity.payload_hash_matches);
        assert!(report.integrity.canonical_bytes_parse_ok);
    }

    // ── verify_receipt_v1: hash mismatch + no sig ───────────────────

    #[test]
    fn verify_receipt_hash_mismatch_no_sig() {
        let (body_bytes, _hash) = make_body_and_hash();
        let bad_hash = [0xFFu8; 32];
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: bad_hash,
            sig_bytes: None,
            keyring: None,
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "BODY_HASH_MISMATCH");
        assert!(!report.integrity.payload_hash_matches);
    }

    // ── verify_receipt_v1: invalid sig CBOR ─────────────────────────

    #[test]
    fn verify_receipt_bad_sig_cbor() {
        let (body_bytes, hash) = make_body_and_hash();
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: Some(b"not valid cbor"),
            keyring: None,
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "SIG_PARSE_ERROR");
    }

    // ── verify_receipt_v1: full valid roundtrip ─────────────────────

    #[test]
    fn verify_receipt_valid_signature() {
        let (body_bytes, hash) = make_body_and_hash();
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        let sig64 = sk.sign(&body_bytes).to_bytes().to_vec();

        let sig = ReceiptSigV1 {
            schema: "cuecrux.receipt.sig.v1".to_string(),
            receipt_id: "r-1".to_string(),
            alg: "ed25519".to_string(),
            key_id: "k1".to_string(),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            signature: sig64,
            signed_payload_hash: hash.to_vec(),
        };
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes).unwrap();

        let keyring = Ed25519KeyRingV1 {
            v: 1,
            keys: vec![Ed25519KeyEntryV1 {
                key_id: "k1".to_string(),
                pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
            }],
        };

        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: Some(&sig_bytes),
            keyring: Some(&keyring),
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "OK");
        assert!(report.signature_valid);
        assert!(report.integrity.payload_hash_matches);
        assert!(report.pubkey_fingerprint.is_some());
    }

    // ── verify_receipt_v1: wrong receipt_id in sig ──────────────────

    #[test]
    fn verify_receipt_sig_receipt_id_mismatch() {
        let (body_bytes, hash) = make_body_and_hash();
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let sig64 = sk.sign(&body_bytes).to_bytes().to_vec();

        let sig = ReceiptSigV1 {
            schema: "cuecrux.receipt.sig.v1".to_string(),
            receipt_id: "WRONG-ID".to_string(),
            alg: "ed25519".to_string(),
            key_id: "k1".to_string(),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            signature: sig64,
            signed_payload_hash: hash.to_vec(),
        };
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes).unwrap();

        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: Some(&sig_bytes),
            keyring: None,
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "SIG_RECEIPT_ID_MISMATCH");
    }

    // ── verify_receipt_v1: unsupported alg ──────────────────────────

    #[test]
    fn verify_receipt_unsupported_alg() {
        let (body_bytes, hash) = make_body_and_hash();
        let sig = ReceiptSigV1 {
            schema: "cuecrux.receipt.sig.v1".to_string(),
            receipt_id: "r-1".to_string(),
            alg: "rsa256".to_string(),
            key_id: "k1".to_string(),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            signature: vec![0u8; 64],
            signed_payload_hash: hash.to_vec(),
        };
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes).unwrap();

        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: Some(&sig_bytes),
            keyring: None,
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "SIG_ALG_UNSUPPORTED");
    }

    // ── verify_receipt_v1: no keyring ───────────────────────────────

    #[test]
    fn verify_receipt_keyring_missing() {
        let (body_bytes, hash) = make_body_and_hash();
        let sig = ReceiptSigV1 {
            schema: "cuecrux.receipt.sig.v1".to_string(),
            receipt_id: "r-1".to_string(),
            alg: "ed25519".to_string(),
            key_id: "k1".to_string(),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            signature: vec![0u8; 64],
            signed_payload_hash: hash.to_vec(),
        };
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes).unwrap();

        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: Some(&sig_bytes),
            keyring: None,
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "KEYRING_MISSING");
    }

    // ── verify_receipt_v1: key not found ────────────────────────────

    #[test]
    fn verify_receipt_key_not_found() {
        let (body_bytes, hash) = make_body_and_hash();
        let sig = ReceiptSigV1 {
            schema: "cuecrux.receipt.sig.v1".to_string(),
            receipt_id: "r-1".to_string(),
            alg: "ed25519".to_string(),
            key_id: "missing-key".to_string(),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            signature: vec![0u8; 64],
            signed_payload_hash: hash.to_vec(),
        };
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes).unwrap();

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        let keyring = Ed25519KeyRingV1 {
            v: 1,
            keys: vec![Ed25519KeyEntryV1 {
                key_id: "different-key".to_string(),
                pub_key_base64: base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()),
            }],
        };

        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: Some(&sig_bytes),
            keyring: Some(&keyring),
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "KEY_NOT_FOUND");
    }

    // ── verify_receipt_v1: payload hash mismatch in sig ─────────────

    #[test]
    fn verify_receipt_sig_payload_hash_mismatch() {
        let (body_bytes, hash) = make_body_and_hash();
        let sig = ReceiptSigV1 {
            schema: "cuecrux.receipt.sig.v1".to_string(),
            receipt_id: "r-1".to_string(),
            alg: "ed25519".to_string(),
            key_id: "k1".to_string(),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            signature: vec![0u8; 64],
            signed_payload_hash: vec![0xAAu8; 32], // different from hash
        };
        let mut sig_bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut sig_bytes).unwrap();

        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: Some(&sig_bytes),
            keyring: None,
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "SIG_PAYLOAD_HASH_MISMATCH");
    }

    // ── hex32 ───────────────────────────────────────────────────────

    #[test]
    fn hex32_produces_64_char_hex() {
        let bytes = [0u8; 32];
        assert_eq!(hex32(&bytes), "0".repeat(64));
        let bytes = [0xFFu8; 32];
        assert_eq!(hex32(&bytes), "f".repeat(64));
    }

    // ── VerificationReportV1 serde roundtrip ────────────────────────

    #[test]
    fn verification_report_serde_roundtrip() {
        let report = VerificationReportV1 {
            schema: "cuecrux.receipt.verify.v1".to_string(),
            receipt_id: "r-1".to_string(),
            tenant_id: "t-1".to_string(),
            payload_hash_hex: "aa".repeat(32),
            signature: VerificationSigInfoV1 {
                alg: "ed25519".to_string(),
                key_id: Some("k1".to_string()),
            },
            integrity: VerificationIntegrityV1 {
                payload_hash_matches: true,
                canonical_bytes_parse_ok: true,
            },
            binding: Default::default(),
            trace_checks: VerificationTraceChecksV1::default(),
            trace_summary: None,
            signature_valid: true,
            pubkey_fingerprint: Some("abc".to_string()),
            error_code: "OK".to_string(),
            error_message: None,
            verified_at: "2026-01-01T00:00:00Z".to_string(),
            verifier_build: "0.0.1@test".to_string(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: VerificationReportV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.receipt_id, "r-1");
        assert_eq!(parsed.error_code, "OK");
        assert!(parsed.signature_valid);
    }

    // ── ReceiptSigV1 serde roundtrip ────────────────────────────────

    #[test]
    fn receipt_sig_cbor_roundtrip() {
        let sig = ReceiptSigV1 {
            schema: "cuecrux.receipt.sig.v1".to_string(),
            receipt_id: "r-test".to_string(),
            alg: "ed25519".to_string(),
            key_id: "k-test".to_string(),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            signature: vec![1, 2, 3, 4],
            signed_payload_hash: vec![5, 6, 7, 8],
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&sig, &mut bytes).unwrap();
        let parsed: ReceiptSigV1 = ciborium::de::from_reader(std::io::Cursor::new(&bytes)).unwrap();
        assert_eq!(parsed.receipt_id, "r-test");
        assert_eq!(parsed.alg, "ed25519");
        assert_eq!(parsed.signature, vec![1, 2, 3, 4]);
    }

    // ── val_to_candidate_digest_string ──────────────────────────────

    #[test]
    fn val_to_digest_text() {
        let v = ciborium::value::Value::Text("digest_value".to_string());
        assert_eq!(val_to_candidate_digest_string(&v), Some("digest_value".to_string()));
    }

    #[test]
    fn val_to_digest_empty_text() {
        let v = ciborium::value::Value::Text("   ".to_string());
        assert_eq!(val_to_candidate_digest_string(&v), None);
    }

    #[test]
    fn val_to_digest_bytes_32() {
        let v = ciborium::value::Value::Bytes(vec![0xABu8; 32]);
        let result = val_to_candidate_digest_string(&v).unwrap();
        assert!(result.starts_with("blake3:hex:"));
        assert_eq!(result.len(), "blake3:hex:".len() + 64);
    }

    #[test]
    fn val_to_digest_bytes_wrong_len() {
        let v = ciborium::value::Value::Bytes(vec![0xABu8; 16]);
        assert_eq!(val_to_candidate_digest_string(&v), None);
    }

    #[test]
    fn val_to_digest_integer_returns_none() {
        let v = ciborium::value::Value::Integer(42.into());
        assert_eq!(val_to_candidate_digest_string(&v), None);
    }

    // ── VerificationTraceChecksV1 default ───────────────────────────

    #[test]
    fn trace_checks_default_all_false() {
        let tc = VerificationTraceChecksV1::default();
        assert!(!tc.retrieval_trace_present);
        assert!(!tc.lanes_used_present);
        assert!(!tc.candidate_generation_present);
        assert!(!tc.filters_present);
        assert!(!tc.normalisation_present);
        assert!(!tc.fusion_present);
        assert!(!tc.priors_applied_present);
        assert!(!tc.anchors_present);
        assert!(!tc.anchors_ids_present);
        assert!(!tc.anchors_derivation_method_present);
        assert!(!tc.rerank_present);
        assert!(!tc.candidates_present);
        assert!(!tc.candidate_digest_present);
        assert!(tc.candidate_digest_matches_recompute.is_none());
    }

    // ── helpers for the mutation-killing tests below ────────────────

    fn keyring_with(key_id: &str, pub_key_base64: &str) -> Ed25519KeyRingV1 {
        Ed25519KeyRingV1 {
            v: 1,
            keys: vec![Ed25519KeyEntryV1 {
                key_id: key_id.to_string(),
                pub_key_base64: pub_key_base64.to_string(),
            }],
        }
    }

    fn encode_sig(sig: &ReceiptSigV1) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::ser::into_writer(sig, &mut b).unwrap();
        b
    }

    fn sig_over(receipt_id: &str, hash: [u8; 32], signature: Vec<u8>) -> ReceiptSigV1 {
        ReceiptSigV1 {
            schema: "cuecrux.receipt.sig.v1".to_string(),
            receipt_id: receipt_id.to_string(),
            alg: "ed25519".to_string(),
            key_id: "k1".to_string(),
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            signature,
            signed_payload_hash: hash.to_vec(),
        }
    }

    // Deterministically find a 32-byte value that is NOT a valid Ed25519
    // compressed point, so `VerifyingKey::from_bytes` rejects it.
    fn invalid_ed25519_point() -> [u8; 32] {
        for seed in 0u32..=1_000_000 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&seed.to_le_bytes());
            if VerifyingKey::from_bytes(&b).is_err() {
                return b;
            }
        }
        panic!("no invalid compressed point found in search range");
    }

    // ── error_message discipline (no spurious payload-mismatch text) ─

    #[test]
    fn verify_receipt_no_sig_matching_hash_has_no_error_message() {
        // Sig missing but the body hash matches: there must be NO payload-hash
        // error message. Pins the `if !payload_hash_matches` guard on the
        // err_msg assignment in the no-sig branch.
        let (body_bytes, hash) = make_body_and_hash();
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: None,
            keyring: None,
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "SIG_MISSING");
        assert!(report.error_message.is_none(), "unexpected: {:?}", report.error_message);
    }

    #[test]
    fn verify_receipt_valid_signature_has_no_error_message() {
        // On a fully-valid OK verification, error_message must be absent. Pins
        // the `err == BodyCborParseError` check (mutating to `!=` would attach a
        // spurious "not valid CBOR" message to OK results).
        let (body_bytes, hash) = make_body_and_hash();
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        let sig = sig_over("r-1", hash, sk.sign(&body_bytes).to_bytes().to_vec());
        let sig_bytes = encode_sig(&sig);
        let keyring = keyring_with("k1", &base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()));
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: Some(&sig_bytes),
            keyring: Some(&keyring),
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "OK");
        assert!(report.signature_valid);
        assert!(report.error_message.is_none(), "unexpected: {:?}", report.error_message);
    }

    #[test]
    fn verify_receipt_bad_signature_matching_hash_reports_sig_error_not_payload_mismatch() {
        // A 64-byte but bogus signature over a body whose hash matches: the
        // failure is SIG_INVALID and the message is the signature error, never
        // the payload-hash-mismatch text. Pins the `if !payload_hash_matches`
        // guard in the verify-failed branch.
        let (body_bytes, hash) = make_body_and_hash();
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        let sig = sig_over("r-1", hash, vec![0u8; 64]); // wrong signature
        let sig_bytes = encode_sig(&sig);
        let keyring = keyring_with("k1", &base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()));
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: Some(&sig_bytes),
            keyring: Some(&keyring),
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "SIG_INVALID");
        assert!(report.integrity.payload_hash_matches);
        let msg = report.error_message.expect("sig-invalid carries a message");
        assert!(!msg.contains("payload_hash mismatch"), "unexpected: {msg}");
    }

    // ── pubkey / signature validation (fail-closed, hash matching) ──

    #[test]
    fn verify_receipt_pubkey_invalid_when_keyring_undecodable() {
        // Keyring pubkey is not valid base64 → to_index_map fails. With a
        // matching body hash the code must be PUBKEY_INVALID, not
        // BODY_HASH_MISMATCH. Pins the `if !payload_hash_matches` guard.
        let (body_bytes, hash) = make_body_and_hash();
        let sig = sig_over("r-1", hash, vec![0u8; 64]);
        let sig_bytes = encode_sig(&sig);
        let keyring = keyring_with("k1", "!!! not base64 !!!");
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: Some(&sig_bytes),
            keyring: Some(&keyring),
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "PUBKEY_INVALID");
        assert!(report.integrity.payload_hash_matches);
    }

    #[test]
    fn verify_receipt_pubkey_invalid_when_point_off_curve() {
        // Keyring pubkey decodes to 32 bytes but is not a valid curve point →
        // VerifyingKey::from_bytes fails. Matching hash → PUBKEY_INVALID. Pins
        // the `if !payload_hash_matches` guard at the from_bytes error branch.
        let (body_bytes, hash) = make_body_and_hash();
        let sig = sig_over("r-1", hash, vec![0u8; 64]);
        let sig_bytes = encode_sig(&sig);
        let bad = invalid_ed25519_point();
        let keyring = keyring_with("k1", &base64::engine::general_purpose::STANDARD.encode(bad));
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: Some(&sig_bytes),
            keyring: Some(&keyring),
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "PUBKEY_INVALID");
        assert!(report.integrity.payload_hash_matches);
    }

    #[test]
    fn verify_receipt_sig_invalid_when_signature_length_wrong() {
        // Valid keyring + key + pubkey, but the signature is not 64 bytes.
        // Matching hash → SIG_INVALID, not BODY_HASH_MISMATCH. Pins the
        // `if !payload_hash_matches` guard at the length-check branch.
        let (body_bytes, hash) = make_body_and_hash();
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        let sig = sig_over("r-1", hash, vec![0u8; 10]); // length != 64
        let sig_bytes = encode_sig(&sig);
        let keyring = keyring_with("k1", &base64::engine::general_purpose::STANDARD.encode(vk.as_bytes()));
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body_bytes,
            stored_body_payload_hash: hash,
            sig_bytes: Some(&sig_bytes),
            keyring: Some(&keyring),
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert_eq!(report.error_code, "SIG_INVALID");
        assert!(report.integrity.payload_hash_matches);
    }

    // ── compute_trace_checks: recompute flag + anchors arm ──────────

    fn recompute_matches_flag(body: &[u8]) -> Option<bool> {
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: body,
            stored_body_payload_hash: *blake3::hash(body).as_bytes(),
            sig_bytes: None,
            keyring: None,
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: true,
        })
        .unwrap();
        report.trace_checks.candidate_digest_matches_recompute
    }

    #[test]
    fn recompute_flag_is_some_false_when_body_unparsable() {
        // Genuinely invalid CBOR → the parsed_body None branch. With recompute
        // requested the field must be Some(false), not defaulted to None.
        // Gotcha: an ASCII string like b"not cbor at all" can accidentally be
        // VALID CBOR (0x6e is a 14-byte text-string header), which decodes as
        // Text and lands in the not-a-Map branch instead. A bare 0xff break
        // byte is never valid at the top level.
        assert_eq!(recompute_matches_flag(&[0xff]), Some(false));
    }

    #[test]
    fn recompute_flag_is_some_false_when_body_not_a_map() {
        // CBOR that parses but is not a Map → the not-a-map branch.
        let mut body = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Integer(7.into()), &mut body).unwrap();
        assert_eq!(recompute_matches_flag(&body), Some(false));
    }

    #[test]
    fn recompute_flag_is_some_false_when_no_retrieval_trace() {
        // A Map body with no retrieval_trace → the no-retrieval branch.
        let (body_bytes, _hash) = make_body_and_hash();
        assert_eq!(recompute_matches_flag(&body_bytes), Some(false));
    }

    #[test]
    fn trace_checks_detect_anchors_map() {
        use ciborium::value::Value;
        // retrieval_trace.anchors is a Map with ids + derivation method: the
        // `Some(Value::Map(am))` arm must report all three anchor flags true.
        // Deleting that arm collapses to (false, false, false).
        let anchors = Value::Map(vec![
            (
                Value::Text("anchor_set_ids".to_string()),
                Value::Array(vec![Value::Text("a1".to_string())]),
            ),
            (
                Value::Text("derivation_method".to_string()),
                Value::Text("merkle".to_string()),
            ),
        ]);
        let rt = Value::Map(vec![(Value::Text("anchors".to_string()), anchors)]);
        let body_val = Value::Map(vec![
            (
                Value::Text("schema".to_string()),
                Value::Text("cuecrux.receipt.body.v1".to_string()),
            ),
            (Value::Text("retrieval_trace".to_string()), rt),
        ]);
        let mut body = Vec::new();
        ciborium::ser::into_writer(&body_val, &mut body).unwrap();
        let build = test_build_info();
        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id: "t-1",
            receipt_id: "r-1",
            body_bytes: &body,
            stored_body_payload_hash: *blake3::hash(&body).as_bytes(),
            sig_bytes: None,
            keyring: None,
            verified_at: "2026-01-01T00:00:00Z",
            verifier_build: &build,
            recompute_candidate_digest: false,
        })
        .unwrap();
        assert!(report.trace_checks.anchors_present);
        assert!(report.trace_checks.anchors_ids_present);
        assert!(report.trace_checks.anchors_derivation_method_present);
    }
}
