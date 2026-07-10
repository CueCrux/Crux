// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Default-off witness/TSA runtime preflight.
//!
//! This module deliberately performs local configuration and trust-root checks
//! only. M3 needs an operator-smokeable scaffold before any live Rekor or TSA
//! network submission path is enabled.

use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, serde::Serialize)]
pub struct WitnessRuntimeStatusV1 {
    pub ok: bool,
    pub mode: &'static str,
    pub witness: WitnessProviderStatusV1,
    pub tsa: TsaProviderStatusV1,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WitnessProviderStatusV1 {
    pub enabled: bool,
    pub provider: String,
    pub timeout_ms: u64,
    pub configured: bool,
    pub ok: bool,
    pub rekor_url: Option<String>,
    pub rekor_public_key_path: Option<String>,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TsaProviderStatusV1 {
    pub enabled: bool,
    pub configured: bool,
    pub ok: bool,
    pub tsa_url: Option<String>,
    pub tsa_root_cert_path: Option<String>,
    pub tsa_root_cert_sha256_fingerprints: Vec<String>,
    pub tsa_root_cert_count: usize,
    pub tsa_policy_oid: Option<String>,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WitnessRuntimeConfigV1 {
    pub witness_enabled: bool,
    pub witness_provider: String,
    pub witness_timeout_ms: u64,
    pub rekor_url: Option<String>,
    pub rekor_public_key_path: Option<PathBuf>,
    pub tsa_enabled: bool,
    pub tsa_url: Option<String>,
    pub tsa_root_cert_path: Option<PathBuf>,
    pub tsa_policy_oid: Option<String>,
}

impl WitnessRuntimeConfigV1 {
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self {
            witness_enabled: config.witness_enabled,
            witness_provider: config.witness_provider.clone(),
            witness_timeout_ms: config.witness_timeout_ms,
            rekor_url: config.rekor_url.clone(),
            rekor_public_key_path: config.rekor_public_key_path.clone(),
            tsa_enabled: config.tsa_enabled,
            tsa_url: config.tsa_url.clone(),
            tsa_root_cert_path: config.tsa_root_cert_path.clone(),
            tsa_policy_oid: config.tsa_policy_oid.clone(),
        }
    }

    #[cfg(test)]
    pub fn disabled() -> Self {
        Self {
            witness_enabled: false,
            witness_provider: "disabled".to_string(),
            witness_timeout_ms: 5_000,
            rekor_url: None,
            rekor_public_key_path: None,
            tsa_enabled: false,
            tsa_url: None,
            tsa_root_cert_path: None,
            tsa_policy_oid: None,
        }
    }

    pub fn smoke_report(&self) -> WitnessRuntimeStatusV1 {
        let mut warnings = Vec::new();
        let witness = self.witness_status(&mut warnings);
        let tsa = self.tsa_status(&mut warnings);
        WitnessRuntimeStatusV1 {
            ok: witness.ok && tsa.ok,
            mode: "local_config_only",
            witness,
            tsa,
            warnings,
        }
    }

    fn witness_status(&self, warnings: &mut Vec<String>) -> WitnessProviderStatusV1 {
        if !self.witness_enabled {
            return WitnessProviderStatusV1 {
                enabled: false,
                provider: self.witness_provider.clone(),
                timeout_ms: self.witness_timeout_ms,
                configured: false,
                ok: true,
                rekor_url: self.rekor_url.clone(),
                rekor_public_key_path: path_string(self.rekor_public_key_path.as_deref()),
                failure_reason: None,
            };
        }

        if self.witness_timeout_ms == 0 {
            return WitnessProviderStatusV1 {
                enabled: true,
                provider: self.witness_provider.clone(),
                timeout_ms: self.witness_timeout_ms,
                configured: false,
                ok: false,
                rekor_url: self.rekor_url.clone(),
                rekor_public_key_path: path_string(self.rekor_public_key_path.as_deref()),
                failure_reason: Some("CORECRUXD_WITNESS_TIMEOUT_MS must be greater than zero".to_string()),
            };
        }

        if !self.witness_provider.trim().eq_ignore_ascii_case("rekor") {
            return WitnessProviderStatusV1 {
                enabled: true,
                provider: self.witness_provider.clone(),
                timeout_ms: self.witness_timeout_ms,
                configured: false,
                ok: false,
                rekor_url: self.rekor_url.clone(),
                rekor_public_key_path: path_string(self.rekor_public_key_path.as_deref()),
                failure_reason: Some(format!("unsupported witness provider: {}", self.witness_provider)),
            };
        }
        if self.rekor_url.as_deref().is_none_or(str::is_empty) {
            return WitnessProviderStatusV1 {
                enabled: true,
                provider: self.witness_provider.clone(),
                timeout_ms: self.witness_timeout_ms,
                configured: false,
                ok: false,
                rekor_url: self.rekor_url.clone(),
                rekor_public_key_path: path_string(self.rekor_public_key_path.as_deref()),
                failure_reason: Some("CORECRUXD_REKOR_URL is required when Rekor witness is enabled".to_string()),
            };
        }
        if self.rekor_url.as_deref().is_some_and(|url| !looks_https_url(url)) {
            warnings.push("Rekor witness URL is not HTTPS; use only for local/non-prod mocks".to_string());
        }
        if let Some(path) = &self.rekor_public_key_path {
            if !path.is_file() {
                return WitnessProviderStatusV1 {
                    enabled: true,
                    provider: self.witness_provider.clone(),
                    timeout_ms: self.witness_timeout_ms,
                    configured: false,
                    ok: false,
                    rekor_url: self.rekor_url.clone(),
                    rekor_public_key_path: path_string(Some(path)),
                    failure_reason: Some(format!("Rekor public key path is not readable: {}", path.display())),
                };
            }
        } else {
            warnings.push("Rekor witness is enabled without CORECRUXD_REKOR_PUBLIC_KEY_PATH".to_string());
        }

        WitnessProviderStatusV1 {
            enabled: true,
            provider: self.witness_provider.clone(),
            timeout_ms: self.witness_timeout_ms,
            configured: true,
            ok: true,
            rekor_url: self.rekor_url.clone(),
            rekor_public_key_path: path_string(self.rekor_public_key_path.as_deref()),
            failure_reason: None,
        }
    }

    fn tsa_status(&self, warnings: &mut Vec<String>) -> TsaProviderStatusV1 {
        if !self.tsa_enabled {
            return TsaProviderStatusV1 {
                enabled: false,
                configured: false,
                ok: true,
                tsa_url: self.tsa_url.clone(),
                tsa_root_cert_path: path_string(self.tsa_root_cert_path.as_deref()),
                tsa_root_cert_sha256_fingerprints: Vec::new(),
                tsa_root_cert_count: 0,
                tsa_policy_oid: self.tsa_policy_oid.clone(),
                failure_reason: None,
            };
        }
        if self.tsa_url.as_deref().is_none_or(str::is_empty) {
            return self.tsa_fail("CORECRUXD_TSA_URL is required when TSA is enabled", 0);
        }
        if self.tsa_url.as_deref().is_some_and(|url| !looks_https_url(url)) {
            warnings.push("TSA URL is not HTTPS; use only for local/non-prod mocks".to_string());
        }
        if let Some(policy_oid) = &self.tsa_policy_oid {
            if !corecrux_receipts::is_valid_object_identifier_text_v1(policy_oid) {
                return self.tsa_fail("CORECRUXD_TSA_POLICY_OID must be a valid dotted object identifier", 0);
            }
        }
        let Some(root_path) = self.tsa_root_cert_path.as_ref() else {
            return self.tsa_fail("CORECRUXD_TSA_ROOT_CERT_PATH is required when TSA is enabled", 0);
        };
        let cert_bytes = match std::fs::read(root_path) {
            Ok(bytes) => bytes,
            Err(err) => {
                return self.tsa_fail(
                    &format!("failed to read TSA root certificate {}: {err}", root_path.display()),
                    0,
                )
            }
        };
        let certs = match corecrux_receipts::parse_x509_certs_der_or_pem_v1(&cert_bytes) {
            Ok(certs) => certs,
            Err(err) => {
                return self.tsa_fail(
                    &format!("failed to parse TSA root certificate {}: {err}", root_path.display()),
                    0,
                )
            }
        };
        let fingerprints = certs
            .iter()
            .map(|cert| format!("sha256:{}", sha256_hex(cert)))
            .collect::<Vec<_>>();
        TsaProviderStatusV1 {
            enabled: true,
            configured: true,
            ok: true,
            tsa_url: self.tsa_url.clone(),
            tsa_root_cert_path: path_string(Some(root_path)),
            tsa_root_cert_sha256_fingerprints: fingerprints,
            tsa_root_cert_count: certs.len(),
            tsa_policy_oid: self.tsa_policy_oid.clone(),
            failure_reason: None,
        }
    }

    fn tsa_fail(&self, reason: &str, tsa_root_cert_count: usize) -> TsaProviderStatusV1 {
        TsaProviderStatusV1 {
            enabled: true,
            configured: false,
            ok: false,
            tsa_url: self.tsa_url.clone(),
            tsa_root_cert_path: path_string(self.tsa_root_cert_path.as_deref()),
            tsa_root_cert_sha256_fingerprints: Vec::new(),
            tsa_root_cert_count,
            tsa_policy_oid: self.tsa_policy_oid.clone(),
            failure_reason: Some(reason.to_string()),
        }
    }
}

fn path_string(path: Option<&Path>) -> Option<String> {
    path.map(|p| p.display().to_string())
}

fn looks_https_url(url: &str) -> bool {
    url.trim_start().starts_with("https://")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_witness_and_tsa_are_smoke_ok() {
        let report = WitnessRuntimeConfigV1::disabled().smoke_report();
        assert!(report.ok);
        assert!(!report.witness.enabled);
        assert!(!report.tsa.enabled);
    }

    #[test]
    fn enabled_tsa_requires_root_cert_path() {
        let cfg = WitnessRuntimeConfigV1 {
            tsa_enabled: true,
            tsa_url: Some("https://tsa.example".to_string()),
            ..WitnessRuntimeConfigV1::disabled()
        };
        let report = cfg.smoke_report();
        assert!(!report.ok);
        assert!(report
            .tsa
            .failure_reason
            .as_deref()
            .unwrap_or("")
            .contains("CORECRUXD_TSA_ROOT_CERT_PATH"));
    }

    #[test]
    fn enabled_witness_requires_positive_timeout() {
        let cfg = WitnessRuntimeConfigV1 {
            witness_enabled: true,
            witness_provider: "rekor".to_string(),
            witness_timeout_ms: 0,
            rekor_url: Some("https://rekor.example".to_string()),
            ..WitnessRuntimeConfigV1::disabled()
        };
        let report = cfg.smoke_report();
        assert!(!report.ok);
        assert_eq!(
            report.witness.failure_reason.as_deref(),
            Some("CORECRUXD_WITNESS_TIMEOUT_MS must be greater than zero")
        );
    }

    #[test]
    fn enabled_tsa_rejects_malformed_policy_oid() {
        let cfg = WitnessRuntimeConfigV1 {
            tsa_enabled: true,
            tsa_url: Some("https://tsa.example".to_string()),
            tsa_root_cert_path: Some(PathBuf::from("/tmp/tsa-root.pem")),
            tsa_policy_oid: Some("not-an-oid".to_string()),
            ..WitnessRuntimeConfigV1::disabled()
        };
        let report = cfg.smoke_report();
        assert!(!report.ok);
        assert_eq!(
            report.tsa.failure_reason.as_deref(),
            Some("CORECRUXD_TSA_POLICY_OID must be a valid dotted object identifier")
        );
        assert!(report.tsa.tsa_root_cert_sha256_fingerprints.is_empty());
    }

    #[test]
    fn enabled_non_https_provider_urls_are_warnings_only() {
        let cfg = WitnessRuntimeConfigV1 {
            witness_enabled: true,
            witness_provider: "rekor".to_string(),
            rekor_url: Some("http://127.0.0.1:3000".to_string()),
            tsa_enabled: true,
            tsa_url: Some("http://127.0.0.1:3001".to_string()),
            tsa_policy_oid: Some("not-an-oid".to_string()),
            ..WitnessRuntimeConfigV1::disabled()
        };
        let report = cfg.smoke_report();
        assert!(!report.ok);
        assert!(report
            .warnings
            .contains(&"Rekor witness URL is not HTTPS; use only for local/non-prod mocks".to_string()));
        assert!(report
            .warnings
            .contains(&"TSA URL is not HTTPS; use only for local/non-prod mocks".to_string()));
    }
}
