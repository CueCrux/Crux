// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use crate::candidate_digest_v1::{
    parse_stored_candidate_digest_bytes_v1, recompute_candidate_digest_bytes_v1,
};
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
    #[serde(rename = "trace_checks", default)]
    pub trace_checks: VerificationTraceChecksV1,
    /// Best-effort extracted trace values from the receipt body (for drift tools).
    ///
    /// This is additive metadata; the canonical truth is always the stored receipt body bytes.
    #[serde(
        rename = "trace_summary",
        skip_serializing_if = "Option::is_none",
        default
    )]
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
    #[serde(
        rename = "candidate_digest",
        skip_serializing_if = "Option::is_none",
        default
    )]
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

pub fn verify_receipt_v1(
    input: VerifyReceiptInput<'_>,
) -> Result<VerificationReportV1, VerifyError> {
    let computed = blake3::hash(input.body_bytes);
    let payload_hash_matches = computed.as_bytes() == &input.stored_body_payload_hash;

    // Optional parseability check: we only care that it's valid CBOR; canonical-form checks are
    // explicitly producer-side in Phase 8.
    let mut parsed_body: Option<ciborium::value::Value> = None;
    let canonical_bytes_parse_ok = match ciborium::de::from_reader::<ciborium::value::Value, _>(
        std::io::Cursor::new(input.body_bytes),
    ) {
        Ok(v) => {
            parsed_body = Some(v);
            true
        }
        Err(_) => false,
    };

    let (trace_checks, trace_summary) =
        compute_trace_checks(parsed_body.as_ref(), input.recompute_candidate_digest);

    // Report the stored header payloadHash; this is the anchor value exported and indexed by CoreCrux.
    let payload_hash_hex = hex32(&input.stored_body_payload_hash);
    let verifier_build = format!(
        "{}@{}",
        input.verifier_build.version, input.verifier_build.commit
    );

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

    sig_info.alg = sig.alg.clone();
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

    if sig.signed_payload_hash.len() != 32
        || sig.signed_payload_hash.as_slice() != input.stored_body_payload_hash
    {
        err = if !payload_hash_matches {
            VerifyErrorCodeV1::BodyHashMismatch
        } else {
            VerifyErrorCodeV1::SigPayloadHashMismatch
        };
        err_msg = Some(format!(
            "signed_payload_hash mismatch: expected {} got {}",
            hex32(&input.stored_body_payload_hash),
            if sig.signed_payload_hash.len() == 32 {
                hex32(sig.signed_payload_hash.as_slice().try_into().unwrap())
            } else {
                format!("len({})", sig.signed_payload_hash.len())
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
) -> (
    VerificationTraceChecksV1,
    Option<VerificationTraceSummaryV1>,
) {
    use ciborium::value::Value;

    let Some(parsed_body) = parsed_body else {
        return (
            VerificationTraceChecksV1 {
                candidate_digest_matches_recompute: if recompute_candidate_digest {
                    Some(false)
                } else {
                    None
                },
                ..Default::default()
            },
            None,
        );
    };

    let Value::Map(map) = parsed_body else {
        return (
            VerificationTraceChecksV1 {
                candidate_digest_matches_recompute: if recompute_candidate_digest {
                    Some(false)
                } else {
                    None
                },
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
                candidate_digest_matches_recompute: if recompute_candidate_digest {
                    Some(false)
                } else {
                    None
                },
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
    let rerank_present = get_val(rt, "rerank")
        .or_else(|| get_val(rt, "reranker"))
        .is_some();
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
            candidate_digest
                .clone()
                .map(|v| VerificationTraceSummaryV1 {
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
        candidate_digest
            .clone()
            .map(|v| VerificationTraceSummaryV1 {
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
        assert_eq!(VerifyErrorCodeV1::SigReceiptIdMismatch.as_str(), "SIG_RECEIPT_ID_MISMATCH");
        assert_eq!(VerifyErrorCodeV1::SigPayloadHashMismatch.as_str(), "SIG_PAYLOAD_HASH_MISMATCH");
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
                pub_key_base64: base64::engine::general_purpose::STANDARD
                    .encode(vk.as_bytes()),
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
                pub_key_base64: base64::engine::general_purpose::STANDARD
                    .encode(vk.as_bytes()),
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
        let parsed: ReceiptSigV1 =
            ciborium::de::from_reader(std::io::Cursor::new(&bytes)).unwrap();
        assert_eq!(parsed.receipt_id, "r-test");
        assert_eq!(parsed.alg, "ed25519");
        assert_eq!(parsed.signature, vec![1, 2, 3, 4]);
    }

    // ── val_to_candidate_digest_string ──────────────────────────────

    #[test]
    fn val_to_digest_text() {
        let v = ciborium::value::Value::Text("digest_value".to_string());
        assert_eq!(
            val_to_candidate_digest_string(&v),
            Some("digest_value".to_string())
        );
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
}
