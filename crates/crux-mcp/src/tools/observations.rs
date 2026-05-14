// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! MCP tool handlers for session observations: `list_observations`,
//! `get_observation`, `verify_observation`.
//!
//! These are the read-and-verify side of the multi-provider capture system
//! shipped in Phase 1
//! (`PlanCrux/.agent/execplans/crux-daemon-session-observations-multi-provider-2026-05-13.md`).
//! The daemon already writes signed observations as JSONL under
//! `<data_dir>/observations/<scoped_session_id>.jsonl`; these tools let
//! agents and IDE plugins query and verify those records without going
//! through HTTP.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};
use crate::scope;

const OBS_SUBDIR: &str = "observations";
const DEFAULT_LIST_LIMIT: usize = 50;
const MAX_LIST_LIMIT: usize = 500;

// ── Param helpers ─────────────────────────────────────────────────────────

fn require_str(args: &Value, key: &str) -> Result<String, JsonRpcError> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("missing required param: {key}"),
            data: Some(json!({"param": key, "required": true})),
        })
}

fn require_data_dir(ctx: &McpContext) -> Result<&Path, JsonRpcError> {
    ctx.data_dir.as_deref().ok_or_else(|| JsonRpcError {
        code: INTERNAL_ERROR,
        message: "data_dir not configured on MCP context".to_string(),
        data: Some(json!({"hint": "this is a daemon misconfiguration, not a caller error"})),
    })
}

// ── Path + IO helpers (mirror http::observations) ─────────────────────────

fn sanitize_session_id_for_filename(session_id: &str) -> String {
    session_id
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .collect()
}

fn observation_file_path(data_dir: &Path, scoped_session_id: &str) -> PathBuf {
    let filename = format!("{}.jsonl", sanitize_session_id_for_filename(scoped_session_id));
    data_dir.join(OBS_SUBDIR).join(filename)
}

fn read_jsonl(path: &Path) -> Result<Vec<Value>, JsonRpcError> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    let file = match File::open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(JsonRpcError {
                code: INTERNAL_ERROR,
                message: format!("open observation file: {err}"),
                data: Some(json!({"path": path.display().to_string()})),
            })
        }
    };
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|err| JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!("read line: {err}"),
            data: None,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(&line) {
            out.push(value);
        }
    }
    Ok(out)
}

// ── Canonicalisation + verification (mirror http::observations) ───────────

fn strip_receipt_and_serialise(record: &Value) -> Result<Vec<u8>, JsonRpcError> {
    let mut working = record.clone();
    if let Value::Object(obj) = &mut working {
        obj.remove("receipt");
    }
    serde_json::to_vec(&working).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("canonicalise: {err}"),
        data: None,
    })
}

#[derive(Debug)]
struct VerifyResult {
    hash_match: bool,
    signature_valid: bool,
    recomputed_hash: String,
    receipt_hash: String,
    reason: Option<String>,
}

/// Result of `validate_chain`: maps directly to corecruxd's `ChainStatus`
/// but lives here independently so the MCP crate doesn't depend on
/// corecruxd's internals.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChainOutcome {
    /// Where this record sits relative to the chain.
    record_status: ChainRecordStatus,
    /// Whole-file chain status, for context.
    file_status: ChainFileStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChainRecordStatus {
    Legacy,
    Chained {
        seq: u64,
    },
    /// The record's chain link is broken (seq gap or prev_hash mismatch).
    Broken {
        reason: String,
    },
    /// Record not present in the supplied JSONL — verify against record
    /// alone, can't assess chain.
    NotInFile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChainFileStatus {
    NoChain,
    Ok {
        legacy_prefix_len: usize,
        chained_len: usize,
    },
    Broken {
        at_index: usize,
        reason: String,
    },
}

fn validate_chain(records: &[Value], target_observation_id: &str) -> ChainOutcome {
    let mut legacy_prefix_len = 0usize;
    let mut chain_started = false;
    let mut last_seq: Option<u64> = None;
    let mut last_hash: Option<String> = None;
    let mut chained_len = 0usize;
    let mut record_status = ChainRecordStatus::NotInFile;

    for (i, record) in records.iter().enumerate() {
        let is_target = record.get("observation_id").and_then(Value::as_str) == Some(target_observation_id);
        let seq = record.get("seq").and_then(Value::as_u64);
        match seq {
            None => {
                if chain_started {
                    let reason = "legacy record after chained suffix started".to_string();
                    if is_target {
                        record_status = ChainRecordStatus::Broken { reason: reason.clone() };
                    }
                    return ChainOutcome {
                        record_status,
                        file_status: ChainFileStatus::Broken { at_index: i, reason },
                    };
                }
                if is_target {
                    record_status = ChainRecordStatus::Legacy;
                }
                legacy_prefix_len += 1;
            }
            Some(s) => {
                let expected_prev = last_seq.map_or(0, |p| p + 1);
                if s != expected_prev {
                    let reason = format!("seq gap: expected {expected_prev}, found {s}");
                    if is_target {
                        record_status = ChainRecordStatus::Broken { reason: reason.clone() };
                    }
                    return ChainOutcome {
                        record_status,
                        file_status: ChainFileStatus::Broken { at_index: i, reason },
                    };
                }
                let prev_hash_field = record.get("prev_hash").and_then(Value::as_str).map(String::from);
                if prev_hash_field != last_hash {
                    let reason = format!(
                        "prev_hash mismatch at seq={s}: expected {:?}, found {:?}",
                        last_hash, prev_hash_field
                    );
                    if is_target {
                        record_status = ChainRecordStatus::Broken { reason: reason.clone() };
                    }
                    return ChainOutcome {
                        record_status,
                        file_status: ChainFileStatus::Broken { at_index: i, reason },
                    };
                }
                if is_target {
                    record_status = ChainRecordStatus::Chained { seq: s };
                }
                chain_started = true;
                last_seq = Some(s);
                last_hash = record
                    .get("receipt")
                    .and_then(|r| r.get("body_hash"))
                    .and_then(Value::as_str)
                    .and_then(|s| s.strip_prefix("blake3:"))
                    .map(String::from);
                chained_len += 1;
            }
        }
    }
    let file_status = if chained_len == 0 {
        ChainFileStatus::NoChain
    } else {
        ChainFileStatus::Ok {
            legacy_prefix_len,
            chained_len,
        }
    };
    ChainOutcome {
        record_status,
        file_status,
    }
}

fn verify_record(record: &Value, pubkey_hex: &str) -> Result<VerifyResult, JsonRpcError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let receipt = match record.get("receipt") {
        Some(r) => r,
        None => {
            return Ok(VerifyResult {
                hash_match: false,
                signature_valid: false,
                recomputed_hash: String::new(),
                receipt_hash: String::new(),
                reason: Some("record has no receipt field".to_string()),
            })
        }
    };
    let body_hash_field = receipt.get("body_hash").and_then(|v| v.as_str()).unwrap_or("");
    let body_hash_hex = body_hash_field
        .strip_prefix("blake3:")
        .unwrap_or(body_hash_field)
        .to_string();
    let sig_hex = receipt.get("signature").and_then(|v| v.as_str()).unwrap_or("");

    let body_bytes = strip_receipt_and_serialise(record)?;
    let recomputed = blake3::hash(&body_bytes);
    let recomputed_hex = hex::encode(recomputed.as_bytes());
    let hash_match = recomputed_hex == body_hash_hex;

    // Even if hash mismatched, attempt signature verification so the caller
    // sees both signals. A real attacker would have to break both.
    let pubkey_bytes = hex::decode(pubkey_hex).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("invalid daemon pubkey hex: {err}"),
        data: None,
    })?;
    if pubkey_bytes.len() != 32 {
        return Err(JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!("daemon pubkey must be 32 bytes, got {}", pubkey_bytes.len()),
            data: None,
        });
    }
    let mut pubkey_arr = [0_u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);
    let verifying = VerifyingKey::from_bytes(&pubkey_arr).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("invalid daemon pubkey: {err}"),
        data: None,
    })?;
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(err) => {
            return Ok(VerifyResult {
                hash_match,
                signature_valid: false,
                recomputed_hash: recomputed_hex,
                receipt_hash: body_hash_hex,
                reason: Some(format!("sig hex decode: {err}")),
            })
        }
    };
    if sig_bytes.len() != 64 {
        return Ok(VerifyResult {
            hash_match,
            signature_valid: false,
            recomputed_hash: recomputed_hex,
            receipt_hash: body_hash_hex,
            reason: Some(format!("sig length: {}", sig_bytes.len())),
        });
    }
    let mut sig_arr = [0_u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);
    let signature_valid = verifying.verify(recomputed.as_bytes(), &signature).is_ok();
    let reason = if !hash_match {
        Some("body_hash mismatch (tampered or schema drift)".to_string())
    } else if !signature_valid {
        Some("signature did not verify against daemon public key".to_string())
    } else {
        None
    };
    Ok(VerifyResult {
        hash_match,
        signature_valid,
        recomputed_hash: recomputed_hex,
        receipt_hash: body_hash_hex,
        reason,
    })
}

// ── Tool handlers ─────────────────────────────────────────────────────────

/// `list_observations` — paginate observations for a given session id.
#[allow(clippy::unused_async)] // Async required by MCP tool dispatch signature.
pub async fn handle_list_observations(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let session_id = require_str(args, "session_id")?;
    let data_dir = require_data_dir(ctx)?;
    let scoped = scope::scoped_session_id(scope::agent_name(ctx.agent.as_ref()), &session_id);
    let path = observation_file_path(data_dir, &scoped);

    let mut records = read_jsonl(&path)?;

    // Optional `since` filter (RFC3339).
    if let Some(since_str) = args.get("since").and_then(|v| v.as_str()) {
        if let Ok(since) = chrono::DateTime::parse_from_rfc3339(since_str) {
            let since_utc = since.with_timezone(&chrono::Utc);
            records.retain(|r| {
                r.get("ts")
                    .and_then(|v| v.as_str())
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .is_none_or(|t| t.with_timezone(&chrono::Utc) >= since_utc)
            });
        }
    }

    // Optional `provider` filter (e.g. "claude-code", "openai", "codex-cli").
    if let Some(provider) = args.get("provider").and_then(|v| v.as_str()) {
        records.retain(|r| r.get("provider").and_then(|v| v.as_str()) == Some(provider));
    }

    let limit = args
        .get("limit")
        .and_then(|v| v.as_u64())
        .map_or(DEFAULT_LIST_LIMIT, |n| n as usize)
        .min(MAX_LIST_LIMIT);
    if records.len() > limit {
        records.truncate(limit);
    }

    let count = records.len();
    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!("{count} observation(s) for session {session_id}"),
        }],
        "structuredContent": {
            "session_id": session_id,
            "count": count,
            "observations": records,
        }
    }))
}

/// `get_observation` — fetch a single observation by id.
#[allow(clippy::unused_async)] // Async required by MCP tool dispatch signature.
pub async fn handle_get_observation(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let session_id = require_str(args, "session_id")?;
    let observation_id = require_str(args, "observation_id")?;
    let data_dir = require_data_dir(ctx)?;
    let scoped = scope::scoped_session_id(scope::agent_name(ctx.agent.as_ref()), &session_id);
    let path = observation_file_path(data_dir, &scoped);

    let records = read_jsonl(&path)?;
    for record in records {
        if record.get("observation_id").and_then(|v| v.as_str()) == Some(observation_id.as_str()) {
            return Ok(json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&record).unwrap_or_default(),
                }],
                "structuredContent": record,
            }));
        }
    }
    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!("observation {observation_id} not found in session {session_id}"),
        }],
        "isError": false,
    }))
}

/// `verify_observation` — re-canonicalise and validate a single record's
/// Ed25519 receipt against the daemon's published passport public key.
#[allow(clippy::unused_async)] // Async required by MCP tool dispatch signature.
pub async fn handle_verify_observation(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let session_id = require_str(args, "session_id")?;
    let observation_id = require_str(args, "observation_id")?;
    let data_dir = require_data_dir(ctx)?;
    let pubkey_hex = ctx.passport_public_key_hex.as_deref().ok_or_else(|| JsonRpcError {
        code: INTERNAL_ERROR,
        message: "passport_public_key_hex not configured on MCP context".to_string(),
        data: None,
    })?;
    let scoped = scope::scoped_session_id(scope::agent_name(ctx.agent.as_ref()), &session_id);
    let path = observation_file_path(data_dir, &scoped);

    let records = read_jsonl(&path)?;
    let record = match records
        .iter()
        .find(|r| r.get("observation_id").and_then(|v| v.as_str()) == Some(observation_id.as_str()))
        .cloned()
    {
        Some(r) => r,
        None => {
            return Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!("observation {observation_id} not found in session {session_id}"),
                }],
                "isError": false,
            }))
        }
    };

    let result = verify_record(&record, pubkey_hex)?;
    let chain = validate_chain(&records, observation_id.as_str());

    // Combine per-record + chain into a single `ok` and a `reason` chain.
    let chain_ok = matches!(chain.file_status, ChainFileStatus::Ok { .. } | ChainFileStatus::NoChain)
        && !matches!(chain.record_status, ChainRecordStatus::Broken { .. });
    let ok = result.hash_match && result.signature_valid && chain_ok;
    let reason = if !result.hash_match || !result.signature_valid {
        result.reason.clone()
    } else if let ChainRecordStatus::Broken { reason } = &chain.record_status {
        Some(format!("chain broken at this record: {reason}"))
    } else if let ChainFileStatus::Broken { reason, at_index } = &chain.file_status {
        Some(format!("chain broken in file at index {at_index}: {reason}"))
    } else {
        None
    };

    let summary = if ok {
        let chain_note = match &chain.record_status {
            ChainRecordStatus::Chained { seq } => format!(" + chain (seq={seq})"),
            ChainRecordStatus::Legacy => " (legacy record, pre-chain)".to_string(),
            _ => String::new(),
        };
        format!("verified observation {observation_id}: hash + signature OK{chain_note}")
    } else {
        format!(
            "verification FAILED for {observation_id}: {}",
            reason.as_deref().unwrap_or("unknown")
        )
    };

    let chain_record_json = match &chain.record_status {
        ChainRecordStatus::Legacy => json!({ "status": "legacy" }),
        ChainRecordStatus::Chained { seq } => json!({ "status": "chained", "seq": seq }),
        ChainRecordStatus::Broken { reason } => json!({ "status": "broken", "reason": reason }),
        ChainRecordStatus::NotInFile => json!({ "status": "not_in_file" }),
    };
    let chain_file_json = match &chain.file_status {
        ChainFileStatus::NoChain => json!({ "status": "no_chain" }),
        ChainFileStatus::Ok {
            legacy_prefix_len,
            chained_len,
        } => json!({
            "status": "ok",
            "legacy_prefix_len": legacy_prefix_len,
            "chained_len": chained_len,
        }),
        ChainFileStatus::Broken { at_index, reason } => json!({
            "status": "broken",
            "at_index": at_index,
            "reason": reason,
        }),
    };

    Ok(json!({
        "content": [{ "type": "text", "text": summary }],
        "structuredContent": {
            "observation_id": observation_id,
            "ok": ok,
            "hash_match": result.hash_match,
            "signature_valid": result.signature_valid,
            "chain_valid": chain_ok,
            "chain": {
                "record": chain_record_json,
                "file": chain_file_json,
            },
            "recomputed_hash": format!("blake3:{}", result.recomputed_hash),
            "receipt_hash": format!("blake3:{}", result.receipt_hash),
            "reason": reason,
        }
    }))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    fn write_signed_fixture(data_dir: &Path, session_id: &str, obs_id: &str) -> (String, String) {
        // Generate an Ed25519 key + sign a fixture observation (M5e chained,
        // seq=0). Returns (observation_id, pubkey_hex).
        let key_dir = tempfile::tempdir().unwrap();
        let key_path = key_dir.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();

        let mut record = json!({
            "observation_id": obs_id,
            "session_id": session_id,
            "ts": chrono::Utc::now(),
            "provider": "claude-code",
            "principal": key.passport_fpr(),
            "kind": "tool_use",
            "payload": {"tool": "Read"},
            "seq": 0_u64,
            "receipt": {"alg": "", "signed_by": "", "body_hash": "", "signature": ""},
        });
        let mut canonical = record.clone();
        if let Value::Object(obj) = &mut canonical {
            obj.remove("receipt");
        }
        let body_bytes = serde_json::to_vec(&canonical).unwrap();
        let hash = blake3::hash(&body_bytes);
        let sig = key.sign_hash(hash.as_bytes());
        record["receipt"] = json!({
            "alg": "ed25519",
            "signed_by": key.passport_fpr(),
            "body_hash": format!("blake3:{}", hex::encode(hash.as_bytes())),
            "signature": hex::encode(sig),
        });

        let path = observation_file_path(data_dir, session_id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut line = serde_json::to_string(&record).unwrap();
        line.push('\n');
        fs::write(&path, line).unwrap();
        (obs_id.to_string(), key.public_key_hex().to_string())
    }

    fn ctx_with_data_dir(data_dir: &Path, pubkey_hex: &str) -> McpContext {
        McpContext::new_default("test-node")
            .with_data_dir(data_dir.to_path_buf())
            .with_passport_public_key(pubkey_hex.to_string())
    }

    #[tokio::test]
    async fn list_observations_empty_session() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with_data_dir(tmp.path(), "00".repeat(32).as_str());
        let result = handle_list_observations(&json!({"session_id": "nope"}), &ctx)
            .await
            .unwrap();
        assert_eq!(result["structuredContent"]["count"], 0);
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("0 observation"));
    }

    #[tokio::test]
    async fn list_observations_with_fixture() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, pubkey_hex) = write_signed_fixture(tmp.path(), "sess-list", "obs-list-1");
        let ctx = ctx_with_data_dir(tmp.path(), &pubkey_hex);
        let result = handle_list_observations(&json!({"session_id": "sess-list"}), &ctx)
            .await
            .unwrap();
        assert_eq!(result["structuredContent"]["count"], 1);
        assert_eq!(
            result["structuredContent"]["observations"][0]["observation_id"],
            "obs-list-1"
        );
    }

    #[tokio::test]
    async fn list_observations_provider_filter() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, pubkey_hex) = write_signed_fixture(tmp.path(), "sess-filter", "obs-filter-1");
        let ctx = ctx_with_data_dir(tmp.path(), &pubkey_hex);
        // Only matching provider returns the record.
        let yes = handle_list_observations(&json!({"session_id": "sess-filter", "provider": "claude-code"}), &ctx)
            .await
            .unwrap();
        assert_eq!(yes["structuredContent"]["count"], 1);
        // Non-matching provider yields zero.
        let no = handle_list_observations(&json!({"session_id": "sess-filter", "provider": "openai"}), &ctx)
            .await
            .unwrap();
        assert_eq!(no["structuredContent"]["count"], 0);
    }

    #[tokio::test]
    async fn get_observation_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let (obs_id, pubkey_hex) = write_signed_fixture(tmp.path(), "sess-get", "obs-get-1");
        let ctx = ctx_with_data_dir(tmp.path(), &pubkey_hex);
        let result = handle_get_observation(&json!({"session_id": "sess-get", "observation_id": obs_id}), &ctx)
            .await
            .unwrap();
        assert_eq!(result["structuredContent"]["observation_id"], "obs-get-1");
    }

    #[tokio::test]
    async fn get_observation_missing_id() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, pubkey_hex) = write_signed_fixture(tmp.path(), "sess-miss", "obs-real");
        let ctx = ctx_with_data_dir(tmp.path(), &pubkey_hex);
        let result = handle_get_observation(&json!({"session_id": "sess-miss", "observation_id": "obs-nope"}), &ctx)
            .await
            .unwrap();
        assert!(result["content"][0]["text"].as_str().unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn verify_observation_succeeds_for_signed_fixture() {
        let tmp = tempfile::tempdir().unwrap();
        let (obs_id, pubkey_hex) = write_signed_fixture(tmp.path(), "sess-verify", "obs-verify-1");
        let ctx = ctx_with_data_dir(tmp.path(), &pubkey_hex);
        let result = handle_verify_observation(&json!({"session_id": "sess-verify", "observation_id": obs_id}), &ctx)
            .await
            .unwrap();
        assert_eq!(result["structuredContent"]["ok"], true);
        assert_eq!(result["structuredContent"]["hash_match"], true);
        assert_eq!(result["structuredContent"]["signature_valid"], true);
    }

    #[tokio::test]
    async fn verify_observation_rejects_tampered_record() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, pubkey_hex) = write_signed_fixture(tmp.path(), "sess-tamper", "obs-tamper-1");
        // Tamper the on-disk JSONL: mutate observation_id in the file.
        let path = observation_file_path(tmp.path(), "sess-tamper");
        let content = fs::read_to_string(&path).unwrap();
        let mut record: Value = serde_json::from_str(content.trim()).unwrap();
        record["observation_id"] = json!("tampered-obs-tamper-1");
        let mut line = serde_json::to_string(&record).unwrap();
        line.push('\n');
        fs::write(&path, line).unwrap();

        let ctx = ctx_with_data_dir(tmp.path(), &pubkey_hex);
        let result = handle_verify_observation(
            &json!({"session_id": "sess-tamper", "observation_id": "tampered-obs-tamper-1"}),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(result["structuredContent"]["ok"], false);
        assert_eq!(result["structuredContent"]["hash_match"], false);
    }
}
