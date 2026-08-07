// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl inspect-receipt <id>` — Human-readable CROWN receipt breakdown.

use std::path::PathBuf;

pub fn run(data_dir: &str, receipt_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let data_path = PathBuf::from(data_dir);
    if !data_path.exists() {
        return Err(format!("data directory does not exist: {}", data_dir).into());
    }

    println!("CROWN Receipt Inspection");
    println!("========================");
    println!("Receipt ID: {}", receipt_id);
    println!("Data Dir:   {}", data_dir);
    println!();

    // Scan shards for the receipt
    let mut found = false;
    for entry in std::fs::read_dir(&data_path)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let dir_name = path.file_name().unwrap_or_default().to_string_lossy();
        if !dir_name.starts_with("shard-") {
            continue;
        }

        // Walk segments looking for receipt events
        for seg_entry in std::fs::read_dir(&path)? {
            let seg_entry = seg_entry?;
            let seg_path = seg_entry.path();
            if seg_path.extension().is_some_and(|e| e == "ccxseg") {
                // Try to find receipts in this segment
                if let Ok(bytes) = std::fs::read(&seg_path) {
                    // Simple scan for receipt ID in raw bytes
                    let receipt_bytes = receipt_id.as_bytes();
                    if bytes.windows(receipt_bytes.len()).any(|w| w == receipt_bytes) {
                        println!("Found in: {}", seg_path.display());
                        println!("  Shard:   {}", dir_name);
                        println!(
                            "  Segment: {}",
                            seg_path.file_name().unwrap_or_default().to_string_lossy()
                        );
                        found = true;
                    }
                }
            }
        }
    }

    // Governance receipts (tenant corpus erasure, compact_facts erasure,
    // memory_forget, held hard-erasure overrides) are never written to a
    // sealed segment — they ARE the observation record, in a governance
    // journal. Before this fallback the CLI reported them as missing, which
    // meant a daemon could mint a signed audit artefact that no supported
    // tool would confirm.
    if !found {
        found = inspect_governance_receipt(&data_path, receipt_id)?;
    }

    if !found {
        println!("Receipt '{}' not found in any segment.", receipt_id);
        println!();
        println!("Hint: receipts are stored in sealed segments. If the data was recently");
        println!("      ingested, it may not yet be sealed. Run `verify-store` to check");
        println!("      segment integrity.");
    }

    Ok(())
}

/// Resolve and verify an observation-envelope (governance) receipt.
///
/// The scan is restricted to `__governance__*` logs deliberately: a
/// production node carries tens of thousands of per-session observation logs
/// (59,022 against 5 mediation logs on host crux), so walking all of them on
/// an audit lookup would be a denial-of-service surface.
///
/// Verification uses `corecrux_receipts::verify_observation_envelope` — the
/// same function the daemon's HTTP path calls — so the CLI cannot drift into
/// disagreeing with the daemon about whether a receipt is valid.
fn inspect_governance_receipt(
    data_path: &std::path::Path,
    receipt_id: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let obs_dir = data_path.join("observations");
    let entries = match std::fs::read_dir(&obs_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    };

    let mut logs: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
                && name.starts_with("__governance__")
        })
        .map(|e| e.path())
        .collect();
    logs.sort();

    for log in logs {
        let Ok(text) = std::fs::read_to_string(&log) else {
            continue;
        };
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(record) = serde_json::from_str::<corecrux_receipts::ObservationRecordV1>(line) else {
                continue;
            };
            if record.observation_id != receipt_id {
                continue;
            }

            println!("Found in: {}", log.display());
            println!("  Kind:      {}", record.kind);
            println!("  Session:   {}", record.session_id);
            println!("  Principal: {}", record.principal);
            println!("  Recorded:  {}", record.ts.to_rfc3339());
            println!("  Signer:    {}", record.receipt.signed_by);
            println!("  Body hash: {}", record.receipt.body_hash);

            // The signer is the node that minted it; a receipt signed by
            // another node's passport is reported unverified rather than
            // silently accepted.
            let key_path = data_path.join("passport.key");
            match crux_session::LocalPassportKey::from_path(&key_path) {
                Ok(key) => {
                    match corecrux_receipts::verify_observation_envelope(
                        &record,
                        key.passport_fpr(),
                        key.public_key_hex(),
                    ) {
                        Ok(()) => println!("  Signature: VERIFIED (ed25519, this node's passport)"),
                        Err(detail) => println!("  Signature: UNVERIFIED — {detail}"),
                    }
                }
                Err(err) => {
                    println!("  Signature: UNCHECKED — cannot load {}: {err}", key_path.display());
                }
            }
            println!();
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn nonexistent_dir_returns_error() {
        let err = run("/tmp/__corecruxctl_test_nonexistent_dir__", "r-0001").unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn empty_data_dir_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let result = run(dir.path().to_str().unwrap(), "r-0001");
        assert!(result.is_ok());
        // No shards → receipt not found (prints hint message)
    }

    #[test]
    fn shard_with_no_matching_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard-0001");
        fs::create_dir(&shard).unwrap();
        // Write a segment file that does NOT contain the receipt ID
        fs::write(shard.join("000000.ccxseg"), b"some unrelated data").unwrap();

        let result = run(dir.path().to_str().unwrap(), "r-missing");
        assert!(result.is_ok());
    }

    #[test]
    fn shard_with_matching_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard-0001");
        fs::create_dir(&shard).unwrap();
        // Write a segment file that contains the receipt ID bytes
        let mut data = b"prefix-data-".to_vec();
        data.extend_from_slice(b"r-found-42");
        data.extend_from_slice(b"-suffix");
        fs::write(shard.join("000000.ccxseg"), &data).unwrap();

        let result = run(dir.path().to_str().unwrap(), "r-found-42");
        assert!(result.is_ok());
    }

    #[test]
    fn non_shard_dirs_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        // Create a directory that doesn't start with "shard-"
        let other = dir.path().join("other-dir");
        fs::create_dir(&other).unwrap();
        fs::write(other.join("000000.ccxseg"), b"r-0001").unwrap();

        let result = run(dir.path().to_str().unwrap(), "r-0001");
        assert!(result.is_ok());
        // Should not find the receipt because the dir name doesn't match "shard-*"
    }

    /// Build a real signed governance record so the CLI verifies the same
    /// bytes the daemon would, rather than a hand-rolled fixture that could
    /// drift from the wire format.
    fn write_signed_governance_record(data_dir: &std::path::Path, receipt_id: &str) -> String {
        let key = crux_session::LocalPassportKey::from_path(&data_dir.join("passport.key")).unwrap();
        let mut record = corecrux_receipts::ObservationRecordV1 {
            observation_id: receipt_id.to_string(),
            session_id: "__governance__::erasure".to_string(),
            ts: chrono::Utc::now(),
            client_ts: None,
            provider: "corecruxd".to_string(),
            principal: key.passport_fpr().to_string(),
            kind: "erasure.forget_tenant_corpus".to_string(),
            payload: serde_json::json!({ "tenant_id": "t-1", "segments_reclaimed": 17 }),
            seq: Some(0),
            prev_hash: None,
            receipt: corecrux_receipts::ReceiptEnvelopeV1 {
                alg: "ed25519".to_string(),
                signed_by: key.passport_fpr().to_string(),
                body_hash: String::new(),
                signature: String::new(),
            },
        };
        let body = corecrux_receipts::canonical_body_bytes(&record).unwrap();
        let hash = blake3::hash(&body);
        record.receipt.body_hash = format!("blake3:{}", hex::encode(hash.as_bytes()));
        record.receipt.signature = hex::encode(key.sign_hash(hash.as_bytes()));

        let obs = data_dir.join("observations");
        fs::create_dir_all(&obs).unwrap();
        fs::write(
            obs.join("__governance____erasure.jsonl"),
            format!("{}\n", serde_json::to_string(&record).unwrap()),
        )
        .unwrap();
        key.passport_fpr().to_string()
    }

    /// The gap this closes: a governance receipt is never written to a sealed
    /// segment, so before the fallback the CLI called a perfectly valid,
    /// signed audit artefact "not found in any segment".
    #[test]
    fn governance_receipt_is_found_and_verified() {
        let dir = tempfile::tempdir().unwrap();
        write_signed_governance_record(dir.path(), "gov-receipt-1");

        assert!(
            inspect_governance_receipt(dir.path(), "gov-receipt-1").unwrap(),
            "a signed governance receipt must resolve"
        );
        assert!(
            !inspect_governance_receipt(dir.path(), "no-such-id").unwrap(),
            "an unknown id must not resolve"
        );
        // Full command path also succeeds (no shards present).
        assert!(run(dir.path().to_str().unwrap(), "gov-receipt-1").is_ok());
    }

    /// Bounded-scan guarantee. Host crux carries 59,022 observation logs
    /// against 5 mediation ones, so an unbounded walk would turn an audit
    /// lookup into a DoS. The decoy is unparseable: if the filter ever
    /// widens, this stops returning `false`.
    #[test]
    fn non_governance_observation_logs_are_never_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let obs = dir.path().join("observations");
        fs::create_dir_all(&obs).unwrap();
        fs::write(
            obs.join("__agent_session__agent_anthropic__decoy.jsonl"),
            "{\"observation_id\":\"planted\", this is not valid json\n",
        )
        .unwrap();

        assert!(
            !inspect_governance_receipt(dir.path(), "planted").unwrap(),
            "a non-governance log must never be consulted"
        );
    }

    #[test]
    fn non_ccxseg_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard-0001");
        fs::create_dir(&shard).unwrap();
        // Write files with wrong extensions
        fs::write(shard.join("000000.txt"), b"r-0001").unwrap();
        fs::write(shard.join("000000.ccxi"), b"r-0001").unwrap();

        let result = run(dir.path().to_str().unwrap(), "r-0001");
        assert!(result.is_ok());
    }
}
