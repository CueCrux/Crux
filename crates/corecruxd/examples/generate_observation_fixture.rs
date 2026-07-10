// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

#![allow(clippy::print_stdout, clippy::print_stderr)]

//! Generate a fixture observation JSONL signed with a deterministic in-memory
//! passport key. Used by `scripts/smoke-observations.sh` to exercise the
//! verifier example without needing a running daemon.
//!
//! Usage:
//!     cargo run --example generate_observation_fixture -- \
//!         --out <jsonl path> --pubkey-out <pubkey hex path> [--lines N]

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;

use serde_json::json;

#[derive(Debug)]
struct Args {
    out: PathBuf,
    pubkey_out: PathBuf,
    lines: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut out: Option<PathBuf> = None;
    let mut pubkey_out: Option<PathBuf> = None;
    let mut lines: usize = 3;
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--out" => out = iter.next().map(PathBuf::from),
            "--pubkey-out" => pubkey_out = iter.next().map(PathBuf::from),
            "--lines" => {
                lines = iter
                    .next()
                    .ok_or_else(|| "--lines requires a value".to_string())?
                    .parse()
                    .map_err(|err| format!("--lines: {err}"))?;
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(Args {
        out: out.ok_or_else(|| "--out is required".to_string())?,
        pubkey_out: pubkey_out.ok_or_else(|| "--pubkey-out is required".to_string())?,
        lines,
    })
}

fn main() -> Result<(), String> {
    let args = parse_args()?;

    // Deterministic passport key for reproducible fixtures.
    let tmp = tempfile::tempdir().map_err(|err| format!("tempdir: {err}"))?;
    let key_path = tmp.path().join("passport.key");
    let key = crux_session::LocalPassportKey::from_path(&key_path).map_err(|err| format!("passport key: {err}"))?;

    if let Some(parent) = args.out.parent() {
        create_dir_all(parent).map_err(|err| format!("mkdir {}: {err}", parent.display()))?;
    }
    let mut jsonl = File::create(&args.out).map_err(|err| format!("create {}: {err}", args.out.display()))?;

    // Carry the previous record's body_hash forward so the generated
    // JSONL is a contiguous M5e chain (seq=0,1,2,…).
    let mut prev_body_hash_hex: Option<String> = None;
    for i in 0..args.lines {
        // Build a record the same way the daemon does, then sign it.
        let ts = chrono::Utc::now() - chrono::Duration::seconds(i as i64);
        let mut record = json!({
            "observation_id": uuid::Uuid::new_v4().to_string(),
            "session_id": "smoke-session",
            "ts": ts,
            "provider": if i % 2 == 0 { "claude-code" } else { "openai" },
            "principal": key.passport_fpr(),
            "kind": if i == 0 { "session_start" } else if i + 1 == args.lines { "session_end" } else { "tool_use" },
            "payload": {"tool": "Read", "iteration": i},
            "seq": i as u64,
            "receipt": {"alg": "", "signed_by": "", "body_hash": "", "signature": ""},
        });
        // Only emit prev_hash when there IS a previous record. Matches the
        // daemon's `skip_serializing_if = "Option::is_none"` exactly.
        if let Some(ref prev) = prev_body_hash_hex {
            record["prev_hash"] = json!(prev);
        }
        let mut canonical = record.clone();
        if let serde_json::Value::Object(obj) = &mut canonical {
            obj.remove("receipt");
        }
        let body_bytes = serde_json::to_vec(&canonical).map_err(|err| format!("canonicalise: {err}"))?;
        let hash = blake3::hash(&body_bytes);
        let sig = key.sign_hash(hash.as_bytes());
        let hash_hex = hex::encode(hash.as_bytes());
        record["receipt"] = json!({
            "alg": "ed25519",
            "signed_by": key.passport_fpr(),
            "body_hash": format!("blake3:{hash_hex}"),
            "signature": hex::encode(sig),
        });
        prev_body_hash_hex = Some(hash_hex);
        let line = serde_json::to_string(&record).map_err(|err| format!("serialise: {err}"))?;
        jsonl
            .write_all(line.as_bytes())
            .map_err(|err| format!("write line: {err}"))?;
        jsonl.write_all(b"\n").map_err(|err| format!("write nl: {err}"))?;
    }
    jsonl.flush().map_err(|err| format!("flush: {err}"))?;

    if let Some(parent) = args.pubkey_out.parent() {
        create_dir_all(parent).map_err(|err| format!("mkdir {}: {err}", parent.display()))?;
    }
    std::fs::write(&args.pubkey_out, key.public_key_hex()).map_err(|err| format!("write pubkey: {err}"))?;

    println!(
        "wrote {} observations to {}\npublic key (fpr={}) at {}",
        args.lines,
        args.out.display(),
        key.passport_fpr(),
        args.pubkey_out.display(),
    );
    Ok(())
}
