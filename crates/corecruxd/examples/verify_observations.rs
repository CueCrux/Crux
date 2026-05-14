// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

#![allow(clippy::print_stdout, clippy::print_stderr)]

//! Standalone verifier for observation JSONL files produced by
//! `POST /v1/sessions/{id}/observations`.
//!
//! Usage:
//!     cargo run --example verify_observations -- \
//!         --jsonl <path/to/session.jsonl> \
//!         --pubkey-hex <64-char hex of daemon's passport public key>
//!
//! For every line in the JSONL, it:
//!   1. Strips the receipt field.
//!   2. Re-canonicalises the remaining record bytes using the same
//!      canonicalisation function as `crates/corecruxd/src/http/observations.rs`.
//!   3. Recomputes the BLAKE3 hash and compares against `receipt.body_hash`.
//!   4. Verifies the Ed25519 signature against the supplied public key.
//!
//! Then validates the **chain** across the whole file: every chained record
//! (`seq` present) must form a contiguous monotonic sequence 0,1,2,…, each
//! pointing back at the previous record's `body_hash` via `prev_hash`.
//! Pre-M5e records (no `seq` field) are tolerated as a legacy prefix.
//!
//! Exit code is `0` if every line verifies *and* the chain is intact;
//! `1` if any record fails or the chain is broken.
//!
//! This is the cheapest possible offline auditor — a regulator or a peer can
//! validate observations from a JSONL file alone, given the daemon's
//! published public key. No daemon needs to be running.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(Debug)]
struct Args {
    jsonl: PathBuf,
    pubkey_hex: String,
}

fn parse_args() -> Result<Args, String> {
    let mut jsonl: Option<PathBuf> = None;
    let mut pubkey_hex: Option<String> = None;
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--jsonl" => jsonl = iter.next().map(PathBuf::from),
            "--pubkey-hex" => pubkey_hex = iter.next(),
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(Args {
        jsonl: jsonl.ok_or_else(|| "--jsonl is required".to_string())?,
        pubkey_hex: pubkey_hex.ok_or_else(|| "--pubkey-hex is required".to_string())?,
    })
}

fn print_usage() {
    eprintln!(
        "verify_observations --jsonl <path> --pubkey-hex <64-char hex>\n\
         \n\
         Validates every observation receipt in the JSONL file against the\n\
         supplied public key. Exits 0 on full pass, 1 on any failure."
    );
}

/// Reproduce the canonicalisation used by the daemon when computing the
/// receipt body hash. Must match `canonical_body_bytes` in
/// `crates/corecruxd/src/http/observations.rs` exactly.
///
/// The shared rule: strip `receipt` from the JSON Value, then re-serialise.
/// `serde_json` writes `Value::Object` (a BTreeMap) in alphabetical key
/// order, which makes the bytes deterministic across the producer (daemon)
/// and any consumer (this verifier).
fn canonical_body_bytes(record: &serde_json::Value) -> Result<Vec<u8>, String> {
    let mut working = record.clone();
    if let serde_json::Value::Object(obj) = &mut working {
        obj.remove("receipt");
    }
    serde_json::to_vec(&working).map_err(|err| format!("canonicalise: {err}"))
}

#[derive(Debug)]
enum VerifyOutcome {
    Pass,
    Fail { reason: String },
}

fn verify_line(line: &str, verifying_key: &VerifyingKey) -> VerifyOutcome {
    let record: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(err) => {
            return VerifyOutcome::Fail {
                reason: format!("parse: {err}"),
            }
        }
    };
    let receipt = match record.get("receipt") {
        Some(r) => r.clone(),
        None => {
            return VerifyOutcome::Fail {
                reason: "missing receipt".to_string(),
            }
        }
    };
    let alg = receipt.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "ed25519" {
        return VerifyOutcome::Fail {
            reason: format!("unsupported alg: {alg}"),
        };
    }
    let body_hash_field = receipt.get("body_hash").and_then(|v| v.as_str()).unwrap_or("");
    let body_hash_hex = body_hash_field.strip_prefix("blake3:").unwrap_or(body_hash_field);
    let sig_hex = receipt.get("signature").and_then(|v| v.as_str()).unwrap_or("");

    let body_bytes = match canonical_body_bytes(&record) {
        Ok(b) => b,
        Err(err) => return VerifyOutcome::Fail { reason: err },
    };
    let recomputed = blake3::hash(&body_bytes);
    let recomputed_hex = hex::encode(recomputed.as_bytes());
    if recomputed_hex != body_hash_hex {
        return VerifyOutcome::Fail {
            reason: format!("hash mismatch: recomputed={recomputed_hex}, receipt={body_hash_hex}"),
        };
    }

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(err) => {
            return VerifyOutcome::Fail {
                reason: format!("sig hex: {err}"),
            }
        }
    };
    if sig_bytes.len() != 64 {
        return VerifyOutcome::Fail {
            reason: format!("sig length: {}", sig_bytes.len()),
        };
    }
    let mut sig_arr = [0_u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);
    match verifying_key.verify(recomputed.as_bytes(), &signature) {
        Ok(()) => VerifyOutcome::Pass,
        Err(err) => VerifyOutcome::Fail {
            reason: format!("ed25519 verify: {err}"),
        },
    }
}

fn main() -> std::process::ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(err) => {
            eprintln!("error: {err}");
            print_usage();
            return std::process::ExitCode::from(2);
        }
    };

    let pubkey_bytes = match hex::decode(&args.pubkey_hex) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("invalid --pubkey-hex: {err}");
            return std::process::ExitCode::from(2);
        }
    };
    if pubkey_bytes.len() != 32 {
        eprintln!(
            "--pubkey-hex must be 32 bytes (64 hex chars), got {}",
            pubkey_bytes.len()
        );
        return std::process::ExitCode::from(2);
    }
    let mut pubkey_arr = [0_u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);
    let verifying_key = match VerifyingKey::from_bytes(&pubkey_arr) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("invalid Ed25519 public key: {err}");
            return std::process::ExitCode::from(2);
        }
    };

    let file = match File::open(&args.jsonl) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("open {}: {err}", args.jsonl.display());
            return std::process::ExitCode::from(2);
        }
    };

    let mut pass = 0_u64;
    let mut fail = 0_u64;
    let mut records: Vec<serde_json::Value> = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(err) => {
                eprintln!("line {}: io error: {err}", i + 1);
                fail += 1;
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match verify_line(&line, &verifying_key) {
            VerifyOutcome::Pass => pass += 1,
            VerifyOutcome::Fail { reason } => {
                fail += 1;
                eprintln!("line {}: FAIL — {reason}", i + 1);
            }
        }
        // Keep the parsed record around for chain validation. We parse it
        // again here (cheap) so the verify path stays independent.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            records.push(v);
        }
    }

    // Chain validation: walk the records and ensure every `seq`-bearing
    // record has the expected (seq, prev_hash) link.
    let chain_outcome = validate_chain(&records);
    match &chain_outcome {
        ChainStatus::NoChain => {
            println!("chain: no chained records (legacy-only file)");
        }
        ChainStatus::Ok {
            legacy_prefix_len,
            chained_len,
        } => {
            println!("chain: OK — {chained_len} chained record(s), {legacy_prefix_len} legacy prefix");
        }
        ChainStatus::Broken { at_index, reason } => {
            fail += 1;
            eprintln!("chain: BROKEN at line {} — {reason}", at_index + 1);
        }
    }

    println!("verified: {pass}  failed: {fail}");
    if fail == 0 {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(1)
    }
}

#[derive(Debug)]
enum ChainStatus {
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

fn validate_chain(records: &[serde_json::Value]) -> ChainStatus {
    let mut legacy_prefix_len = 0usize;
    let mut chain_started = false;
    let mut last_seq: Option<u64> = None;
    let mut last_hash: Option<String> = None;
    let mut chained_len = 0usize;

    for (i, record) in records.iter().enumerate() {
        let seq = record.get("seq").and_then(serde_json::Value::as_u64);
        match seq {
            None => {
                if chain_started {
                    return ChainStatus::Broken {
                        at_index: i,
                        reason: "legacy record after chained suffix started".to_string(),
                    };
                }
                legacy_prefix_len += 1;
            }
            Some(s) => {
                let expected_prev = last_seq.map_or(0, |p| p + 1);
                if s != expected_prev {
                    return ChainStatus::Broken {
                        at_index: i,
                        reason: format!("seq gap: expected {expected_prev}, found {s}"),
                    };
                }
                let prev_hash_field = record
                    .get("prev_hash")
                    .and_then(serde_json::Value::as_str)
                    .map(String::from);
                if prev_hash_field != last_hash {
                    return ChainStatus::Broken {
                        at_index: i,
                        reason: format!(
                            "prev_hash mismatch at seq={s}: expected {:?}, found {:?}",
                            last_hash, prev_hash_field,
                        ),
                    };
                }
                let body_hash_hex = record
                    .get("receipt")
                    .and_then(|r| r.get("body_hash"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .strip_prefix("blake3:")
                    .map(String::from);
                chain_started = true;
                last_seq = Some(s);
                last_hash = body_hash_hex;
                chained_len += 1;
            }
        }
    }
    if chained_len == 0 {
        ChainStatus::NoChain
    } else {
        ChainStatus::Ok {
            legacy_prefix_len,
            chained_len,
        }
    }
}
