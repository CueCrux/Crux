// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! v1 candidate-digest parser + recomputer — extracts `candidate_digest` from a stored retrieval trace for verification.

use ciborium::value::Value;

const SCALE: f64 = 1_000_000.0;

pub(crate) fn parse_stored_candidate_digest_bytes_v1(retrieval_trace: &[(Value, Value)]) -> Option<[u8; 32]> {
    let digest = get_val(retrieval_trace, &["candidate_digest", "candidateDigest"])?;
    parse_digest_bytes(digest)
}

pub(crate) fn recompute_candidate_digest_bytes_v1(retrieval_trace: &[(Value, Value)]) -> Result<[u8; 32], String> {
    let lanes_used = parse_lanes_used(retrieval_trace)?;
    let candidates = parse_candidates(retrieval_trace)?;
    compute_candidate_digest_bytes_v1(&lanes_used, &candidates)
}

#[derive(Debug)]
struct CandidateV1 {
    chunk_id: String,
    sparse_score: Option<f64>,
    lane_scores: std::collections::BTreeMap<String, Option<f64>>,
    fusion_score: Option<f64>,
    priors_score: Option<f64>,
    anchor_score: Option<f64>,
    rerank_score: Option<f64>,
}

fn parse_lanes_used(retrieval_trace: &[(Value, Value)]) -> Result<Vec<String>, String> {
    let Some(Value::Array(arr)) = get_val(retrieval_trace, &["lanes_used", "lanesUsed"]) else {
        return Err("missing lanes_used".to_string());
    };

    let mut lanes = Vec::new();
    for el in arr {
        match el {
            Value::Text(s) => lanes.push(s.to_string()),
            Value::Map(m) => {
                if let Some(Value::Text(s)) = get_val(m, &["lane_key", "laneKey", "key"]) {
                    lanes.push(s.to_string());
                }
            }
            _ => {}
        }
    }

    if lanes.is_empty() {
        return Err("lanes_used empty".to_string());
    }
    Ok(lanes)
}

fn parse_candidates(retrieval_trace: &[(Value, Value)]) -> Result<Vec<CandidateV1>, String> {
    let Some(Value::Array(arr)) = get_val(retrieval_trace, &["candidates"]) else {
        return Err("missing candidates".to_string());
    };

    let mut out = Vec::with_capacity(arr.len());
    for el in arr {
        let Value::Map(m) = el else { continue };

        let chunk_id = match get_val(m, &["chunk_id", "chunkId"]) {
            Some(Value::Text(s)) => s.to_string(),
            _ => continue,
        };

        let sparse_score = get_val(m, &["sparse_score", "sparseScore"]).and_then(val_to_f64_opt);
        let fusion_score = get_val(m, &["fusion_score", "fusionScore"]).and_then(val_to_f64_opt);
        let priors_score = get_val(m, &["priors_score", "priorsScore"]).and_then(val_to_f64_opt);
        let anchor_score = get_val(m, &["anchor_score", "anchorScore"]).and_then(val_to_f64_opt);
        let rerank_score = get_val(m, &["rerank_score", "rerankScore"]).and_then(val_to_f64_opt);

        let mut lane_scores = std::collections::BTreeMap::new();
        if let Some(Value::Map(ls)) = get_val(m, &["lane_scores", "laneScores"]) {
            for (k, v) in ls {
                if let Value::Text(lk) = k {
                    lane_scores.insert(lk.to_string(), val_to_f64_opt(v));
                }
            }
        }

        out.push(CandidateV1 {
            chunk_id,
            sparse_score,
            lane_scores,
            fusion_score,
            priors_score,
            anchor_score,
            rerank_score,
        });
    }

    if out.is_empty() {
        return Err("candidates empty/unparseable".to_string());
    }
    Ok(out)
}

fn compute_candidate_digest_bytes_v1(
    lanes_used: &[String],
    ordered_candidates: &[CandidateV1],
) -> Result<[u8; 32], String> {
    let mut lanes: Vec<String> = lanes_used.iter().map(|s| s.to_string()).collect();
    lanes.sort();
    lanes.dedup();
    if lanes.len() > 27 {
        return Err(format!("candidate_digest_lane_overflow:{}", lanes.len()));
    }

    let mut buf: Vec<u8> = Vec::new();
    write_str(&mut buf, "candidate_digest/v1")?;
    write_u32_le(&mut buf, ordered_candidates.len() as u32)?;

    // lanes_used
    write_u32_le(&mut buf, lanes.len() as u32)?;
    for lk in &lanes {
        write_str(&mut buf, lk)?;
    }

    for c in ordered_candidates {
        write_str(&mut buf, &c.chunk_id.to_lowercase())?;

        // null bitmap layout: [sparse, fusion, priors, anchor, rerank, lane0, lane1, ...]
        let mut bit: u32 = 0;
        let mut bitmap: u32 = 0;

        let sparse = q_score(c.sparse_score);
        if sparse.is_null {
            bitmap |= 1u32 << bit;
        }
        bit += 1;

        let fusion = q_score(c.fusion_score);
        if fusion.is_null {
            bitmap |= 1u32 << bit;
        }
        bit += 1;

        let priors = q_score(c.priors_score);
        if priors.is_null {
            bitmap |= 1u32 << bit;
        }
        bit += 1;

        let anchor = q_score(c.anchor_score);
        if anchor.is_null {
            bitmap |= 1u32 << bit;
        }
        bit += 1;

        let rerank = q_score(c.rerank_score);
        if rerank.is_null {
            bitmap |= 1u32 << bit;
        }
        bit += 1;

        let mut lane_qs: Vec<i32> = Vec::with_capacity(lanes.len());
        for lk in &lanes {
            let v = c.lane_scores.get(lk).copied().flatten();
            let q = q_score(v);
            if q.is_null {
                bitmap |= 1u32 << bit;
            }
            bit += 1;
            lane_qs.push(q.q);
        }

        write_u32_le(&mut buf, bitmap)?;
        write_i32_le(&mut buf, sparse.q)?;
        for q in lane_qs {
            write_i32_le(&mut buf, q)?;
        }
        write_i32_le(&mut buf, fusion.q)?;
        write_i32_le(&mut buf, priors.q)?;
        write_i32_le(&mut buf, anchor.q)?;
        write_i32_le(&mut buf, rerank.q)?;
    }

    Ok(*blake3::hash(&buf).as_bytes())
}

#[derive(Debug, Clone, Copy)]
struct QScore {
    q: i32,
    is_null: bool,
}

fn q_score(x: Option<f64>) -> QScore {
    let Some(x) = x else {
        return QScore { q: 0, is_null: true };
    };
    if x.is_nan() {
        return QScore { q: 0, is_null: true };
    }

    let clamped = x.clamp(-4.0, 4.0);
    // JS Math.round semantics: floor(x + 0.5).
    let scaled = clamped * SCALE;
    let q = (scaled + 0.5).floor() as i32;
    QScore { q, is_null: false }
}

#[allow(clippy::unnecessary_wraps)] // Result return kept for consistency with write_str and caller `?` chains
fn write_u32_le(buf: &mut Vec<u8>, n: u32) -> Result<(), String> {
    buf.extend_from_slice(&n.to_le_bytes());
    Ok(())
}

#[allow(clippy::unnecessary_wraps)] // Result return kept for consistency with write_str and caller `?` chains
fn write_i32_le(buf: &mut Vec<u8>, n: i32) -> Result<(), String> {
    buf.extend_from_slice(&n.to_le_bytes());
    Ok(())
}

fn write_str(buf: &mut Vec<u8>, s: &str) -> Result<(), String> {
    let bytes = s.as_bytes();
    let len: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| format!("string too long: len={}", bytes.len()))?;
    write_u32_le(buf, len)?;
    buf.extend_from_slice(bytes);
    Ok(())
}

fn parse_digest_bytes(v: &Value) -> Option<[u8; 32]> {
    match v {
        Value::Bytes(b) => {
            if b.len() != 32 {
                return None;
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(b.as_slice());
            Some(out)
        }
        Value::Text(s) => parse_digest_hex_string(s),
        _ => None,
    }
}

fn parse_digest_hex_string(s: &str) -> Option<[u8; 32]> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }

    let hex = trimmed
        .strip_prefix("blake3:hex:")
        .or_else(|| trimmed.strip_prefix("BLAKE3:HEX:"))
        .unwrap_or(trimmed);

    if hex.len() != 64 {
        return None;
    }

    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for i in 0..32 {
        let hi = from_hex(bytes[i * 2])?;
        let lo = from_hex(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn val_to_f64_opt(v: &Value) -> Option<f64> {
    match v {
        Value::Null => None,
        Value::Float(f) => Some(*f),
        Value::Integer(i) => {
            if let Ok(n) = i64::try_from(*i) {
                Some(n as f64)
            } else if let Ok(n) = u64::try_from(*i) {
                Some(n as f64)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn get_val<'a>(map: &'a [(Value, Value)], keys: &[&str]) -> Option<&'a Value> {
    for key in keys {
        if let Some(v) = get_val_one(map, key) {
            return Some(v);
        }
    }
    None
}

fn get_val_one<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    for (k, v) in map {
        if let Value::Text(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}
