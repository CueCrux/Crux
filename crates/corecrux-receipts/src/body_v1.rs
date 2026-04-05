// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::io::Cursor;

use ciborium::value::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptBodyIndexV1 {
    pub kind: Option<String>,         // "answer" | "action" (Phase 8)
    pub mode: Option<String>,         // "light" | "verified" | "audit" (Phase 8)
    pub subject_type: Option<String>, // e.g. "answer_id" | "action_id" | ...
    pub subject_id: Option<String>,   // e.g. answerId/actionId
}

/// Best-effort extract of a few stable fields from ReceiptBody canonical CBOR bytes.
///
/// CoreCrux never reserializes; canonicalization is producer-owned. We only decode to populate
/// optional derived-state indexes (subject mapping, trace summaries, etc).
pub fn extract_body_index_v1(body_bytes: &[u8]) -> Option<ReceiptBodyIndexV1> {
    let v: Value = ciborium::de::from_reader(Cursor::new(body_bytes)).ok()?;
    let Value::Map(map) = v else {
        return None;
    };

    let kind = get_text(&map, "kind");
    let mode = get_text(&map, "mode");

    let mut subject_type: Option<String> = None;
    let mut subject_id: Option<String> = None;
    if let Some(Value::Map(subject_map)) = get_val(&map, "subject") {
        subject_type = get_text(subject_map, "type");
        subject_id = get_text(subject_map, "id");
    }

    Some(ReceiptBodyIndexV1 {
        kind,
        mode,
        subject_type,
        subject_id,
    })
}

/// Best-effort extract of action/lineage linkage for exports.
///
/// Phase 8 allows `linked_receipts[]` to appear either:
/// - top-level: `linked_receipts: [<receipt_id>, ...]`
/// - under an `action` block: `action: { linked_receipts: [...] }`
///
/// If the receipt parses but no linkage exists, this returns `Some(vec![])`.
pub fn extract_linked_receipts_v1(body_bytes: &[u8]) -> Option<Vec<String>> {
    let v: Value = ciborium::de::from_reader(Cursor::new(body_bytes)).ok()?;
    let Value::Map(map) = v else {
        return None;
    };

    if let Some(v) = get_val(&map, "linked_receipts") {
        if let Some(out) = parse_text_array(v) {
            return Some(out);
        }
    }

    if let Some(Value::Map(action_map)) = get_val(&map, "action") {
        if let Some(v) = get_val(action_map, "linked_receipts") {
            if let Some(out) = parse_text_array(v) {
                return Some(out);
            }
        }
    }

    Some(Vec::new())
}

fn get_val<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    for (k, v) in map {
        if let Value::Text(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}

fn get_text(map: &[(Value, Value)], key: &str) -> Option<String> {
    match get_val(map, key) {
        Some(Value::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

fn parse_text_array(v: &Value) -> Option<Vec<String>> {
    let Value::Array(arr) = v else {
        return None;
    };
    let mut out = Vec::new();
    for el in arr {
        match el {
            Value::Text(s) => out.push(s.clone()),
            _ => return None,
        }
    }
    Some(out)
}
