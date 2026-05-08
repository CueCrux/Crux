// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Intent shaping (master-plan §4.4, Phase 7).
//!
//! An agent can pass an `intent` hint to the handshake; the generator
//! reorders the capability graph so intent-relevant capabilities come
//! first. If the agent also sets `hints.max_capabilities`, lower-priority
//! capabilities can be elided from the graph.
//!
//! **Key invariants:**
//!
//! - Intent shaping is **deterministic** — same intent + passport + flags
//!   always produce the same (ordered) graph. The sort is stable.
//! - The intent string binds cryptographically into the
//!   `capability_graph_hash` (via [`hash_capability_graph_with_intent`]).
//!   Two different intents producing otherwise identical capability
//!   lists still produce different graph hashes.
//! - The table is conservative: unknown intents fall through to the
//!   default (unshaped) order. No silent "did you mean?" matching.
//!
//! **When the intent is `None`** the generator runs its normal path and
//! hashes just the capability array; the two hash paths differ by one
//! byte (the presence-flag of the intent in the hash input) which also
//! prevents cross-mode replay.

use std::collections::HashMap;

use blake3::Hasher;

use crate::canonical::CborValue;
use crate::plan::{Capability, HASH_LEN};

/// Maps a known intent to a per-affinity bias (higher = earlier in the
/// reordered graph). The table is static: all capabilities whose affinity
/// is not in the map get a bias of 0 (they land at the end, preserving
/// their catalogue order).
pub type IntentTable = HashMap<&'static str, Vec<(&'static str, i32)>>;

/// Built-in intent vocabulary. Conservative: only intents that have
/// an obvious shaping story live here. Unknown intents silently fall
/// through to the default order.
pub fn default_intent_table() -> IntentTable {
    let mut t: IntentTable = HashMap::new();
    t.insert("audit_review", vec![("audit", 30), ("proof", 20), ("retrieval", 10)]);
    t.insert(
        "document_ingest",
        vec![("memory", 30), ("journal", 20), ("retrieval", 10)],
    );
    t.insert("session_review", vec![("session", 30), ("memory", 20), ("journal", 10)]);
    t.insert("compliance_export", vec![("audit", 30), ("proof", 25), ("economy", 10)]);
    t.insert(
        "knowledge_query",
        vec![("retrieval", 30), ("memory", 20), ("session", 5)],
    );
    t
}

/// Reorder `capabilities` in place according to the intent's bias
/// table. Stable sort — capabilities with the same bias keep their
/// catalogue order. If `max_capabilities` is supplied AND the shaped
/// graph is longer, truncate to the highest-bias N.
///
/// Unknown intent = no-op.
/// Reorder `capabilities` using a caller-supplied `affinity_of`
/// resolver. This is the form the generator uses (it knows each
/// capability's source catalogue entry and therefore its affinity).
pub fn apply_intent_shaping_with_affinity(
    capabilities: &mut Vec<Capability>,
    table: &IntentTable,
    intent: Option<&str>,
    max_capabilities: Option<usize>,
    affinity_of: impl Fn(&Capability) -> &str,
) -> bool {
    let Some(intent_key) = intent else { return false };
    let Some(biases) = table.get(intent_key) else {
        return false;
    };

    let bias_for = |affinity: &str| -> i32 { biases.iter().find(|(aff, _)| *aff == affinity).map_or(0, |(_, b)| *b) };

    // Decorate each capability with (bias, original_index) so the sort
    // is stable by catalogue order on ties — deterministic output.
    let mut decorated: Vec<(i32, usize, Capability)> = capabilities
        .drain(..)
        .enumerate()
        .map(|(i, cap)| {
            let bias = bias_for(affinity_of(&cap));
            (bias, i, cap)
        })
        .collect();
    // Sort descending by bias, ascending by original index on ties.
    decorated.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    *capabilities = decorated.into_iter().map(|(_, _, c)| c).collect();

    if let Some(n) = max_capabilities {
        capabilities.truncate(n);
    }
    true
}

/// BLAKE3 hash over a canonical-CBOR encoding that binds the intent
/// string to the capability graph (master-plan §4.4). The shape is:
///
/// ```text
/// {
///   "intent": <text | null>,
///   "caps":   [ <cap>, ... ],
/// }
/// ```
///
/// When `intent` is `None`, the field encodes as CBOR null; when it's
/// `Some("x")` it encodes as the text string. Two distinct intents can
/// never collapse to the same hash even if they happen to produce the
/// same capability list.
pub fn hash_capability_graph_with_intent(caps: &[Capability], intent: Option<&str>) -> [u8; HASH_LEN] {
    let intent_value = match intent {
        Some(s) => CborValue::Text(s.to_string()),
        None => CborValue::Null,
    };
    let cap_array = CborValue::Array(
        caps.iter()
            .map(|c| {
                CborValue::Map(vec![
                    ("cap".into(), CborValue::Text(c.cap.clone())),
                    ("prefer".into(), CborValue::Text(c.prefer.clone())),
                    ("shape".into(), CborValue::Text(c.shape.clone())),
                    (
                        "min_tier".into(),
                        match &c.min_tier {
                            Some(s) => CborValue::Text(s.clone()),
                            None => CborValue::Null,
                        },
                    ),
                    ("cost_class".into(), CborValue::Text(c.cost_class.clone())),
                    (
                        "impl_path".into(),
                        CborValue::Map(vec![
                            (
                                "ce".into(),
                                match &c.impl_path.ce {
                                    Some(s) => CborValue::Text(s.clone()),
                                    None => CborValue::Null,
                                },
                            ),
                            (
                                "core".into(),
                                match &c.impl_path.core {
                                    Some(s) => CborValue::Text(s.clone()),
                                    None => CborValue::Null,
                                },
                            ),
                        ]),
                    ),
                ])
            })
            .collect(),
    );
    let tree = CborValue::Map(vec![("intent".into(), intent_value), ("caps".into(), cap_array)]);
    let encoded = tree.encode();
    let mut hasher = Hasher::new();
    hasher.update(&encoded);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::ImplPath;

    fn cap(name: &str, _affinity: &str) -> Capability {
        Capability::legacy(name, "mcp", "Receipt", None, "free", ImplPath { ce: None, core: None })
    }

    fn caps_with_affinity() -> Vec<(Capability, &'static str)> {
        vec![
            (cap("retrieve", "retrieval"), "retrieval"),
            (cap("memory_get", "memory"), "memory"),
            (cap("audit_replay", "audit"), "audit"),
            (cap("proof_verify", "proof"), "proof"),
            (cap("session_context", "session"), "session"),
            (cap("journal_append", "journal"), "journal"),
        ]
    }

    #[test]
    fn audit_review_puts_audit_first() {
        let table = default_intent_table();
        let with_aff = caps_with_affinity();
        let affinity_map: HashMap<String, &'static str> = with_aff.iter().map(|(c, a)| (c.cap.clone(), *a)).collect();
        let mut caps: Vec<Capability> = with_aff.iter().map(|(c, _)| c.clone()).collect();

        let applied = apply_intent_shaping_with_affinity(&mut caps, &table, Some("audit_review"), None, |c| {
            affinity_map.get(&c.cap).copied().unwrap_or("")
        });
        assert!(applied);
        assert_eq!(caps[0].cap, "audit_replay");
        assert_eq!(caps[1].cap, "proof_verify");
        assert_eq!(caps[2].cap, "retrieve");
    }

    #[test]
    fn max_capabilities_truncates_to_top_n() {
        let table = default_intent_table();
        let with_aff = caps_with_affinity();
        let affinity_map: HashMap<String, &'static str> = with_aff.iter().map(|(c, a)| (c.cap.clone(), *a)).collect();
        let mut caps: Vec<Capability> = with_aff.iter().map(|(c, _)| c.clone()).collect();
        apply_intent_shaping_with_affinity(&mut caps, &table, Some("audit_review"), Some(2), |c| {
            affinity_map.get(&c.cap).copied().unwrap_or("")
        });
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].cap, "audit_replay");
        assert_eq!(caps[1].cap, "proof_verify");
    }

    #[test]
    fn unknown_intent_is_a_noop() {
        let table = default_intent_table();
        let with_aff = caps_with_affinity();
        let original: Vec<String> = with_aff.iter().map(|(c, _)| c.cap.clone()).collect();
        let affinity_map: HashMap<String, &'static str> = with_aff.iter().map(|(c, a)| (c.cap.clone(), *a)).collect();
        let mut caps: Vec<Capability> = with_aff.iter().map(|(c, _)| c.clone()).collect();
        let applied = apply_intent_shaping_with_affinity(&mut caps, &table, Some("nonexistent_intent"), None, |c| {
            affinity_map.get(&c.cap).copied().unwrap_or("")
        });
        assert!(!applied);
        let after: Vec<String> = caps.iter().map(|c| c.cap.clone()).collect();
        assert_eq!(after, original);
    }

    #[test]
    fn ordering_is_deterministic_across_runs() {
        let table = default_intent_table();
        let with_aff = caps_with_affinity();
        let affinity_map: HashMap<String, &'static str> = with_aff.iter().map(|(c, a)| (c.cap.clone(), *a)).collect();

        let run_once = || {
            let mut caps: Vec<Capability> = with_aff.iter().map(|(c, _)| c.clone()).collect();
            apply_intent_shaping_with_affinity(&mut caps, &table, Some("document_ingest"), None, |c| {
                affinity_map.get(&c.cap).copied().unwrap_or("")
            });
            caps.into_iter().map(|c| c.cap).collect::<Vec<_>>()
        };
        assert_eq!(run_once(), run_once());
    }

    #[test]
    fn different_intents_produce_different_graph_hashes() {
        let caps: Vec<Capability> = caps_with_affinity().into_iter().map(|(c, _)| c).collect();
        let h_audit = hash_capability_graph_with_intent(&caps, Some("audit_review"));
        let h_ingest = hash_capability_graph_with_intent(&caps, Some("document_ingest"));
        let h_none = hash_capability_graph_with_intent(&caps, None);
        assert_ne!(h_audit, h_ingest);
        assert_ne!(h_audit, h_none);
        assert_ne!(h_ingest, h_none);
    }

    #[test]
    fn same_intent_and_caps_produce_identical_hash() {
        let caps: Vec<Capability> = caps_with_affinity().into_iter().map(|(c, _)| c).collect();
        let a = hash_capability_graph_with_intent(&caps, Some("audit_review"));
        let b = hash_capability_graph_with_intent(&caps, Some("audit_review"));
        assert_eq!(a, b);
    }
}
