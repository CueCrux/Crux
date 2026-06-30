// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! M3 — wire-payload compaction (Headroom *SmartCrusher* analogue).
//!
//! ExecPlan: `crux-headroom-token-efficiency-learnings-2026-06-24` (milestone M3).
//!
//! The retrieval tool handlers serialize their JSON payload with minified
//! [`serde_json::to_string`] — **identical parsed semantics, fewer wire bytes**
//! than the pretty form. The M0 baseline measured a near-constant ~4×
//! bytes:tokens ratio across every retrieval surface; the bulk of that was
//! pretty-print indentation + newlines, not content.
//!
//! Compaction here is structural-only on the JSON *envelope*: no opaque string
//! value is ever touched (R4), so a code/string payload that happens to contain
//! significant whitespace is preserved byte-for-byte inside its quotes.
//!
//! ## History — flag removed (CO-5, 2026-06-30)
//!
//! Compaction shipped behind `CRUX_PAYLOAD_COMPACT` (CO-1, default-ON 2026-06-25)
//! and was confirmed safe across every consumer. The escape-hatch env flag is now
//! **removed**: compaction is unconditional. The pretty path survives only as
//! [`serialize_with`]`(.., false)`, used by the holdout control arm
//! ([`crate::holdout`]) to measure the saving against an unshaped baseline.

use serde_json::Value;

/// Serialize a retrieval payload for the wire. `compact == true` ⇒ minified
/// [`serde_json::to_string`] (the unconditional default since CO-5); `false` ⇒
/// [`serde_json::to_string_pretty`], retained for the holdout control arm. The
/// parsed `Value` is identical in both modes — only inter-token whitespace differs.
pub fn serialize_with(value: &Value, compact: bool) -> String {
    if compact {
        serde_json::to_string(value).unwrap_or_default()
    } else {
        serde_json::to_string_pretty(value).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "contract": "crc-v1",
            "pointers": [{"id": "3:8801", "score": 12.4}, {"id": "7:2140", "score": 9.1}],
            "cost_estimate": {"pointer": 80, "summary": 300, "full": 150},
            "meta": {"score_space": "bm25_lexical", "total_candidates": 30},
            "note": "a string  with   embedded     whitespace kept verbatim"
        })
    }

    #[test]
    fn unshaped_serialize_is_pretty() {
        let v = sample();
        // The holdout control arm's unshaped serialization == pretty.
        assert_eq!(serialize_with(&v, false), serde_json::to_string_pretty(&v).unwrap());
    }

    #[test]
    fn compact_parses_identically_and_is_smaller() {
        let v = sample();
        let pretty = serialize_with(&v, false);
        let compact = serialize_with(&v, true);
        // Identical parsed semantics (the golden invariant M3 must hold).
        let p: Value = serde_json::from_str(&pretty).unwrap();
        let c: Value = serde_json::from_str(&compact).unwrap();
        assert_eq!(p, c);
        assert_eq!(c, v);
        // Strictly fewer bytes on the wire (pretty whitespace removed).
        assert!(
            compact.len() < pretty.len(),
            "compact {} !< pretty {}",
            compact.len(),
            pretty.len()
        );
    }

    #[test]
    fn opaque_string_whitespace_preserved() {
        // R4: structural compaction never touches inside string values.
        let v = sample();
        let compact = serialize_with(&v, true);
        let parsed: Value = serde_json::from_str(&compact).unwrap();
        assert_eq!(parsed["note"], v["note"]);
    }
}
