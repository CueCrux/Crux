// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! M3 — wire-payload compaction (Headroom *SmartCrusher* analogue).
//!
//! ExecPlan: `crux-headroom-token-efficiency-learnings-2026-06-24` (milestone M3).
//!
//! The retrieval tool handlers serialize their JSON payload with
//! [`serde_json::to_string_pretty`] — whitespace-padded JSON on the wire. The
//! M0 baseline measured a near-constant ~4× bytes:tokens ratio across every
//! retrieval surface; the bulk of that is pretty-print indentation + newlines,
//! not content. Behind the `CRUX_PAYLOAD_COMPACT` flag (default **OFF**) we emit
//! minified [`serde_json::to_string`] instead — **identical parsed semantics,
//! fewer wire bytes**.
//!
//! Compaction here is structural-only on the JSON *envelope*: no opaque string
//! value is ever touched (R4), so a code/string payload that happens to contain
//! significant whitespace is preserved byte-for-byte inside its quotes.
//!
//! Flag OFF ⇒ byte-identical to today (the regression safety net for every
//! consumer: VaultCrux BFF, Crucible backends, WikiCrux deref).

use serde_json::Value;

/// Env flag name for M3 payload compaction. Default OFF.
pub const COMPACT_ENV: &str = "CRUX_PAYLOAD_COMPACT";

/// Truthy-env parse matching the crate convention (see `ledger::env_truthy`):
/// unset / `""` / `0` / `false` / `off` / `no` ⇒ false; anything else ⇒ true.
fn env_truthy(var: &str) -> bool {
    match std::env::var(var) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// True when wire-payload compaction is enabled via `CRUX_PAYLOAD_COMPACT`.
pub fn compact_enabled() -> bool {
    env_truthy(COMPACT_ENV)
}

/// Serialize a retrieval payload for the wire. `compact == true` ⇒ minified
/// [`serde_json::to_string`]; `false` ⇒ [`serde_json::to_string_pretty`]
/// (today's byte-identical default). The parsed `Value` is identical in both
/// modes — only inter-token whitespace differs.
pub fn serialize_with(value: &Value, compact: bool) -> String {
    if compact {
        serde_json::to_string(value).unwrap_or_default()
    } else {
        serde_json::to_string_pretty(value).unwrap_or_default()
    }
}

/// Serialize a retrieval payload honoring the `CRUX_PAYLOAD_COMPACT` flag
/// (default OFF ⇒ pretty, byte-identical to pre-M3 behaviour).
pub fn serialize(value: &Value) -> String {
    serialize_with(value, compact_enabled())
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
    fn flag_off_is_byte_identical_to_pretty() {
        let v = sample();
        // The regression net: serialize_with(.., false) == today's call.
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

    #[test]
    fn env_truthy_matches_convention() {
        // Default OFF when unset (cannot rely on env in parallel tests, so test
        // the parse via a name we control and set/unset locally).
        std::env::set_var("CRUX_PAYLOAD_COMPACT_TEST_A", "1");
        assert!(env_truthy("CRUX_PAYLOAD_COMPACT_TEST_A"));
        std::env::set_var("CRUX_PAYLOAD_COMPACT_TEST_A", "off");
        assert!(!env_truthy("CRUX_PAYLOAD_COMPACT_TEST_A"));
        std::env::remove_var("CRUX_PAYLOAD_COMPACT_TEST_A");
        assert!(!env_truthy("CRUX_PAYLOAD_COMPACT_TEST_A"));
    }
}
