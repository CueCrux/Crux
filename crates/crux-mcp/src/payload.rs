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
//! ## Default-ON cutover (CO-1, 2026-06-25)
//!
//! As of the token-efficiency default-ON cutover (CO-1), compaction is the
//! **default**: it is pure whitespace minification with identical parsed
//! semantics, the cross-client consumers all `JSON.parse` the body (whitespace-
//! insensitive), and the contract pre-flight confirmed no consumer string-scrapes
//! the payload. An operator opts back out to pretty with
//! `CRUX_PAYLOAD_COMPACT=0` (also `false`/`off`/`no`) — that OFF path is still
//! byte-identical to pre-M3, the permanent escape hatch / instant rollback.

use serde_json::Value;

/// Env flag name for M3 payload compaction. **Default ON** since the CO-1
/// cutover; set to `0`/`false`/`off`/`no` to opt back out to pretty.
pub const COMPACT_ENV: &str = "CRUX_PAYLOAD_COMPACT";

/// Opt-out env parse: the flag is **ON unless explicitly disabled**. Unset /
/// `""` / any value other than `0`/`false`/`off`/`no` ⇒ true; only an explicit
/// falsey value ⇒ false. (Inverts the pre-cutover `env_truthy` default.)
fn env_opt_out_enabled(var: &str) -> bool {
    match std::env::var(var) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "0" | "false" | "off" | "no")
        }
        // Unset ⇒ default ON (the CO-1 cutover).
        Err(_) => true,
    }
}

/// True when wire-payload compaction is enabled (the default since CO-1).
/// `CRUX_PAYLOAD_COMPACT=0`/`false`/`off`/`no` opts back out to pretty.
pub fn compact_enabled() -> bool {
    env_opt_out_enabled(COMPACT_ENV)
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
/// (**default ON** since CO-1 ⇒ minified; opt out with `CRUX_PAYLOAD_COMPACT=0`
/// for the byte-identical pre-M3 pretty payload).
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
    fn env_opt_out_default_on_and_explicit_off() {
        // CO-1: default ON when unset; only an explicit falsey value opts out.
        // (Test the parse via a name we control to avoid racing the real env.)
        let k = "CRUX_PAYLOAD_COMPACT_TEST_A";
        std::env::remove_var(k);
        assert!(env_opt_out_enabled(k), "unset ⇒ default ON");
        std::env::set_var(k, "1");
        assert!(env_opt_out_enabled(k), "truthy ⇒ ON");
        std::env::set_var(k, "0");
        assert!(!env_opt_out_enabled(k), "0 ⇒ opt-out OFF");
        std::env::set_var(k, "off");
        assert!(!env_opt_out_enabled(k), "off ⇒ opt-out OFF");
        std::env::set_var(k, "false");
        assert!(!env_opt_out_enabled(k), "false ⇒ opt-out OFF");
        std::env::remove_var(k);
        assert!(env_opt_out_enabled(k));
    }
}
