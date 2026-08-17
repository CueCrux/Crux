// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Shared token estimator for the MCP surface (action-ledger M1).
//!
//! One consistent heuristic — serialized JSON length divided by
//! [`CHARS_PER_TOKEN`] (~4 chars/token), floored at 1 — replacing the
//! ad-hoc per-module guesses that used to live in `traces.rs`
//! (`token_budget / 50`) and `tools/freshness.rs` (`f.tokens.max(8)`).
//!
//! Precision is explicitly a non-goal (no tokenizer dependency); the
//! point is *comparability*: every budget check, ledger record, and
//! accumulator increment uses the same yardstick, so per-tool and
//! per-passport numbers can be compared and summed meaningfully.
//!
//! The [`Value`] path serialises through a counting writer — no
//! intermediate `String` allocation — so it is safe to call on the tool
//! dispatch hot path even for large (multi-hundred-KB) results.

use serde_json::Value;

/// Heuristic chars-per-token divisor. ~4 chars/token is the standard
/// rule of thumb for English text + JSON punctuation under BPE-family
/// tokenizers.
pub const CHARS_PER_TOKEN: u64 = 4;

/// `io::Write` sink that counts bytes and discards them.
struct CountingWriter {
    bytes: u64,
}

impl std::io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Compact-serialized byte length of a JSON value, computed through a
/// counting writer (no intermediate `String`). Returns 0 if
/// serialisation fails (never happens for `Value` in practice — object
/// keys are always strings).
pub fn serialized_len(value: &Value) -> u64 {
    let mut sink = CountingWriter { bytes: 0 };
    if serde_json::to_writer(&mut sink, value).is_err() {
        return 0;
    }
    sink.bytes
}

/// Estimate the token cost of a JSON value: compact-serialized byte
/// length / [`CHARS_PER_TOKEN`], floored at 1 (everything costs at
/// least one token to emit). Estimation must never break a tool —
/// serialisation failure yields the floor.
pub fn estimate_tokens(value: &Value) -> u64 {
    (serialized_len(value) / CHARS_PER_TOKEN).max(1)
}

/// Estimate the token cost of a raw string slice (no JSON quoting
/// overhead added — used for error messages and pre-serialized lines).
pub fn estimate_tokens_str(s: &str) -> u64 {
    (s.len() as u64 / CHARS_PER_TOKEN).max(1)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn null_floors_at_one() {
        // "null" = 4 bytes → exactly 1; still ≥ 1 by the floor.
        assert_eq!(estimate_tokens(&Value::Null), 1);
    }

    #[test]
    fn empty_string_floors_at_one() {
        // "\"\"" = 2 bytes → 0 before floor.
        assert_eq!(estimate_tokens(&json!("")), 1);
        assert_eq!(estimate_tokens_str(""), 1);
    }

    #[test]
    fn fixed_string_fixture_is_stable() {
        // 400 'a' chars + 2 quote bytes = 402 bytes → 100 tokens.
        let s = "a".repeat(400);
        assert_eq!(estimate_tokens(&json!(s)), 100);
        // Raw string: 400 bytes → 100 tokens.
        assert_eq!(estimate_tokens_str(&"a".repeat(400)), 100);
    }

    #[test]
    fn fixed_object_fixture_is_stable() {
        // Compact form: {"entity":"project-x","key":"status","value":"done"}
        // = 53 bytes → 13 tokens. If this assertion ever moves, the
        // estimator semantics changed — bump deliberately.
        let v = json!({"entity": "project-x", "key": "status", "value": "done"});
        assert_eq!(estimate_tokens(&v), 13);
    }

    #[test]
    fn array_scales_linearly_with_content() {
        let small = json!([1, 2, 3]);
        let big = json!(vec!["x".repeat(40); 50]);
        assert!(estimate_tokens(&big) > estimate_tokens(&small) * 10);
    }

    #[test]
    fn matches_serialized_length() {
        let v = json!({"a": [1, 2, 3], "b": {"c": "deep"}});
        let expected = (serde_json::to_string(&v).unwrap().len() as u64 / CHARS_PER_TOKEN).max(1);
        assert_eq!(estimate_tokens(&v), expected);
    }
}
