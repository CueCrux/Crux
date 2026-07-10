// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Deterministic **extractive** summariser for reasoning capture (M3).
//!
//! Given the raw `type:"thinking"` text of an assistant turn, produce a short
//! summary by *selecting* a few sentences — the opening, any decision-marker
//! lines, and the conclusion — never by paraphrasing or calling a model. The
//! output is therefore always a **compression of the input** (a subset of its
//! sentences), which makes the R1 guarantee — "never raw chain-of-thought in
//! the signed chain" — mechanical: the caller asserts the summary is shorter
//! than and not byte-equal to the raw thinking before it is ever written.
//!
//! No LLM dependency (the free/local path stays deterministic + replayable);
//! an LLM-summary mode is a registered, unimplemented opt-in for a later plan.

use std::collections::HashSet;

/// Phrases that mark a load-bearing reasoning sentence — the "why", the choice,
/// the pivot. Matched case-insensitively as substrings.
const DECISION_MARKERS: &[&str] = &[
    "because",
    "so i",
    "therefore",
    "decide",
    "decision",
    "chose",
    "choose",
    "the issue",
    "the problem",
    "root cause",
    "the fix",
    "instead",
    "actually",
    "wait",
    "key ",
    "the point",
    "let me",
    "i'll",
    "i will",
    "should",
    "must",
    "avoid",
    "risk",
    "the plan",
    "conclusion",
];

/// Produce an extractive summary of `text`, bounded to ~`max_chars` characters.
///
/// Selection (deterministic, order-preserving, de-duplicated): the first
/// sentence, every interior sentence containing a decision marker (the "why" /
/// the choice / the pivot), and the last sentence. Returns an empty string for
/// empty input.
#[must_use]
pub fn extractive_summary(text: &str, max_chars: usize) -> String {
    let sentences = split_sentences(text);
    if sentences.is_empty() {
        return String::new();
    }

    let mut picked: Vec<&str> = Vec::new();
    picked.push(sentences[0]);
    if sentences.len() >= 2 {
        let last = sentences.len() - 1;
        for s in &sentences[1..last] {
            if is_decision_sentence(s) {
                picked.push(s);
            }
        }
        picked.push(sentences[last]);
    }

    let mut out = String::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for s in picked {
        if s.is_empty() || !seen.insert(s) {
            continue;
        }
        let extra = s.chars().count() + usize::from(!out.is_empty());
        if !out.is_empty() && out.chars().count() + extra > max_chars {
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(s);
    }
    out
}

/// Split into trimmed, non-empty sentences on terminal punctuation and newlines.
fn split_sentences(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut start = 0usize;
    for (i, ch) in text.char_indices() {
        let after = i + ch.len_utf8();
        if ch == '\n' {
            // Newline always splits; drop the newline itself.
            let seg = text[start..i].trim();
            if !seg.is_empty() {
                out.push(seg);
            }
            start = after;
        } else if matches!(ch, '.' | '!' | '?') && bytes.get(after).is_none_or(|b| b.is_ascii_whitespace()) {
            // Terminal `.`/`!`/`?` followed by whitespace/EOF (so "v0.5" / "e.g."
            // don't shatter). Keep the punctuation in the sentence for readability.
            let seg = text[start..after].trim();
            if !seg.is_empty() {
                out.push(seg);
            }
            start = after;
        }
    }
    let tail = text[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

fn is_decision_sentence(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    DECISION_MARKERS.iter().any(|m| lower.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_empty_summary() {
        assert_eq!(extractive_summary("", 200), "");
        assert_eq!(extractive_summary("   \n  ", 200), "");
    }

    #[test]
    fn picks_first_markers_and_last() {
        let thinking = "Let me look at the parser first. \
            The input is a JSON list. \
            The problem is the offset is wrong because we skipped the header. \
            Some filler sentence here. \
            So I will add one to the index. \
            Done, the fix works.";
        let s = extractive_summary(thinking, 500);
        // First + last present.
        assert!(s.starts_with("Let me look at the parser first"));
        assert!(s.contains("the fix works"));
        // Decision-marker sentences pulled in.
        assert!(s.contains("the offset is wrong"));
        assert!(s.contains("add one to the index"));
        // Pure filler dropped.
        assert!(!s.contains("Some filler sentence"));
    }

    #[test]
    fn summary_is_a_compression_r1_guard() {
        let thinking = "First I considered approach A. \
            Then approach B, but the problem is B is slow because it re-reads. \
            A bunch of middle reasoning that is just narration and more narration. \
            Even more narration that adds nothing of substance to the trace. \
            Therefore I chose A.";
        let s = extractive_summary(thinking, 1000);
        // The whole point of R1: the summary must be strictly shorter than and
        // never byte-equal to the raw thinking.
        assert!(
            s.len() < thinking.len(),
            "summary must compress: {} vs {}",
            s.len(),
            thinking.len()
        );
        assert_ne!(s, thinking);
    }

    #[test]
    fn respects_max_chars() {
        let thinking = "Alpha decided one. Beta because two. Gamma therefore three. Delta the fix four.";
        let s = extractive_summary(thinking, 20);
        assert!(s.chars().count() <= 20, "got {} chars: {s:?}", s.chars().count());
        assert!(!s.is_empty());
    }

    #[test]
    fn single_sentence_returns_it_once() {
        // A lone sentence: first == last; de-dup keeps one copy (caller applies
        // the size threshold to decide whether to emit a blob at all).
        let s = extractive_summary("Just one thought here.", 200);
        assert_eq!(s, "Just one thought here.");
    }

    #[test]
    fn does_not_split_on_decimal_or_abbrev() {
        let s = extractive_summary("We shipped v0.5.9 today. It works.", 200);
        // "v0.5.9" stays intact (not split into v0 / 5 / 9).
        assert!(s.contains("v0.5.9"));
    }
}
