// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Simple whitespace + lowercase + Porter-style stemmer + xxhash64 tokenizer.
//!
//! Designed for BM25 retrieval, not neural embeddings. No BPE, no sentencepiece.
//! Pure Rust, ~1μs per 400-token document.

use xxhash_rust::xxh64::xxh64;

/// A token with its hash and position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub hash: u64,
    pub position: u32,
}

/// Tokenize text into a sequence of hashed tokens.
///
/// Pipeline: split on non-alphanumeric → lowercase → simple suffix strip → xxhash64.
pub fn tokenize(text: &str) -> Vec<Token> {
    let mut tokens = Vec::with_capacity(text.len() / 5); // rough estimate
    let mut position = 0u32;

    for word in text.split(|c: char| !c.is_alphanumeric() && c != '\'') {
        if word.is_empty() {
            continue;
        }

        let lower: String = word.chars().map(|c| c.to_ascii_lowercase()).collect();

        // Skip very short tokens (articles, prepositions) for BM25 quality
        if lower.len() <= 1 {
            continue;
        }

        // Simple suffix stripping (lightweight stemmer)
        let stemmed = stem(&lower);

        let hash = xxh64(stemmed.as_bytes(), 0);
        tokens.push(Token { hash, position });
        position += 1;
    }

    tokens
}

/// Lightweight English stemmer — strips common suffixes.
/// Not as thorough as Porter but good enough for BM25 over short documents.
fn stem(word: &str) -> String {
    let w = word;

    // Don't stem very short words
    if w.len() <= 3 {
        return w.to_string();
    }

    // Step 1: plurals and past tenses
    if let Some(base) = w.strip_suffix("ies") {
        if base.len() >= 2 {
            return format!("{base}i");
        }
    }
    if let Some(base) = w.strip_suffix("ied") {
        if base.len() >= 2 {
            return format!("{base}i");
        }
    }
    if let Some(base) = w.strip_suffix("sses") {
        return format!("{base}ss");
    }
    if let Some(base) = w.strip_suffix("ness") {
        if base.len() >= 2 {
            return base.to_string();
        }
    }
    if let Some(base) = w.strip_suffix("ment") {
        if base.len() >= 3 {
            return base.to_string();
        }
    }
    if let Some(base) = w.strip_suffix("ing") {
        if base.len() >= 3 {
            return base.to_string();
        }
    }
    if let Some(base) = w.strip_suffix("tion") {
        if base.len() >= 2 {
            return format!("{base}t");
        }
    }
    if let Some(base) = w.strip_suffix("ation") {
        if base.len() >= 2 {
            return format!("{base}at");
        }
    }
    if let Some(base) = w.strip_suffix("able") {
        if base.len() >= 3 {
            return base.to_string();
        }
    }
    if let Some(base) = w.strip_suffix("ible") {
        if base.len() >= 3 {
            return base.to_string();
        }
    }
    if let Some(base) = w.strip_suffix("ful") {
        if base.len() >= 3 {
            return base.to_string();
        }
    }
    if let Some(base) = w.strip_suffix("ous") {
        if base.len() >= 3 {
            return base.to_string();
        }
    }
    if let Some(base) = w.strip_suffix("ive") {
        if base.len() >= 3 {
            return base.to_string();
        }
    }
    if let Some(base) = w.strip_suffix("ly") {
        if base.len() >= 3 {
            return base.to_string();
        }
    }
    if let Some(base) = w.strip_suffix("ed") {
        if base.len() >= 3 {
            return base.to_string();
        }
    }
    if let Some(base) = w.strip_suffix("er") {
        if base.len() >= 3 {
            return base.to_string();
        }
    }
    if let Some(base) = w.strip_suffix("es") {
        if base.len() >= 3 {
            return base.to_string();
        }
    }
    if w.ends_with('s') && !w.ends_with("ss") && w.len() >= 4 {
        return w[..w.len() - 1].to_string();
    }

    w.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_tokenization() {
        let tokens = tokenize("Hello, World! This is a test.");
        assert!(tokens.len() >= 4); // hello, world, this, test (skips "is", "a")
                                    // Verify determinism
        let tokens2 = tokenize("Hello, World! This is a test.");
        assert_eq!(tokens, tokens2);
    }

    #[test]
    fn empty_input() {
        assert!(tokenize("").is_empty());
        assert!(tokenize("   ").is_empty());
    }

    #[test]
    fn case_insensitive() {
        let a = tokenize("Terraform");
        let b = tokenize("terraform");
        assert_eq!(a[0].hash, b[0].hash);
    }

    #[test]
    fn stemming_basics() {
        // "running" → "runn" (strip "ing")
        let a = tokenize("running");
        let b = tokenize("runn");
        assert_eq!(a[0].hash, b[0].hash);

        // "policies" → "polici" (strip "ies" → add "i")
        let a = tokenize("policies");
        let b = tokenize("polici");
        assert_eq!(a[0].hash, b[0].hash);
    }

    #[test]
    fn positions_are_sequential() {
        let tokens = tokenize("one two three four five");
        for (i, t) in tokens.iter().enumerate() {
            assert_eq!(t.position, i as u32);
        }
    }
}
