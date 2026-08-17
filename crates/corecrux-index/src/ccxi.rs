// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `.ccxi` file format — per-segment companion inverted index.
//!
//! Layout (v2):
//!   CcxiHeader (256 bytes, page-aligned)
//!   VocabTable (vocab_size × 16 bytes)
//!   PostingsArea (PForDelta compressed posting lists)
//!   DocTable (total_frames × 16 bytes)
//!   CcxiFooter (64 bytes)
//!
//! v2 change: DocEntry extended from 8 to 16 bytes, adding `tenant_hash_full: u64`.
//! BM25 uses `tenant_hash_lo16` for fast postings-level skip; fused retrieval uses
//! the full 64-bit hash for exact tenant isolation (prevents 16-bit hash collisions
//! from leaking data across tenants).

use std::collections::BTreeMap;

use crate::pfordelta::{pfordelta_decode, pfordelta_encode};
use crate::tokenizer::tokenize;
use crate::IndexError;

pub const CCXI_MAGIC: u32 = 0x4343_5849; // "CCXI"
pub const CCXI_VERSION: u16 = 2;
pub const CCXI_HEADER_LEN: usize = 256;
pub const CCXI_FOOTER_LEN: usize = 64;
pub const VOCAB_ENTRY_LEN: usize = 16;
pub const DOC_ENTRY_LEN: usize = 16; // u32 frame_offset + u16 doc_length_tokens + u16 tenant_hash_lo16 + u64 tenant_hash_full

#[derive(Debug, Clone)]
pub struct CcxiHeader {
    pub magic: u32,
    pub version: u16,
    pub shard_id: u32,
    pub segment_seq: u64,
    pub epoch: u64,
    pub vocab_size: u32,
    pub total_postings: u64,
    pub total_frames: u32,
    pub tokenizer_version: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct VocabEntry {
    pub token_hash: u64,
    pub postings_offset: u32,
    pub postings_len: u32, // byte length of compressed postings
}

#[derive(Debug, Clone, Copy)]
pub struct DocEntry {
    pub frame_offset: u32, // offset within segment record area
    pub doc_length_tokens: u16,
    pub tenant_hash_lo16: u16, // fast-path filter in BM25 postings scan
    pub tenant_hash_full: u64, // exact tenant isolation — prevents lo16 collision leaks
}

/// Builder: accumulates documents and produces a complete .ccxi file.
pub struct CcxiBuilder {
    shard_id: u32,
    segment_seq: u64,
    epoch: u64,
    // token_hash → vec of (doc_id, term_frequency)
    postings: BTreeMap<u64, Vec<(u32, u16)>>,
    docs: Vec<DocEntry>,
}

impl CcxiBuilder {
    pub fn new(shard_id: u32, segment_seq: u64, epoch: u64) -> Self {
        Self {
            shard_id,
            segment_seq,
            epoch,
            postings: BTreeMap::new(),
            docs: Vec::new(),
        }
    }

    /// Add a document (frame) to the index.
    ///
    /// `doc_id` is the local index within this segment (0-based).
    /// `text` is the payload content to tokenize.
    /// `frame_offset` is the byte offset in the segment record area.
    /// `tenant_hash` is the full tenant hash (we store low 16 bits).
    pub fn add_document(&mut self, doc_id: u32, text: &str, frame_offset: u32, tenant_hash: u64) {
        let tokens = tokenize(text);
        let doc_len = tokens.len() as u16;

        // Count term frequencies
        let mut tf_map: BTreeMap<u64, u16> = BTreeMap::new();
        for t in &tokens {
            *tf_map.entry(t.hash).or_insert(0) += 1;
        }

        // Add to posting lists
        for (token_hash, tf) in tf_map {
            self.postings.entry(token_hash).or_default().push((doc_id, tf));
        }

        // Add doc entry
        while self.docs.len() <= doc_id as usize {
            self.docs.push(DocEntry {
                frame_offset: 0,
                doc_length_tokens: 0,
                tenant_hash_lo16: 0,
                tenant_hash_full: 0,
            });
        }
        self.docs[doc_id as usize] = DocEntry {
            frame_offset,
            doc_length_tokens: doc_len,
            tenant_hash_lo16: (tenant_hash & 0xFFFF) as u16,
            tenant_hash_full: tenant_hash,
        };
    }

    /// Build the complete .ccxi file bytes.
    pub fn build(&self) -> Vec<u8> {
        let vocab_size = self.postings.len() as u32;
        let total_frames = self.docs.len() as u32;

        // Build compressed postings and vocab table
        let mut vocab_entries: Vec<VocabEntry> = Vec::with_capacity(vocab_size as usize);
        let mut postings_area: Vec<u8> = Vec::new();
        let mut total_postings: u64 = 0;

        for (&token_hash, posting_list) in &self.postings {
            let offset = postings_area.len() as u32;

            // Separate doc_ids and term_frequencies
            let doc_ids: Vec<u32> = posting_list.iter().map(|(d, _)| *d).collect();
            let tfs: Vec<u16> = posting_list.iter().map(|(_, t)| *t).collect();

            // PForDelta encode doc_ids
            let compressed_ids = pfordelta_encode(&doc_ids);
            postings_area.extend_from_slice(&compressed_ids);

            // Store TFs as raw u16 LE (they're small, compression not worth it)
            let tf_count = tfs.len() as u32;
            postings_area.extend_from_slice(&tf_count.to_le_bytes());
            for tf in &tfs {
                postings_area.extend_from_slice(&tf.to_le_bytes());
            }

            let postings_len = (postings_area.len() as u32) - offset;
            total_postings += doc_ids.len() as u64;

            vocab_entries.push(VocabEntry {
                token_hash,
                postings_offset: offset,
                postings_len,
            });
        }

        // Calculate sizes
        let header_len = CCXI_HEADER_LEN;
        let vocab_len = vocab_entries.len() * VOCAB_ENTRY_LEN;
        let postings_len = postings_area.len();
        let doc_table_len = self.docs.len() * DOC_ENTRY_LEN;
        let footer_len = CCXI_FOOTER_LEN;
        let total_len = header_len + vocab_len + postings_len + doc_table_len + footer_len;

        let mut out = Vec::with_capacity(total_len);

        // === Header (256 bytes, zero-padded) ===
        let mut header_buf = vec![0u8; CCXI_HEADER_LEN];
        write_u32(&mut header_buf, 0, CCXI_MAGIC);
        write_u16(&mut header_buf, 4, CCXI_VERSION);
        write_u32(&mut header_buf, 6, self.shard_id);
        write_u64(&mut header_buf, 10, self.segment_seq);
        write_u64(&mut header_buf, 18, self.epoch);
        write_u32(&mut header_buf, 26, vocab_size);
        write_u64(&mut header_buf, 30, total_postings);
        write_u32(&mut header_buf, 38, total_frames);
        write_u16(&mut header_buf, 42, 1); // tokenizer_version
        out.extend_from_slice(&header_buf);

        // === Vocab Table ===
        for ve in &vocab_entries {
            out.extend_from_slice(&ve.token_hash.to_le_bytes());
            out.extend_from_slice(&ve.postings_offset.to_le_bytes());
            out.extend_from_slice(&ve.postings_len.to_le_bytes());
        }

        // === Postings Area ===
        out.extend_from_slice(&postings_area);

        // === Doc Table (v2: 16 bytes per entry) ===
        for de in &self.docs {
            out.extend_from_slice(&de.frame_offset.to_le_bytes());
            out.extend_from_slice(&de.doc_length_tokens.to_le_bytes());
            out.extend_from_slice(&de.tenant_hash_lo16.to_le_bytes());
            out.extend_from_slice(&de.tenant_hash_full.to_le_bytes());
        }

        // === Footer (64 bytes) ===
        let vocab_hash = blake3::hash(&out[CCXI_HEADER_LEN..CCXI_HEADER_LEN + vocab_len]);
        let postings_hash = blake3::hash(&out[CCXI_HEADER_LEN + vocab_len..CCXI_HEADER_LEN + vocab_len + postings_len]);

        let mut footer = vec![0u8; CCXI_FOOTER_LEN];
        footer[0..32].copy_from_slice(vocab_hash.as_bytes());
        footer[32..64].copy_from_slice(postings_hash.as_bytes());
        out.extend_from_slice(&footer);

        out
    }

    pub fn doc_count(&self) -> u32 {
        self.docs.len() as u32
    }

    pub fn vocab_size(&self) -> u32 {
        self.postings.len() as u32
    }
}

/// Reader: loads a .ccxi file and provides access to vocabulary, postings, and doc table.
pub struct CcxiReader {
    pub header: CcxiHeader,
    pub vocab: Vec<VocabEntry>,
    pub postings_area: Vec<u8>,
    pub docs: Vec<DocEntry>,
}

impl CcxiReader {
    /// Parse a .ccxi file from bytes.
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        if data.len() < CCXI_HEADER_LEN + CCXI_FOOTER_LEN {
            return Err(IndexError::BufferTooSmall);
        }

        // Parse header
        let magic = read_u32(data, 0);
        if magic != CCXI_MAGIC {
            return Err(IndexError::InvalidMagic {
                expected: CCXI_MAGIC,
                actual: magic,
            });
        }
        let version = read_u16(data, 4);
        if version != CCXI_VERSION {
            return Err(IndexError::UnsupportedVersion { version });
        }
        // v2 format required — DocEntry is 16 bytes with tenant_hash_full

        let header = CcxiHeader {
            magic,
            version,
            shard_id: read_u32(data, 6),
            segment_seq: read_u64(data, 10),
            epoch: read_u64(data, 18),
            vocab_size: read_u32(data, 26),
            total_postings: read_u64(data, 30),
            total_frames: read_u32(data, 38),
            tokenizer_version: read_u16(data, 42),
        };

        let vocab_len = header.vocab_size as usize * VOCAB_ENTRY_LEN;
        let vocab_start = CCXI_HEADER_LEN;
        let vocab_end = vocab_start + vocab_len;

        if vocab_end > data.len() {
            return Err(IndexError::BufferTooSmall);
        }

        // Parse vocab
        let mut vocab = Vec::with_capacity(header.vocab_size as usize);
        let mut cursor = vocab_start;
        for _ in 0..header.vocab_size {
            vocab.push(VocabEntry {
                token_hash: read_u64(data, cursor),
                postings_offset: read_u32(data, cursor + 8),
                postings_len: read_u32(data, cursor + 12),
            });
            cursor += VOCAB_ENTRY_LEN;
        }

        // Calculate postings area size: from vocab end to doc table start
        let doc_table_len = header.total_frames as usize * DOC_ENTRY_LEN;
        let footer_start = data.len() - CCXI_FOOTER_LEN;
        let doc_table_start = footer_start - doc_table_len;
        let postings_start = vocab_end;
        let postings_end = doc_table_start;

        if postings_end < postings_start || doc_table_start + doc_table_len > footer_start {
            return Err(IndexError::BufferTooSmall);
        }

        let postings_area = data[postings_start..postings_end].to_vec();

        // Parse doc table (v2: 16 bytes per entry)
        let mut docs = Vec::with_capacity(header.total_frames as usize);
        let mut cursor = doc_table_start;
        for _ in 0..header.total_frames {
            docs.push(DocEntry {
                frame_offset: read_u32(data, cursor),
                doc_length_tokens: read_u16(data, cursor + 4),
                tenant_hash_lo16: read_u16(data, cursor + 6),
                tenant_hash_full: read_u64(data, cursor + 8),
            });
            cursor += DOC_ENTRY_LEN;
        }

        // Verify footer integrity
        let vocab_hash = blake3::hash(&data[vocab_start..vocab_end]);
        let postings_hash = blake3::hash(&data[postings_start..postings_end]);

        if &data[footer_start..footer_start + 32] != vocab_hash.as_bytes() {
            return Err(IndexError::IntegrityFailure {
                msg: "vocab table hash mismatch".to_string(),
            });
        }
        if &data[footer_start + 32..footer_start + 64] != postings_hash.as_bytes() {
            return Err(IndexError::IntegrityFailure {
                msg: "postings area hash mismatch".to_string(),
            });
        }

        Ok(Self {
            header,
            vocab,
            postings_area,
            docs,
        })
    }

    /// Decompress posting list for a given vocab entry.
    /// Returns (doc_ids, term_frequencies).
    pub fn decode_postings(&self, entry: &VocabEntry) -> (Vec<u32>, Vec<u16>) {
        let start = entry.postings_offset as usize;
        let end = start + entry.postings_len as usize;

        if end > self.postings_area.len() {
            return (Vec::new(), Vec::new());
        }

        let data = &self.postings_area[start..end];

        // Decode doc_ids (PForDelta)
        let doc_ids = pfordelta_decode(data);
        let doc_count = doc_ids.len();

        // Find where TF data starts (after PForDelta data)
        // PForDelta starts with a u32 count, then blocks.
        // We need to scan past the PForDelta data to find the TF section.
        // The TF section starts with a u32 count followed by u16 values.
        //
        // Strategy: re-encode and measure the PForDelta size, or search for the TF header.
        // Simpler: scan from the end. TF section = 4 + doc_count*2 bytes from end of entry.
        let tf_section_len = 4 + doc_count * 2;
        if data.len() < tf_section_len {
            return (doc_ids, vec![1u16; doc_count]);
        }

        let tf_start = data.len() - tf_section_len;
        let tf_count = u32::from_le_bytes(data[tf_start..tf_start + 4].try_into().unwrap_or([0; 4])) as usize;

        if tf_count != doc_count {
            // Fallback: assume TF=1 for all
            return (doc_ids, vec![1u16; doc_count]);
        }

        let mut tfs = Vec::with_capacity(tf_count);
        let mut cursor = tf_start + 4;
        for _ in 0..tf_count {
            if cursor + 2 <= data.len() {
                // SAFETY: data[cursor..cursor+2] is a 2-byte slice — try_into to [u8; 2] is infallible.
                #[allow(clippy::unwrap_used)]
                tfs.push(u16::from_le_bytes(data[cursor..cursor + 2].try_into().unwrap()));
                cursor += 2;
            }
        }

        (doc_ids, tfs)
    }

    /// Find a vocab entry by token hash (binary search, vocab is sorted by hash).
    pub fn find_token(&self, token_hash: u64) -> Option<&VocabEntry> {
        self.vocab
            .binary_search_by_key(&token_hash, |v| v.token_hash)
            .ok()
            .map(|idx| &self.vocab[idx])
    }

    /// Average document length in tokens.
    pub fn avg_doc_length(&self) -> f32 {
        if self.docs.is_empty() {
            return 0.0;
        }
        let total: u64 = self.docs.iter().map(|d| d.doc_length_tokens as u64).sum();
        total as f32 / self.docs.len() as f32
    }
}

// ── helpers ──

fn write_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}

fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0; 2]))
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4]))
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_build_and_read() {
        let mut builder = CcxiBuilder::new(0, 1, 100);
        builder.add_document(0, "hello world this is a test document", 0, 0x1234);
        builder.add_document(1, "another test document with different words", 100, 0x1234);
        builder.add_document(2, "hello again world test", 200, 0x5678);

        let bytes = builder.build();
        let reader = CcxiReader::from_bytes(&bytes).expect("parse .ccxi");

        assert_eq!(reader.header.magic, CCXI_MAGIC);
        assert_eq!(reader.header.version, CCXI_VERSION);
        assert_eq!(reader.header.total_frames, 3);
        assert!(reader.header.vocab_size > 0);
        assert_eq!(reader.docs.len(), 3);
        assert_eq!(reader.docs[0].tenant_hash_lo16, 0x1234);
        assert_eq!(reader.docs[0].tenant_hash_full, 0x1234);
        assert_eq!(reader.docs[2].tenant_hash_lo16, 0x5678);
        assert_eq!(reader.docs[2].tenant_hash_full, 0x5678);
    }

    #[test]
    fn full_tenant_hash_round_trip() {
        let full_hash: u64 = 0xDEAD_BEEF_CAFE_1234;
        let mut builder = CcxiBuilder::new(0, 1, 100);
        builder.add_document(0, "test document for hash", 0, full_hash);
        let bytes = builder.build();
        let reader = CcxiReader::from_bytes(&bytes).expect("parse");
        assert_eq!(reader.docs[0].tenant_hash_lo16, 0x1234);
        assert_eq!(reader.docs[0].tenant_hash_full, full_hash);
    }

    #[test]
    fn token_lookup_works() {
        let mut builder = CcxiBuilder::new(0, 1, 100);
        builder.add_document(0, "terraform module drift detection", 0, 0);
        builder.add_document(1, "terraform workspace management", 100, 0);
        builder.add_document(2, "kubernetes deployment strategy", 200, 0);

        let bytes = builder.build();
        let reader = CcxiReader::from_bytes(&bytes).expect("parse");

        // "terraform" should appear in docs 0 and 1
        let tokens = crate::tokenize("terraform");
        assert!(!tokens.is_empty());
        let entry = reader.find_token(tokens[0].hash);
        assert!(entry.is_some(), "terraform token not found in vocab");

        let (doc_ids, tfs) = reader.decode_postings(entry.unwrap());
        assert_eq!(doc_ids.len(), 2);
        assert!(doc_ids.contains(&0));
        assert!(doc_ids.contains(&1));
        assert!(tfs.iter().all(|&tf| tf >= 1));
    }

    #[test]
    fn integrity_check_catches_corruption() {
        let mut builder = CcxiBuilder::new(0, 1, 100);
        builder.add_document(0, "test document", 0, 0);
        let mut bytes = builder.build();

        // Corrupt a byte in the vocab table
        bytes[CCXI_HEADER_LEN + 3] ^= 0xFF;

        let result = CcxiReader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn avg_doc_length() {
        let mut builder = CcxiBuilder::new(0, 1, 100);
        builder.add_document(0, "one two three four", 0, 0);
        builder.add_document(1, "five six", 100, 0);

        let bytes = builder.build();
        let reader = CcxiReader::from_bytes(&bytes).expect("parse");

        let avg = reader.avg_doc_length();
        assert!(avg > 0.0);
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    /// Generate a simple word from lowercase letters.
    fn word_strategy() -> impl Strategy<Value = String> {
        "[a-z]{3,8}"
    }

    /// Generate a document as space-separated words.
    fn doc_strategy(words_per_doc: usize) -> impl Strategy<Value = String> {
        prop::collection::vec(word_strategy(), 1..=words_per_doc).prop_map(|words| words.join(" "))
    }

    proptest! {
        #[test]
        fn ccxi_build_and_read_roundtrip(
            num_docs in 1..50usize,
            shard_id in any::<u32>(),
            segment_seq in any::<u64>(),
            epoch in any::<u64>(),
        ) {
            // Generate random documents
            let runner = proptest::test_runner::TestRunner::new(Default::default());
            let _ = runner; // just to silence unused warning

            let mut builder = CcxiBuilder::new(shard_id, segment_seq, epoch);
            for doc_id in 0..num_docs {
                // Use doc_id as seed for deterministic but varied content
                let text = format!(
                    "doc{} word{} term{} {}",
                    doc_id,
                    doc_id % 7,
                    doc_id % 3,
                    if doc_id % 2 == 0 { "alpha beta" } else { "gamma delta" },
                );
                let frame_offset = (doc_id * 100) as u32;
                let tenant_hash = (doc_id as u64) * 0x1111_1111;
                builder.add_document(doc_id as u32, &text, frame_offset, tenant_hash);
            }

            let bytes = builder.build();
            let reader = CcxiReader::from_bytes(&bytes).expect("should parse .ccxi");

            // Verify header roundtrip
            prop_assert_eq!(reader.header.magic, CCXI_MAGIC);
            prop_assert_eq!(reader.header.version, CCXI_VERSION);
            prop_assert_eq!(reader.header.shard_id, shard_id);
            prop_assert_eq!(reader.header.segment_seq, segment_seq);
            prop_assert_eq!(reader.header.epoch, epoch);
            prop_assert_eq!(reader.header.total_frames, num_docs as u32);
            prop_assert_eq!(reader.docs.len(), num_docs);

            // Verify doc entries roundtrip
            for doc_id in 0..num_docs {
                let doc = &reader.docs[doc_id];
                prop_assert_eq!(doc.frame_offset, (doc_id * 100) as u32);
                let expected_hash = (doc_id as u64) * 0x1111_1111;
                prop_assert_eq!(doc.tenant_hash_full, expected_hash);
                prop_assert_eq!(doc.tenant_hash_lo16, (expected_hash & 0xFFFF) as u16);
                prop_assert!(doc.doc_length_tokens > 0);
            }

            // Verify vocab is non-empty (we always add text)
            prop_assert!(reader.header.vocab_size > 0);

            // Verify postings can be decoded without panic
            for entry in &reader.vocab {
                let (doc_ids, tfs) = reader.decode_postings(entry);
                prop_assert!(!doc_ids.is_empty());
                prop_assert_eq!(doc_ids.len(), tfs.len());
                // All doc_ids should be in range
                for &did in &doc_ids {
                    prop_assert!((did as usize) < num_docs);
                }
            }
        }

        #[test]
        fn ccxi_single_doc_roundtrip(
            text in doc_strategy(10),
            tenant_hash in any::<u64>(),
            frame_offset in any::<u32>(),
        ) {
            let mut builder = CcxiBuilder::new(0, 1, 100);
            builder.add_document(0, &text, frame_offset, tenant_hash);

            let bytes = builder.build();
            let reader = CcxiReader::from_bytes(&bytes).expect("should parse");

            prop_assert_eq!(reader.header.total_frames, 1);
            prop_assert_eq!(reader.docs[0].frame_offset, frame_offset);
            prop_assert_eq!(reader.docs[0].tenant_hash_full, tenant_hash);
            prop_assert_eq!(reader.docs[0].tenant_hash_lo16, (tenant_hash & 0xFFFF) as u16);
        }
    }
}
