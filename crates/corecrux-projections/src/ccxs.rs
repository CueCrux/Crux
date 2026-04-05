// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CcxsError {
    #[error("buffer too small")]
    BufferTooSmall,
    #[error("invalid magic: expected {expected:?}, got {actual:?}")]
    InvalidMagic { expected: [u8; 4], actual: [u8; 4] },
    #[error("unsupported ccxs version {v}")]
    UnsupportedVersion { v: u32 },
    #[error("unsupported projection id {id}")]
    UnsupportedProjectionId { id: u32 },
    #[error(
        "block hash mismatch for block_type={block_type}: expected={expected} actual={actual}"
    )]
    BlockHashMismatch {
        block_type: u32,
        expected: String,
        actual: String,
    },
    #[error("invalid snapshot: {msg}")]
    Invalid { msg: String },
}

pub type Result<T> = std::result::Result<T, CcxsError>;

pub const CCXS_MAGIC: [u8; 4] = *b"CCXS";
pub const CCXS_V1: u32 = 1;
pub const CCXS_CODEC_NONE: u32 = 0;

// Block type identifiers (v1). Keep stable.
pub const CCXS_BLOCK_ROWS_V1: u32 = 1;
pub const CCXS_BLOCK_EDGES_V1: u32 = 2;
pub const CCXS_BLOCK_EVENTS_V1: u32 = 3;
pub const CCXS_BLOCK_STATS_V1: u32 = 4;
pub const CCXS_BLOCK_ADJ_INDEX_V1: u32 = 5;
pub const CCXS_BLOCK_HOT_PTRS_V1: u32 = 6;
pub const CCXS_BLOCK_COLD_SEGMENT_DIR_V1: u32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CcxsProjectionId {
    ArtifactLivingState = 1,
    ArtifactRelations = 2,
    PressureEvents = 3,
    ArtifactDependents = 4,
    // Phase 6: Entity projections for MemoryCrux knowledge graph
    EntityCount = 10,
    EntityTimeline = 11,
    EntityCurrentState = 12,
}

impl CcxsProjectionId {
    pub fn from_u32(id: u32) -> Result<Self> {
        match id {
            1 => Ok(Self::ArtifactLivingState),
            2 => Ok(Self::ArtifactRelations),
            3 => Ok(Self::PressureEvents),
            4 => Ok(Self::ArtifactDependents),
            10 => Ok(Self::EntityCount),
            11 => Ok(Self::EntityTimeline),
            12 => Ok(Self::EntityCurrentState),
            other => Err(CcxsError::UnsupportedProjectionId { id: other }),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ArtifactLivingState => "artifact_living_state",
            Self::ArtifactRelations => "artifact_relations",
            Self::PressureEvents => "pressure_events",
            Self::ArtifactDependents => "artifact_dependents",
            Self::EntityCount => "entity_count",
            Self::EntityTimeline => "entity_timeline",
            Self::EntityCurrentState => "entity_current_state",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcxsSnapshotHeaderV1 {
    pub projection_id: CcxsProjectionId,
    pub schema_version: u32,
    pub created_at_unix_ns: u64,
    pub shard_id: u32,
    pub epoch: u64,
    pub cursor_segment_seq: u64,
    pub cursor_offset: u64,
    pub block_count: u32,
    pub codec: u32,
}

#[derive(Debug, Clone)]
pub struct CcxsSnapshot {
    pub header: CcxsSnapshotHeaderV1,
    pub blocks: Vec<(u32, Vec<u8>)>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CcxsSnapshotSummary {
    pub projection: String,
    pub schema_version: u32,
    pub created_at_unix_ns: u64,
    pub shard_id: u32,
    pub epoch: u64,
    pub cursor_segment_seq: u64,
    pub cursor_offset: u64,
    pub block_count: u32,
    pub snapshot_blake3: String,
    pub blocks: Vec<CcxsBlockSummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CcxsBlockSummary {
    pub block_type: u32,
    pub len: u64,
    pub blake3: String,
}

impl CcxsSnapshot {
    pub fn snapshot_blake3_hex(bytes: &[u8]) -> String {
        blake3::hash(bytes).to_hex().to_string()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.header.codec != CCXS_CODEC_NONE {
            return Err(CcxsError::Invalid {
                msg: format!("unsupported codec {}", self.header.codec),
            });
        }
        let mut out: Vec<u8> = Vec::with_capacity(4096);

        out.extend_from_slice(&CCXS_MAGIC);
        out.extend_from_slice(&CCXS_V1.to_le_bytes());
        out.extend_from_slice(&(self.header.projection_id as u32).to_le_bytes());
        out.extend_from_slice(&self.header.schema_version.to_le_bytes());
        out.extend_from_slice(&self.header.created_at_unix_ns.to_le_bytes());
        out.extend_from_slice(&self.header.shard_id.to_le_bytes());
        out.extend_from_slice(&self.header.epoch.to_le_bytes());
        out.extend_from_slice(&self.header.cursor_segment_seq.to_le_bytes());
        out.extend_from_slice(&self.header.cursor_offset.to_le_bytes());
        out.extend_from_slice(&(self.blocks.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.header.codec.to_le_bytes());
        // reserved/padding for future header extensions
        out.extend_from_slice(&[0u8; 64]);

        for (block_type, bytes) in &self.blocks {
            out.extend_from_slice(&block_type.to_le_bytes());
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            let h = blake3::hash(bytes);
            out.extend_from_slice(h.as_bytes());
            out.extend_from_slice(bytes);
        }

        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(input);
        let magic = c.read_4()?;
        if magic != CCXS_MAGIC {
            return Err(CcxsError::InvalidMagic {
                expected: CCXS_MAGIC,
                actual: magic,
            });
        }
        let v = c.read_u32()?;
        if v != CCXS_V1 {
            return Err(CcxsError::UnsupportedVersion { v });
        }
        let projection_id = CcxsProjectionId::from_u32(c.read_u32()?)?;
        let schema_version = c.read_u32()?;
        let created_at_unix_ns = c.read_u64()?;
        let shard_id = c.read_u32()?;
        let epoch = c.read_u64()?;
        let cursor_segment_seq = c.read_u64()?;
        let cursor_offset = c.read_u64()?;
        let block_count = c.read_u32()?;
        let codec = c.read_u32()?;
        let _ = c.read_exact(64)?; // reserved

        if codec != CCXS_CODEC_NONE {
            return Err(CcxsError::Invalid {
                msg: format!("unsupported codec {}", codec),
            });
        }

        let mut blocks: Vec<(u32, Vec<u8>)> = Vec::with_capacity(block_count as usize);
        for _ in 0..block_count {
            let block_type = c.read_u32()?;
            let len = c.read_u64()? as usize;
            let expected_hash = c.read_32()?;
            let bytes = c.read_exact(len)?.to_vec();
            let actual_hash = blake3::hash(&bytes);
            if actual_hash.as_bytes() != &expected_hash {
                return Err(CcxsError::BlockHashMismatch {
                    block_type,
                    expected: blake3::Hash::from(expected_hash).to_hex().to_string(),
                    actual: actual_hash.to_hex().to_string(),
                });
            }
            blocks.push((block_type, bytes));
        }

        Ok(Self {
            header: CcxsSnapshotHeaderV1 {
                projection_id,
                schema_version,
                created_at_unix_ns,
                shard_id,
                epoch,
                cursor_segment_seq,
                cursor_offset,
                block_count,
                codec,
            },
            blocks,
        })
    }

    pub fn summary(input: &[u8]) -> Result<CcxsSnapshotSummary> {
        let snap = Self::decode(input)?;
        let snapshot_blake3 = Self::snapshot_blake3_hex(input);
        let mut blocks = Vec::new();

        // Re-parse blocks to capture hashes without decoding again.
        let mut c = Cursor::new(input);
        let _magic = c.read_4()?;
        let _v = c.read_u32()?;
        let _projection_id = c.read_u32()?;
        let _schema_version = c.read_u32()?;
        let _created_at_unix_ns = c.read_u64()?;
        let _shard_id = c.read_u32()?;
        let _epoch = c.read_u64()?;
        let _cursor_segment_seq = c.read_u64()?;
        let _cursor_offset = c.read_u64()?;
        let block_count = c.read_u32()?;
        let _codec = c.read_u32()?;
        let _reserved = c.read_exact(64)?;
        for _ in 0..block_count {
            let block_type = c.read_u32()?;
            let len = c.read_u64()?;
            let h = c.read_32()?;
            let _bytes = c.read_exact(len as usize)?;
            blocks.push(CcxsBlockSummary {
                block_type,
                len,
                blake3: blake3::Hash::from(h).to_hex().to_string(),
            });
        }

        Ok(CcxsSnapshotSummary {
            projection: snap.header.projection_id.as_str().to_string(),
            schema_version: snap.header.schema_version,
            created_at_unix_ns: snap.header.created_at_unix_ns,
            shard_id: snap.header.shard_id,
            epoch: snap.header.epoch,
            cursor_segment_seq: snap.header.cursor_segment_seq,
            cursor_offset: snap.header.cursor_offset,
            block_count: snap.header.block_count,
            snapshot_blake3,
            blocks,
        })
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(CcxsError::BufferTooSmall)?;
        if end > self.input.len() {
            return Err(CcxsError::BufferTooSmall);
        }
        let out = &self.input[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn read_4(&mut self) -> Result<[u8; 4]> {
        let b = self.read_exact(4)?;
        let mut out = [0u8; 4];
        out.copy_from_slice(b);
        Ok(out)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let b = self.read_exact(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let b = self.read_exact(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_32(&mut self) -> Result<[u8; 32]> {
        let b = self.read_exact(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(b);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CcxsProjectionId ────────────────────────────────────────────

    #[test]
    fn projection_id_from_u32_valid_values() {
        assert!(matches!(CcxsProjectionId::from_u32(1), Ok(CcxsProjectionId::ArtifactLivingState)));
        assert!(matches!(CcxsProjectionId::from_u32(2), Ok(CcxsProjectionId::ArtifactRelations)));
        assert!(matches!(CcxsProjectionId::from_u32(3), Ok(CcxsProjectionId::PressureEvents)));
        assert!(matches!(CcxsProjectionId::from_u32(4), Ok(CcxsProjectionId::ArtifactDependents)));
        assert!(matches!(CcxsProjectionId::from_u32(10), Ok(CcxsProjectionId::EntityCount)));
        assert!(matches!(CcxsProjectionId::from_u32(11), Ok(CcxsProjectionId::EntityTimeline)));
        assert!(matches!(CcxsProjectionId::from_u32(12), Ok(CcxsProjectionId::EntityCurrentState)));
    }

    #[test]
    fn projection_id_from_u32_invalid() {
        assert!(CcxsProjectionId::from_u32(0).is_err());
        assert!(CcxsProjectionId::from_u32(5).is_err());
        assert!(CcxsProjectionId::from_u32(9).is_err());
        assert!(CcxsProjectionId::from_u32(100).is_err());
    }

    #[test]
    fn projection_id_as_str() {
        assert_eq!(CcxsProjectionId::ArtifactLivingState.as_str(), "artifact_living_state");
        assert_eq!(CcxsProjectionId::ArtifactRelations.as_str(), "artifact_relations");
        assert_eq!(CcxsProjectionId::PressureEvents.as_str(), "pressure_events");
        assert_eq!(CcxsProjectionId::ArtifactDependents.as_str(), "artifact_dependents");
        assert_eq!(CcxsProjectionId::EntityCount.as_str(), "entity_count");
        assert_eq!(CcxsProjectionId::EntityTimeline.as_str(), "entity_timeline");
        assert_eq!(CcxsProjectionId::EntityCurrentState.as_str(), "entity_current_state");
    }

    #[test]
    fn projection_id_repr_roundtrip() {
        for id in [1u32, 2, 3, 4, 10, 11, 12] {
            let pid = CcxsProjectionId::from_u32(id).unwrap();
            assert_eq!(pid as u32, id);
        }
    }

    // ── CcxsSnapshot encode/decode roundtrip ────────────────────────

    fn sample_snapshot() -> CcxsSnapshot {
        CcxsSnapshot {
            header: CcxsSnapshotHeaderV1 {
                projection_id: CcxsProjectionId::ArtifactLivingState,
                schema_version: 1,
                created_at_unix_ns: 1_700_000_000_000_000_000,
                shard_id: 7,
                epoch: 3,
                cursor_segment_seq: 42,
                cursor_offset: 128,
                block_count: 2,
                codec: CCXS_CODEC_NONE,
            },
            blocks: vec![
                (CCXS_BLOCK_ROWS_V1, vec![1, 2, 3, 4]),
                (CCXS_BLOCK_EDGES_V1, vec![10, 20, 30]),
            ],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let snap = sample_snapshot();
        let bytes = snap.encode().unwrap();
        let decoded = CcxsSnapshot::decode(&bytes).unwrap();

        assert_eq!(decoded.header.projection_id, CcxsProjectionId::ArtifactLivingState);
        assert_eq!(decoded.header.schema_version, 1);
        assert_eq!(decoded.header.shard_id, 7);
        assert_eq!(decoded.header.epoch, 3);
        assert_eq!(decoded.header.cursor_segment_seq, 42);
        assert_eq!(decoded.header.cursor_offset, 128);
        assert_eq!(decoded.blocks.len(), 2);
        assert_eq!(decoded.blocks[0].0, CCXS_BLOCK_ROWS_V1);
        assert_eq!(decoded.blocks[0].1, vec![1, 2, 3, 4]);
        assert_eq!(decoded.blocks[1].0, CCXS_BLOCK_EDGES_V1);
        assert_eq!(decoded.blocks[1].1, vec![10, 20, 30]);
    }

    #[test]
    fn encode_decode_empty_blocks() {
        let snap = CcxsSnapshot {
            header: CcxsSnapshotHeaderV1 {
                projection_id: CcxsProjectionId::PressureEvents,
                schema_version: 1,
                created_at_unix_ns: 0,
                shard_id: 0,
                epoch: 1,
                cursor_segment_seq: 0,
                cursor_offset: 0,
                block_count: 0,
                codec: CCXS_CODEC_NONE,
            },
            blocks: vec![],
        };
        let bytes = snap.encode().unwrap();
        let decoded = CcxsSnapshot::decode(&bytes).unwrap();
        assert_eq!(decoded.blocks.len(), 0);
        assert_eq!(decoded.header.projection_id, CcxsProjectionId::PressureEvents);
    }

    #[test]
    fn snapshot_blake3_hex_is_deterministic() {
        let snap = sample_snapshot();
        let bytes = snap.encode().unwrap();
        let h1 = CcxsSnapshot::snapshot_blake3_hex(&bytes);
        let h2 = CcxsSnapshot::snapshot_blake3_hex(&bytes);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut bytes = sample_snapshot().encode().unwrap();
        bytes[0] = b'X';
        let err = CcxsSnapshot::decode(&bytes).unwrap_err();
        assert!(matches!(err, CcxsError::InvalidMagic { .. }));
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let mut bytes = sample_snapshot().encode().unwrap();
        // Version field is at offset 4..8
        bytes[4] = 99;
        bytes[5] = 0;
        bytes[6] = 0;
        bytes[7] = 0;
        let err = CcxsSnapshot::decode(&bytes).unwrap_err();
        assert!(matches!(err, CcxsError::UnsupportedVersion { v: 99 }));
    }

    #[test]
    fn decode_rejects_corrupted_block_hash() {
        let mut bytes = sample_snapshot().encode().unwrap();
        // Corrupt a byte in the first block's data (after header + block_type + len + hash)
        let last_idx = bytes.len() - 1;
        bytes[last_idx] ^= 0xFF;
        let err = CcxsSnapshot::decode(&bytes).unwrap_err();
        assert!(matches!(err, CcxsError::BlockHashMismatch { .. }));
    }

    #[test]
    fn decode_rejects_empty_buffer() {
        let err = CcxsSnapshot::decode(&[]).unwrap_err();
        assert!(matches!(err, CcxsError::BufferTooSmall));
    }

    #[test]
    fn decode_rejects_truncated_header() {
        let bytes = sample_snapshot().encode().unwrap();
        let err = CcxsSnapshot::decode(&bytes[..20]).unwrap_err();
        assert!(matches!(err, CcxsError::BufferTooSmall));
    }

    #[test]
    fn encode_rejects_unsupported_codec() {
        let mut snap = sample_snapshot();
        snap.header.codec = 99;
        let err = snap.encode().unwrap_err();
        assert!(matches!(err, CcxsError::Invalid { .. }));
    }

    #[test]
    fn decode_rejects_unsupported_codec_in_data() {
        let snap = sample_snapshot();
        let mut bytes = snap.encode().unwrap();
        // codec field is at a specific offset in the header; after reserved fields
        // header layout: magic(4) + v(4) + proj_id(4) + schema_v(4) + ts(8) + shard_id(4) + epoch(8) + cursor_seg(8) + cursor_off(8) + block_count(4) + codec(4)
        // = 4+4+4+4+8+4+8+8+8+4+4 = 60
        let codec_offset = 56;
        bytes[codec_offset] = 5;
        bytes[codec_offset + 1] = 0;
        bytes[codec_offset + 2] = 0;
        bytes[codec_offset + 3] = 0;
        let err = CcxsSnapshot::decode(&bytes).unwrap_err();
        assert!(matches!(err, CcxsError::Invalid { .. }));
    }

    #[test]
    fn summary_round_trip() {
        let snap = sample_snapshot();
        let bytes = snap.encode().unwrap();
        let summary = CcxsSnapshot::summary(&bytes).unwrap();
        assert_eq!(summary.projection, "artifact_living_state");
        assert_eq!(summary.schema_version, 1);
        assert_eq!(summary.shard_id, 7);
        assert_eq!(summary.epoch, 3);
        assert_eq!(summary.block_count, 2);
        assert_eq!(summary.blocks.len(), 2);
        assert_eq!(summary.blocks[0].block_type, CCXS_BLOCK_ROWS_V1);
        assert_eq!(summary.blocks[0].len, 4);
        assert_eq!(summary.blocks[1].block_type, CCXS_BLOCK_EDGES_V1);
        assert_eq!(summary.blocks[1].len, 3);
        assert!(!summary.snapshot_blake3.is_empty());
    }

    // ── CcxsSnapshotSummary serialization ───────────────────────────

    #[test]
    fn snapshot_summary_serializes() {
        let summary = CcxsSnapshotSummary {
            projection: "artifact_living_state".to_string(),
            schema_version: 1,
            created_at_unix_ns: 0,
            shard_id: 0,
            epoch: 1,
            cursor_segment_seq: 0,
            cursor_offset: 0,
            block_count: 1,
            snapshot_blake3: "abc".to_string(),
            blocks: vec![CcxsBlockSummary {
                block_type: CCXS_BLOCK_ROWS_V1,
                len: 10,
                blake3: "def".to_string(),
            }],
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["projection"], "artifact_living_state");
        assert_eq!(json["block_count"], 1);
        assert_eq!(json["blocks"][0]["block_type"], CCXS_BLOCK_ROWS_V1);
    }

    // ── CcxsError display ───────────────────────────────────────────

    #[test]
    fn error_display_messages() {
        let e = CcxsError::BufferTooSmall;
        assert_eq!(e.to_string(), "buffer too small");

        let e = CcxsError::InvalidMagic {
            expected: CCXS_MAGIC,
            actual: [0, 0, 0, 0],
        };
        assert!(e.to_string().contains("invalid magic"));

        let e = CcxsError::UnsupportedVersion { v: 99 };
        assert!(e.to_string().contains("99"));

        let e = CcxsError::UnsupportedProjectionId { id: 42 };
        assert!(e.to_string().contains("42"));

        let e = CcxsError::BlockHashMismatch {
            block_type: 1,
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        };
        assert!(e.to_string().contains("block hash mismatch"));

        let e = CcxsError::Invalid { msg: "test error".to_string() };
        assert!(e.to_string().contains("test error"));
    }

    // ── Cursor edge cases ───────────────────────────────────────────

    #[test]
    fn cursor_read_exact_at_boundary() {
        let data = [1u8, 2, 3, 4];
        let mut c = Cursor::new(&data);
        let slice = c.read_exact(4).unwrap();
        assert_eq!(slice, &[1, 2, 3, 4]);
        // Reading 0 more bytes should succeed
        let empty = c.read_exact(0).unwrap();
        assert!(empty.is_empty());
        // Reading 1 more should fail
        assert!(c.read_exact(1).is_err());
    }

    #[test]
    fn cursor_overflow_protection() {
        let data = [0u8; 8];
        let mut c = Cursor::new(&data);
        c.pos = usize::MAX - 1;
        // This should return BufferTooSmall due to overflow
        assert!(c.read_exact(4).is_err());
    }

    // ── Cursor: sequential reads ────────────────────────────────────

    #[test]
    fn cursor_sequential_reads() {
        let data = [1u8, 0, 0, 0, 2, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0];
        let mut c = Cursor::new(&data);
        let v1 = c.read_u32().unwrap();
        assert_eq!(v1, 1);
        let v2 = c.read_u32().unwrap();
        assert_eq!(v2, 2);
    }

    #[test]
    fn cursor_read_u64() {
        let val: u64 = 0xDEAD_BEEF_1234_5678;
        let data = val.to_le_bytes();
        let mut c = Cursor::new(&data);
        assert_eq!(c.read_u64().unwrap(), val);
    }

    #[test]
    fn cursor_read_32() {
        let data = [0xAA; 32];
        let mut c = Cursor::new(&data);
        let out = c.read_32().unwrap();
        assert_eq!(out, [0xAA; 32]);
    }

    #[test]
    fn cursor_read_4() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut c = Cursor::new(&data);
        let out = c.read_4().unwrap();
        assert_eq!(out, [0x01, 0x02, 0x03, 0x04]);
    }

    // ── CcxsSnapshot: various projection IDs ────────────────────────

    #[test]
    fn encode_decode_all_projection_ids() {
        for (id, name) in [
            (CcxsProjectionId::ArtifactLivingState, "artifact_living_state"),
            (CcxsProjectionId::ArtifactRelations, "artifact_relations"),
            (CcxsProjectionId::PressureEvents, "pressure_events"),
            (CcxsProjectionId::ArtifactDependents, "artifact_dependents"),
            (CcxsProjectionId::EntityCount, "entity_count"),
            (CcxsProjectionId::EntityTimeline, "entity_timeline"),
            (CcxsProjectionId::EntityCurrentState, "entity_current_state"),
        ] {
            let snap = CcxsSnapshot {
                header: CcxsSnapshotHeaderV1 {
                    projection_id: id,
                    schema_version: 1,
                    created_at_unix_ns: 0,
                    shard_id: 0,
                    epoch: 1,
                    cursor_segment_seq: 0,
                    cursor_offset: 0,
                    block_count: 0,
                    codec: CCXS_CODEC_NONE,
                },
                blocks: vec![],
            };
            let bytes = snap.encode().unwrap();
            let decoded = CcxsSnapshot::decode(&bytes).unwrap();
            assert_eq!(decoded.header.projection_id.as_str(), name);
        }
    }

    // ── Block type constants ────────────────────────────────────────

    #[test]
    fn block_type_constants_are_distinct() {
        let types = [
            CCXS_BLOCK_ROWS_V1,
            CCXS_BLOCK_EDGES_V1,
            CCXS_BLOCK_EVENTS_V1,
            CCXS_BLOCK_STATS_V1,
            CCXS_BLOCK_ADJ_INDEX_V1,
            CCXS_BLOCK_HOT_PTRS_V1,
            CCXS_BLOCK_COLD_SEGMENT_DIR_V1,
        ];
        let mut seen = std::collections::HashSet::new();
        for t in types {
            assert!(seen.insert(t), "duplicate block type {t}");
        }
    }

    // ── CcxsSnapshotHeaderV1 equality ──────────────────────────────

    #[test]
    fn ccxs_snapshot_header_equality() {
        let h1 = CcxsSnapshotHeaderV1 {
            projection_id: CcxsProjectionId::ArtifactLivingState,
            schema_version: 1,
            created_at_unix_ns: 100,
            shard_id: 1,
            epoch: 2,
            cursor_segment_seq: 3,
            cursor_offset: 4,
            block_count: 0,
            codec: CCXS_CODEC_NONE,
        };
        let h2 = h1.clone();
        assert_eq!(h1, h2);
    }

    // ── Multiple blocks encode/decode ───────────────────────────────

    #[test]
    fn encode_decode_many_blocks() {
        let snap = CcxsSnapshot {
            header: CcxsSnapshotHeaderV1 {
                projection_id: CcxsProjectionId::ArtifactRelations,
                schema_version: 2,
                created_at_unix_ns: 42,
                shard_id: 3,
                epoch: 7,
                cursor_segment_seq: 100,
                cursor_offset: 200,
                block_count: 5,
                codec: CCXS_CODEC_NONE,
            },
            blocks: vec![
                (CCXS_BLOCK_ROWS_V1, vec![1; 100]),
                (CCXS_BLOCK_EDGES_V1, vec![2; 200]),
                (CCXS_BLOCK_EVENTS_V1, vec![3; 50]),
                (CCXS_BLOCK_STATS_V1, vec![4; 10]),
                (CCXS_BLOCK_ADJ_INDEX_V1, vec![5; 150]),
            ],
        };
        let bytes = snap.encode().unwrap();
        let decoded = CcxsSnapshot::decode(&bytes).unwrap();
        assert_eq!(decoded.blocks.len(), 5);
        assert_eq!(decoded.blocks[0].1.len(), 100);
        assert_eq!(decoded.blocks[4].1.len(), 150);
        assert_eq!(decoded.header.schema_version, 2);
    }

    // ── summary validates block hashes ──────────────────────────────

    #[test]
    fn summary_block_hashes_match_blake3() {
        let data = vec![42u8; 64];
        let expected_hash = blake3::hash(&data).to_hex().to_string();
        let snap = CcxsSnapshot {
            header: CcxsSnapshotHeaderV1 {
                projection_id: CcxsProjectionId::PressureEvents,
                schema_version: 1,
                created_at_unix_ns: 0,
                shard_id: 0,
                epoch: 1,
                cursor_segment_seq: 0,
                cursor_offset: 0,
                block_count: 1,
                codec: CCXS_CODEC_NONE,
            },
            blocks: vec![(CCXS_BLOCK_EVENTS_V1, data)],
        };
        let bytes = snap.encode().unwrap();
        let summary = CcxsSnapshot::summary(&bytes).unwrap();
        assert_eq!(summary.blocks[0].blake3, expected_hash);
    }

    // ── snapshot_blake3_hex changes with content ────────────────────

    #[test]
    fn snapshot_blake3_hex_differs_for_different_content() {
        let snap1 = CcxsSnapshot {
            header: CcxsSnapshotHeaderV1 {
                projection_id: CcxsProjectionId::ArtifactLivingState,
                schema_version: 1,
                created_at_unix_ns: 0,
                shard_id: 0,
                epoch: 1,
                cursor_segment_seq: 0,
                cursor_offset: 0,
                block_count: 1,
                codec: CCXS_CODEC_NONE,
            },
            blocks: vec![(CCXS_BLOCK_ROWS_V1, vec![1, 2, 3])],
        };
        let bytes1 = snap1.encode().unwrap();

        let snap2 = CcxsSnapshot {
            header: CcxsSnapshotHeaderV1 {
                projection_id: CcxsProjectionId::ArtifactLivingState,
                schema_version: 1,
                created_at_unix_ns: 0,
                shard_id: 0,
                epoch: 1,
                cursor_segment_seq: 0,
                cursor_offset: 0,
                block_count: 1,
                codec: CCXS_CODEC_NONE,
            },
            blocks: vec![(CCXS_BLOCK_ROWS_V1, vec![4, 5, 6])],
        };
        let bytes2 = snap2.encode().unwrap();

        assert_ne!(
            CcxsSnapshot::snapshot_blake3_hex(&bytes1),
            CcxsSnapshot::snapshot_blake3_hex(&bytes2)
        );
    }

    // ── decode truncated block data ────────────────────────────────

    #[test]
    fn decode_rejects_truncated_block_data() {
        let snap = sample_snapshot();
        let bytes = snap.encode().unwrap();
        // Truncate in the middle of block data
        let truncated = &bytes[..bytes.len() - 1];
        let err = CcxsSnapshot::decode(truncated).unwrap_err();
        // Should be either BufferTooSmall or BlockHashMismatch
        assert!(matches!(err, CcxsError::BufferTooSmall | CcxsError::BlockHashMismatch { .. }));
    }

    // ── decode rejects unsupported projection ID ────────────────────

    #[test]
    fn decode_rejects_unsupported_projection_id() {
        let snap = sample_snapshot();
        let mut bytes = snap.encode().unwrap();
        // projection_id is at offset 8..12
        bytes[8] = 99;
        bytes[9] = 0;
        bytes[10] = 0;
        bytes[11] = 0;
        let err = CcxsSnapshot::decode(&bytes).unwrap_err();
        assert!(matches!(err, CcxsError::UnsupportedProjectionId { id: 99 }));
    }
}
