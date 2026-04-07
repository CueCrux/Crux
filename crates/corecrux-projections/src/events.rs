// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use uuid::Uuid;

use crate::{ProjectionError, Result};

// Phase 7 event types. These are the minimum set of "artifact-local" contracts needed for the
// four Living Objects projections.
//
// Note: Stage 2 migration (Phase 12) will have Engine shadow-write these events.
pub const EVT_LIVING_STATE_UPDATE_V1: &str = "corecrux.proj.living_state.update.v1";
pub const EVT_RELATION_UPSERT_V1: &str = "corecrux.proj.relation.upsert.v1";
pub const EVT_RELATION_DELETE_V1: &str = "corecrux.proj.relation.delete.v1";
pub const EVT_PRESSURE_UPSERT_V1: &str = "corecrux.proj.pressure.upsert.v1";
pub const EVT_DEPENDENT_EVIDENCE_UPSERT_V1: &str = "corecrux.proj.dependent.evidence_upsert.v1";

// Phase 6: Entity projection events for MemoryCrux knowledge graph
pub const EVT_ENTITY_FACT_V1: &str = "corecrux.proj.entity.fact.v1";
pub const CONTENT_TYPE_ENTITY_JSON_V1: &str = "application/x-corecrux-entity-json-v1";

pub const CONTENT_TYPE_PROJ_BIN_V1: &str = "application/x-corecrux-proj-bin-v1";

#[derive(Debug, Clone)]
pub enum ProjectionEventV1 {
    LivingStateUpdate(LivingStateUpdateV1),
    RelationUpsert(RelationUpsertV1),
    RelationDelete(RelationDeleteV1),
    PressureUpsert(PressureEventUpsertV1),
    DependentEvidenceUpsert(DependentEvidenceUpsertV1),
    // Phase 6: Entity fact event — carries a structured entity relation
    EntityFact(EntityFactV1),
}

/// Phase 6: Entity fact event — a single (subject, predicate, object) relation
/// with entity type classification and timestamp.
/// Uses JSON encoding for flexibility (entity names are variable-length strings).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntityFactV1 {
    pub tenant_id: String,
    pub entity_type: String,  // Person, Place, Item, Activity, Event, Organization, Creative_Work
    pub entity_name: String,  // "Science Museum", "Dr. Jones", "Guitar"
    pub predicate: String,    // visited, owns, sees, bought, changed, NOT_owns, stopped
    pub object_value: String, // value/target of the predicate
    pub occurred_at_micros: i64, // 0 if unknown
    pub session_id: String,   // source session/document
    pub confidence_q16: u16,  // 0..65535 mapped to 0.0..1.0
}

impl EntityFactV1 {
    pub const V: u16 = 1;

    /// Binary layout (v1):
    /// version: u16
    /// tenant_id:      u16 len + bytes
    /// entity_type:    u16 len + bytes
    /// entity_name:    u16 len + bytes
    /// predicate:      u16 len + bytes
    /// object_value:   u16 len + bytes
    /// session_id:     u16 len + bytes
    /// occurred_at_micros: i64
    /// confidence_q16: u16
    pub fn decode_bin(payload: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(payload);
        let v = c.read_u16()?;
        if v != Self::V {
            return Err(ProjectionError::InvalidEvent {
                msg: format!("EntityFactV1 unsupported version {v}"),
            });
        }
        let tenant_id = c.read_str()?;
        let entity_type = c.read_str()?;
        let entity_name = c.read_str()?;
        let predicate = c.read_str()?;
        let object_value = c.read_str()?;
        let session_id = c.read_str()?;
        let occurred_at_micros = c.read_i64()?;
        let confidence_q16 = c.read_u16()?;

        Ok(Self {
            tenant_id,
            entity_type,
            entity_name,
            predicate,
            object_value,
            occurred_at_micros,
            session_id,
            confidence_q16,
        })
    }

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            2 + 6 * (2 + 64) + 8 + 2, // version + 6 strings avg 64 + i64 + u16
        );
        out.extend_from_slice(&Self::V.to_le_bytes());
        write_str(&mut out, &self.tenant_id);
        write_str(&mut out, &self.entity_type);
        write_str(&mut out, &self.entity_name);
        write_str(&mut out, &self.predicate);
        write_str(&mut out, &self.object_value);
        write_str(&mut out, &self.session_id);
        out.extend_from_slice(&self.occurred_at_micros.to_le_bytes());
        out.extend_from_slice(&self.confidence_q16.to_le_bytes());
        out
    }

    pub fn decode_json(payload: &[u8]) -> Result<Self> {
        serde_json::from_slice(payload).map_err(|e| ProjectionError::InvalidEvent {
            msg: format!("EntityFactV1 JSON decode: {e}"),
        })
    }

    pub fn encode_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("EntityFactV1 serialization should not fail")
    }

    pub fn occurred_at_iso(&self) -> Option<String> {
        if self.occurred_at_micros == 0 {
            return None;
        }
        let secs = self.occurred_at_micros / 1_000_000;
        let nanos = ((self.occurred_at_micros % 1_000_000) * 1000) as u32;
        chrono::DateTime::from_timestamp(secs, nanos).map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
    }
}

/// Write a length-prefixed string (u16 len + UTF-8 bytes)
fn write_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(u16::MAX as usize) as u16;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&bytes[..len as usize]);
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LivingStateUpdateV1 {
    pub fields_mask: u32,
    pub artifact_id: u32,
    pub living_status: u8,
    pub confidence_q16: u16,
    pub last_validated_at_micros: i64,
    pub next_review_at_micros: i64,
    pub trunk_tier: u8,
    pub updated_at_micros: i64,
}

impl LivingStateUpdateV1 {
    pub const V: u16 = 1;

    pub const MASK_LIVING_STATUS: u32 = 1 << 0;
    pub const MASK_CONFIDENCE: u32 = 1 << 1;
    pub const MASK_LAST_VALIDATED_AT: u32 = 1 << 2;
    pub const MASK_NEXT_REVIEW_AT: u32 = 1 << 3;
    pub const MASK_TRUNK_TIER: u32 = 1 << 4;
    pub const MASK_UPDATED_AT: u32 = 1 << 5;

    pub fn decode_bin(payload: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(payload);
        let v = c.read_u16()?;
        if v != Self::V {
            return Err(ProjectionError::InvalidEvent {
                msg: format!("LivingStateUpdateV1 unsupported version {v}"),
            });
        }
        Ok(Self {
            fields_mask: c.read_u32()?,
            artifact_id: c.read_u32()?,
            living_status: c.read_u8()?,
            confidence_q16: c.read_u16()?,
            last_validated_at_micros: c.read_i64()?,
            next_review_at_micros: c.read_i64()?,
            trunk_tier: c.read_u8()?,
            updated_at_micros: c.read_i64()?,
        })
    }

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 4 + 4 + 1 + 2 + 8 + 8 + 1 + 8);
        out.extend_from_slice(&Self::V.to_le_bytes());
        out.extend_from_slice(&self.fields_mask.to_le_bytes());
        out.extend_from_slice(&self.artifact_id.to_le_bytes());
        out.push(self.living_status);
        out.extend_from_slice(&self.confidence_q16.to_le_bytes());
        out.extend_from_slice(&self.last_validated_at_micros.to_le_bytes());
        out.extend_from_slice(&self.next_review_at_micros.to_le_bytes());
        out.push(self.trunk_tier);
        out.extend_from_slice(&self.updated_at_micros.to_le_bytes());
        out
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelationUpsertV1 {
    pub src_artifact_id: u32,
    pub dst_artifact_id: u32,
    pub relation_type: u8,
    pub confidence_q16: u16,
    pub evidence_ref_hash16: [u8; 16],
    pub created_at_micros: i64,
    pub updated_at_micros: i64,
}

impl RelationUpsertV1 {
    pub const V: u16 = 1;

    pub fn decode_bin(payload: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(payload);
        let v = c.read_u16()?;
        if v != Self::V {
            return Err(ProjectionError::InvalidEvent {
                msg: format!("RelationUpsertV1 unsupported version {v}"),
            });
        }
        let src_artifact_id = c.read_u32()?;
        let dst_artifact_id = c.read_u32()?;
        let relation_type = c.read_u8()?;
        let confidence_q16 = c.read_u16()?;
        let mut evidence_ref_hash16 = [0u8; 16];
        evidence_ref_hash16.copy_from_slice(c.read_exact(16)?);
        Ok(Self {
            src_artifact_id,
            dst_artifact_id,
            relation_type,
            confidence_q16,
            evidence_ref_hash16,
            created_at_micros: c.read_i64()?,
            updated_at_micros: c.read_i64()?,
        })
    }

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 4 + 4 + 1 + 2 + 16 + 8 + 8);
        out.extend_from_slice(&Self::V.to_le_bytes());
        out.extend_from_slice(&self.src_artifact_id.to_le_bytes());
        out.extend_from_slice(&self.dst_artifact_id.to_le_bytes());
        out.push(self.relation_type);
        out.extend_from_slice(&self.confidence_q16.to_le_bytes());
        out.extend_from_slice(&self.evidence_ref_hash16);
        out.extend_from_slice(&self.created_at_micros.to_le_bytes());
        out.extend_from_slice(&self.updated_at_micros.to_le_bytes());
        out
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelationDeleteV1 {
    pub src_artifact_id: u32,
    pub dst_artifact_id: u32,
    pub relation_type: u8,
}

impl RelationDeleteV1 {
    pub const V: u16 = 1;

    pub fn decode_bin(payload: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(payload);
        let v = c.read_u16()?;
        if v != Self::V {
            return Err(ProjectionError::InvalidEvent {
                msg: format!("RelationDeleteV1 unsupported version {v}"),
            });
        }
        Ok(Self {
            src_artifact_id: c.read_u32()?,
            dst_artifact_id: c.read_u32()?,
            relation_type: c.read_u8()?,
        })
    }

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 4 + 4 + 1);
        out.extend_from_slice(&Self::V.to_le_bytes());
        out.extend_from_slice(&self.src_artifact_id.to_le_bytes());
        out.extend_from_slice(&self.dst_artifact_id.to_le_bytes());
        out.push(self.relation_type);
        out
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DependentEvidenceUpsertV1 {
    pub artifact_id: u32,
    pub dependent_type: u8,
    pub dependent_id: Uuid,
    pub last_seen_at_micros: i64,
    pub usage_weight_q16: u16,
}

impl DependentEvidenceUpsertV1 {
    pub const V: u16 = 1;

    pub fn decode_bin(payload: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(payload);
        let v = c.read_u16()?;
        if v != Self::V {
            return Err(ProjectionError::InvalidEvent {
                msg: format!("DependentEvidenceUpsertV1 unsupported version {v}"),
            });
        }
        let artifact_id = c.read_u32()?;
        let dependent_type = c.read_u8()?;
        let dependent_id = c.read_uuid()?;
        Ok(Self {
            artifact_id,
            dependent_type,
            dependent_id,
            last_seen_at_micros: c.read_i64()?,
            usage_weight_q16: c.read_u16()?,
        })
    }

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 4 + 1 + 16 + 8 + 2);
        out.extend_from_slice(&Self::V.to_le_bytes());
        out.extend_from_slice(&self.artifact_id.to_le_bytes());
        out.push(self.dependent_type);
        out.extend_from_slice(self.dependent_id.as_bytes());
        out.extend_from_slice(&self.last_seen_at_micros.to_le_bytes());
        out.extend_from_slice(&self.usage_weight_q16.to_le_bytes());
        out
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PressureEventUpsertV1 {
    pub artifact_id: u32,
    pub pressure_event_id: Uuid,
    pub pressure_code_id: u16,
    pub severity: u8, // Engine uses 1..=5; CoreCrux derived pressure_level is computed elsewhere.
    pub observed_at_micros: i64,
    pub acknowledged_at_micros: i64, // 0 means null
    pub resolved_at_micros: i64,     // 0 means null
    pub receipt_id: Option<Uuid>,
}

impl PressureEventUpsertV1 {
    pub const V: u16 = 1;

    pub fn decode_bin(payload: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(payload);
        let v = c.read_u16()?;
        if v != Self::V {
            return Err(ProjectionError::InvalidEvent {
                msg: format!("PressureEventUpsertV1 unsupported version {v}"),
            });
        }
        let artifact_id = c.read_u32()?;
        let pressure_event_id = c.read_uuid()?;
        let pressure_code_id = c.read_u16()?;
        let severity = c.read_u8()?;
        let observed_at_micros = c.read_i64()?;
        let acknowledged_at_micros = c.read_i64()?;
        let resolved_at_micros = c.read_i64()?;
        let receipt_id = {
            let rid = c.read_uuid()?;
            if rid.as_bytes().iter().all(|b| *b == 0) {
                None
            } else {
                Some(rid)
            }
        };
        Ok(Self {
            artifact_id,
            pressure_event_id,
            pressure_code_id,
            severity,
            observed_at_micros,
            acknowledged_at_micros,
            resolved_at_micros,
            receipt_id,
        })
    }

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 4 + 16 + 2 + 1 + 8 + 8 + 8 + 16);
        out.extend_from_slice(&Self::V.to_le_bytes());
        out.extend_from_slice(&self.artifact_id.to_le_bytes());
        out.extend_from_slice(self.pressure_event_id.as_bytes());
        out.extend_from_slice(&self.pressure_code_id.to_le_bytes());
        out.push(self.severity);
        out.extend_from_slice(&self.observed_at_micros.to_le_bytes());
        out.extend_from_slice(&self.acknowledged_at_micros.to_le_bytes());
        out.extend_from_slice(&self.resolved_at_micros.to_le_bytes());
        match self.receipt_id {
            Some(rid) => out.extend_from_slice(rid.as_bytes()),
            None => out.extend_from_slice(&[0u8; 16]),
        }
        out
    }
}

pub fn parse_projection_event(
    event_type: &str,
    content_type: &str,
    payload: &[u8],
) -> Result<Option<ProjectionEventV1>> {
    let is_json = content_type.starts_with("application/json");

    let ev = match event_type {
        EVT_LIVING_STATE_UPDATE_V1 => {
            if is_json {
                ProjectionEventV1::LivingStateUpdate(serde_json::from_slice(payload).map_err(|e| {
                    ProjectionError::InvalidEvent {
                        msg: format!("LivingStateUpdateV1 json decode failed: {e}"),
                    }
                })?)
            } else {
                ProjectionEventV1::LivingStateUpdate(LivingStateUpdateV1::decode_bin(payload)?)
            }
        }
        EVT_RELATION_UPSERT_V1 => {
            if is_json {
                ProjectionEventV1::RelationUpsert(serde_json::from_slice(payload).map_err(|e| {
                    ProjectionError::InvalidEvent {
                        msg: format!("RelationUpsertV1 json decode failed: {e}"),
                    }
                })?)
            } else {
                ProjectionEventV1::RelationUpsert(RelationUpsertV1::decode_bin(payload)?)
            }
        }
        EVT_RELATION_DELETE_V1 => {
            if is_json {
                ProjectionEventV1::RelationDelete(serde_json::from_slice(payload).map_err(|e| {
                    ProjectionError::InvalidEvent {
                        msg: format!("RelationDeleteV1 json decode failed: {e}"),
                    }
                })?)
            } else {
                ProjectionEventV1::RelationDelete(RelationDeleteV1::decode_bin(payload)?)
            }
        }
        EVT_PRESSURE_UPSERT_V1 => {
            if is_json {
                ProjectionEventV1::PressureUpsert(serde_json::from_slice(payload).map_err(|e| {
                    ProjectionError::InvalidEvent {
                        msg: format!("PressureEventUpsertV1 json decode failed: {e}"),
                    }
                })?)
            } else {
                ProjectionEventV1::PressureUpsert(PressureEventUpsertV1::decode_bin(payload)?)
            }
        }
        EVT_DEPENDENT_EVIDENCE_UPSERT_V1 => {
            if is_json {
                ProjectionEventV1::DependentEvidenceUpsert(serde_json::from_slice(payload).map_err(|e| {
                    ProjectionError::InvalidEvent {
                        msg: format!("DependentEvidenceUpsertV1 json decode failed: {e}"),
                    }
                })?)
            } else {
                ProjectionEventV1::DependentEvidenceUpsert(DependentEvidenceUpsertV1::decode_bin(payload)?)
            }
        }
        EVT_ENTITY_FACT_V1 => {
            if is_json || content_type == CONTENT_TYPE_ENTITY_JSON_V1 {
                ProjectionEventV1::EntityFact(EntityFactV1::decode_json(payload)?)
            } else {
                ProjectionEventV1::EntityFact(EntityFactV1::decode_bin(payload)?)
            }
        }
        _ => return Ok(None),
    };

    Ok(Some(ev))
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
        let end = self.pos.checked_add(n).ok_or_else(|| ProjectionError::InvalidEvent {
            msg: "cursor overflow".to_string(),
        })?;
        if end > self.input.len() {
            return Err(ProjectionError::InvalidEvent {
                msg: "payload too small".to_string(),
            });
        }
        let out = &self.input[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let b = self.read_exact(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let b = self.read_exact(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_i64(&mut self) -> Result<i64> {
        let b = self.read_exact(8)?;
        Ok(i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    fn read_uuid(&mut self) -> Result<Uuid> {
        let b = self.read_exact(16)?;
        let mut buf = [0u8; 16];
        buf.copy_from_slice(b);
        Ok(Uuid::from_bytes(buf))
    }

    /// Read a length-prefixed UTF-8 string (u16 len + bytes)
    fn read_str(&mut self) -> Result<String> {
        let len = self.read_u16()? as usize;
        let bytes = self.read_exact(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|e| ProjectionError::InvalidEvent {
            msg: format!("invalid UTF-8 in string field: {e}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    // ---- LivingStateUpdateV1 ----

    #[test]
    fn living_state_update_bin_roundtrip() {
        let orig = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS
                | LivingStateUpdateV1::MASK_CONFIDENCE
                | LivingStateUpdateV1::MASK_TRUNK_TIER,
            artifact_id: 42,
            living_status: 2, // stale
            confidence_q16: 32768,
            last_validated_at_micros: 1_000_000,
            next_review_at_micros: 2_000_000,
            trunk_tier: 3,
            updated_at_micros: 3_000_000,
        };
        let bytes = orig.encode_bin();
        let decoded = LivingStateUpdateV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.fields_mask, orig.fields_mask);
        assert_eq!(decoded.artifact_id, orig.artifact_id);
        assert_eq!(decoded.living_status, orig.living_status);
        assert_eq!(decoded.confidence_q16, orig.confidence_q16);
        assert_eq!(decoded.last_validated_at_micros, orig.last_validated_at_micros);
        assert_eq!(decoded.next_review_at_micros, orig.next_review_at_micros);
        assert_eq!(decoded.trunk_tier, orig.trunk_tier);
        assert_eq!(decoded.updated_at_micros, orig.updated_at_micros);
    }

    #[test]
    fn living_state_update_wrong_version() {
        let mut bytes = LivingStateUpdateV1 {
            fields_mask: 0,
            artifact_id: 1,
            living_status: 0,
            confidence_q16: 0,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 0,
        }
        .encode_bin();
        // Corrupt the version field to 99.
        bytes[0] = 99;
        bytes[1] = 0;
        assert!(LivingStateUpdateV1::decode_bin(&bytes).is_err());
    }

    #[test]
    fn living_state_update_truncated_payload() {
        let bytes = LivingStateUpdateV1 {
            fields_mask: 0,
            artifact_id: 1,
            living_status: 0,
            confidence_q16: 0,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 0,
        }
        .encode_bin();
        // Truncate to just the version field.
        assert!(LivingStateUpdateV1::decode_bin(&bytes[..4]).is_err());
    }

    // ---- RelationUpsertV1 ----

    #[test]
    fn relation_upsert_bin_roundtrip() {
        let orig = RelationUpsertV1 {
            src_artifact_id: 10,
            dst_artifact_id: 20,
            relation_type: 3,
            confidence_q16: 50000,
            evidence_ref_hash16: [0xAB; 16],
            created_at_micros: 100_000,
            updated_at_micros: 200_000,
        };
        let bytes = orig.encode_bin();
        let decoded = RelationUpsertV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.src_artifact_id, orig.src_artifact_id);
        assert_eq!(decoded.dst_artifact_id, orig.dst_artifact_id);
        assert_eq!(decoded.relation_type, orig.relation_type);
        assert_eq!(decoded.confidence_q16, orig.confidence_q16);
        assert_eq!(decoded.evidence_ref_hash16, orig.evidence_ref_hash16);
        assert_eq!(decoded.created_at_micros, orig.created_at_micros);
        assert_eq!(decoded.updated_at_micros, orig.updated_at_micros);
    }

    #[test]
    fn relation_upsert_wrong_version() {
        let mut bytes = RelationUpsertV1 {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: 0,
            confidence_q16: 0,
            evidence_ref_hash16: [0; 16],
            created_at_micros: 0,
            updated_at_micros: 0,
        }
        .encode_bin();
        bytes[0] = 5;
        assert!(RelationUpsertV1::decode_bin(&bytes).is_err());
    }

    // ---- RelationDeleteV1 ----

    #[test]
    fn relation_delete_bin_roundtrip() {
        let orig = RelationDeleteV1 {
            src_artifact_id: 7,
            dst_artifact_id: 8,
            relation_type: 2,
        };
        let bytes = orig.encode_bin();
        let decoded = RelationDeleteV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.src_artifact_id, orig.src_artifact_id);
        assert_eq!(decoded.dst_artifact_id, orig.dst_artifact_id);
        assert_eq!(decoded.relation_type, orig.relation_type);
    }

    #[test]
    fn relation_delete_wrong_version() {
        let mut bytes = RelationDeleteV1 {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: 0,
        }
        .encode_bin();
        bytes[0] = 42;
        assert!(RelationDeleteV1::decode_bin(&bytes).is_err());
    }

    #[test]
    fn relation_delete_empty_payload() {
        assert!(RelationDeleteV1::decode_bin(&[]).is_err());
    }

    // ---- DependentEvidenceUpsertV1 ----

    #[test]
    fn dependent_evidence_upsert_bin_roundtrip() {
        let dep_id = Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890").unwrap();
        let orig = DependentEvidenceUpsertV1 {
            artifact_id: 99,
            dependent_type: 1,
            dependent_id: dep_id,
            last_seen_at_micros: 5_000_000,
            usage_weight_q16: 12345,
        };
        let bytes = orig.encode_bin();
        let decoded = DependentEvidenceUpsertV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.artifact_id, orig.artifact_id);
        assert_eq!(decoded.dependent_type, orig.dependent_type);
        assert_eq!(decoded.dependent_id, orig.dependent_id);
        assert_eq!(decoded.last_seen_at_micros, orig.last_seen_at_micros);
        assert_eq!(decoded.usage_weight_q16, orig.usage_weight_q16);
    }

    #[test]
    fn dependent_evidence_upsert_wrong_version() {
        let mut bytes = DependentEvidenceUpsertV1 {
            artifact_id: 1,
            dependent_type: 0,
            dependent_id: Uuid::nil(),
            last_seen_at_micros: 0,
            usage_weight_q16: 0,
        }
        .encode_bin();
        bytes[0] = 200;
        assert!(DependentEvidenceUpsertV1::decode_bin(&bytes).is_err());
    }

    // ---- PressureEventUpsertV1 ----

    #[test]
    fn pressure_upsert_bin_roundtrip_with_receipt() {
        let eid = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let rid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let orig = PressureEventUpsertV1 {
            artifact_id: 77,
            pressure_event_id: eid,
            pressure_code_id: 1001,
            severity: 4,
            observed_at_micros: 10_000_000,
            acknowledged_at_micros: 20_000_000,
            resolved_at_micros: 0,
            receipt_id: Some(rid),
        };
        let bytes = orig.encode_bin();
        let decoded = PressureEventUpsertV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.artifact_id, orig.artifact_id);
        assert_eq!(decoded.pressure_event_id, orig.pressure_event_id);
        assert_eq!(decoded.pressure_code_id, orig.pressure_code_id);
        assert_eq!(decoded.severity, orig.severity);
        assert_eq!(decoded.observed_at_micros, orig.observed_at_micros);
        assert_eq!(decoded.acknowledged_at_micros, orig.acknowledged_at_micros);
        assert_eq!(decoded.resolved_at_micros, orig.resolved_at_micros);
        assert_eq!(decoded.receipt_id, Some(rid));
    }

    #[test]
    fn pressure_upsert_bin_roundtrip_without_receipt() {
        let eid = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let orig = PressureEventUpsertV1 {
            artifact_id: 77,
            pressure_event_id: eid,
            pressure_code_id: 500,
            severity: 2,
            observed_at_micros: 100,
            acknowledged_at_micros: 0,
            resolved_at_micros: 0,
            receipt_id: None,
        };
        let bytes = orig.encode_bin();
        let decoded = PressureEventUpsertV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.receipt_id, None);
    }

    #[test]
    fn pressure_upsert_wrong_version() {
        let mut bytes = PressureEventUpsertV1 {
            artifact_id: 1,
            pressure_event_id: Uuid::nil(),
            pressure_code_id: 0,
            severity: 0,
            observed_at_micros: 0,
            acknowledged_at_micros: 0,
            resolved_at_micros: 0,
            receipt_id: None,
        }
        .encode_bin();
        bytes[0] = 10;
        assert!(PressureEventUpsertV1::decode_bin(&bytes).is_err());
    }

    // ---- EntityFactV1 ----

    #[test]
    fn entity_fact_bin_roundtrip() {
        let orig = EntityFactV1 {
            tenant_id: "tenant-x".to_string(),
            entity_type: "Person".to_string(),
            entity_name: "Dr. Jones".to_string(),
            predicate: "visited".to_string(),
            object_value: "Science Museum".to_string(),
            session_id: "session-abc".to_string(),
            occurred_at_micros: 1_700_000_000_000_000,
            confidence_q16: 60000,
        };
        let bytes = orig.encode_bin();
        let decoded = EntityFactV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.tenant_id, orig.tenant_id);
        assert_eq!(decoded.entity_type, orig.entity_type);
        assert_eq!(decoded.entity_name, orig.entity_name);
        assert_eq!(decoded.predicate, orig.predicate);
        assert_eq!(decoded.object_value, orig.object_value);
        assert_eq!(decoded.session_id, orig.session_id);
        assert_eq!(decoded.occurred_at_micros, orig.occurred_at_micros);
        assert_eq!(decoded.confidence_q16, orig.confidence_q16);
    }

    #[test]
    fn entity_fact_json_roundtrip() {
        let orig = EntityFactV1 {
            tenant_id: "t1".to_string(),
            entity_type: "Place".to_string(),
            entity_name: "London".to_string(),
            predicate: "located_in".to_string(),
            object_value: "UK".to_string(),
            session_id: "s1".to_string(),
            occurred_at_micros: 0,
            confidence_q16: 65535,
        };
        let json_bytes = orig.encode_json();
        let decoded = EntityFactV1::decode_json(&json_bytes).unwrap();
        assert_eq!(decoded.tenant_id, "t1");
        assert_eq!(decoded.entity_name, "London");
        assert_eq!(decoded.confidence_q16, 65535);
    }

    #[test]
    fn entity_fact_wrong_version() {
        let mut bytes = EntityFactV1 {
            tenant_id: "t".to_string(),
            entity_type: "X".to_string(),
            entity_name: "Y".to_string(),
            predicate: "Z".to_string(),
            object_value: "W".to_string(),
            session_id: "S".to_string(),
            occurred_at_micros: 0,
            confidence_q16: 0,
        }
        .encode_bin();
        bytes[0] = 99;
        assert!(EntityFactV1::decode_bin(&bytes).is_err());
    }

    #[test]
    fn entity_fact_json_invalid() {
        let bad = b"not json";
        assert!(EntityFactV1::decode_json(bad).is_err());
    }

    #[test]
    fn entity_fact_occurred_at_iso_nonzero() {
        let fact = EntityFactV1 {
            tenant_id: "t".to_string(),
            entity_type: "X".to_string(),
            entity_name: "Y".to_string(),
            predicate: "Z".to_string(),
            object_value: "W".to_string(),
            session_id: "S".to_string(),
            occurred_at_micros: 1_700_000_000_000_000, // 2023-11-14T22:13:20Z
            confidence_q16: 0,
        };
        let iso = fact.occurred_at_iso();
        assert!(iso.is_some());
        assert!(iso.unwrap().contains("2023"));
    }

    #[test]
    fn entity_fact_occurred_at_iso_zero() {
        let fact = EntityFactV1 {
            tenant_id: "t".to_string(),
            entity_type: "X".to_string(),
            entity_name: "Y".to_string(),
            predicate: "Z".to_string(),
            object_value: "W".to_string(),
            session_id: "S".to_string(),
            occurred_at_micros: 0,
            confidence_q16: 0,
        };
        assert!(fact.occurred_at_iso().is_none());
    }

    // ---- parse_projection_event ----

    #[test]
    fn parse_projection_event_living_bin() {
        let living = LivingStateUpdateV1 {
            fields_mask: LivingStateUpdateV1::MASK_LIVING_STATUS,
            artifact_id: 5,
            living_status: 1,
            confidence_q16: 100,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 0,
        };
        let payload = living.encode_bin();
        let result = parse_projection_event(EVT_LIVING_STATE_UPDATE_V1, CONTENT_TYPE_PROJ_BIN_V1, &payload).unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), ProjectionEventV1::LivingStateUpdate(_)));
    }

    #[test]
    fn parse_projection_event_living_json() {
        let living = LivingStateUpdateV1 {
            fields_mask: 0,
            artifact_id: 1,
            living_status: 0,
            confidence_q16: 0,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            trunk_tier: 0,
            updated_at_micros: 0,
        };
        let payload = serde_json::to_vec(&living).unwrap();
        let result = parse_projection_event(EVT_LIVING_STATE_UPDATE_V1, "application/json", &payload).unwrap();
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), ProjectionEventV1::LivingStateUpdate(_)));
    }

    #[test]
    fn parse_projection_event_relation_upsert_bin() {
        let rel = RelationUpsertV1 {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: 0,
            confidence_q16: 1000,
            evidence_ref_hash16: [0; 16],
            created_at_micros: 0,
            updated_at_micros: 0,
        };
        let payload = rel.encode_bin();
        let result = parse_projection_event(EVT_RELATION_UPSERT_V1, CONTENT_TYPE_PROJ_BIN_V1, &payload).unwrap();
        assert!(matches!(result.unwrap(), ProjectionEventV1::RelationUpsert(_)));
    }

    #[test]
    fn parse_projection_event_relation_delete_json() {
        let del = RelationDeleteV1 {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: 1,
        };
        let payload = serde_json::to_vec(&del).unwrap();
        let result = parse_projection_event(EVT_RELATION_DELETE_V1, "application/json", &payload).unwrap();
        assert!(matches!(result.unwrap(), ProjectionEventV1::RelationDelete(_)));
    }

    #[test]
    fn parse_projection_event_pressure_bin() {
        let pres = PressureEventUpsertV1 {
            artifact_id: 1,
            pressure_event_id: Uuid::nil(),
            pressure_code_id: 0,
            severity: 1,
            observed_at_micros: 100,
            acknowledged_at_micros: 0,
            resolved_at_micros: 0,
            receipt_id: None,
        };
        let payload = pres.encode_bin();
        let result = parse_projection_event(EVT_PRESSURE_UPSERT_V1, CONTENT_TYPE_PROJ_BIN_V1, &payload).unwrap();
        assert!(matches!(result.unwrap(), ProjectionEventV1::PressureUpsert(_)));
    }

    #[test]
    fn parse_projection_event_dependent_evidence_json() {
        let dep = DependentEvidenceUpsertV1 {
            artifact_id: 10,
            dependent_type: 0,
            dependent_id: Uuid::nil(),
            last_seen_at_micros: 50,
            usage_weight_q16: 100,
        };
        let payload = serde_json::to_vec(&dep).unwrap();
        let result = parse_projection_event(EVT_DEPENDENT_EVIDENCE_UPSERT_V1, "application/json", &payload).unwrap();
        assert!(matches!(result.unwrap(), ProjectionEventV1::DependentEvidenceUpsert(_)));
    }

    #[test]
    fn parse_projection_event_entity_fact_json() {
        let fact = EntityFactV1 {
            tenant_id: "t".to_string(),
            entity_type: "Person".to_string(),
            entity_name: "Alice".to_string(),
            predicate: "knows".to_string(),
            object_value: "Bob".to_string(),
            session_id: "s1".to_string(),
            occurred_at_micros: 1000,
            confidence_q16: 50000,
        };
        let payload = fact.encode_json();
        let result = parse_projection_event(EVT_ENTITY_FACT_V1, CONTENT_TYPE_ENTITY_JSON_V1, &payload).unwrap();
        assert!(matches!(result.unwrap(), ProjectionEventV1::EntityFact(_)));
    }

    #[test]
    fn parse_projection_event_entity_fact_bin() {
        let fact = EntityFactV1 {
            tenant_id: "t".to_string(),
            entity_type: "Place".to_string(),
            entity_name: "London".to_string(),
            predicate: "in".to_string(),
            object_value: "UK".to_string(),
            session_id: "s2".to_string(),
            occurred_at_micros: 0,
            confidence_q16: 0,
        };
        let payload = fact.encode_bin();
        let result = parse_projection_event(EVT_ENTITY_FACT_V1, CONTENT_TYPE_PROJ_BIN_V1, &payload).unwrap();
        assert!(matches!(result.unwrap(), ProjectionEventV1::EntityFact(_)));
    }

    #[test]
    fn parse_projection_event_unknown_type_returns_none() {
        let result = parse_projection_event("unknown.event.type", "application/json", &[]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_projection_event_bad_json_returns_err() {
        let result = parse_projection_event(EVT_LIVING_STATE_UPDATE_V1, "application/json", b"not json");
        assert!(result.is_err());
    }

    // ---- Cursor ----

    #[test]
    fn cursor_read_exact_overflow() {
        let data = [0u8; 4];
        let mut c = Cursor::new(&data);
        // Advance near the end.
        c.pos = 3;
        // Requesting usize::MAX should trigger checked_add overflow.
        assert!(c.read_exact(usize::MAX).is_err());
    }

    #[test]
    fn cursor_read_exact_past_end() {
        let data = [0u8; 2];
        let mut c = Cursor::new(&data);
        assert!(c.read_exact(3).is_err());
    }

    #[test]
    fn cursor_read_str_invalid_utf8() {
        // Build a payload: version u16 + len-prefixed string with invalid UTF-8.
        let mut buf = Vec::new();
        let len: u16 = 3;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // Invalid UTF-8
        let mut c = Cursor::new(&buf);
        assert!(c.read_str().is_err());
    }
}
