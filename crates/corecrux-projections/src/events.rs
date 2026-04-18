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

// Session-handshake events (master-plan §7.2). These record the existence
// and lifecycle of every session plan issued by VaultCrux / Crux CE, so
// that the segment log remains the authoritative truth even when the hot
// registry is lost or rebuilt. Plan bodies are stored in `plan_bytes_cbor`
// exactly as produced by the `crux-session` canonical encoder.
pub const EVT_SESSION_PLAN_SEALED_V1: &str = "corecrux.session.plan_sealed.v1";
pub const EVT_SESSION_CLOSED_V1: &str = "corecrux.session.closed.v1";
pub const EVT_SESSION_REVOKED_V1: &str = "corecrux.session.revoked.v1";
pub const EVT_INVOCATION_RECEIPTED_V1: &str = "corecrux.session.invocation_receipted.v1";
// CE → Core import (master-plan §9; M8). The countersignature event that
// vouches for imported CE segments being carried intact into a hosted
// tenant.
pub const EVT_CE_INSTALL_IMPORTED_V1: &str = "corecrux.session.ce_install_imported.v1";

pub const CONTENT_TYPE_PROJ_BIN_V1: &str = "application/x-corecrux-proj-bin-v1";
pub const CONTENT_TYPE_SESSION_BIN_V1: &str = "application/x-corecrux-session-bin-v1";

#[derive(Debug, Clone)]
pub enum ProjectionEventV1 {
    LivingStateUpdate(LivingStateUpdateV1),
    RelationUpsert(RelationUpsertV1),
    RelationDelete(RelationDeleteV1),
    PressureUpsert(PressureEventUpsertV1),
    DependentEvidenceUpsert(DependentEvidenceUpsertV1),
    // Phase 6: Entity fact event — carries a structured entity relation
    EntityFact(EntityFactV1),
    // Session-handshake events (M2; master-plan §7.2). Additive.
    SessionPlanSealed(SessionPlanSealedV1),
    SessionClosed(SessionClosedV1),
    SessionRevoked(SessionRevokedV1),
    InvocationReceipted(InvocationReceiptedV1),
    // CE → Core migration (M8; master-plan §9.3).
    CeInstallImported(CeInstallImportedV1),
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
        // SAFETY: EntityFactV1 fields are all primitive/String types — serialization cannot fail.
        #[allow(clippy::expect_used)]
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
        // Session events are binary-only in M2. A hex-encoded JSON form may
        // be added later; for now we route everything through decode_bin.
        EVT_SESSION_PLAN_SEALED_V1 => {
            ProjectionEventV1::SessionPlanSealed(SessionPlanSealedV1::decode_bin(payload)?)
        }
        EVT_SESSION_CLOSED_V1 => {
            ProjectionEventV1::SessionClosed(SessionClosedV1::decode_bin(payload)?)
        }
        EVT_SESSION_REVOKED_V1 => {
            ProjectionEventV1::SessionRevoked(SessionRevokedV1::decode_bin(payload)?)
        }
        EVT_INVOCATION_RECEIPTED_V1 => {
            ProjectionEventV1::InvocationReceipted(InvocationReceiptedV1::decode_bin(payload)?)
        }
        EVT_CE_INSTALL_IMPORTED_V1 => {
            ProjectionEventV1::CeInstallImported(CeInstallImportedV1::decode_bin(payload)?)
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

    fn read_array16(&mut self) -> Result<[u8; 16]> {
        let b = self.read_exact(16)?;
        let mut out = [0u8; 16];
        out.copy_from_slice(b);
        Ok(out)
    }

    fn read_array32(&mut self) -> Result<[u8; 32]> {
        let b = self.read_exact(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(b);
        Ok(out)
    }

    fn read_opt_array32(&mut self) -> Result<Option<[u8; 32]>> {
        let flag = self.read_u8()?;
        match flag {
            0 => Ok(None),
            1 => Ok(Some(self.read_array32()?)),
            _ => Err(ProjectionError::InvalidEvent {
                msg: format!("invalid option flag {flag} for bytes(32)"),
            }),
        }
    }

    fn read_opt_array64(&mut self) -> Result<Option<[u8; 64]>> {
        let flag = self.read_u8()?;
        match flag {
            0 => Ok(None),
            1 => {
                let b = self.read_exact(64)?;
                let mut out = [0u8; 64];
                out.copy_from_slice(b);
                Ok(Some(out))
            }
            _ => Err(ProjectionError::InvalidEvent {
                msg: format!("invalid option flag {flag} for bytes(64)"),
            }),
        }
    }
}

// ─── Session-handshake events (M2; master-plan §7.2) ──────────────────────
//
// Binary encodings use the same length-prefix + LE-integer patterns as the
// other projection events in this file, plus:
//   - fixed-size byte arrays written in-place (no length prefix)
//   - `option<bytes(N)>` written as `presence: u8 | (0x00|0x01)` + bytes(N)
//     when present; `0x00` alone otherwise.
//   - `bytes(var)` (plan CBOR) written as u32 LE length + bytes.
//
// See `Crux/crates/crux-session/src/plan.rs` for the source types.

#[derive(Debug, Clone)]
pub struct SessionPlanSealedV1 {
    pub event_id: [u8; 16],
    pub plan_id: [u8; 16],
    pub session_id: [u8; 16],
    pub principal_id: String,
    pub origin: String,
    pub origin_install: Option<[u8; 32]>,
    pub minted_at_ms: i64,
    pub expires_at_ms: i64,
    pub plan_receipt_hash: [u8; 32],
    pub plan_receipt_signature: Option<[u8; 64]>,
    pub capability_graph_hash: [u8; 32],
    pub plan_bytes_cbor: Vec<u8>,
}

impl SessionPlanSealedV1 {
    pub const V: u16 = 1;

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(2 + 48 + 2 * (2 + 32) + 32 + 64 + 32 + 16 + 4 + self.plan_bytes_cbor.len());
        out.extend_from_slice(&Self::V.to_le_bytes());
        out.extend_from_slice(&self.event_id);
        out.extend_from_slice(&self.plan_id);
        out.extend_from_slice(&self.session_id);
        write_str(&mut out, &self.principal_id);
        write_str(&mut out, &self.origin);
        write_opt_bytes_32(&mut out, self.origin_install.as_ref());
        out.extend_from_slice(&self.minted_at_ms.to_le_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_le_bytes());
        out.extend_from_slice(&self.plan_receipt_hash);
        write_opt_bytes_64(&mut out, self.plan_receipt_signature.as_ref());
        out.extend_from_slice(&self.capability_graph_hash);
        let cbor_len = u32::try_from(self.plan_bytes_cbor.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&cbor_len.to_le_bytes());
        out.extend_from_slice(&self.plan_bytes_cbor[..cbor_len as usize]);
        out
    }

    pub fn decode_bin(payload: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(payload);
        let v = c.read_u16()?;
        if v != Self::V {
            return Err(ProjectionError::InvalidEvent {
                msg: format!("SessionPlanSealedV1 unsupported version {v}"),
            });
        }
        let event_id = c.read_array16()?;
        let plan_id = c.read_array16()?;
        let session_id = c.read_array16()?;
        let principal_id = c.read_str()?;
        let origin = c.read_str()?;
        let origin_install = c.read_opt_array32()?;
        let minted_at_ms = c.read_i64()?;
        let expires_at_ms = c.read_i64()?;
        let plan_receipt_hash = c.read_array32()?;
        let plan_receipt_signature = c.read_opt_array64()?;
        let capability_graph_hash = c.read_array32()?;
        let cbor_len = c.read_u32()? as usize;
        let plan_bytes_cbor = c.read_exact(cbor_len)?.to_vec();
        Ok(Self {
            event_id,
            plan_id,
            session_id,
            principal_id,
            origin,
            origin_install,
            minted_at_ms,
            expires_at_ms,
            plan_receipt_hash,
            plan_receipt_signature,
            capability_graph_hash,
            plan_bytes_cbor,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SessionClosedV1 {
    pub event_id: [u8; 16],
    pub session_id: [u8; 16],
    pub reason: String, // "ttl_expired" | "client_closed" | "admin_closed"
    pub closed_at_ms: i64,
}

impl SessionClosedV1 {
    pub const V: u16 = 1;

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 16 + 16 + 2 + 16 + 8);
        out.extend_from_slice(&Self::V.to_le_bytes());
        out.extend_from_slice(&self.event_id);
        out.extend_from_slice(&self.session_id);
        write_str(&mut out, &self.reason);
        out.extend_from_slice(&self.closed_at_ms.to_le_bytes());
        out
    }

    pub fn decode_bin(payload: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(payload);
        let v = c.read_u16()?;
        if v != Self::V {
            return Err(ProjectionError::InvalidEvent {
                msg: format!("SessionClosedV1 unsupported version {v}"),
            });
        }
        Ok(Self {
            event_id: c.read_array16()?,
            session_id: c.read_array16()?,
            reason: c.read_str()?,
            closed_at_ms: c.read_i64()?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SessionRevokedV1 {
    pub event_id: [u8; 16],
    pub session_id: [u8; 16],
    pub reason: String,
    pub revoked_at_ms: i64,
    pub revocation_receipt_hash: [u8; 32],
}

impl SessionRevokedV1 {
    pub const V: u16 = 1;

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 16 + 16 + 2 + 32 + 8 + 32);
        out.extend_from_slice(&Self::V.to_le_bytes());
        out.extend_from_slice(&self.event_id);
        out.extend_from_slice(&self.session_id);
        write_str(&mut out, &self.reason);
        out.extend_from_slice(&self.revoked_at_ms.to_le_bytes());
        out.extend_from_slice(&self.revocation_receipt_hash);
        out
    }

    pub fn decode_bin(payload: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(payload);
        let v = c.read_u16()?;
        if v != Self::V {
            return Err(ProjectionError::InvalidEvent {
                msg: format!("SessionRevokedV1 unsupported version {v}"),
            });
        }
        Ok(Self {
            event_id: c.read_array16()?,
            session_id: c.read_array16()?,
            reason: c.read_str()?,
            revoked_at_ms: c.read_i64()?,
            revocation_receipt_hash: c.read_array32()?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct InvocationReceiptedV1 {
    pub event_id: [u8; 16],
    pub session_id: [u8; 16],
    pub capability: String,
    pub channel: String, // "bulk" | "mcp"
    pub invocation_at_ms: i64,
    pub invocation_receipt_hash: [u8; 32],
    pub parent_plan_receipt_hash: [u8; 32],
}

impl InvocationReceiptedV1 {
    pub const V: u16 = 1;

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 16 + 16 + 2 + 64 + 2 + 8 + 8 + 32 + 32);
        out.extend_from_slice(&Self::V.to_le_bytes());
        out.extend_from_slice(&self.event_id);
        out.extend_from_slice(&self.session_id);
        write_str(&mut out, &self.capability);
        write_str(&mut out, &self.channel);
        out.extend_from_slice(&self.invocation_at_ms.to_le_bytes());
        out.extend_from_slice(&self.invocation_receipt_hash);
        out.extend_from_slice(&self.parent_plan_receipt_hash);
        out
    }

    pub fn decode_bin(payload: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(payload);
        let v = c.read_u16()?;
        if v != Self::V {
            return Err(ProjectionError::InvalidEvent {
                msg: format!("InvocationReceiptedV1 unsupported version {v}"),
            });
        }
        Ok(Self {
            event_id: c.read_array16()?,
            session_id: c.read_array16()?,
            capability: c.read_str()?,
            channel: c.read_str()?,
            invocation_at_ms: c.read_i64()?,
            invocation_receipt_hash: c.read_array32()?,
            parent_plan_receipt_hash: c.read_array32()?,
        })
    }
}

/// CE → Core import countersignature event (master-plan §9.3 step 3).
///
/// Emitted on the hosted side when a CE install's sessions are accepted
/// into a tenant. The event's `import_receipt_signature` is the only new
/// signature over the whole bundle — individual CE receipts retain their
/// original `mode: "local"` + BLAKE3 hashes; this event vouches for them
/// en masse.
#[derive(Debug, Clone)]
pub struct CeInstallImportedV1 {
    pub event_id: [u8; 16],
    pub origin_install: [u8; 32],
    pub tenant_id: String,
    pub ce_principal_id: String,
    pub core_principal_id: String,
    /// BLAKE3 hashes of each plan carried in the bundle. The hashes must
    /// match a later `SessionPlanSealedV1` that replayed the CE plan's
    /// canonical bytes — that's the chain-verification step.
    pub imported_plan_hashes: Vec<[u8; 32]>,
    /// Number of invocation receipts carried in the bundle. Used only
    /// for telemetry; individual receipts are re-sealed separately.
    pub imported_invocation_count: u32,
    pub imported_at_ms: i64,
    /// BLAKE3 over canonical-CBOR of this event with
    /// `import_receipt_hash` + `import_receipt_signature` zeroed.
    pub import_receipt_hash: [u8; 32],
    /// ed25519 over `import_receipt_hash`; hosted-only. None in local
    /// dev / test paths.
    pub import_receipt_signature: Option<[u8; 64]>,
    pub signer_kid: Option<String>,
}

impl CeInstallImportedV1 {
    pub const V: u16 = 1;

    pub fn encode_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 16 + 32 + 2 * 64 + 4 + 4 + 8 + 32 + 64);
        out.extend_from_slice(&Self::V.to_le_bytes());
        out.extend_from_slice(&self.event_id);
        out.extend_from_slice(&self.origin_install);
        write_str(&mut out, &self.tenant_id);
        write_str(&mut out, &self.ce_principal_id);
        write_str(&mut out, &self.core_principal_id);
        let count = u32::try_from(self.imported_plan_hashes.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for h in &self.imported_plan_hashes[..count as usize] {
            out.extend_from_slice(h);
        }
        out.extend_from_slice(&self.imported_invocation_count.to_le_bytes());
        out.extend_from_slice(&self.imported_at_ms.to_le_bytes());
        out.extend_from_slice(&self.import_receipt_hash);
        write_opt_bytes_64(&mut out, self.import_receipt_signature.as_ref());
        match &self.signer_kid {
            Some(s) => {
                out.push(1);
                write_str(&mut out, s);
            }
            None => out.push(0),
        }
        out
    }

    pub fn decode_bin(payload: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(payload);
        let v = c.read_u16()?;
        if v != Self::V {
            return Err(ProjectionError::InvalidEvent {
                msg: format!("CeInstallImportedV1 unsupported version {v}"),
            });
        }
        let event_id = c.read_array16()?;
        let origin_install = c.read_array32()?;
        let tenant_id = c.read_str()?;
        let ce_principal_id = c.read_str()?;
        let core_principal_id = c.read_str()?;
        let count = c.read_u32()? as usize;
        let mut imported_plan_hashes = Vec::with_capacity(count);
        for _ in 0..count {
            imported_plan_hashes.push(c.read_array32()?);
        }
        let imported_invocation_count = c.read_u32()?;
        let imported_at_ms = c.read_i64()?;
        let import_receipt_hash = c.read_array32()?;
        let import_receipt_signature = c.read_opt_array64()?;
        let has_kid = c.read_u8()?;
        let signer_kid = match has_kid {
            0 => None,
            1 => Some(c.read_str()?),
            _ => {
                return Err(ProjectionError::InvalidEvent {
                    msg: format!("invalid flag {has_kid} for signer_kid"),
                })
            }
        };
        Ok(Self {
            event_id,
            origin_install,
            tenant_id,
            ce_principal_id,
            core_principal_id,
            imported_plan_hashes,
            imported_invocation_count,
            imported_at_ms,
            import_receipt_hash,
            import_receipt_signature,
            signer_kid,
        })
    }

    /// BLAKE3 over the canonical binary encoding with
    /// `import_receipt_hash` + `import_receipt_signature` + `signer_kid`
    /// zeroed. This is the value that goes in `import_receipt_hash` and
    /// (on hosted) is signed to produce `import_receipt_signature`.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut zeroed = self.clone();
        zeroed.import_receipt_hash = [0u8; 32];
        zeroed.import_receipt_signature = None;
        zeroed.signer_kid = None;
        let bytes = zeroed.encode_bin();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }
}

// ─── helpers for the four session events ──────────────────────────────────

fn write_opt_bytes_32(buf: &mut Vec<u8>, value: Option<&[u8; 32]>) {
    match value {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(v);
        }
        None => buf.push(0),
    }
}

fn write_opt_bytes_64(buf: &mut Vec<u8>, value: Option<&[u8; 64]>) {
    match value {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(v);
        }
        None => buf.push(0),
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

    // ---- Session-handshake events (M2) ----

    fn sample_session_plan_sealed() -> SessionPlanSealedV1 {
        SessionPlanSealedV1 {
            event_id: [0xA1; 16],
            plan_id: [0xB2; 16],
            session_id: [0xC3; 16],
            principal_id: "tenant:cuecrux_ltd:myles".into(),
            origin: "core".into(),
            origin_install: None,
            minted_at_ms: 1_745_000_000_000,
            expires_at_ms: 1_745_000_003_600_000,
            plan_receipt_hash: [0xD4; 32],
            plan_receipt_signature: Some([0xE5; 64]),
            capability_graph_hash: [0xF6; 32],
            plan_bytes_cbor: vec![0xa0, 0x01, 0x02, 0x03, 0x04],
        }
    }

    #[test]
    fn session_plan_sealed_bin_roundtrip() {
        let orig = sample_session_plan_sealed();
        let bytes = orig.encode_bin();
        let decoded = SessionPlanSealedV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.event_id, orig.event_id);
        assert_eq!(decoded.plan_id, orig.plan_id);
        assert_eq!(decoded.session_id, orig.session_id);
        assert_eq!(decoded.principal_id, orig.principal_id);
        assert_eq!(decoded.origin, orig.origin);
        assert_eq!(decoded.origin_install, orig.origin_install);
        assert_eq!(decoded.minted_at_ms, orig.minted_at_ms);
        assert_eq!(decoded.expires_at_ms, orig.expires_at_ms);
        assert_eq!(decoded.plan_receipt_hash, orig.plan_receipt_hash);
        assert_eq!(decoded.plan_receipt_signature, orig.plan_receipt_signature);
        assert_eq!(decoded.capability_graph_hash, orig.capability_graph_hash);
        assert_eq!(decoded.plan_bytes_cbor, orig.plan_bytes_cbor);
    }

    #[test]
    fn session_plan_sealed_ce_roundtrip_no_signature() {
        let orig = SessionPlanSealedV1 {
            origin: "ce".into(),
            origin_install: Some([0x11; 32]),
            plan_receipt_signature: None,
            ..sample_session_plan_sealed()
        };
        let bytes = orig.encode_bin();
        let decoded = SessionPlanSealedV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.origin, "ce");
        assert_eq!(decoded.origin_install, Some([0x11; 32]));
        assert!(decoded.plan_receipt_signature.is_none());
    }

    #[test]
    fn session_plan_sealed_version_guard() {
        let mut bytes = sample_session_plan_sealed().encode_bin();
        // Corrupt the version.
        bytes[0] = 0xff;
        bytes[1] = 0xff;
        assert!(SessionPlanSealedV1::decode_bin(&bytes).is_err());
    }

    #[test]
    fn session_closed_bin_roundtrip() {
        let orig = SessionClosedV1 {
            event_id: [0x0A; 16],
            session_id: [0x0B; 16],
            reason: "ttl_expired".into(),
            closed_at_ms: 2_000_000,
        };
        let bytes = orig.encode_bin();
        let decoded = SessionClosedV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.event_id, orig.event_id);
        assert_eq!(decoded.session_id, orig.session_id);
        assert_eq!(decoded.reason, orig.reason);
        assert_eq!(decoded.closed_at_ms, orig.closed_at_ms);
    }

    #[test]
    fn session_revoked_bin_roundtrip() {
        let orig = SessionRevokedV1 {
            event_id: [0x0C; 16],
            session_id: [0x0D; 16],
            reason: "admin_revoked".into(),
            revoked_at_ms: 3_000_000,
            revocation_receipt_hash: [0x0E; 32],
        };
        let bytes = orig.encode_bin();
        let decoded = SessionRevokedV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.event_id, orig.event_id);
        assert_eq!(decoded.reason, orig.reason);
        assert_eq!(decoded.revoked_at_ms, orig.revoked_at_ms);
        assert_eq!(decoded.revocation_receipt_hash, orig.revocation_receipt_hash);
    }

    #[test]
    fn invocation_receipted_bin_roundtrip() {
        let orig = InvocationReceiptedV1 {
            event_id: [0x10; 16],
            session_id: [0x11; 16],
            capability: "retrieve".into(),
            channel: "bulk".into(),
            invocation_at_ms: 4_000_000,
            invocation_receipt_hash: [0x12; 32],
            parent_plan_receipt_hash: [0x13; 32],
        };
        let bytes = orig.encode_bin();
        let decoded = InvocationReceiptedV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.capability, "retrieve");
        assert_eq!(decoded.channel, "bulk");
        assert_eq!(decoded.invocation_at_ms, orig.invocation_at_ms);
        assert_eq!(decoded.invocation_receipt_hash, orig.invocation_receipt_hash);
        assert_eq!(decoded.parent_plan_receipt_hash, orig.parent_plan_receipt_hash);
    }

    #[test]
    fn dispatcher_decodes_session_events() {
        let sealed = sample_session_plan_sealed();
        let bytes = sealed.encode_bin();
        let parsed = parse_projection_event(EVT_SESSION_PLAN_SEALED_V1, CONTENT_TYPE_SESSION_BIN_V1, &bytes)
            .expect("parse")
            .expect("some");
        match parsed {
            ProjectionEventV1::SessionPlanSealed(s) => {
                assert_eq!(s.principal_id, sealed.principal_id);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn dispatcher_returns_none_for_unknown_event() {
        let parsed = parse_projection_event("corecrux.unknown.v1", "application/octet-stream", &[])
            .expect("parse");
        assert!(parsed.is_none());
    }

    // ---- CeInstallImportedV1 (M8) ----

    fn sample_ce_install_imported() -> CeInstallImportedV1 {
        CeInstallImportedV1 {
            event_id: [0x20; 16],
            origin_install: [0x21; 32],
            tenant_id: "cuecrux_ltd".into(),
            ce_principal_id: "ce:a4f3b1c2:myles".into(),
            core_principal_id: "tenant:cuecrux_ltd:myles".into(),
            imported_plan_hashes: vec![[0x30; 32], [0x31; 32], [0x32; 32]],
            imported_invocation_count: 42,
            imported_at_ms: 1_745_500_000_000,
            import_receipt_hash: [0x40; 32],
            import_receipt_signature: Some([0x50; 64]),
            signer_kid: Some("vault-transit://cuecrux-ce-import-signer-v1".into()),
        }
    }

    #[test]
    fn ce_install_imported_bin_roundtrip() {
        let orig = sample_ce_install_imported();
        let bytes = orig.encode_bin();
        let decoded = CeInstallImportedV1::decode_bin(&bytes).unwrap();
        assert_eq!(decoded.event_id, orig.event_id);
        assert_eq!(decoded.origin_install, orig.origin_install);
        assert_eq!(decoded.tenant_id, orig.tenant_id);
        assert_eq!(decoded.ce_principal_id, orig.ce_principal_id);
        assert_eq!(decoded.core_principal_id, orig.core_principal_id);
        assert_eq!(decoded.imported_plan_hashes, orig.imported_plan_hashes);
        assert_eq!(decoded.imported_invocation_count, orig.imported_invocation_count);
        assert_eq!(decoded.imported_at_ms, orig.imported_at_ms);
        assert_eq!(decoded.import_receipt_hash, orig.import_receipt_hash);
        assert_eq!(decoded.import_receipt_signature, orig.import_receipt_signature);
        assert_eq!(decoded.signer_kid, orig.signer_kid);
    }

    #[test]
    fn ce_install_imported_without_signature_roundtrip() {
        let orig = CeInstallImportedV1 {
            import_receipt_signature: None,
            signer_kid: None,
            imported_plan_hashes: vec![],
            imported_invocation_count: 0,
            ..sample_ce_install_imported()
        };
        let bytes = orig.encode_bin();
        let decoded = CeInstallImportedV1::decode_bin(&bytes).unwrap();
        assert!(decoded.import_receipt_signature.is_none());
        assert!(decoded.signer_kid.is_none());
        assert!(decoded.imported_plan_hashes.is_empty());
    }

    #[test]
    fn ce_install_imported_version_guard() {
        let mut bytes = sample_ce_install_imported().encode_bin();
        bytes[0] = 0xff;
        bytes[1] = 0xff;
        assert!(CeInstallImportedV1::decode_bin(&bytes).is_err());
    }

    #[test]
    fn ce_install_imported_compute_hash_stable_and_ignores_own_fields() {
        let a = sample_ce_install_imported();
        // Flipping `import_receipt_hash` must NOT affect compute_hash (zeroed).
        let mut b = a.clone();
        b.import_receipt_hash = [0xFF; 32];
        let mut c = a.clone();
        c.import_receipt_signature = None;
        c.signer_kid = None;
        assert_eq!(a.compute_hash(), b.compute_hash());
        assert_eq!(a.compute_hash(), c.compute_hash());

        // But flipping a content field DOES change the hash.
        let mut d = a.clone();
        d.imported_invocation_count = 99;
        assert_ne!(a.compute_hash(), d.compute_hash());
    }

    #[test]
    fn dispatcher_decodes_ce_install_imported_event() {
        let event = sample_ce_install_imported();
        let bytes = event.encode_bin();
        let parsed = parse_projection_event(
            EVT_CE_INSTALL_IMPORTED_V1,
            CONTENT_TYPE_SESSION_BIN_V1,
            &bytes,
        )
        .expect("parse")
        .expect("some");
        match parsed {
            ProjectionEventV1::CeInstallImported(s) => {
                assert_eq!(s.tenant_id, "cuecrux_ltd");
                assert_eq!(s.imported_plan_hashes.len(), 3);
            }
            _ => panic!("wrong variant"),
        }
    }
}
