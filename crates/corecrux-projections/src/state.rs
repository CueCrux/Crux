// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;
use xxhash_rust::xxh64::xxh64;

use crate::events::{DependentEvidenceUpsertV1, LivingStateUpdateV1, PressureEventUpsertV1};
use crate::events::{ProjectionEventV1, RelationDeleteV1, RelationUpsertV1};

pub fn tenant_hash_xxhash64(tenant_id: &str) -> u64 {
    xxh64(tenant_id.as_bytes(), 0)
}

pub fn pressure_code_id_xxhash16(code: &str) -> u16 {
    let h = xxh64(code.as_bytes(), 0);
    (h & 0xFFFF) as u16
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LivingStatusV1 {
    Dormant,
    Active,
    Stale,
    Contested,
    Superseded,
    Deprecated,
}

impl LivingStatusV1 {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Active,
            2 => Self::Stale,
            3 => Self::Contested,
            4 => Self::Superseded,
            5 => Self::Deprecated,
            _ => Self::Dormant,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Dormant => 0,
            Self::Active => 1,
            Self::Stale => 2,
            Self::Contested => 3,
            Self::Superseded => 4,
            Self::Deprecated => 5,
        }
    }

    pub fn from_engine_str(s: &str) -> Option<Self> {
        match s {
            "dormant" => Some(Self::Dormant),
            "active" => Some(Self::Active),
            "stale" => Some(Self::Stale),
            "contested" => Some(Self::Contested),
            "superseded" => Some(Self::Superseded),
            "deprecated" => Some(Self::Deprecated),
            _ => None,
        }
    }

    pub fn as_engine_str(&self) -> &'static str {
        match self {
            Self::Dormant => "dormant",
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Contested => "contested",
            Self::Superseded => "superseded",
            Self::Deprecated => "deprecated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationTypeV1 {
    Supports,
    Contradicts,
    Supersedes,
    Duplicates,
    Elaborates,
    DerivedFrom,
    Cites,
    AboutSameEntity,
}

impl RelationTypeV1 {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Supports),
            1 => Some(Self::Contradicts),
            2 => Some(Self::Supersedes),
            3 => Some(Self::Duplicates),
            4 => Some(Self::Elaborates),
            5 => Some(Self::DerivedFrom),
            6 => Some(Self::Cites),
            7 => Some(Self::AboutSameEntity),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Supports => 0,
            Self::Contradicts => 1,
            Self::Supersedes => 2,
            Self::Duplicates => 3,
            Self::Elaborates => 4,
            Self::DerivedFrom => 5,
            Self::Cites => 6,
            Self::AboutSameEntity => 7,
        }
    }

    pub fn from_engine_str(s: &str) -> Option<Self> {
        match s {
            "supports" => Some(Self::Supports),
            "contradicts" => Some(Self::Contradicts),
            "supersedes" => Some(Self::Supersedes),
            "duplicates" => Some(Self::Duplicates),
            "elaborates" => Some(Self::Elaborates),
            "derived_from" => Some(Self::DerivedFrom),
            "cites" => Some(Self::Cites),
            "about_same_entity" => Some(Self::AboutSameEntity),
            _ => None,
        }
    }

    pub fn as_engine_str(&self) -> &'static str {
        match self {
            Self::Supports => "supports",
            Self::Contradicts => "contradicts",
            Self::Supersedes => "supersedes",
            Self::Duplicates => "duplicates",
            Self::Elaborates => "elaborates",
            Self::DerivedFrom => "derived_from",
            Self::Cites => "cites",
            Self::AboutSameEntity => "about_same_entity",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependentTypeV1 {
    Answer,
    Mises,
    Collection,
    Artifact,
}

impl DependentTypeV1 {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Answer),
            1 => Some(Self::Mises),
            2 => Some(Self::Collection),
            3 => Some(Self::Artifact),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Answer => 0,
            Self::Mises => 1,
            Self::Collection => 2,
            Self::Artifact => 3,
        }
    }

    pub fn from_engine_str(s: &str) -> Option<Self> {
        match s {
            "answer" => Some(Self::Answer),
            "mises" => Some(Self::Mises),
            "collection" => Some(Self::Collection),
            "artifact" => Some(Self::Artifact),
            _ => None,
        }
    }

    pub fn as_engine_str(&self) -> &'static str {
        match self {
            Self::Answer => "answer",
            Self::Mises => "mises",
            Self::Collection => "collection",
            Self::Artifact => "artifact",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivingStateRowV1 {
    pub living_status: LivingStatusV1,
    pub confidence_q16: u16,
    pub last_validated_at_micros: i64,
    pub next_review_at_micros: i64,
    pub pressure_level: u8,         // derived
    pub pressure_reasons_mask: u32, // derived
    pub trunk_tier: u8,
    pub relations_out_count: i32, // derived
    pub relations_in_count: i32,  // derived
    pub dependents_count: i32,    // derived
    pub updated_at_micros: i64,
}

impl Default for LivingStateRowV1 {
    fn default() -> Self {
        Self {
            living_status: LivingStatusV1::Dormant,
            confidence_q16: 0,
            last_validated_at_micros: 0,
            next_review_at_micros: 0,
            pressure_level: 0,
            pressure_reasons_mask: 0,
            trunk_tier: 0,
            relations_out_count: 0,
            relations_in_count: 0,
            dependents_count: 0,
            updated_at_micros: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationEdgeV1 {
    pub confidence_q16: u16,
    pub evidence_ref_hash16: [u8; 16],
    pub created_at_micros: i64,
    pub updated_at_micros: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependentEdgeV1 {
    pub last_seen_at_micros: i64,
    pub usage_weight_q16: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PressureEventRowV1 {
    pub pressure_code_id: u16,
    pub severity: u8,
    pub observed_at_micros: i64,
    pub acknowledged_at_micros: i64,
    pub resolved_at_micros: i64,
    pub receipt_id: Option<Uuid>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ProjectionApplyStats {
    pub living_updates: u64,
    pub relation_upserts: u64,
    pub relation_deletes: u64,
    pub dependent_upserts: u64,
    pub pressure_upserts: u64,
    pub entity_facts: u64,
}

/// Phase 6: Entity count — tracks unique entity names per (tenant, type, predicate)
#[derive(Debug, Clone, Default)]
pub struct EntityCountRowV1 {
    pub items: BTreeSet<String>, // deduplicated entity names
    pub last_updated_micros: i64,
}

/// Phase 6: Entity timeline entry
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntityTimelineEntryV1 {
    pub occurred_at_micros: i64,
    pub entity_name: String,
    pub object_value: String,
}

/// Phase 6: Entity current state — latest value per (tenant, entity_name, predicate)
#[derive(Debug, Clone)]
pub struct EntityCurrentStateRowV1 {
    pub current_value: String,
    pub occurred_at_micros: i64,
    pub previous_value: Option<String>,
    pub previous_occurred_at_micros: i64,
}

#[derive(Default)]
pub struct ProjectionState {
    pub living: BTreeMap<(u64, u32), LivingStateRowV1>,
    pub relations: BTreeMap<(u64, u32, u32, u8), RelationEdgeV1>,
    pub dependents: BTreeMap<(u64, u32, u8, Uuid), DependentEdgeV1>,
    pub pressure: BTreeMap<(u64, u32, Uuid), PressureEventRowV1>,
    // Phase 6: Entity projections — keyed by (tenant_hash, entity_type_hash, predicate_hash)
    pub entity_counts: BTreeMap<(u64, u64, u64), EntityCountRowV1>,
    // Timeline: sorted set of events per (tenant, type, predicate)
    pub entity_timelines: BTreeMap<(u64, u64, u64), BTreeSet<EntityTimelineEntryV1>>,
    // Current state: keyed by (tenant_hash, entity_name_hash, predicate_hash)
    pub entity_current_state: BTreeMap<(u64, u64, u64), EntityCurrentStateRowV1>,
}

impl ProjectionState {
    pub fn apply(&mut self, tenant_hash: u64, ev: ProjectionEventV1) -> ProjectionApplyStats {
        let mut stats = ProjectionApplyStats::default();
        match ev {
            ProjectionEventV1::LivingStateUpdate(p) => {
                self.apply_living_update(tenant_hash, &p);
                stats.living_updates = 1;
            }
            ProjectionEventV1::RelationUpsert(p) => {
                self.apply_relation_upsert(tenant_hash, &p);
                stats.relation_upserts = 1;
            }
            ProjectionEventV1::RelationDelete(p) => {
                self.apply_relation_delete(tenant_hash, &p);
                stats.relation_deletes = 1;
            }
            ProjectionEventV1::PressureUpsert(p) => {
                self.apply_pressure_upsert(tenant_hash, &p);
                stats.pressure_upserts = 1;
            }
            ProjectionEventV1::DependentEvidenceUpsert(p) => {
                self.apply_dependent_upsert(tenant_hash, &p);
                stats.dependent_upserts = 1;
            }
            ProjectionEventV1::EntityFact(p) => {
                self.apply_entity_fact(tenant_hash, &p);
                stats.entity_facts = 1;
            }
        }
        stats
    }

    fn apply_entity_fact(&mut self, tenant_hash: u64, p: &crate::events::EntityFactV1) {
        let type_hash = xxh64(p.entity_type.as_bytes(), 0);
        let predicate_hash = xxh64(p.predicate.as_bytes(), 0);
        let name_hash = xxh64(p.entity_name.as_bytes(), 0);

        // Update count projection: add entity name to deduplicated set
        let count_key = (tenant_hash, type_hash, predicate_hash);
        let count_row = self.entity_counts.entry(count_key).or_default();
        count_row.items.insert(p.entity_name.clone());
        count_row.last_updated_micros = p.occurred_at_micros;

        // Update timeline projection: add event sorted by time
        if p.occurred_at_micros > 0 {
            let tl_key = (tenant_hash, type_hash, predicate_hash);
            let timeline = self.entity_timelines.entry(tl_key).or_default();
            timeline.insert(EntityTimelineEntryV1 {
                occurred_at_micros: p.occurred_at_micros,
                entity_name: p.entity_name.clone(),
                object_value: p.object_value.clone(),
            });
        }

        // Update current state projection: latest value wins
        let state_key = (tenant_hash, name_hash, predicate_hash);
        let existing = self.entity_current_state.get(&state_key);
        let should_update = match existing {
            None => true,
            Some(row) => p.occurred_at_micros >= row.occurred_at_micros,
        };
        if should_update {
            let prev = self
                .entity_current_state
                .get(&state_key)
                .map(|r| (r.current_value.clone(), r.occurred_at_micros));
            self.entity_current_state.insert(
                state_key,
                EntityCurrentStateRowV1 {
                    current_value: p.object_value.clone(),
                    occurred_at_micros: p.occurred_at_micros,
                    previous_value: prev.as_ref().map(|(v, _)| v.clone()),
                    previous_occurred_at_micros: prev.map_or(0, |(_, t)| t),
                },
            );
        }
    }

    fn ensure_living_row(&mut self, tenant_hash: u64, artifact_id: u32) -> &mut LivingStateRowV1 {
        self.living.entry((tenant_hash, artifact_id)).or_default()
    }

    fn apply_living_update(&mut self, tenant_hash: u64, p: &LivingStateUpdateV1) {
        let row = self.ensure_living_row(tenant_hash, p.artifact_id);
        let mask = p.fields_mask;
        if (mask & LivingStateUpdateV1::MASK_LIVING_STATUS) != 0 {
            row.living_status = LivingStatusV1::from_u8(p.living_status);
        }
        if (mask & LivingStateUpdateV1::MASK_CONFIDENCE) != 0 {
            row.confidence_q16 = p.confidence_q16;
        }
        if (mask & LivingStateUpdateV1::MASK_LAST_VALIDATED_AT) != 0 {
            row.last_validated_at_micros = p.last_validated_at_micros;
        }
        if (mask & LivingStateUpdateV1::MASK_NEXT_REVIEW_AT) != 0 {
            row.next_review_at_micros = p.next_review_at_micros;
        }
        if (mask & LivingStateUpdateV1::MASK_TRUNK_TIER) != 0 {
            row.trunk_tier = p.trunk_tier;
        }
        if (mask & LivingStateUpdateV1::MASK_UPDATED_AT) != 0 {
            row.updated_at_micros = p.updated_at_micros;
        }
    }

    fn apply_relation_upsert(&mut self, tenant_hash: u64, p: &RelationUpsertV1) {
        let key = (tenant_hash, p.src_artifact_id, p.dst_artifact_id, p.relation_type);
        let _ = self.ensure_living_row(tenant_hash, p.src_artifact_id);
        let _ = self.ensure_living_row(tenant_hash, p.dst_artifact_id);
        self.relations.insert(
            key,
            RelationEdgeV1 {
                confidence_q16: p.confidence_q16,
                evidence_ref_hash16: p.evidence_ref_hash16,
                created_at_micros: p.created_at_micros,
                updated_at_micros: p.updated_at_micros,
            },
        );
    }

    fn apply_relation_delete(&mut self, tenant_hash: u64, p: &RelationDeleteV1) {
        let key = (tenant_hash, p.src_artifact_id, p.dst_artifact_id, p.relation_type);
        self.relations.remove(&key);
    }

    fn apply_dependent_upsert(&mut self, tenant_hash: u64, p: &DependentEvidenceUpsertV1) {
        let key = (tenant_hash, p.artifact_id, p.dependent_type, p.dependent_id);
        let _ = self.ensure_living_row(tenant_hash, p.artifact_id);

        self.dependents
            .entry(key)
            .and_modify(|e| {
                e.last_seen_at_micros = e.last_seen_at_micros.max(p.last_seen_at_micros);
                e.usage_weight_q16 = e.usage_weight_q16.max(p.usage_weight_q16);
            })
            .or_insert_with(|| DependentEdgeV1 {
                last_seen_at_micros: p.last_seen_at_micros,
                usage_weight_q16: p.usage_weight_q16,
            });
    }

    fn apply_pressure_upsert(&mut self, tenant_hash: u64, p: &PressureEventUpsertV1) {
        let key = (tenant_hash, p.artifact_id, p.pressure_event_id);
        let _ = self.ensure_living_row(tenant_hash, p.artifact_id);
        self.pressure.insert(
            key,
            PressureEventRowV1 {
                pressure_code_id: p.pressure_code_id,
                severity: p.severity,
                observed_at_micros: p.observed_at_micros,
                acknowledged_at_micros: p.acknowledged_at_micros,
                resolved_at_micros: p.resolved_at_micros,
                receipt_id: p.receipt_id,
            },
        );
    }

    /// Recompute derived count fields and pressure summary deterministically from the other
    /// projection tables.
    pub fn recompute_derived_fields(&mut self) {
        let mut rel_out: BTreeMap<(u64, u32), i32> = BTreeMap::new();
        let mut rel_in: BTreeMap<(u64, u32), i32> = BTreeMap::new();

        for (tenant_hash, src, dst, _rt) in self.relations.keys() {
            *rel_out.entry((*tenant_hash, *src)).or_default() += 1;
            *rel_in.entry((*tenant_hash, *dst)).or_default() += 1;
        }

        let mut deps: BTreeMap<(u64, u32), i32> = BTreeMap::new();
        for (tenant_hash, artifact_id, _dt, _did) in self.dependents.keys() {
            *deps.entry((*tenant_hash, *artifact_id)).or_default() += 1;
        }

        let mut pressure_by_artifact: BTreeMap<(u64, u32), (u8, u32)> = BTreeMap::new();
        for (k, ev) in &self.pressure {
            let (tenant_hash, artifact_id, _eid) = k;
            if ev.resolved_at_micros != 0 {
                continue;
            }
            let cur = pressure_by_artifact
                .entry((*tenant_hash, *artifact_id))
                .or_insert((0, 0));

            let lvl = severity_to_level(ev.severity);
            cur.0 = cur.0.max(lvl);
            cur.1 |= pressure_code_id_to_mask(ev.pressure_code_id);
        }

        // Determine the full set of artifact keys to update (living is sparse, but counts should be
        // consistent for any present rows).
        let mut touched: BTreeSet<(u64, u32)> = BTreeSet::new();
        touched.extend(self.living.keys().copied());
        touched.extend(rel_out.keys().copied());
        touched.extend(rel_in.keys().copied());
        touched.extend(deps.keys().copied());
        touched.extend(pressure_by_artifact.keys().copied());

        for key in touched {
            let row = self.living.entry(key).or_default();
            row.relations_out_count = *rel_out.get(&key).unwrap_or(&0);
            row.relations_in_count = *rel_in.get(&key).unwrap_or(&0);
            row.dependents_count = *deps.get(&key).unwrap_or(&0);
            if let Some((lvl, mask)) = pressure_by_artifact.get(&key) {
                row.pressure_level = *lvl;
                row.pressure_reasons_mask = *mask;
            } else {
                row.pressure_level = 0;
                row.pressure_reasons_mask = 0;
            }
        }
    }
}

pub fn quantize_confidence_q16(conf: f32) -> u16 {
    let c = conf.clamp(0.0, 1.0);
    (c * 65535.0).round() as u16
}

pub fn dequantize_confidence_f32(q16: u16) -> f32 {
    (q16 as f32) / 65535.0
}

fn severity_to_level(sev: u8) -> u8 {
    match sev {
        0 => 0,
        1 | 2 => 1,
        3 => 2,
        _ => 3, // 4-5 => 3
    }
}

fn pressure_code_id_to_mask(code_id: u16) -> u32 {
    1u32 << ((code_id as u32) & 31)
}
