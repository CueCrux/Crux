// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `SessionPlan` type family.
//!
//! Schema lives in master-plan §3. Field order here matches the plan's
//! textual definition for readability; on-the-wire order is fixed by the
//! canonical encoder (sorted map keys), not by struct layout.

use crate::canonical::CborValue;
use crate::error::SessionError;

pub const SESSION_PLAN_VERSION: u64 = 1;
pub const INVOCATION_RECEIPT_VERSION: u64 = 1;
pub const CAPABILITY_GRAPH_VERSION: u64 = 1;

pub const HASH_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const ULID_LEN: usize = 16;

/// Receipt mode. `"local"` = BLAKE3 only. `"verified"` = BLAKE3 + ed25519
/// (hosted). `"audit"` = reserved for future audit-grade signing policy.
#[derive(Debug, Clone, PartialEq, Eq)]

pub enum ReceiptMode {
    Local,
    Verified,
    Audit,
}

impl ReceiptMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Verified => "verified",
            Self::Audit => "audit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passport {
    pub principal_id: String,
    pub tier: String,
    pub affinities: Vec<String>,
    pub denied_capabilities: Option<Vec<String>>,
    pub grant_expansions: Option<Vec<String>>,
    /// BLAKE3 of the source passport record; hosted only. None on Crux Daemon.
    pub passport_receipt: Option<[u8; HASH_LEN]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelDeclaration {
    pub declared: Option<String>,
    pub declared_family: Option<String>,
    pub declared_size: Option<String>,
    pub auth_bound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Channels {
    /// h2:// URL for the Layer 2 bulk channel. May be absent before Layer 2 ships.
    pub bulk: Option<String>,
    /// Always present; fallback MCP URL.
    pub mcp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    pub tokens_cap: Option<u64>,
    pub crux_cap: Option<u64>,
    pub ttl_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImplPath {
    pub ce: Option<String>,
    pub core: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaRef {
    pub kind: String,
    pub uri: String,
    pub hash: [u8; HASH_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostEstimate {
    pub p50_crux: Option<u64>,
    pub p95_crux: Option<u64>,
    pub estimation_method: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationRef {
    pub issuer: String,
    pub typ: String,
    pub hash: [u8; HASH_LEN],
    pub uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitHints {
    pub calls_per_minute: Option<u64>,
    pub tokens_per_minute: Option<u64>,
    pub bursts_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcurrencyHints {
    pub max_parallel: Option<u64>,
    pub rate_limit: Option<RateLimitHints>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelPolicy {
    pub min_family: Option<Vec<String>>,
    pub min_size: Option<String>,
    pub deny_models: Option<Vec<String>>,
    pub auth_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityTokenRef {
    pub token_id: String,
    pub issued_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub cap: String,
    pub category: String,
    /// "bulk" | "mcp"
    pub prefer: String,
    /// Payload shape, e.g. `stream<Chunk>`, `Receipt`, `Snapshot`.
    pub shape: String,
    pub input_schema: Option<SchemaRef>,
    pub output_schema: Option<SchemaRef>,
    pub min_tier: Option<String>,
    pub required_affinity: Option<String>,
    /// "free" | "metered" | "heavy"
    pub cost_class: String,
    pub cost_estimate: Option<CostEstimate>,
    pub stability: String,
    pub since: Option<String>,
    pub sunset_at: Option<u64>,
    pub model_policy: Option<ModelPolicy>,
    pub attestations: Vec<AttestationRef>,
    pub concurrency: Option<ConcurrencyHints>,
    pub impl_path: ImplPath,
    pub token_ref: Option<CapabilityTokenRef>,
}

impl Capability {
    pub fn category_for(min_tier: Option<&str>, required_affinity: Option<&str>) -> String {
        if required_affinity.is_some() {
            "affinity_required".to_string()
        } else if min_tier.is_some() {
            "tier_gated".to_string()
        } else {
            "public".to_string()
        }
    }

    pub fn legacy(
        cap: impl Into<String>,
        prefer: impl Into<String>,
        shape: impl Into<String>,
        min_tier: Option<String>,
        cost_class: impl Into<String>,
        impl_path: ImplPath,
    ) -> Self {
        Self::v2(cap, prefer, shape, min_tier, None, cost_class, impl_path)
    }

    pub fn v2(
        cap: impl Into<String>,
        prefer: impl Into<String>,
        shape: impl Into<String>,
        min_tier: Option<String>,
        required_affinity: Option<String>,
        cost_class: impl Into<String>,
        impl_path: ImplPath,
    ) -> Self {
        let category = Self::category_for(min_tier.as_deref(), required_affinity.as_deref());
        Self {
            cap: cap.into(),
            category,
            prefer: prefer.into(),
            shape: shape.into(),
            input_schema: None,
            output_schema: None,
            min_tier,
            required_affinity,
            cost_class: cost_class.into(),
            cost_estimate: None,
            stability: "stable".to_string(),
            since: Some("1.0.0".to_string()),
            sunset_at: None,
            model_policy: None,
            attestations: Vec::new(),
            concurrency: None,
            impl_path,
            token_ref: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub weight: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exclusion {
    pub cap: String,
    pub reason: String,
    pub layer: String,
    pub hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptEnvelope {
    pub mode: ReceiptMode,
    /// 32-byte BLAKE3 of the canonical plan bytes with this field, `signature`,
    /// and `signer_kid` zeroed.
    pub hash: [u8; HASH_LEN],
    pub signature: Option<[u8; SIGNATURE_LEN]>,
    pub signer_kid: Option<String>,
    pub parent_chain: Option<Vec<[u8; HASH_LEN]>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPlan {
    pub plan_id: [u8; ULID_LEN],
    pub plan_version: u64,
    pub minted_at: u64,

    /// "ce" | "core"
    pub origin: String,
    /// BLAKE3(install_uuid), required iff `origin == "ce"`.
    pub origin_install: Option<[u8; HASH_LEN]>,

    pub session_id: [u8; ULID_LEN],
    pub session_ttl_s: u64,

    pub passport: Passport,
    pub model: Option<ModelDeclaration>,
    pub channels: Channels,

    pub capability_graph: Vec<Capability>,
    pub capability_graph_edges: Vec<Edge>,
    pub capability_graph_excluded: Option<Vec<Exclusion>>,
    pub capability_graph_version: u64,
    pub capability_graph_valid_until: u64,
    pub capability_graph_refresh_hint: Option<String>,
    pub capability_graph_hash: [u8; HASH_LEN],

    pub budget: Budget,
    pub receipt: ReceiptEnvelope,

    /// Optional intent hint. Observable in the plan receipt via the
    /// capability-graph-hash input (master-plan §4.4).
    pub intent_hint: Option<String>,
}

impl SessionPlan {
    /// Build the canonical-CBOR `CborValue` tree for this plan. The caller
    /// decides whether the receipt is zeroed (for hashing) or populated (for
    /// on-the-wire transport) via `zero_receipt`.
    pub fn to_cbor_value(&self, zero_receipt: bool) -> CborValue {
        let mut pairs = Vec::with_capacity(16);
        pairs.push(("plan_id".into(), CborValue::Bytes(self.plan_id.to_vec())));
        pairs.push(("plan_version".into(), CborValue::Uint(self.plan_version)));
        pairs.push(("minted_at".into(), CborValue::Uint(self.minted_at)));
        pairs.push(("origin".into(), CborValue::Text(self.origin.clone())));
        pairs.push((
            "origin_install".into(),
            match &self.origin_install {
                Some(b) => CborValue::Bytes(b.to_vec()),
                None => CborValue::Null,
            },
        ));
        pairs.push(("session_id".into(), CborValue::Bytes(self.session_id.to_vec())));
        pairs.push(("session_ttl_s".into(), CborValue::Uint(self.session_ttl_s)));
        pairs.push(("passport".into(), passport_to_cbor(&self.passport)));
        pairs.push((
            "model".into(),
            match &self.model {
                Some(model) => model_to_cbor(model),
                None => CborValue::Null,
            },
        ));
        pairs.push(("channels".into(), channels_to_cbor(&self.channels)));
        pairs.push(("capability_graph".into(), capability_graph_to_cbor(self)));
        pairs.push((
            "capability_graph_hash".into(),
            CborValue::Bytes(self.capability_graph_hash.to_vec()),
        ));
        pairs.push(("budget".into(), budget_to_cbor(&self.budget)));
        pairs.push(("receipt".into(), receipt_to_cbor(&self.receipt, zero_receipt)));
        pairs.push((
            "intent_hint".into(),
            match &self.intent_hint {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            },
        ));
        CborValue::Map(pairs)
    }

    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.to_cbor_value(false).encode()
    }

    /// Canonical CBOR with the receipt hash+signature+signer_kid zeroed
    /// (master-plan §3.3). This is the input to the plan-receipt hash.
    pub fn to_zeroed_canonical_cbor(&self) -> Vec<u8> {
        self.to_cbor_value(true).encode()
    }

    pub fn to_canonical_json(&self) -> String {
        crate::canonical::to_canonical_json(&self.to_cbor_value(false))
    }

    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SessionError> {
        let value = crate::canonical::decode(bytes)?;
        Self::from_cbor_value(&value)
    }

    pub fn from_cbor_value(value: &CborValue) -> Result<Self, SessionError> {
        let map = as_map(value, "SessionPlan")?;

        Ok(Self {
            plan_id: take_bytes_fixed(map, "plan_id")?,
            plan_version: take_uint(map, "plan_version")?,
            minted_at: take_uint(map, "minted_at")?,
            origin: take_text(map, "origin")?,
            origin_install: take_bytes_fixed_opt(map, "origin_install")?,
            session_id: take_bytes_fixed(map, "session_id")?,
            session_ttl_s: take_uint(map, "session_ttl_s")?,
            passport: passport_from_cbor(get(map, "passport")?)?,
            model: model_from_cbor(find(map, "model").unwrap_or(&CborValue::Null))?,
            channels: channels_from_cbor(get(map, "channels")?)?,
            capability_graph: capability_nodes_from_cbor(get(map, "capability_graph")?)?,
            capability_graph_edges: capability_edges_from_cbor(get(map, "capability_graph")?)?,
            capability_graph_excluded: capability_excluded_from_cbor(get(map, "capability_graph")?)?,
            capability_graph_version: capability_graph_version_from_cbor(get(map, "capability_graph")?)?,
            capability_graph_valid_until: capability_graph_valid_until_from_cbor(
                get(map, "capability_graph")?,
                take_uint(map, "minted_at")?,
                take_uint(map, "session_ttl_s")?,
            )?,
            capability_graph_refresh_hint: capability_graph_refresh_hint_from_cbor(get(map, "capability_graph")?)?,
            capability_graph_hash: take_bytes_fixed(map, "capability_graph_hash")?,
            budget: budget_from_cbor(get(map, "budget")?)?,
            receipt: receipt_from_cbor(get(map, "receipt")?)?,
            intent_hint: take_text_opt(map, "intent_hint")?,
        })
    }
}

// ─── encoders ──────────────────────────────────────────────────────────────

fn passport_to_cbor(p: &Passport) -> CborValue {
    CborValue::Map(vec![
        ("principal_id".into(), CborValue::Text(p.principal_id.clone())),
        ("tier".into(), CborValue::Text(p.tier.clone())),
        (
            "affinities".into(),
            CborValue::Array(p.affinities.iter().map(|s| CborValue::Text(s.clone())).collect()),
        ),
        (
            "denied_capabilities".into(),
            text_array_opt_to_cbor(p.denied_capabilities.as_ref()),
        ),
        (
            "grant_expansions".into(),
            text_array_opt_to_cbor(p.grant_expansions.as_ref()),
        ),
        (
            "passport_receipt".into(),
            match &p.passport_receipt {
                Some(b) => CborValue::Bytes(b.to_vec()),
                None => CborValue::Null,
            },
        ),
    ])
}

fn model_to_cbor(model: &ModelDeclaration) -> CborValue {
    CborValue::Map(vec![
        ("declared".into(), text_opt_to_cbor(model.declared.as_deref())),
        (
            "declared_family".into(),
            text_opt_to_cbor(model.declared_family.as_deref()),
        ),
        ("declared_size".into(), text_opt_to_cbor(model.declared_size.as_deref())),
        ("auth_bound".into(), CborValue::Bool(model.auth_bound)),
    ])
}

fn channels_to_cbor(c: &Channels) -> CborValue {
    CborValue::Map(vec![
        (
            "bulk".into(),
            match &c.bulk {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            },
        ),
        ("mcp".into(), CborValue::Text(c.mcp.clone())),
    ])
}

fn budget_to_cbor(b: &Budget) -> CborValue {
    CborValue::Map(vec![
        (
            "tokens_cap".into(),
            match b.tokens_cap {
                Some(n) => CborValue::Uint(n),
                None => CborValue::Null,
            },
        ),
        (
            "crux_cap".into(),
            match b.crux_cap {
                Some(n) => CborValue::Uint(n),
                None => CborValue::Null,
            },
        ),
        ("ttl_s".into(), CborValue::Uint(b.ttl_s)),
    ])
}

fn capability_to_cbor(c: &Capability) -> CborValue {
    let mut pairs = vec![
        ("cap".into(), CborValue::Text(c.cap.clone())),
        ("category".into(), CborValue::Text(c.category.clone())),
        ("prefer".into(), CborValue::Text(c.prefer.clone())),
        ("shape".into(), CborValue::Text(c.shape.clone())),
        ("input_schema".into(), schema_ref_opt_to_cbor(c.input_schema.as_ref())),
        ("output_schema".into(), schema_ref_opt_to_cbor(c.output_schema.as_ref())),
        (
            "min_tier".into(),
            match &c.min_tier {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            },
        ),
        (
            "required_affinity".into(),
            text_opt_to_cbor(c.required_affinity.as_deref()),
        ),
        ("cost_class".into(), CborValue::Text(c.cost_class.clone())),
        (
            "cost_estimate".into(),
            cost_estimate_opt_to_cbor(c.cost_estimate.as_ref()),
        ),
        ("stability".into(), CborValue::Text(c.stability.clone())),
        ("since".into(), text_opt_to_cbor(c.since.as_deref())),
        ("sunset_at".into(), uint_opt_to_cbor(c.sunset_at)),
        ("model_policy".into(), model_policy_opt_to_cbor(c.model_policy.as_ref())),
        (
            "attestations".into(),
            CborValue::Array(c.attestations.iter().map(attestation_to_cbor).collect()),
        ),
        ("concurrency".into(), concurrency_opt_to_cbor(c.concurrency.as_ref())),
        (
            "impl_path".into(),
            CborValue::Map(vec![
                (
                    "ce".into(),
                    match &c.impl_path.ce {
                        Some(s) => CborValue::Text(s.clone()),
                        None => CborValue::Null,
                    },
                ),
                (
                    "core".into(),
                    match &c.impl_path.core {
                        Some(s) => CborValue::Text(s.clone()),
                        None => CborValue::Null,
                    },
                ),
            ]),
        ),
    ];
    if let Some(token_ref) = &c.token_ref {
        pairs.push(("token_ref".into(), token_ref_to_cbor(token_ref)));
    }
    CborValue::Map(pairs)
}

fn capability_graph_to_cbor(plan: &SessionPlan) -> CborValue {
    CborValue::Map(vec![
        (
            "nodes".into(),
            CborValue::Array(plan.capability_graph.iter().map(capability_to_cbor).collect()),
        ),
        (
            "edges".into(),
            CborValue::Array(plan.capability_graph_edges.iter().map(edge_to_cbor).collect()),
        ),
        (
            "excluded".into(),
            match &plan.capability_graph_excluded {
                Some(items) => CborValue::Array(items.iter().map(exclusion_to_cbor).collect()),
                None => CborValue::Null,
            },
        ),
        ("intent_hint".into(), text_opt_to_cbor(plan.intent_hint.as_deref())),
        ("version".into(), CborValue::Uint(plan.capability_graph_version)),
        ("valid_until".into(), CborValue::Uint(plan.capability_graph_valid_until)),
        (
            "refresh_hint".into(),
            text_opt_to_cbor(plan.capability_graph_refresh_hint.as_deref()),
        ),
    ])
}

fn edge_to_cbor(edge: &Edge) -> CborValue {
    CborValue::Map(vec![
        ("from".into(), CborValue::Text(edge.from.clone())),
        ("to".into(), CborValue::Text(edge.to.clone())),
        ("kind".into(), CborValue::Text(edge.kind.clone())),
        ("weight".into(), uint_opt_to_cbor(edge.weight)),
    ])
}

fn exclusion_to_cbor(exclusion: &Exclusion) -> CborValue {
    CborValue::Map(vec![
        ("cap".into(), CborValue::Text(exclusion.cap.clone())),
        ("reason".into(), CborValue::Text(exclusion.reason.clone())),
        ("layer".into(), CborValue::Text(exclusion.layer.clone())),
        ("hint".into(), text_opt_to_cbor(exclusion.hint.as_deref())),
    ])
}

fn schema_ref_opt_to_cbor(schema: Option<&SchemaRef>) -> CborValue {
    match schema {
        Some(schema) => CborValue::Map(vec![
            ("kind".into(), CborValue::Text(schema.kind.clone())),
            ("uri".into(), CborValue::Text(schema.uri.clone())),
            ("hash".into(), CborValue::Bytes(schema.hash.to_vec())),
        ]),
        None => CborValue::Null,
    }
}

fn cost_estimate_opt_to_cbor(cost: Option<&CostEstimate>) -> CborValue {
    match cost {
        Some(cost) => CborValue::Map(vec![
            ("p50_crux".into(), uint_opt_to_cbor(cost.p50_crux)),
            ("p95_crux".into(), uint_opt_to_cbor(cost.p95_crux)),
            (
                "estimation_method".into(),
                CborValue::Text(cost.estimation_method.clone()),
            ),
        ]),
        None => CborValue::Null,
    }
}

fn model_policy_opt_to_cbor(policy: Option<&ModelPolicy>) -> CborValue {
    match policy {
        Some(policy) => CborValue::Map(vec![
            ("min_family".into(), text_array_opt_to_cbor(policy.min_family.as_ref())),
            ("min_size".into(), text_opt_to_cbor(policy.min_size.as_deref())),
            (
                "deny_models".into(),
                text_array_opt_to_cbor(policy.deny_models.as_ref()),
            ),
            ("auth_required".into(), CborValue::Bool(policy.auth_required)),
        ]),
        None => CborValue::Null,
    }
}

fn attestation_to_cbor(attestation: &AttestationRef) -> CborValue {
    CborValue::Map(vec![
        ("issuer".into(), CborValue::Text(attestation.issuer.clone())),
        ("type".into(), CborValue::Text(attestation.typ.clone())),
        ("hash".into(), CborValue::Bytes(attestation.hash.to_vec())),
        ("uri".into(), text_opt_to_cbor(attestation.uri.as_deref())),
    ])
}

fn concurrency_opt_to_cbor(concurrency: Option<&ConcurrencyHints>) -> CborValue {
    match concurrency {
        Some(concurrency) => CborValue::Map(vec![
            ("max_parallel".into(), uint_opt_to_cbor(concurrency.max_parallel)),
            (
                "rate_limit".into(),
                rate_limit_opt_to_cbor(concurrency.rate_limit.as_ref()),
            ),
        ]),
        None => CborValue::Null,
    }
}

fn rate_limit_opt_to_cbor(rate_limit: Option<&RateLimitHints>) -> CborValue {
    match rate_limit {
        Some(rate_limit) => CborValue::Map(vec![
            ("calls_per_minute".into(), uint_opt_to_cbor(rate_limit.calls_per_minute)),
            (
                "tokens_per_minute".into(),
                uint_opt_to_cbor(rate_limit.tokens_per_minute),
            ),
            ("bursts_allowed".into(), CborValue::Bool(rate_limit.bursts_allowed)),
        ]),
        None => CborValue::Null,
    }
}

fn token_ref_to_cbor(token_ref: &CapabilityTokenRef) -> CborValue {
    CborValue::Map(vec![
        ("token_id".into(), CborValue::Text(token_ref.token_id.clone())),
        ("issued_at".into(), CborValue::Uint(token_ref.issued_at)),
    ])
}

fn text_opt_to_cbor(value: Option<&str>) -> CborValue {
    match value {
        Some(value) => CborValue::Text(value.to_string()),
        None => CborValue::Null,
    }
}

fn uint_opt_to_cbor(value: Option<u64>) -> CborValue {
    match value {
        Some(value) => CborValue::Uint(value),
        None => CborValue::Null,
    }
}

fn text_array_opt_to_cbor(values: Option<&Vec<String>>) -> CborValue {
    match values {
        Some(values) => CborValue::Array(values.iter().map(|s| CborValue::Text(s.clone())).collect()),
        None => CborValue::Null,
    }
}

fn receipt_to_cbor(r: &ReceiptEnvelope, zero: bool) -> CborValue {
    let hash = if zero { vec![0u8; HASH_LEN] } else { r.hash.to_vec() };
    let signature = if zero {
        CborValue::Null
    } else {
        match &r.signature {
            Some(s) => CborValue::Bytes(s.to_vec()),
            None => CborValue::Null,
        }
    };
    let signer_kid = if zero {
        CborValue::Null
    } else {
        match &r.signer_kid {
            Some(s) => CborValue::Text(s.clone()),
            None => CborValue::Null,
        }
    };
    let parent_chain = match &r.parent_chain {
        Some(list) => CborValue::Array(list.iter().map(|h| CborValue::Bytes(h.to_vec())).collect()),
        None => CborValue::Null,
    };
    CborValue::Map(vec![
        ("mode".into(), CborValue::Text(r.mode.as_str().to_string())),
        ("hash".into(), CborValue::Bytes(hash)),
        ("signature".into(), signature),
        ("signer_kid".into(), signer_kid),
        ("parent_chain".into(), parent_chain),
    ])
}

// ─── decoders ──────────────────────────────────────────────────────────────

fn passport_from_cbor(v: &CborValue) -> Result<Passport, SessionError> {
    let map = as_map(v, "passport")?;
    Ok(Passport {
        principal_id: take_text(map, "principal_id")?,
        tier: take_text(map, "tier")?,
        affinities: take_text_array(map, "affinities")?,
        denied_capabilities: take_text_array_opt(map, "denied_capabilities")?,
        grant_expansions: take_text_array_opt(map, "grant_expansions")?,
        passport_receipt: take_bytes_fixed_opt(map, "passport_receipt")?,
    })
}

fn model_from_cbor(v: &CborValue) -> Result<Option<ModelDeclaration>, SessionError> {
    if matches!(v, CborValue::Null) {
        return Ok(None);
    }
    let map = as_map(v, "model")?;
    Ok(Some(ModelDeclaration {
        declared: take_text_opt(map, "declared")?,
        declared_family: take_text_opt(map, "declared_family")?,
        declared_size: take_text_opt(map, "declared_size")?,
        auth_bound: take_bool(map, "auth_bound")?,
    }))
}

fn channels_from_cbor(v: &CborValue) -> Result<Channels, SessionError> {
    let map = as_map(v, "channels")?;
    Ok(Channels {
        bulk: take_text_opt(map, "bulk")?,
        mcp: take_text(map, "mcp")?,
    })
}

fn budget_from_cbor(v: &CborValue) -> Result<Budget, SessionError> {
    let map = as_map(v, "budget")?;
    Ok(Budget {
        tokens_cap: take_uint_opt(map, "tokens_cap")?,
        crux_cap: take_uint_opt(map, "crux_cap")?,
        ttl_s: take_uint(map, "ttl_s")?,
    })
}

fn capability_nodes_from_cbor(v: &CborValue) -> Result<Vec<Capability>, SessionError> {
    match v {
        CborValue::Array(items) => items.iter().map(capability_from_legacy_cbor).collect(),
        CborValue::Map(pairs) => {
            let CborValue::Array(items) = get(pairs, "nodes")? else {
                return Err(SessionError::Decode("capability_graph.nodes not array".to_string()));
            };
            items.iter().map(capability_from_cbor).collect()
        }
        _ => Err(SessionError::Decode("capability_graph not array or map".to_string())),
    }
}

fn capability_edges_from_cbor(v: &CborValue) -> Result<Vec<Edge>, SessionError> {
    let CborValue::Map(pairs) = v else {
        return Ok(Vec::new());
    };
    let CborValue::Array(items) = get(pairs, "edges")? else {
        return Err(SessionError::Decode("capability_graph.edges not array".to_string()));
    };
    items.iter().map(edge_from_cbor).collect()
}

fn capability_excluded_from_cbor(v: &CborValue) -> Result<Option<Vec<Exclusion>>, SessionError> {
    let CborValue::Map(pairs) = v else {
        return Ok(None);
    };
    match get(pairs, "excluded")? {
        CborValue::Null => Ok(None),
        CborValue::Array(items) => items
            .iter()
            .map(exclusion_from_cbor)
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err(SessionError::Decode(
            "capability_graph.excluded not array or null".to_string(),
        )),
    }
}

fn capability_graph_version_from_cbor(v: &CborValue) -> Result<u64, SessionError> {
    let CborValue::Map(pairs) = v else {
        return Ok(CAPABILITY_GRAPH_VERSION);
    };
    take_uint(pairs, "version")
}

fn capability_graph_valid_until_from_cbor(v: &CborValue, minted_at: u64, ttl_s: u64) -> Result<u64, SessionError> {
    let CborValue::Map(pairs) = v else {
        return Ok(minted_at.saturating_add(ttl_s.saturating_mul(1000)));
    };
    take_uint(pairs, "valid_until")
}

fn capability_graph_refresh_hint_from_cbor(v: &CborValue) -> Result<Option<String>, SessionError> {
    let CborValue::Map(pairs) = v else {
        return Ok(None);
    };
    take_text_opt(pairs, "refresh_hint")
}

fn capability_from_cbor(v: &CborValue) -> Result<Capability, SessionError> {
    let map = as_map(v, "Capability")?;
    let impl_path_map = as_map(get(map, "impl_path")?, "impl_path")?;
    Ok(Capability {
        cap: take_text(map, "cap")?,
        category: take_text(map, "category")?,
        prefer: take_text(map, "prefer")?,
        shape: take_text(map, "shape")?,
        input_schema: schema_ref_from_cbor(get(map, "input_schema")?)?,
        output_schema: schema_ref_from_cbor(get(map, "output_schema")?)?,
        min_tier: take_text_opt(map, "min_tier")?,
        required_affinity: take_text_opt(map, "required_affinity")?,
        cost_class: take_text(map, "cost_class")?,
        cost_estimate: cost_estimate_from_cbor(get(map, "cost_estimate")?)?,
        stability: take_text(map, "stability")?,
        since: take_text_opt(map, "since")?,
        sunset_at: take_uint_opt(map, "sunset_at")?,
        model_policy: model_policy_from_cbor(get(map, "model_policy")?)?,
        attestations: attestations_from_cbor(get(map, "attestations")?)?,
        concurrency: concurrency_from_cbor(get(map, "concurrency")?)?,
        impl_path: ImplPath {
            ce: take_text_opt(impl_path_map, "ce")?,
            core: take_text_opt(impl_path_map, "core")?,
        },
        token_ref: match find(map, "token_ref") {
            Some(v) => token_ref_from_cbor(v)?,
            None => None,
        },
    })
}

fn capability_from_legacy_cbor(v: &CborValue) -> Result<Capability, SessionError> {
    let map = as_map(v, "Capability")?;
    let impl_path_map = as_map(get(map, "impl_path")?, "impl_path")?;
    let min_tier = take_text_opt(map, "min_tier")?;
    Ok(Capability::legacy(
        take_text(map, "cap")?,
        take_text(map, "prefer")?,
        take_text(map, "shape")?,
        min_tier,
        take_text(map, "cost_class")?,
        ImplPath {
            ce: take_text_opt(impl_path_map, "ce")?,
            core: take_text_opt(impl_path_map, "core")?,
        },
    ))
}

fn edge_from_cbor(v: &CborValue) -> Result<Edge, SessionError> {
    let map = as_map(v, "Edge")?;
    Ok(Edge {
        from: take_text(map, "from")?,
        to: take_text(map, "to")?,
        kind: take_text(map, "kind")?,
        weight: take_uint_opt(map, "weight")?,
    })
}

fn exclusion_from_cbor(v: &CborValue) -> Result<Exclusion, SessionError> {
    let map = as_map(v, "Exclusion")?;
    Ok(Exclusion {
        cap: take_text(map, "cap")?,
        reason: take_text(map, "reason")?,
        layer: take_text(map, "layer")?,
        hint: take_text_opt(map, "hint")?,
    })
}

fn schema_ref_from_cbor(v: &CborValue) -> Result<Option<SchemaRef>, SessionError> {
    if matches!(v, CborValue::Null) {
        return Ok(None);
    }
    let map = as_map(v, "SchemaRef")?;
    Ok(Some(SchemaRef {
        kind: take_text(map, "kind")?,
        uri: take_text(map, "uri")?,
        hash: take_bytes_fixed(map, "hash")?,
    }))
}

fn cost_estimate_from_cbor(v: &CborValue) -> Result<Option<CostEstimate>, SessionError> {
    if matches!(v, CborValue::Null) {
        return Ok(None);
    }
    let map = as_map(v, "CostEstimate")?;
    Ok(Some(CostEstimate {
        p50_crux: take_uint_opt(map, "p50_crux")?,
        p95_crux: take_uint_opt(map, "p95_crux")?,
        estimation_method: take_text(map, "estimation_method")?,
    }))
}

fn model_policy_from_cbor(v: &CborValue) -> Result<Option<ModelPolicy>, SessionError> {
    if matches!(v, CborValue::Null) {
        return Ok(None);
    }
    let map = as_map(v, "ModelPolicy")?;
    Ok(Some(ModelPolicy {
        min_family: take_text_array_opt(map, "min_family")?,
        min_size: take_text_opt(map, "min_size")?,
        deny_models: take_text_array_opt(map, "deny_models")?,
        auth_required: take_bool(map, "auth_required")?,
    }))
}

fn attestations_from_cbor(v: &CborValue) -> Result<Vec<AttestationRef>, SessionError> {
    match v {
        CborValue::Null => Ok(Vec::new()),
        CborValue::Array(items) => items.iter().map(attestation_from_cbor).collect(),
        _ => Err(SessionError::Decode("attestations not array or null".to_string())),
    }
}

fn attestation_from_cbor(v: &CborValue) -> Result<AttestationRef, SessionError> {
    let map = as_map(v, "AttestationRef")?;
    Ok(AttestationRef {
        issuer: take_text(map, "issuer")?,
        typ: take_text(map, "type")?,
        hash: take_bytes_fixed(map, "hash")?,
        uri: take_text_opt(map, "uri")?,
    })
}

fn concurrency_from_cbor(v: &CborValue) -> Result<Option<ConcurrencyHints>, SessionError> {
    if matches!(v, CborValue::Null) {
        return Ok(None);
    }
    let map = as_map(v, "ConcurrencyHints")?;
    Ok(Some(ConcurrencyHints {
        max_parallel: take_uint_opt(map, "max_parallel")?,
        rate_limit: rate_limit_from_cbor(get(map, "rate_limit")?)?,
    }))
}

fn rate_limit_from_cbor(v: &CborValue) -> Result<Option<RateLimitHints>, SessionError> {
    if matches!(v, CborValue::Null) {
        return Ok(None);
    }
    let map = as_map(v, "RateLimitHints")?;
    Ok(Some(RateLimitHints {
        calls_per_minute: take_uint_opt(map, "calls_per_minute")?,
        tokens_per_minute: take_uint_opt(map, "tokens_per_minute")?,
        bursts_allowed: take_bool(map, "bursts_allowed")?,
    }))
}

fn token_ref_from_cbor(v: &CborValue) -> Result<Option<CapabilityTokenRef>, SessionError> {
    if matches!(v, CborValue::Null) {
        return Ok(None);
    }
    let map = as_map(v, "CapabilityTokenRef")?;
    Ok(Some(CapabilityTokenRef {
        token_id: take_text(map, "token_id")?,
        issued_at: take_uint(map, "issued_at")?,
    }))
}

fn receipt_from_cbor(v: &CborValue) -> Result<ReceiptEnvelope, SessionError> {
    let map = as_map(v, "receipt")?;
    let mode_str = take_text(map, "mode")?;
    let mode = match mode_str.as_str() {
        "local" => ReceiptMode::Local,
        "verified" => ReceiptMode::Verified,
        "audit" => ReceiptMode::Audit,
        other => return Err(SessionError::UnsupportedMode(other.to_string())),
    };
    let signature = match get(map, "signature")? {
        CborValue::Null => None,
        CborValue::Bytes(b) => {
            if b.len() != SIGNATURE_LEN {
                return Err(SessionError::SignatureLength(b.len()));
            }
            let mut arr = [0u8; SIGNATURE_LEN];
            arr.copy_from_slice(b);
            Some(arr)
        }
        _ => return Err(SessionError::Decode("signature must be bytes or null".to_string())),
    };
    let parent_chain = match get(map, "parent_chain")? {
        CborValue::Null => None,
        CborValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let CborValue::Bytes(b) = item else {
                    return Err(SessionError::Decode("parent_chain item not bytes".to_string()));
                };
                if b.len() != HASH_LEN {
                    return Err(SessionError::HashLength(b.len()));
                }
                let mut arr = [0u8; HASH_LEN];
                arr.copy_from_slice(b);
                out.push(arr);
            }
            Some(out)
        }
        _ => return Err(SessionError::Decode("parent_chain must be array or null".to_string())),
    };
    Ok(ReceiptEnvelope {
        mode,
        hash: take_bytes_fixed(map, "hash")?,
        signature,
        signer_kid: take_text_opt(map, "signer_kid")?,
        parent_chain,
    })
}

// ─── map-lookup helpers ────────────────────────────────────────────────────

type Pair = (String, CborValue);

fn as_map<'a>(value: &'a CborValue, ctx: &'static str) -> Result<&'a [Pair], SessionError> {
    match value {
        CborValue::Map(pairs) => Ok(pairs),
        _ => Err(SessionError::Decode(format!("{ctx} is not a map"))),
    }
}

fn get<'a>(map: &'a [Pair], key: &'static str) -> Result<&'a CborValue, SessionError> {
    for (k, v) in map {
        if k == key {
            return Ok(v);
        }
    }
    Err(SessionError::Decode(format!("missing field `{key}`")))
}

fn find<'a>(map: &'a [Pair], key: &'static str) -> Option<&'a CborValue> {
    map.iter().find_map(|(k, v)| (k == key).then_some(v))
}

fn take_uint(map: &[Pair], key: &'static str) -> Result<u64, SessionError> {
    match get(map, key)? {
        CborValue::Uint(n) => Ok(*n),
        _ => Err(SessionError::Decode(format!("{key} not uint"))),
    }
}

fn take_uint_opt(map: &[Pair], key: &'static str) -> Result<Option<u64>, SessionError> {
    match find(map, key).unwrap_or(&CborValue::Null) {
        CborValue::Null => Ok(None),
        CborValue::Uint(n) => Ok(Some(*n)),
        _ => Err(SessionError::Decode(format!("{key} not uint or null"))),
    }
}

fn take_bool(map: &[Pair], key: &'static str) -> Result<bool, SessionError> {
    match get(map, key)? {
        CborValue::Bool(value) => Ok(*value),
        _ => Err(SessionError::Decode(format!("{key} not bool"))),
    }
}

fn take_text(map: &[Pair], key: &'static str) -> Result<String, SessionError> {
    match get(map, key)? {
        CborValue::Text(s) => Ok(s.clone()),
        _ => Err(SessionError::Decode(format!("{key} not text"))),
    }
}

fn take_text_opt(map: &[Pair], key: &'static str) -> Result<Option<String>, SessionError> {
    match find(map, key).unwrap_or(&CborValue::Null) {
        CborValue::Null => Ok(None),
        CborValue::Text(s) => Ok(Some(s.clone())),
        _ => Err(SessionError::Decode(format!("{key} not text or null"))),
    }
}

fn take_text_array(map: &[Pair], key: &'static str) -> Result<Vec<String>, SessionError> {
    match get(map, key)? {
        CborValue::Array(items) => items
            .iter()
            .map(|it| match it {
                CborValue::Text(s) => Ok(s.clone()),
                _ => Err(SessionError::Decode(format!("{key} item not text"))),
            })
            .collect(),
        _ => Err(SessionError::Decode(format!("{key} not array"))),
    }
}

fn take_text_array_opt(map: &[Pair], key: &'static str) -> Result<Option<Vec<String>>, SessionError> {
    match find(map, key).unwrap_or(&CborValue::Null) {
        CborValue::Null => Ok(None),
        CborValue::Array(items) => items
            .iter()
            .map(|it| match it {
                CborValue::Text(s) => Ok(s.clone()),
                _ => Err(SessionError::Decode(format!("{key} item not text"))),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err(SessionError::Decode(format!("{key} not array or null"))),
    }
}

fn take_bytes_fixed<const N: usize>(map: &[Pair], key: &'static str) -> Result<[u8; N], SessionError> {
    match get(map, key)? {
        CborValue::Bytes(b) => {
            if b.len() != N {
                return Err(SessionError::ByteArrayLength {
                    field: key,
                    expected: N,
                    actual: b.len(),
                });
            }
            let mut arr = [0u8; N];
            arr.copy_from_slice(b);
            Ok(arr)
        }
        _ => Err(SessionError::Decode(format!("{key} not bytes"))),
    }
}

fn take_bytes_fixed_opt<const N: usize>(map: &[Pair], key: &'static str) -> Result<Option<[u8; N]>, SessionError> {
    match find(map, key).unwrap_or(&CborValue::Null) {
        CborValue::Null => Ok(None),
        CborValue::Bytes(b) => {
            if b.len() != N {
                return Err(SessionError::ByteArrayLength {
                    field: key,
                    expected: N,
                    actual: b.len(),
                });
            }
            let mut arr = [0u8; N];
            arr.copy_from_slice(b);
            Ok(Some(arr))
        }
        _ => Err(SessionError::Decode(format!("{key} not bytes or null"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<const N: usize>(value: u8) -> [u8; N] {
        [value; N]
    }

    fn full_capability() -> Capability {
        Capability {
            cap: "corecrux.query.local".to_string(),
            category: "tier_gated".to_string(),
            prefer: "mcp".to_string(),
            shape: "QueryRequest".to_string(),
            input_schema: Some(SchemaRef {
                kind: "json-schema".to_string(),
                uri: "schema://input".to_string(),
                hash: bytes(11),
            }),
            output_schema: Some(SchemaRef {
                kind: "json-schema".to_string(),
                uri: "schema://output".to_string(),
                hash: bytes(12),
            }),
            min_tier: Some("basic".to_string()),
            required_affinity: Some("search".to_string()),
            cost_class: "metered".to_string(),
            cost_estimate: Some(CostEstimate {
                p50_crux: Some(7),
                p95_crux: Some(13),
                estimation_method: "fixture".to_string(),
            }),
            stability: "stable".to_string(),
            since: Some("1.2.3".to_string()),
            sunset_at: Some(9_999),
            model_policy: Some(ModelPolicy {
                min_family: Some(vec!["gpt".to_string(), "o".to_string()]),
                min_size: Some("mini".to_string()),
                deny_models: Some(vec!["legacy".to_string()]),
                auth_required: true,
            }),
            attestations: vec![AttestationRef {
                issuer: "issuer".to_string(),
                typ: "soc2".to_string(),
                hash: bytes(13),
                uri: Some("attest://soc2".to_string()),
            }],
            concurrency: Some(ConcurrencyHints {
                max_parallel: Some(4),
                rate_limit: Some(RateLimitHints {
                    calls_per_minute: Some(60),
                    tokens_per_minute: Some(1_000),
                    bursts_allowed: true,
                }),
            }),
            impl_path: ImplPath {
                ce: Some("ce.tool".to_string()),
                core: Some("core.tool".to_string()),
            },
            token_ref: Some(CapabilityTokenRef {
                token_id: "tok_123".to_string(),
                issued_at: 1_700_000_000,
            }),
        }
    }

    fn full_plan() -> SessionPlan {
        SessionPlan {
            plan_id: bytes(1),
            plan_version: SESSION_PLAN_VERSION,
            minted_at: 1_700_000_000_000,
            origin: "ce".to_string(),
            origin_install: Some(bytes(2)),
            session_id: bytes(3),
            session_ttl_s: 600,
            passport: Passport {
                principal_id: "p_test".to_string(),
                tier: "basic".to_string(),
                affinities: vec!["search".to_string()],
                denied_capabilities: Some(vec!["dangerous.cap".to_string()]),
                grant_expansions: Some(vec!["bonus.cap".to_string()]),
                passport_receipt: Some(bytes(4)),
            },
            model: Some(ModelDeclaration {
                declared: Some("gpt-test".to_string()),
                declared_family: Some("gpt".to_string()),
                declared_size: Some("mini".to_string()),
                auth_bound: true,
            }),
            channels: Channels {
                bulk: Some("h2://bulk".to_string()),
                mcp: "mcp://local".to_string(),
            },
            capability_graph: vec![full_capability()],
            capability_graph_edges: vec![Edge {
                from: "corecrux.query.local".to_string(),
                to: "corecrux.receipt.export".to_string(),
                kind: "requires".to_string(),
                weight: Some(10),
            }],
            capability_graph_excluded: Some(vec![Exclusion {
                cap: "hosted.only".to_string(),
                reason: "tier".to_string(),
                layer: "policy".to_string(),
                hint: Some("upgrade".to_string()),
            }]),
            capability_graph_version: CAPABILITY_GRAPH_VERSION,
            capability_graph_valid_until: 1_700_000_600_000,
            capability_graph_refresh_hint: Some("refresh soon".to_string()),
            capability_graph_hash: bytes(5),
            budget: Budget {
                tokens_cap: Some(10_000),
                crux_cap: Some(250),
                ttl_s: 600,
            },
            receipt: ReceiptEnvelope {
                mode: ReceiptMode::Verified,
                hash: bytes(6),
                signature: Some(bytes(7)),
                signer_kid: Some("kid-1".to_string()),
                parent_chain: Some(vec![bytes(8), bytes(9)]),
            },
            intent_hint: Some("audit-review".to_string()),
        }
    }

    #[test]
    fn full_plan_round_trips_all_optional_fields() {
        let plan = full_plan();
        let encoded = plan.to_canonical_cbor();
        let decoded = SessionPlan::from_canonical_cbor(&encoded).expect("decode full plan");

        assert_eq!(decoded, plan);
        assert!(plan.to_zeroed_canonical_cbor().len() < encoded.len());
        let json = plan.to_canonical_json();
        assert!(json.contains("audit-review"));
        assert_eq!(ReceiptMode::Audit.as_str(), "audit");
    }

    #[test]
    fn legacy_capability_graph_array_decodes_with_defaults() {
        let mut plan = full_plan();
        plan.capability_graph_edges.clear();
        plan.capability_graph_excluded = None;
        plan.capability_graph_refresh_hint = None;
        let mut pairs = match plan.to_cbor_value(false) {
            CborValue::Map(pairs) => pairs,
            _ => unreachable!("plan encodes to map"),
        };
        let legacy_cap = Capability::legacy(
            "legacy.cap",
            "bulk",
            "stream<Chunk>",
            Some("trusted".to_string()),
            "heavy",
            ImplPath {
                ce: None,
                core: Some("legacy.core".to_string()),
            },
        );
        for (key, value) in &mut pairs {
            if key == "capability_graph" {
                *value = CborValue::Array(vec![capability_to_cbor(&legacy_cap)]);
            }
        }

        let decoded = SessionPlan::from_cbor_value(&CborValue::Map(pairs)).expect("decode legacy graph");
        assert_eq!(decoded.capability_graph.len(), 1);
        assert_eq!(decoded.capability_graph[0].cap, "legacy.cap");
        assert!(decoded.capability_graph_edges.is_empty());
        assert!(decoded.capability_graph_excluded.is_none());
        assert_eq!(
            decoded.capability_graph_valid_until,
            decoded.minted_at + decoded.session_ttl_s * 1000
        );
    }

    #[test]
    fn decode_rejects_bad_shapes_and_lengths() {
        let err = SessionPlan::from_cbor_value(&CborValue::Text("bad".to_string())).expect_err("not map");
        assert!(err.to_string().contains("SessionPlan"));

        let mut pairs = match full_plan().to_cbor_value(false) {
            CborValue::Map(pairs) => pairs,
            _ => unreachable!("plan encodes to map"),
        };
        for (key, value) in &mut pairs {
            if key == "receipt" {
                *value = CborValue::Map(vec![
                    ("mode".to_string(), CborValue::Text("mystery".to_string())),
                    ("hash".to_string(), CborValue::Bytes(bytes::<HASH_LEN>(1).to_vec())),
                    ("signature".to_string(), CborValue::Null),
                    ("signer_kid".to_string(), CborValue::Null),
                    ("parent_chain".to_string(), CborValue::Null),
                ]);
            }
        }
        let err = SessionPlan::from_cbor_value(&CborValue::Map(pairs)).expect_err("unsupported receipt mode");
        assert!(err.to_string().contains("mystery"));

        let err = schema_ref_from_cbor(&CborValue::Map(vec![
            ("kind".to_string(), CborValue::Text("json-schema".to_string())),
            ("uri".to_string(), CborValue::Text("schema://short".to_string())),
            ("hash".to_string(), CborValue::Bytes(vec![1, 2, 3])),
        ]))
        .expect_err("short hash rejected");
        assert!(err.to_string().contains("hash"));
    }

    #[test]
    fn constructors_set_categories_from_tier_and_affinity() {
        assert_eq!(Capability::category_for(None, None), "public");
        assert_eq!(Capability::category_for(Some("basic"), None), "tier_gated");
        assert_eq!(Capability::category_for(None, Some("ops")), "affinity_required");

        let cap = Capability::v2(
            "cap",
            "mcp",
            "shape",
            None,
            Some("ops".to_string()),
            "free",
            ImplPath { ce: None, core: None },
        );
        assert_eq!(cap.category, "affinity_required");
    }
}
