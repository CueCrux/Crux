// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Built-in capability catalog.
//!
//! The catalog lists every capability the CueCrux platform surfaces. Each
//! entry declares the required affinity tag, minimum tier, cost class, and
//! the local + Core `impl_path`. The generator at [`crate::generator`] filters
//! this catalog per passport.
//!
//! This module is the single source of truth for what capabilities exist.
//! When adding a new capability to the platform, add it here; the generator
//! picks it up automatically on both Crux Daemon and hosted.

use crate::plan::{Capability, ImplPath, SchemaRef};

/// Schema kind advertised on every catalog [`SchemaRef`] (spec §v1.1).
pub const SCHEMA_KIND_JSON_SCHEMA: &str = "json-schema";

/// Route prefix under which the local daemon hosts advertised schema
/// documents: `GET /v1/session/schemas/<cap>.(in|out).json`. `SchemaRef.uri`
/// values are daemon-rooted paths under this prefix, resolvable against the
/// origin that served the session plan. Hosting decision (M2): agent-proposed
/// local-daemon route; the operator may later ratify or switch to
/// `static.rcxprotocol.org` — cheap to change because schemas do not enter
/// `capability_graph_hash` until the gated M3 binding.
pub const SCHEMA_ROUTE_PREFIX: &str = "/v1/session/schemas/";

/// Const-friendly schema advertisement attached to a [`CatalogEntry`]
/// (M2, advertise-only — spec §v1.1; validation at invocation time is
/// explicitly out of scope).
///
/// The embedded `bytes` are the single source of truth: [`Self::to_schema_ref`]
/// hashes exactly these bytes and the daemon route serves exactly these bytes
/// (via [`schema_document`]), so the pinned hash can never drift from the
/// served document (plan R3).
#[derive(Debug, Clone, Copy)]
pub struct CatalogSchema {
    /// Document file name under [`SCHEMA_ROUTE_PREFIX`],
    /// e.g. `proof_verify.in.json`.
    pub file: &'static str,
    /// The embedded schema document — the exact bytes the daemon serves.
    pub bytes: &'static [u8],
}

impl CatalogSchema {
    /// Daemon-rooted URI at which [`schema_document`]-backed routes serve
    /// this document.
    pub fn uri(&self) -> String {
        format!("{SCHEMA_ROUTE_PREFIX}{}", self.file)
    }

    /// Expand into the wire [`SchemaRef`], pinning `hash` = BLAKE3 of the
    /// exact embedded (= served) bytes.
    pub fn to_schema_ref(&self) -> SchemaRef {
        SchemaRef {
            kind: SCHEMA_KIND_JSON_SCHEMA.to_string(),
            uri: self.uri(),
            hash: *blake3::hash(self.bytes).as_bytes(),
        }
    }
}

/// Embedded schema documents for the M2 high-value nodes (receipt/snapshot
/// shapes). Each document is advertise-only and mirrors a real wire shape —
/// see the per-file `description` for the grounding source.
pub const SCHEMA_SESSION_CONTEXT_IN: CatalogSchema = CatalogSchema {
    file: "session_context.in.json",
    bytes: include_bytes!("../schemas/session_context.in.json"),
};
pub const SCHEMA_SESSION_CONTEXT_OUT: CatalogSchema = CatalogSchema {
    file: "session_context.out.json",
    bytes: include_bytes!("../schemas/session_context.out.json"),
};
pub const SCHEMA_JOURNAL_APPEND_IN: CatalogSchema = CatalogSchema {
    file: "journal_append.in.json",
    bytes: include_bytes!("../schemas/journal_append.in.json"),
};
pub const SCHEMA_JOURNAL_APPEND_OUT: CatalogSchema = CatalogSchema {
    file: "journal_append.out.json",
    bytes: include_bytes!("../schemas/journal_append.out.json"),
};
pub const SCHEMA_PROOF_VERIFY_IN: CatalogSchema = CatalogSchema {
    file: "proof_verify.in.json",
    bytes: include_bytes!("../schemas/proof_verify.in.json"),
};
pub const SCHEMA_PROOF_VERIFY_OUT: CatalogSchema = CatalogSchema {
    file: "proof_verify.out.json",
    bytes: include_bytes!("../schemas/proof_verify.out.json"),
};
pub const SCHEMA_OUTPUT_VERIFIABLE_RECEIPTS_IN: CatalogSchema = CatalogSchema {
    file: "output.verifiable_receipts.in.json",
    bytes: include_bytes!("../schemas/output.verifiable_receipts.in.json"),
};
pub const SCHEMA_OUTPUT_VERIFIABLE_RECEIPTS_OUT: CatalogSchema = CatalogSchema {
    file: "output.verifiable_receipts.out.json",
    bytes: include_bytes!("../schemas/output.verifiable_receipts.out.json"),
};

/// Look up an advertised schema document by its file name (the last path
/// segment of the daemon route, e.g. `proof_verify.in.json`).
///
/// The daemon's `GET /v1/session/schemas/{file}` handler serves the bytes
/// returned here — the same bytes [`CatalogSchema::to_schema_ref`] hashes —
/// so served bytes and pinned hash cannot diverge (plan R3).
pub fn schema_document(file: &str) -> Option<CatalogSchema> {
    DEFAULT_CATALOG
        .iter()
        .flat_map(|entry| [entry.input_schema, entry.output_schema])
        .flatten()
        .find(|schema| schema.file == file)
}

/// Static description of a catalog entry. Expanded into a [`Capability`] by
/// the generator after per-passport filtering.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub cap: &'static str,
    pub affinity: &'static str,
    pub prefer_bulk: bool,
    pub shape: &'static str,
    pub min_tier: Option<&'static str>,
    pub cost_class: &'static str,
    pub ce_path: Option<&'static str>,
    pub core_path: Option<&'static str>,
    /// Feature flag that must be enabled for this capability to be surfaced.
    /// `None` = always enabled.
    pub feature_flag: Option<&'static str>,
    /// Advertised input schema (M2, advertise-only). `None` = not advertised.
    pub input_schema: Option<CatalogSchema>,
    /// Advertised output schema (M2, advertise-only). `None` = not advertised.
    pub output_schema: Option<CatalogSchema>,
}

impl CatalogEntry {
    pub fn to_capability(&self, prefer_bulk_mode: bool) -> Capability {
        let prefer = if self.prefer_bulk && prefer_bulk_mode {
            "bulk"
        } else {
            "mcp"
        };
        let required_affinity = (self.cap != "session_context").then(|| self.affinity.to_string());
        let mut capability = Capability::v2(
            self.cap,
            prefer,
            self.shape,
            self.min_tier.map(String::from),
            required_affinity,
            self.cost_class,
            ImplPath {
                ce: self.ce_path.map(String::from),
                core: self.core_path.map(String::from),
            },
        );
        capability.input_schema = self.input_schema.as_ref().map(CatalogSchema::to_schema_ref);
        capability.output_schema = self.output_schema.as_ref().map(CatalogSchema::to_schema_ref);
        capability
    }
}

/// The built-in catalog.
///
/// Affinity tags in use: `retrieval`, `proof`, `audit`, `memory`, `economy`,
/// `session`, `journal`.
pub const DEFAULT_CATALOG: &[CatalogEntry] = &[
    CatalogEntry {
        cap: "retrieve",
        affinity: "retrieval",
        prefer_bulk: true,
        shape: "stream<Chunk>",
        min_tier: Some("free"),
        cost_class: "metered",
        ce_path: Some("retrieve_local"),
        core_path: Some("/v2/retrieve"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        cap: "session_context",
        affinity: "session",
        prefer_bulk: true,
        shape: "Snapshot",
        min_tier: None,
        cost_class: "free",
        ce_path: Some("session_ctx_local"),
        core_path: Some("/v2/session/context"),
        feature_flag: None,
        input_schema: Some(SCHEMA_SESSION_CONTEXT_IN),
        output_schema: Some(SCHEMA_SESSION_CONTEXT_OUT),
    },
    CatalogEntry {
        cap: "journal_append",
        affinity: "journal",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: None,
        cost_class: "free",
        ce_path: Some("journal_local"),
        core_path: Some("/mcp/vault#journal_append"),
        feature_flag: None,
        input_schema: Some(SCHEMA_JOURNAL_APPEND_IN),
        output_schema: Some(SCHEMA_JOURNAL_APPEND_OUT),
    },
    CatalogEntry {
        cap: "journal_stream",
        affinity: "journal",
        prefer_bulk: true,
        shape: "stream<Event>",
        min_tier: Some("starter"),
        cost_class: "free",
        ce_path: Some("journal_stream_local"),
        core_path: Some("/v2/journal/stream"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        cap: "proof_document",
        affinity: "proof",
        prefer_bulk: true,
        shape: "Receipt",
        min_tier: Some("starter"),
        cost_class: "heavy",
        ce_path: Some("proof_local"),
        core_path: Some("/v2/proof"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        cap: "proof_verify",
        affinity: "proof",
        prefer_bulk: false,
        shape: "VerifyResult",
        min_tier: None,
        cost_class: "free",
        ce_path: Some("proof_verify_local"),
        core_path: Some("/mcp/vault#proof_verify"),
        feature_flag: None,
        input_schema: Some(SCHEMA_PROOF_VERIFY_IN),
        output_schema: Some(SCHEMA_PROOF_VERIFY_OUT),
    },
    CatalogEntry {
        cap: "annotation_add",
        affinity: "memory",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: Some("free"),
        cost_class: "free",
        ce_path: Some("annotation_local"),
        core_path: Some("/mcp/vault#annotation_add"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        cap: "memory_get",
        affinity: "memory",
        prefer_bulk: true,
        shape: "Snapshot",
        min_tier: Some("free"),
        cost_class: "free",
        ce_path: Some("memory_get_local"),
        core_path: Some("/v2/memory/get"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        cap: "memory_put",
        affinity: "memory",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: Some("free"),
        cost_class: "metered",
        ce_path: Some("memory_put_local"),
        core_path: Some("/mcp/memory#put"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        cap: "audit_replay",
        affinity: "audit",
        prefer_bulk: true,
        shape: "stream<Event>",
        min_tier: Some("pro"),
        cost_class: "heavy",
        ce_path: Some("audit_replay_local"),
        core_path: Some("/v2/audit/replay"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        cap: "get_counterfactual_summary",
        affinity: "audit",
        prefer_bulk: false,
        shape: "Report",
        min_tier: Some("pro"),
        cost_class: "heavy",
        ce_path: None,
        core_path: Some("/mcp/audit#get_counterfactual_summary"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        cap: "economy_quote",
        affinity: "economy",
        prefer_bulk: false,
        shape: "Quote",
        min_tier: Some("starter"),
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/economy#quote"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        cap: "economy_spend",
        affinity: "economy",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: Some("team"),
        cost_class: "metered",
        ce_path: None,
        core_path: Some("/mcp/economy#spend"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    // ── Wave-A/B agent-UX dimensions (shipped 2026-05-28) ────────────────
    //
    // These entries advertise capabilities surfaced by the wave-A/B agent-UX
    // programme. EVERY entry below carries an inline `file:line` citation to
    // a real shipped MCP tool — that is the load-bearing audit trail (per the
    // workspace QC.5 "no unverified claims" rule). These are ADVERTISEMENTS —
    // never consult them for auth or rate-limiting; the underlying tool
    // surface keeps its own gates.
    // `min_tier = None` keeps them visible on the local-tier passport so the
    // Crux Daemon `POST /session` response is self-describing.
    // Dim 02 (`memory_acknowledge_use`) is deliberately NOT advertised here per
    // the source brief; the tool exists but the dimension was scoped out of
    // wave-A/B shipping.
    CatalogEntry {
        // Dim 01 — readable/editable memory.
        // Tools: `memory_view`  crates/crux-mcp/src/tools/memory.rs:130
        //        `memory_edit`  crates/crux-mcp/src/tools/memory.rs:274
        cap: "memory.readable_editable",
        affinity: "memory",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: None,
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/memory#view"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        // Dim 03 — freshness / decay.
        // Tools: `memory_freshness`   crates/crux-mcp/src/tools/freshness.rs:84
        //        `memory_set_horizon` crates/crux-mcp/src/tools/freshness.rs:155
        //        `memory_reverify`    crates/crux-mcp/src/tools/freshness.rs:214
        cap: "memory.freshness",
        affinity: "memory",
        prefer_bulk: false,
        shape: "Snapshot",
        min_tier: None,
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/memory#freshness"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        // Dim 04 — source-linked traceability.
        // Tools: `fact_history`    crates/crux-mcp/src/tools/facts.rs:92
        //        `entity_history`  crates/crux-mcp/src/tools/entities.rs:102
        cap: "trace.source_linked",
        affinity: "trace",
        prefer_bulk: false,
        shape: "Snapshot",
        min_tier: None,
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/trace#source_linked"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        // Dim 05 — risk-tiered HITL.
        // Tools: `approval_request` crates/crux-mcp/src/tools/approvals.rs:229
        //        `approval_decide`  crates/crux-mcp/src/tools/approvals.rs:373
        cap: "approval.risk_tiered",
        affinity: "approval",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: None,
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/approval#request"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        // Dim 06 — typed action traces.
        // Tools: `tool_trace_recent` crates/crux-mcp/src/tools/traces.rs:72
        cap: "trace.typed_actions",
        affinity: "trace",
        prefer_bulk: false,
        shape: "Snapshot",
        min_tier: None,
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/trace#typed_actions"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        // Dim 07 — verifiable output receipts.
        // Tools: `output_attest`  crates/crux-mcp/src/tools/output_attest.rs:186
        //        `receipt_verify` crates/crux-mcp/src/tools/receipt_verify.rs:95
        cap: "output.verifiable_receipts",
        affinity: "output",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: None,
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/output#attest"),
        feature_flag: None,
        input_schema: Some(SCHEMA_OUTPUT_VERIFIABLE_RECEIPTS_IN),
        output_schema: Some(SCHEMA_OUTPUT_VERIFIABLE_RECEIPTS_OUT),
    },
    CatalogEntry {
        // Dim 08 — identity continuity.
        // Tools: `get_agent_identity`    crates/crux-mcp/src/tools/mod.rs:2039
        //        `passport_link_device`  crates/crux-mcp/src/tools/identity.rs:644
        //        `passport_merge`        crates/crux-mcp/src/tools/identity.rs:395
        //        `passport_split`        crates/crux-mcp/src/tools/identity.rs:190
        cap: "identity.continuity",
        affinity: "identity",
        prefer_bulk: false,
        shape: "Snapshot",
        min_tier: None,
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/identity#continuity"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        // Dim 09 — scoped forget.
        // Tools: `memory_forget_dry_run` crates/crux-mcp/src/tools/forget.rs:243
        //        `memory_forget`         crates/crux-mcp/src/tools/forget.rs:286
        cap: "memory.scoped_forget",
        affinity: "memory",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: None,
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/memory#forget"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        // Dim 10 — visible autonomy contract.
        // Tools: `autonomy_contract` crates/crux-mcp/src/tools/autonomy.rs:243
        cap: "autonomy.contract",
        affinity: "autonomy",
        prefer_bulk: false,
        shape: "Snapshot",
        min_tier: None,
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/autonomy#contract"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        // Dim 11 — BYO audit trail.
        // Tools: `audit_config`        crates/crux-mcp/src/tools/audit.rs:52
        //        `audit_export_bundle` crates/crux-mcp/src/tools/audit_export.rs:140
        cap: "audit.byo_trail",
        affinity: "audit",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: None,
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/audit#byo_trail"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
    CatalogEntry {
        // Dim 12 — calm / deferred output.
        // Tools: `enrich_action` crates/crux-mcp/src/tools/action.rs:16
        cap: "output.calm_deferred",
        affinity: "output",
        prefer_bulk: false,
        shape: "Snapshot",
        min_tier: None,
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/output#calm_deferred"),
        feature_flag: None,
        input_schema: None,
        output_schema: None,
    },
];

/// A statically-configured relationship between two catalog capabilities
/// (Session-Handshake master plan §5.4 + §9 "edge construction from a
/// statically-configured capability relationship table").
///
/// `from`/`to` are capability names that MUST exist in [`DEFAULT_CATALOG`]
/// (enforced by `edge_table_endpoints_exist` test). The generator emits an
/// edge into the graph only when BOTH endpoints survive per-passport
/// filtering (master-plan Step 12) — edges to filtered/excluded capabilities
/// are dropped.
#[derive(Debug, Clone, Copy)]
pub struct CatalogEdge {
    pub from: &'static str,
    pub to: &'static str,
    /// One of `produces_input_for` | `alternative_to` | `composes_with` (§5.4).
    pub kind: &'static str,
    /// Relationship strength on a 0–100 integer scale (the spec's 0.0–1.0
    /// ×100). `Edge.weight` is `Option<u64>`; we always supply a value here.
    pub weight: u64,
}

/// Valid edge kinds (Session-Handshake master plan §5.4).
pub const EDGE_PRODUCES_INPUT_FOR: &str = "produces_input_for";
pub const EDGE_ALTERNATIVE_TO: &str = "alternative_to";
pub const EDGE_COMPOSES_WITH: &str = "composes_with";

/// The built-in capability relationship table.
///
/// Every endpoint is a real [`DEFAULT_CATALOG`] capability name (QC.5: this is
/// an advertisement, never an auth/rate-limit input). Edges are emitted by the
/// generator only when both endpoints clear filtering, so a local-tier graph
/// shows the subset whose endpoints are both visible.
pub const CAPABILITY_EDGES: &[CatalogEdge] = &[
    // ── produces_input_for — output of `from` is a valid input to `to` ──────
    CatalogEdge {
        from: "proof_document",
        to: "proof_verify",
        kind: EDGE_PRODUCES_INPUT_FOR,
        weight: 90,
    },
    CatalogEdge {
        from: "output.verifiable_receipts",
        to: "proof_verify",
        kind: EDGE_PRODUCES_INPUT_FOR,
        weight: 85,
    },
    CatalogEdge {
        from: "memory_put",
        to: "memory_get",
        kind: EDGE_PRODUCES_INPUT_FOR,
        weight: 80,
    },
    CatalogEdge {
        from: "annotation_add",
        to: "memory_get",
        kind: EDGE_PRODUCES_INPUT_FOR,
        weight: 60,
    },
    CatalogEdge {
        from: "audit_replay",
        to: "get_counterfactual_summary",
        kind: EDGE_PRODUCES_INPUT_FOR,
        weight: 75,
    },
    CatalogEdge {
        from: "economy_quote",
        to: "economy_spend",
        kind: EDGE_PRODUCES_INPUT_FOR,
        weight: 85,
    },
    // ── composes_with — commonly used together (co-occurrence, not a dep) ───
    CatalogEdge {
        from: "memory.readable_editable",
        to: "memory.freshness",
        kind: EDGE_COMPOSES_WITH,
        weight: 70,
    },
    CatalogEdge {
        from: "memory.scoped_forget",
        to: "memory.readable_editable",
        kind: EDGE_COMPOSES_WITH,
        weight: 65,
    },
    CatalogEdge {
        from: "trace.source_linked",
        to: "trace.typed_actions",
        kind: EDGE_COMPOSES_WITH,
        weight: 70,
    },
    CatalogEdge {
        from: "approval.risk_tiered",
        to: "autonomy.contract",
        kind: EDGE_COMPOSES_WITH,
        weight: 60,
    },
    CatalogEdge {
        from: "identity.continuity",
        to: "autonomy.contract",
        kind: EDGE_COMPOSES_WITH,
        weight: 55,
    },
    CatalogEdge {
        from: "output.calm_deferred",
        to: "output.verifiable_receipts",
        kind: EDGE_COMPOSES_WITH,
        weight: 60,
    },
    CatalogEdge {
        from: "audit.byo_trail",
        to: "trace.typed_actions",
        kind: EDGE_COMPOSES_WITH,
        weight: 65,
    },
    CatalogEdge {
        from: "audit.byo_trail",
        to: "audit_replay",
        kind: EDGE_COMPOSES_WITH,
        weight: 70,
    },
    CatalogEdge {
        from: "retrieve",
        to: "memory_get",
        kind: EDGE_COMPOSES_WITH,
        weight: 50,
    },
    CatalogEdge {
        from: "journal_append",
        to: "journal_stream",
        kind: EDGE_COMPOSES_WITH,
        weight: 55,
    },
    // ── alternative_to — equivalent semantics, substitutable ───────────────
    CatalogEdge {
        from: "memory_get",
        to: "memory.readable_editable",
        kind: EDGE_ALTERNATIVE_TO,
        weight: 60,
    },
];

/// Ordered list of tier names, lowest to highest. Used by the tier filter.
pub const TIER_ORDER: &[&str] = &["local", "free", "starter", "pro", "team", "enterprise"];

pub fn tier_rank(tier: &str) -> Option<usize> {
    TIER_ORDER.iter().position(|t| *t == tier)
}

pub fn tier_meets(actual: &str, required: &str) -> bool {
    match (tier_rank(actual), tier_rank(required)) {
        (Some(a), Some(r)) => a >= r,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Baseline capabilities visible on a local (tier=local, affinity="*") passport.
    /// Pre-2026-05-29 this list was exhaustive (only these three were tier-None);
    /// the 2026-05-29 refresh adds the 11 wave-A/B agent-UX dimensions alongside.
    const BASELINE_LOCAL_TIER_CAPS: &[&str] = &["session_context", "journal_append", "proof_verify"];

    /// Wave-A/B agent-UX capability strings (dims 01, 03-12 — dim 02 deliberately
    /// excluded; the `memory_acknowledge_use` tool exists but the dimension was
    /// scoped out of wave-A/B shipping).
    const WAVE_AB_AGENT_UX_CAPS: &[&str] = &[
        "memory.readable_editable",   // dim 01
        "memory.freshness",           // dim 03
        "trace.source_linked",        // dim 04
        "approval.risk_tiered",       // dim 05
        "trace.typed_actions",        // dim 06
        "output.verifiable_receipts", // dim 07
        "identity.continuity",        // dim 08
        "memory.scoped_forget",       // dim 09
        "autonomy.contract",          // dim 10
        "audit.byo_trail",            // dim 11
        "output.calm_deferred",       // dim 12
    ];

    /// Every edge endpoint must name a real catalog capability, and every
    /// edge kind must be one of the three spec kinds. A typo here would
    /// silently produce an edge the generator can never emit (both-endpoints
    /// rule) or, worse, a malformed `kind` on the wire.
    #[test]
    fn edge_table_endpoints_exist_and_kinds_valid() {
        let names: HashSet<&str> = DEFAULT_CATALOG.iter().map(|e| e.cap).collect();
        let valid_kinds = [EDGE_PRODUCES_INPUT_FOR, EDGE_ALTERNATIVE_TO, EDGE_COMPOSES_WITH];
        for edge in CAPABILITY_EDGES {
            assert!(
                names.contains(edge.from),
                "edge `from` endpoint `{}` is not a catalog capability",
                edge.from
            );
            assert!(
                names.contains(edge.to),
                "edge `to` endpoint `{}` is not a catalog capability",
                edge.to
            );
            assert_ne!(edge.from, edge.to, "self-edge on `{}`", edge.from);
            assert!(
                valid_kinds.contains(&edge.kind),
                "edge kind `{}` (on {}→{}) is not a spec kind",
                edge.kind,
                edge.from,
                edge.to
            );
            assert!(edge.weight <= 100, "edge weight {} exceeds 0–100 scale", edge.weight);
        }
    }

    /// No duplicate (from, to, kind) triple — a duplicate would emit the same
    /// edge twice and perturb the graph hash for no reason.
    #[test]
    fn edge_table_has_no_duplicate_triples() {
        let mut seen: HashSet<(&str, &str, &str)> = HashSet::new();
        for edge in CAPABILITY_EDGES {
            assert!(
                seen.insert((edge.from, edge.to, edge.kind)),
                "duplicate edge triple: {}→{} ({})",
                edge.from,
                edge.to,
                edge.kind
            );
        }
    }

    #[test]
    fn catalog_has_no_duplicate_capability_names() {
        let mut seen: HashSet<&str> = HashSet::new();
        for entry in DEFAULT_CATALOG {
            assert!(
                seen.insert(entry.cap),
                "duplicate capability name in DEFAULT_CATALOG: {}",
                entry.cap
            );
        }
    }

    #[test]
    fn catalog_has_no_empty_capability_names() {
        for entry in DEFAULT_CATALOG {
            assert!(!entry.cap.is_empty(), "empty capability name in DEFAULT_CATALOG");
            assert!(!entry.affinity.is_empty(), "empty affinity for cap `{}`", entry.cap);
            assert!(!entry.cost_class.is_empty(), "empty cost_class for cap `{}`", entry.cap);
        }
    }

    /// Pin the baseline three capabilities (session_context, journal_append,
    /// proof_verify) so a future refactor cannot silently drop the floor.
    #[test]
    fn catalog_contains_baseline_capabilities() {
        let names: HashSet<&str> = DEFAULT_CATALOG.iter().map(|e| e.cap).collect();
        for baseline in BASELINE_LOCAL_TIER_CAPS {
            assert!(
                names.contains(baseline),
                "baseline capability `{}` missing from DEFAULT_CATALOG",
                baseline
            );
        }
    }

    /// 2026-05-29 refresh: the catalog must advertise the 11 wave-A/B agent-UX
    /// dimensions so `cuecrux_session` / `POST /session` is self-describing.
    /// See ExecPlan `crux-session-capability-catalog-refresh-2026-05-29`.
    #[test]
    fn catalog_advertises_wave_ab_agent_ux_dimensions() {
        let names: HashSet<&str> = DEFAULT_CATALOG.iter().map(|e| e.cap).collect();
        for cap in WAVE_AB_AGENT_UX_CAPS {
            assert!(
                names.contains(cap),
                "wave-A/B agent-UX capability `{}` missing from DEFAULT_CATALOG",
                cap
            );
        }
    }

    /// Local-tier passport (tier=local, affinities=["*"]) must see baseline + all
    /// wave-A/B caps — at least 7 capabilities total (3 baseline + >= 4 agent-UX).
    #[test]
    fn local_tier_passport_sees_at_least_seven_capabilities() {
        // Wave-A/B entries are pinned to `min_tier: None`, so they survive the
        // tier filter on the local-tier passport (which would otherwise drop
        // any min_tier=Some(...) entry — tier `local` is rank 0).
        let visible: Vec<&str> = DEFAULT_CATALOG
            .iter()
            .filter(|e| e.min_tier.is_none())
            .map(|e| e.cap)
            .collect();
        assert!(
            visible.len() >= 7,
            "expected >= 7 local-tier-visible capabilities, got {}: {:?}",
            visible.len(),
            visible
        );
        for baseline in BASELINE_LOCAL_TIER_CAPS {
            assert!(
                visible.contains(baseline),
                "baseline capability `{}` not local-tier-visible",
                baseline
            );
        }
        // Spot-check one agent-UX cap to guard the local-tier visibility path:
        // a future change that adds `min_tier: Some(...)` to a wave-A/B entry
        // would silently drop it on local without this check.
        assert!(
            visible.contains(&"autonomy.contract"),
            "autonomy.contract (dim 10) must be local-tier-visible to clear the scorecard floor"
        );
    }

    // ── M2: node schemas (advertise-only, hash-pinned) ──────────────────────

    /// The M2 high-value nodes (receipt/snapshot shapes) that advertise
    /// schema documents. All four are local-tier-visible (`min_tier: None`).
    const SCHEMA_ADVERTISED_CAPS: &[&str] = &[
        "session_context",
        "journal_append",
        "proof_verify",
        "output.verifiable_receipts",
    ];

    /// Every advertised schema document is valid JSON, is named after its
    /// cap + direction (`<cap>.(in|out).json`), and expands to a `SchemaRef`
    /// whose hash is BLAKE3 of the exact embedded bytes.
    #[test]
    fn schema_documents_are_valid_json_and_hash_pinned() {
        for entry in DEFAULT_CATALOG {
            for (direction, schema) in [("in", entry.input_schema), ("out", entry.output_schema)] {
                let Some(schema) = schema else { continue };
                let doc: serde_json::Value = serde_json::from_slice(schema.bytes)
                    .unwrap_or_else(|e| panic!("schema `{}` is not valid JSON: {e}", schema.file));
                assert!(doc.is_object(), "schema `{}` must be a JSON object", schema.file);
                assert_eq!(
                    schema.file,
                    format!("{}.{}.json", entry.cap, direction),
                    "schema file name must bind the document to its cap + direction"
                );
                let sref = schema.to_schema_ref();
                assert_eq!(sref.kind, SCHEMA_KIND_JSON_SCHEMA);
                assert_eq!(sref.uri, format!("{SCHEMA_ROUTE_PREFIX}{}", schema.file));
                assert_eq!(
                    sref.hash,
                    *blake3::hash(schema.bytes).as_bytes(),
                    "SchemaRef.hash must be BLAKE3 of the embedded bytes for `{}`",
                    schema.file
                );
            }
        }
    }

    /// The four chosen high-value nodes advertise BOTH directions (M2 gate:
    /// "chosen nodes surface non-null input_schema/output_schema").
    #[test]
    fn chosen_high_value_nodes_advertise_both_schema_directions() {
        for cap in SCHEMA_ADVERTISED_CAPS {
            let entry = DEFAULT_CATALOG
                .iter()
                .find(|e| e.cap == *cap)
                .unwrap_or_else(|| panic!("`{cap}` missing from DEFAULT_CATALOG"));
            assert!(entry.input_schema.is_some(), "`{cap}` must advertise an input schema");
            assert!(entry.output_schema.is_some(), "`{cap}` must advertise an output schema");
            assert!(
                entry.min_tier.is_none(),
                "`{cap}` must stay local-tier-visible so the local daemon surfaces its schemas"
            );
        }
    }

    /// `schema_document` (the lookup behind the daemon's
    /// `GET /v1/session/schemas/{file}` route) serves exactly the bytes the
    /// pinned `SchemaRef.hash` covers — served-bytes/hash drift is impossible
    /// by construction (plan R3). Unknown files resolve to nothing.
    #[test]
    fn schema_document_lookup_serves_the_pinned_bytes() {
        let mut advertised = 0;
        for entry in DEFAULT_CATALOG {
            for schema in [entry.input_schema, entry.output_schema].into_iter().flatten() {
                let served = schema_document(schema.file)
                    .unwrap_or_else(|| panic!("advertised schema `{}` must be resolvable", schema.file));
                assert_eq!(served.bytes, schema.bytes, "served bytes must be the embedded bytes");
                assert_eq!(
                    *blake3::hash(served.bytes).as_bytes(),
                    schema.to_schema_ref().hash,
                    "served bytes must BLAKE3-match the pinned hash for `{}`",
                    schema.file
                );
                advertised += 1;
            }
        }
        assert_eq!(
            advertised, 8,
            "expected 4 caps x (in + out) advertised schema documents"
        );
        assert!(schema_document("nonexistent.in.json").is_none());
        assert!(schema_document("").is_none());
    }
}
