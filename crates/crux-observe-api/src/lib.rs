// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Shared wire types for the **agent audit-chain data contract** — the durable
//! backend the agent-observability navigator's *Audit-trail* surface
//! reconstructs from.
//!
//! M0 freezes the `agent_trace_node` projection: its schema, the mapping table
//! from mutation steps to trace nodes, and the reasoning-capture policy. The
//! frozen contract lives here so it is versioned with the code that consumes
//! it. The capture hooks (M2/M3), the reconstruction
//! endpoint (M4), and the verify/export surface (M5) consume these types; the
//! navigator UI ([`crux-agent-observability-graph-2026-05-29`]) consumes them
//! directly so there is a single source of truth for the wire shape (R6).
//!
//! The EU-AI-Act framing per article:
//! - **Art. 12 (record-keeping):** every mutation step resolves to a CROWN
//!   [`TraceNode::receipt_id`]; [`TraceNode::receipt_chain_ok`] is the M6 gate.
//! - **Art. 13 (transparency):** every node is passport-attributed via
//!   [`TraceNode::actor`].
//! - **Art. 15 (accuracy/foresight):** high-risk nodes carry an
//!   [`TraceNode::enrich_ref`] (`/v1/actions/enrich` prediction).
//! - **Art. 10 (data governance):** inputs/reasoning may be PII →
//!   [`TraceNode::private`] defaults `true`.
//!
//! These types are intentionally dependency-light (serde only, no chrono / no
//! ulid): timestamps are RFC-3339 strings and ids are opaque strings so the
//! crate compiles on every target including WASM.

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// Current contract version. Bumped when the `agent_trace_node` schema changes
/// in a way old rows cannot satisfy; rows carry [`TraceNode::contract_version`]
/// so a reader can branch on it rather than orphaning historical nodes.
pub const CONTRACT_VERSION: u32 = 1;

/// Scheme prefix for a `reasoning_ref` that points at a `record_decision` fact.
pub const REASONING_FACT_SCHEME: &str = "fact:";
/// Scheme prefix for a `reasoning_ref` that points at a captured
/// thinking-summary blob written at Stop/PreCompact.
pub const REASONING_BLOB_SCHEME: &str = "blob:";

// ── Enumerations ───────────────────────────────────────────────────────────

/// Position of a node in the session → agent → subagent → tool/step tree.
///
/// `tool_call` and `step` are the leaf kinds that carry the audit chain
/// (`inputs`/`reasoning_ref`/`outputs`/`receipt_id`); the container kinds
/// (`session`/`agent`/`subagent`) group them for the navigator's tree lens.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Session,
    Agent,
    Subagent,
    ToolCall,
    Step,
}

/// Risk class carried per node (Art. 9). Mirrors the ExecPlan risk class so a
/// high-risk step can be required to carry an `enrich_ref` (M6 / Art. 15).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Low,
    Medium,
    High,
}

/// Lifecycle status of a step. These are the canonical **wire** values; the
/// prototype UI renders abbreviated display variants (`run`/`err`) that are a
/// presentation concern and never appear on the wire.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Ok,
    Running,
    Error,
}

/// What the model *saw* — one entry per read / query / cross-linked prior step
/// (Art. 12 input record).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    /// A file (or file-range) read.
    Read,
    /// A retrieval query — carries `hits` + `token_budget`.
    Query,
    /// Provenance cross-link: `reference` is the `node_id` of a prior step
    /// whose output this step consumed.
    PriorStep,
}

/// A command or edit the step *executed* (the output side of the chain).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum OutputKind {
    /// New file written.
    Write,
    /// Existing file edited.
    Edit,
    /// Shell command executed — carries `exit_code`; read-only unless it
    /// produced a `Write`/`Fact` output, so it is not a mutation *by kind*.
    Bash,
    /// A fact stored through the substrate.
    Fact,
    /// The assistant's text answer for the turn — captured by the M3 transcript
    /// ingester. Prose, not a durable mutation, so `is_mutation` is false and no
    /// CROWN receipt is required.
    Answer,
}

impl OutputKind {
    /// Whether an output of this kind mutates durable state and therefore MUST
    /// resolve to a CROWN receipt (R2 / T.4 / Art. 12).
    ///
    /// `Write`, `Edit`, and `Fact` are mutations. `Bash` is *not* classified a
    /// mutation by kind alone — a mutating shell command is represented by the
    /// `Write`/`Fact` outputs it produces (or carries its own receipt), so
    /// classifying it here would either over- or under-count. See the design
    /// doc "reasoning-capture & mutation policy".
    #[must_use]
    pub fn is_mutation(self) -> bool {
        matches!(self, OutputKind::Write | OutputKind::Edit | OutputKind::Fact)
    }
}

// ── reasoning_ref (pointer, never raw chain-of-thought) ──────────────────────

/// A reference to the step's reasoning — **never** raw chain-of-thought (R1).
///
/// Two backends only:
/// - [`ReasoningRef::Fact`] — a `record_decision` fact (explicit, preferred);
///   the payload is the fact locator, e.g. `decision:reconciler-sort`.
/// - [`ReasoningRef::Blob`] — a thinking-summary blob captured at Stop /
///   PreCompact; the payload is the blob path, e.g. `reasoning/<node_id>.txt`.
///
/// On the wire it is a single scheme-prefixed string (`fact:…` / `blob:…`);
/// any other scheme is rejected at deserialise time so the contract can never
/// assert it holds live CoT.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ReasoningRef {
    /// `fact:<locator>` — a `record_decision` fact.
    Fact(String),
    /// `blob:<path>` — a captured thinking-summary blob.
    Blob(String),
}

impl ReasoningRef {
    /// Parse a scheme-prefixed wire string. Returns `None` for an unknown
    /// scheme (the type can only ever name the two sanctioned backends).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        if let Some(rest) = raw.strip_prefix(REASONING_FACT_SCHEME) {
            Some(ReasoningRef::Fact(rest.to_string()))
        } else {
            raw.strip_prefix(REASONING_BLOB_SCHEME)
                .map(|rest| ReasoningRef::Blob(rest.to_string()))
        }
    }

    /// Render to the scheme-prefixed wire string.
    #[must_use]
    pub fn to_wire(&self) -> String {
        match self {
            ReasoningRef::Fact(loc) => format!("{REASONING_FACT_SCHEME}{loc}"),
            ReasoningRef::Blob(path) => format!("{REASONING_BLOB_SCHEME}{path}"),
        }
    }
}

impl Serialize for ReasoningRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_wire())
    }
}

impl<'de> Deserialize<'de> for ReasoningRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        ReasoningRef::parse(&raw).ok_or_else(|| {
            de::Error::custom(format!(
                "reasoning_ref must use the `{REASONING_FACT_SCHEME}` or `{REASONING_BLOB_SCHEME}` scheme, got: {raw:?}"
            ))
        })
    }
}

// ── Sub-structs ──────────────────────────────────────────────────────────────

/// Token usage for a node. Serialises as `{ "in": …, "out": … }` to match the
/// frozen contract; the Rust fields avoid the `in` keyword.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct TokenUsage {
    #[serde(rename = "in")]
    pub input: u64,
    #[serde(rename = "out")]
    pub output: u64,
}

/// One entry in a step's `inputs[]` — what the model saw.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TraceInput {
    #[serde(rename = "type")]
    pub kind: InputKind,
    /// File path (`read`), query string (`query`), or prior step `node_id`
    /// (`prior_step`). Large payloads are a ref + truncated excerpt, never an
    /// inline blob (Art. 10).
    #[serde(rename = "ref")]
    pub reference: String,
    /// Line count read — `read` inputs only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines: Option<u32>,
    /// Hit count returned — `query` inputs only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hits: Option<u32>,
    /// `token_budget` passed on the retrieval — `query` inputs only (QC.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_budget: Option<u32>,
}

impl TraceInput {
    /// A file read.
    #[must_use]
    pub fn read(path: impl Into<String>, lines: u32) -> Self {
        Self {
            kind: InputKind::Read,
            reference: path.into(),
            lines: Some(lines),
            hits: None,
            token_budget: None,
        }
    }

    /// A retrieval query (records the mandatory `token_budget`, QC.2).
    #[must_use]
    pub fn query(query: impl Into<String>, hits: u32, token_budget: u32) -> Self {
        Self {
            kind: InputKind::Query,
            reference: query.into(),
            lines: None,
            hits: Some(hits),
            token_budget: Some(token_budget),
        }
    }

    /// A provenance cross-link to a prior step's `node_id`.
    #[must_use]
    pub fn prior_step(node_id: impl Into<String>) -> Self {
        Self {
            kind: InputKind::PriorStep,
            reference: node_id.into(),
            lines: None,
            hits: None,
            token_budget: None,
        }
    }
}

/// One entry in a step's `outputs[]` — a command or edit the step executed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TraceOutput {
    #[serde(rename = "type")]
    pub kind: OutputKind,
    /// File path (`write`/`edit`), command (`bash`), or fact locator (`fact`).
    #[serde(rename = "ref")]
    pub reference: String,
    /// Lines added — `write`/`edit` outputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<u32>,
    /// Lines removed — `write`/`edit` outputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<u32>,
    /// Process exit code — `bash` outputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// CROWN receipt id for this specific mutation (Art. 12). MUST be present
    /// when [`OutputKind::is_mutation`] is true (R2 / T.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_receipt_id: Option<String>,
}

impl TraceOutput {
    /// Whether this output mutates durable state (delegates to
    /// [`OutputKind::is_mutation`]).
    #[must_use]
    pub fn is_mutation(&self) -> bool {
        self.kind.is_mutation()
    }
}

// ── TraceNode — the agent_trace_node projection row ──────────────────────────

/// One `agent_trace_node` row — a single node in the session trace tree.
///
/// This is the durable, append-only projection the capture hooks write (M1)
/// and the reconstruction endpoint serves (M4). It is the full graph node; the
/// audit-trail surface consumes the narrower [`AuditStep`] projection
/// ([`TraceNode::to_audit_step`]).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TraceNode {
    /// Schema version (defaults to [`CONTRACT_VERSION`] for hand-written rows).
    #[serde(default = "default_contract_version")]
    pub contract_version: u32,
    /// Stable id, e.g. `trace_<ulid>`.
    pub node_id: String,
    /// Owning session, e.g. `execplan:agent-ux-best-in-class-master`.
    pub session_id: String,
    /// Tree edge to the parent node (`None` for the session root).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Monotonic sequence within the session → drives timeline order.
    pub seq: u64,
    pub kind: NodeKind,
    /// Human-facing label, e.g. `Step 2 · write reconciler`.
    pub label: String,
    /// Passport that performed the step (Art. 13). Never empty — anonymous
    /// capture is operator-tagged, not silently allowed (T.3).
    pub actor: String,
    pub risk_class: RiskClass,
    /// RFC-3339 start timestamp.
    pub ts_start: String,
    /// RFC-3339 end timestamp — absent while the step is `running`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenUsage>,
    pub status: StepStatus,

    // ── the audit chain ──────────────────────────────────────────────────
    /// What the model saw (Art. 12 input record).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<TraceInput>,
    /// Pointer to the step's reasoning — a fact or a blob, never raw CoT (R1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_ref: Option<ReasoningRef>,
    /// Commands / edits executed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<TraceOutput>,
    /// CROWN receipt for this step (Art. 12 / T.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// `/v1/actions/enrich` consequence prediction (Art. 15) — high-risk only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrich_ref: Option<String>,
    /// Inputs/reasoning may be PII → localhost-only, never synced (Art. 10).
    /// Defaults `true`: omission must fail safe (T.1).
    #[serde(default = "default_true")]
    pub private: bool,
}

const fn default_contract_version() -> u32 {
    CONTRACT_VERSION
}

const fn default_true() -> bool {
    true
}

impl TraceNode {
    /// Whether this step mutated durable state (any output is a mutation).
    #[must_use]
    pub fn is_mutation_step(&self) -> bool {
        self.outputs.iter().any(TraceOutput::is_mutation)
    }

    /// M6 audit-chain conformance (R2 / T.4 / Art. 12): a step that mutates
    /// durable state MUST carry a step-level `receipt_id` **and** every
    /// mutating output MUST carry its own `mutation_receipt_id`. Non-mutating
    /// steps pass trivially.
    #[must_use]
    pub fn receipt_chain_ok(&self) -> bool {
        if !self.is_mutation_step() {
            return true;
        }
        self.receipt_id.is_some()
            && self
                .outputs
                .iter()
                .filter(|o| o.is_mutation())
                .all(|o| o.mutation_receipt_id.is_some())
    }

    /// M6 attribution conformance (T.3 / Art. 13): every node carries a
    /// non-empty passport `actor`.
    #[must_use]
    pub fn is_attributed(&self) -> bool {
        !self.actor.trim().is_empty()
    }

    /// M6 foresight conformance (Art. 15): a high-risk node MUST carry an
    /// `enrich_ref`. Low/medium risk pass trivially.
    #[must_use]
    pub fn enrich_ok(&self) -> bool {
        self.risk_class != RiskClass::High || self.enrich_ref.is_some()
    }

    /// Project this node to the audit-trail surface's [`AuditStep`] view.
    #[must_use]
    pub fn to_audit_step(&self) -> AuditStep {
        AuditStep {
            node_id: self.node_id.clone(),
            seq: self.seq,
            label: self.label.clone(),
            actor: self.actor.clone(),
            risk_class: self.risk_class,
            ts_start: self.ts_start.clone(),
            ts_end: self.ts_end.clone(),
            status: self.status,
            inputs: self.inputs.clone(),
            reasoning_ref: self.reasoning_ref.clone(),
            outputs: self.outputs.clone(),
            receipt_id: self.receipt_id.clone(),
            enrich_ref: self.enrich_ref.clone(),
            private: self.private,
        }
    }
}

// ── AuditStep — the reconstructed audit-chain entry ──────────────────────────

/// The audit-trail projection of a [`TraceNode`]: the
/// inputs → reasoning → output → receipt chain the EU-AI-Act *Audit-trail*
/// surface renders, with the graph-only fields (`kind`, `parent_id`,
/// `tokens`, `contract_version`) dropped.
///
/// `GET /v1/observe/sessions/{id}/audit` (M4) returns these in `seq` order.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuditStep {
    pub node_id: String,
    pub seq: u64,
    pub label: String,
    pub actor: String,
    pub risk_class: RiskClass,
    pub ts_start: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_end: Option<String>,
    pub status: StepStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<TraceInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_ref: Option<ReasoningRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<TraceOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrich_ref: Option<String>,
    #[serde(default = "default_true")]
    pub private: bool,
}

/// Wire shape for `GET /v1/observe/sessions/{id}/audit` (M4): the ordered,
/// verifiable audit chain for one session.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SessionAudit {
    pub session_id: String,
    pub contract_version: u32,
    pub steps: Vec<AuditStep>,
}

// ── Tests ────────────────────────────────────────────────────────────────────

// Tests round-trip hand-written values and assert against them; `unwrap`/
// `expect`/`assert!` are panic-by-design here. Suppress at module scope to keep
// the workspace `-D warnings` clean.
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    /// serialise → deserialise → re-serialise; assert byte-identical JSON and
    /// equal Rust value. Catches lossy deserialisation and field reordering.
    fn assert_node_roundtrip(node: &TraceNode) {
        let first = serde_json::to_string(node).expect("serialise");
        let parsed: TraceNode = serde_json::from_str(&first).expect("deserialise");
        let second = serde_json::to_string(&parsed).expect("re-serialise");
        assert_eq!(first, second, "round-trip JSON drifted");
        assert_eq!(node, &parsed, "round-trip Rust value drifted");
    }

    // ── The prototype's three mocked audit steps (as1 / as2 / as3) ──────────
    //
    // Source: `Crux/UI-prototype/agent-observability.html` "AUDIT TRAIL" group
    // (au-trail → as1/as2/as3). M0 gate: the schema must faithfully represent
    // each step's inputs → reasoning → output → receipt chain. The prototype's
    // JS objects are graph-render nodes (the parent plan's shape), so we encode
    // the *information they show* as `TraceNode`s and assert it round-trips.

    /// as1 — "diagnose M4 reconciler", read-only, receipt crn_8f21…, risk low.
    fn proto_step_1() -> TraceNode {
        TraceNode {
            contract_version: CONTRACT_VERSION,
            node_id: "trace_as1".into(),
            session_id: "execplan:agent-ux-best-in-class-master".into(),
            parent_id: Some("trace_session".into()),
            seq: 1,
            kind: NodeKind::Step,
            label: "Step 1 · diagnose M4 reconciler".into(),
            actor: "ce:4e6c4e2a:local".into(),
            risk_class: RiskClass::Low,
            ts_start: "2026-05-27T13:05:00Z".into(),
            ts_end: Some("2026-05-27T13:05:40Z".into()),
            tokens: Some(TokenUsage {
                input: 1420,
                output: 210,
            }),
            status: StepStatus::Ok,
            inputs: vec![
                TraceInput::read("corecruxd/src/http/work.rs", 214),
                TraceInput::read("corecrux-memory/src/projection.rs", 96),
                TraceInput::query("reconcile projection", 4, 2000),
            ],
            reasoning_ref: Some(ReasoningRef::Blob("reasoning/trace_as1.txt".into())),
            outputs: vec![], // diagnosis only — no mutation
            receipt_id: Some("crn_8f21".into()),
            enrich_ref: None,
            private: true,
        }
    }

    /// as2 — "write reconciler", mutation (write + edit), receipt crn_b033…,
    /// risk medium, status running. Provenance cross-links back to as1.
    fn proto_step_2() -> TraceNode {
        TraceNode {
            contract_version: CONTRACT_VERSION,
            node_id: "trace_as2".into(),
            session_id: "execplan:agent-ux-best-in-class-master".into(),
            parent_id: Some("trace_session".into()),
            seq: 2,
            kind: NodeKind::Step,
            label: "Step 2 · write reconciler".into(),
            actor: "ce:4e6c4e2a:local".into(),
            risk_class: RiskClass::Medium,
            ts_start: "2026-05-27T13:14:02Z".into(),
            ts_end: Some("2026-05-27T13:14:09Z".into()),
            tokens: Some(TokenUsage {
                input: 1840,
                output: 320,
            }),
            status: StepStatus::Running,
            inputs: vec![TraceInput::prior_step("trace_as1")],
            reasoning_ref: Some(ReasoningRef::Fact("decision:reconciler-sort".into())),
            outputs: vec![
                TraceOutput {
                    kind: OutputKind::Write,
                    reference: "corecruxd/src/http/reconcile.rs".into(),
                    added: Some(140),
                    removed: Some(0),
                    exit_code: None,
                    mutation_receipt_id: Some("crn_b033".into()),
                },
                TraceOutput {
                    kind: OutputKind::Edit,
                    reference: "corecrux-memory/src/projection.rs".into(),
                    added: Some(33),
                    removed: Some(12),
                    exit_code: None,
                    mutation_receipt_id: Some("crn_b033".into()),
                },
            ],
            receipt_id: Some("crn_b033".into()),
            enrich_ref: None,
            private: true,
        }
    }

    /// as3 — "run tests", bash exit 101 (read-only), receipt crn_c7a9…, status
    /// error, risk low.
    fn proto_step_3() -> TraceNode {
        TraceNode {
            contract_version: CONTRACT_VERSION,
            node_id: "trace_as3".into(),
            session_id: "execplan:agent-ux-best-in-class-master".into(),
            parent_id: Some("trace_session".into()),
            seq: 3,
            kind: NodeKind::Step,
            label: "Step 3 · run tests".into(),
            actor: "ce:4e6c4e2a:local".into(),
            risk_class: RiskClass::Low,
            ts_start: "2026-05-27T13:20:00Z".into(),
            ts_end: Some("2026-05-27T13:24:00Z".into()),
            tokens: None,
            status: StepStatus::Error,
            inputs: vec![TraceInput::read("corecruxd/tests/reconcile_test.rs", 60)],
            reasoning_ref: Some(ReasoningRef::Blob("reasoning/trace_as3.txt".into())),
            outputs: vec![TraceOutput {
                kind: OutputKind::Bash,
                reference: "cargo test reconcile".into(),
                added: None,
                removed: None,
                exit_code: Some(101),
                mutation_receipt_id: None,
            }],
            receipt_id: Some("crn_c7a9".into()),
            enrich_ref: None,
            private: true,
        }
    }

    #[test]
    fn prototype_steps_roundtrip() {
        for node in [proto_step_1(), proto_step_2(), proto_step_3()] {
            assert_node_roundtrip(&node);
        }
    }

    #[test]
    fn prototype_chain_is_faithful() {
        // as1: read-only diagnosis → not a mutation step, no outputs.
        let s1 = proto_step_1();
        assert!(!s1.is_mutation_step());
        assert_eq!(s1.inputs.len(), 3);
        assert_eq!(
            s1.inputs[2].token_budget,
            Some(2000),
            "query input keeps token_budget (QC.2)"
        );

        // as2: write+edit mutations → must carry step receipt + per-output ids.
        let s2 = proto_step_2();
        assert!(s2.is_mutation_step());
        assert!(
            s2.receipt_chain_ok(),
            "every mutation output has a mutation_receipt_id + step receipt"
        );
        // Provenance cross-link to as1.
        assert_eq!(s2.inputs[0].kind, InputKind::PriorStep);
        assert_eq!(s2.inputs[0].reference, "trace_as1");

        // as3: bash exit 101 is read-only by kind → not a mutation step.
        let s3 = proto_step_3();
        assert!(!s3.is_mutation_step(), "a bash run is not a mutation by kind");
        assert_eq!(s3.outputs[0].exit_code, Some(101));
    }

    #[test]
    fn audit_chain_gap_is_detected() {
        // A mutation step missing its receipt must fail receipt_chain_ok (R2).
        let mut bad = proto_step_2();
        bad.receipt_id = None;
        assert!(!bad.receipt_chain_ok(), "mutation step with no step receipt must fail");

        let mut bad2 = proto_step_2();
        bad2.outputs[0].mutation_receipt_id = None;
        assert!(!bad2.receipt_chain_ok(), "mutating output with no receipt must fail");
    }

    #[test]
    fn high_risk_requires_enrich_ref() {
        let mut node = proto_step_2();
        node.risk_class = RiskClass::High;
        node.enrich_ref = None;
        assert!(
            !node.enrich_ok(),
            "high-risk node without enrich_ref must fail (Art. 15)"
        );
        node.enrich_ref = Some("enrich_42".into());
        assert!(node.enrich_ok());
        // Medium/low never require it.
        assert!(proto_step_2().enrich_ok());
    }

    #[test]
    fn attribution_required() {
        let mut node = proto_step_1();
        assert!(node.is_attributed());
        node.actor = "  ".into();
        assert!(!node.is_attributed(), "blank passport actor is not attribution (T.3)");
    }

    #[test]
    fn reasoning_ref_rejects_unknown_scheme() {
        // fact: and blob: parse; anything else is rejected on the wire (R1).
        assert_eq!(
            ReasoningRef::parse("fact:decision:x"),
            Some(ReasoningRef::Fact("decision:x".into()))
        );
        assert_eq!(
            ReasoningRef::parse("blob:reasoning/x.txt"),
            Some(ReasoningRef::Blob("reasoning/x.txt".into()))
        );
        assert_eq!(ReasoningRef::parse("cot:raw-thoughts"), None);

        // Deserialise rejects an unknown scheme rather than silently accepting
        // a raw chain-of-thought string.
        let err = serde_json::from_str::<ReasoningRef>("\"cot:secret\"");
        assert!(err.is_err(), "unknown reasoning_ref scheme must fail to deserialise");

        // Round-trip both backends through the wire string form.
        for r in [
            ReasoningRef::Fact("decision:reconciler-sort".into()),
            ReasoningRef::Blob("reasoning/trace_as1.txt".into()),
        ] {
            let s = serde_json::to_string(&r).unwrap();
            let parsed: ReasoningRef = serde_json::from_str(&s).unwrap();
            assert_eq!(parsed, r);
        }
    }

    #[test]
    fn token_usage_serialises_as_in_out() {
        let s = serde_json::to_string(&TokenUsage {
            input: 1840,
            output: 320,
        })
        .unwrap();
        assert_eq!(s, r#"{"in":1840,"out":320}"#);
    }

    #[test]
    fn private_defaults_true_when_omitted() {
        // A row that omits `private` must fail safe to private (Art. 10 / T.1).
        let raw = r#"{
            "node_id": "trace_x",
            "session_id": "s",
            "seq": 1,
            "kind": "step",
            "label": "x",
            "actor": "ce:1:local",
            "risk_class": "low",
            "ts_start": "2026-05-27T00:00:00Z",
            "status": "ok"
        }"#;
        let node: TraceNode = serde_json::from_str(raw).expect("deserialise minimal node");
        assert!(node.private, "omitted private must default to true");
        assert_eq!(
            node.contract_version, CONTRACT_VERSION,
            "omitted contract_version defaults"
        );
        assert!(node.inputs.is_empty());
        assert!(node.outputs.is_empty());
    }

    #[test]
    fn node_kind_wire_values() {
        // The container + leaf kinds serialise snake_case (tool_call, not ToolCall).
        assert_eq!(serde_json::to_string(&NodeKind::ToolCall).unwrap(), "\"tool_call\"");
        assert_eq!(serde_json::to_string(&NodeKind::Step).unwrap(), "\"step\"");
        assert_eq!(serde_json::to_string(&InputKind::PriorStep).unwrap(), "\"prior_step\"");
        assert_eq!(serde_json::to_string(&StepStatus::Running).unwrap(), "\"running\"");
    }

    #[test]
    fn to_audit_step_preserves_chain() {
        let node = proto_step_2();
        let step = node.to_audit_step();
        assert_eq!(step.node_id, node.node_id);
        assert_eq!(step.seq, node.seq);
        assert_eq!(step.inputs, node.inputs);
        assert_eq!(step.outputs, node.outputs);
        assert_eq!(step.reasoning_ref, node.reasoning_ref);
        assert_eq!(step.receipt_id, node.receipt_id);

        // SessionAudit round-trips the ordered chain.
        let audit = SessionAudit {
            session_id: node.session_id.clone(),
            contract_version: CONTRACT_VERSION,
            steps: vec![proto_step_1().to_audit_step(), step, proto_step_3().to_audit_step()],
        };
        let s = serde_json::to_string(&audit).unwrap();
        let parsed: SessionAudit = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, audit);
        assert_eq!(parsed.steps.len(), 3);
        assert_eq!(parsed.steps[0].seq, 1);
    }
}
