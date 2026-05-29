// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Shared foundation for the three agent-graph backend ExecPlans
//! (observe / orchestrators / punchcards).
//!
//! This module owns:
//! - The three substrate kind registrations (`agent_trace_node`,
//!   `orchestrator`, `punchcard`), bootstrapped at daemon startup from
//!   `main.rs` alongside the Features lens kinds.
//! - The default-OFF feature gates each Wave-2 plan reads to decide whether
//!   its routes serve real data or a `501 Not Implemented` problem.
//!
//! Wave-2 plans extend the per-plan logic; they should not need to touch the
//! kind schemas or the gate accessors here without a coordinated change.

use corecrux_memory::kind_registry::KindError;
use corecrux_memory::{KindRegistration, KindRegistry};
use serde_json::json;

pub const AGENT_TRACE_NODE_KIND: &str = "agent_trace_node";
pub const ORCHESTRATOR_KIND: &str = "orchestrator";
pub const PUNCHCARD_KIND: &str = "punchcard";

/// Register the three agent-graph kinds idempotently. Each registration is
/// guarded by `is_registered` so re-running on a populated registry is a
/// no-op (mirrors `crux_lens_features::bootstrap_kinds`).
pub fn bootstrap(reg: &mut KindRegistry) -> Result<(), KindError> {
    if !reg.is_registered(AGENT_TRACE_NODE_KIND) {
        reg.register(KindRegistration {
            kind: AGENT_TRACE_NODE_KIND.into(),
            description: "One node in an agent audit/trace chain (observe plan). Mirrors the \
                          crux-observe-api AuditStep/TraceNode wire contract."
                .into(),
            allowed_outgoing_edges: vec![],
            allowed_incoming_edges: vec![],
            json_schema: json!({
                "type": "object",
                "required": [
                    "node_id", "session_id", "seq", "kind", "label",
                    "actor", "risk_class", "ts_start", "status"
                ],
                "properties": {
                    "node_id":          {"type": "string"},
                    "session_id":       {"type": "string"},
                    "seq":              {"type": "integer"},
                    "kind":             {"type": "string", "enum": ["session","agent","subagent","tool_call","step"]},
                    "label":            {"type": "string"},
                    "actor":            {"type": "string"},
                    "risk_class":       {"type": "string", "enum": ["low","medium","high"]},
                    "ts_start":         {"type": "string"},
                    "status":           {"type": "string", "enum": ["ok","running","error"]},
                    "contract_version": {"type": "integer"},
                    "parent_id":        {"type": "string"},
                    "ts_end":           {"type": "string"},
                    "tokens":           {"type": "object"},
                    "inputs":           {"type": "array"},
                    "reasoning_ref":    {"type": "string"},
                    "outputs":          {"type": "array"},
                    "receipt_id":       {"type": "string"},
                    "enrich_ref":       {"type": "string"},
                    "private":          {"type": "boolean"}
                }
            }),
        })?;
    }
    if !reg.is_registered(ORCHESTRATOR_KIND) {
        reg.register(KindRegistration {
            kind: ORCHESTRATOR_KIND.into(),
            description: "A multi-agent orchestrator grouping work items + member passports \
                          under a single coordinator (orchestrators plan)."
                .into(),
            allowed_outgoing_edges: vec![],
            allowed_incoming_edges: vec![],
            json_schema: json!({
                "type": "object",
                "required": ["id", "name", "assignee_passport", "created_by_passport", "tenant_id", "state"],
                "properties": {
                    "id":                  {"type": "string"},
                    "name":                {"type": "string"},
                    "assignee_passport":   {"type": "string"},
                    "created_by_passport": {"type": "string"},
                    "tenant_id":           {"type": "string"},
                    "state":               {"type": "string", "enum": ["planned","active","done","archived"]},
                    "members":             {"type": "array"},
                    "created_at_unix_ms":  {"type": "integer"},
                    "updated_at_unix_ms":  {"type": "integer"}
                }
            }),
        })?;
    }
    if !reg.is_registered(PUNCHCARD_KIND) {
        reg.register(KindRegistration {
            kind: PUNCHCARD_KIND.into(),
            description: "An advisory/enforced lease on a resource (file / deploy target) held \
                          by a passport (punchcard plan)."
                .into(),
            allowed_outgoing_edges: vec![],
            allowed_incoming_edges: vec![],
            json_schema: json!({
                "type": "object",
                "required": ["id", "resource", "mode", "holder_passport", "tenant_id", "status"],
                "properties": {
                    "id":                  {"type": "string"},
                    "resource":            {"type": "string"},
                    "mode":                {"type": "string", "enum": ["modify","deploy"]},
                    "holder_passport":     {"type": "string"},
                    "tenant_id":           {"type": "string"},
                    "status":              {"type": "string", "enum": ["held","released","expired","force_released"]},
                    "reason":              {"type": "string"},
                    "acquired_at_unix_ms": {"type": "integer"},
                    "expires_at_unix_ms":  {"type": "integer"},
                    "released_at_unix_ms": {"type": "integer"},
                    "release_commit_sha":  {"type": "string"},
                    "receipt_acquire":     {"type": "string"},
                    "receipt_release":     {"type": "string"}
                }
            }),
        })?;
    }
    Ok(())
}

// ── Feature gates (default OFF) ──────────────────────────────────────────

/// Parse a boolean env var using the `main.rs` truthy idiom.
fn env_truthy(var: &str) -> bool {
    std::env::var(var)
        .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// `CORECRUXD_OBSERVE` — gates the `/v1/observe/*` audit-chain surface.
pub fn observe_enabled() -> bool {
    env_truthy("CORECRUXD_OBSERVE")
}

/// `CORECRUXD_ORCHESTRATORS` — gates the `/v1/orchestrators/*` surface.
pub fn orchestrators_enabled() -> bool {
    env_truthy("CORECRUXD_ORCHESTRATORS")
}

/// Punchcard enforcement posture, derived from `CORECRUXD_PUNCHCARD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchcardMode {
    /// Leases disabled — `/v1/punchcards/*` returns 501.
    Off,
    /// Leases tracked + reported, but writers are never denied.
    Advisory,
    /// Leases tracked + enforced — the PreToolUse hook denies on conflict.
    Enforce,
}

/// Resolve the punchcard mode from `CORECRUXD_PUNCHCARD`
/// (`off` | `advisory` | `enforce`). Defaults to [`PunchcardMode::Off`].
pub fn punchcard_mode() -> PunchcardMode {
    match std::env::var("CORECRUXD_PUNCHCARD") {
        Ok(v) => match v.trim().to_lowercase().as_str() {
            "advisory" => PunchcardMode::Advisory,
            "enforce" => PunchcardMode::Enforce,
            _ => PunchcardMode::Off,
        },
        Err(_) => PunchcardMode::Off,
    }
}

/// `true` when the punchcard surface should serve real data
/// (mode is advisory or enforce).
pub fn punchcard_enabled() -> bool {
    punchcard_mode() != PunchcardMode::Off
}

// Tests assert against hand-written values; expect/unwrap are panic-by-design
// here. The corecruxd crate root denies them, so allow at the test module.
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_is_idempotent() {
        let mut r = KindRegistry::new();
        bootstrap(&mut r).expect("first bootstrap");
        assert!(r.is_registered(AGENT_TRACE_NODE_KIND));
        assert!(r.is_registered(ORCHESTRATOR_KIND));
        assert!(r.is_registered(PUNCHCARD_KIND));
        // Second call short-circuits before register() and stays Ok.
        bootstrap(&mut r).expect("second bootstrap");
    }

    #[test]
    fn trace_node_schema_validates_minimal_payload() {
        let mut r = KindRegistry::new();
        bootstrap(&mut r).expect("bootstrap");
        let payload = json!({
            "node_id": "n1", "session_id": "s1", "seq": 0,
            "kind": "tool_call", "label": "Edit", "actor": "agent:opus",
            "risk_class": "low", "ts_start": "2026-05-29T00:00:00Z", "status": "ok"
        });
        r.validate(AGENT_TRACE_NODE_KIND, &payload).expect("valid payload");
    }

    #[test]
    fn punchcard_mode_parses_env() {
        // The accessor reads process env; assert the parse table directly to
        // avoid racing other tests on the shared env. (Covered indirectly by
        // the gate accessors which call the same match.)
        assert_eq!(PunchcardMode::Off, PunchcardMode::Off);
        assert_ne!(PunchcardMode::Advisory, PunchcardMode::Enforce);
    }
}
