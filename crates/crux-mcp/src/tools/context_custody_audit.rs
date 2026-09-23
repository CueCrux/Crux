// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `context_custody_audit` — score this Crux instance against the
//! "race to context" exit test.
//!
//! The market thesis (see PlanCrux `docs/vision/race-to-context-positioning`)
//! is that an AI tool's durable value is *placement of context*, and its
//! durable danger is *lock-in* — the same context that makes it useful makes
//! it expensive to leave. The audit answers the two checklists from that note,
//! against the live daemon, with each verdict backed by a real capability:
//!
//! * The four questions — **SEE / DO / REMEMBER / CHECK**.
//! * The exit test — **EXPORT / INSPECT / REVOKE / ROUTE / KEEP-LOCAL / PROVE**.
//!
//! It is a pure read: it reads runtime flags, [`McpContext`] capability
//! presence and the caller's passport standing, never mutates. Crucially it reports the *runtime* state (a
//! capability that exists in code but is flag-gated OFF is `partial`, not
//! `strong`) so the scorecard cannot overclaim — including Crux's own honest
//! gap (PROVE: witness proofs exist but no dedicated end-to-end custody-proof
//! tool is exposed yet).
//!
//! Handler-gated behind `CRUX_CONTEXT_CUSTODY_AUDIT` (default OFF), matching
//! the additive/flag-gated norm for new surfaces (cf. `audit_export_bundle`,
//! passport-revocation, agent-card).

use corecrux_receipts::{export_identity_posture_v1, ExportIdentityPostureV1, EXPORT_VERIFY_PUBLIC_KEY_ENV};
use serde_json::{json, Value};

use crate::category_enforce::passport_category_for;
use crate::dispatch::{McpContext, SERVER_VERSION};
use crate::protocol::JsonRpcError;
use crate::tools::passport::get_agent_passport;

/// Feature flag (default OFF). When unset, the tool returns a short disabled
/// notice rather than running — so shipping the binary doesn't expose the
/// surface until an operator opts in.
pub const FEATURE_FLAG_ENV: &str = "CRUX_CONTEXT_CUSTODY_AUDIT";

/// Returns `true` for `1` / `true` / `yes` (case-insensitive), matching the
/// flag-reading idiom used elsewhere in the crate.
fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn env_set_nonempty(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|v| !v.trim().is_empty())
}

/// Is the audit surface enabled for this process?
pub fn audit_enabled() -> bool {
    env_flag(FEATURE_FLAG_ENV)
}

/// JSON-Schema for the tool's input. The only knob is an optional
/// `token_budget` (the scorecard is fixed-size, so it is advisory here — kept
/// for surface consistency with the rest of the retrieval-adjacent tools).
pub fn tool_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "token_budget": {
                "type": "integer",
                "description": "Advisory output budget; the scorecard is fixed-size."
            }
        },
        "examples": [{}, { "token_budget": 500 }]
    })
}

pub const CONTEXT_CUSTODY_AUDIT_DESCRIPTION: &str =
    "Score THIS Crux instance against the context-custody exit test: the four \
     questions (SEE / DO / REMEMBER / CHECK) and the exit test (EXPORT / INSPECT \
     / REVOKE / ROUTE / KEEP-LOCAL / PROVE). Pure read. Each verdict reports the \
     RUNTIME state (a flag-gated-OFF capability is `partial`, not `strong`) for \
     the calling agent's passport, and cites the backing capability, so the scorecard never overclaims. Returns a \
     lock-in risk (1 trivial-to-leave .. 5 hostage) and a trust posture. Gated \
     behind CRUX_CONTEXT_CUSTODY_AUDIT.";

/// Runtime inputs gathered from env + [`McpContext`]. Kept as a plain struct so
/// [`build_scorecard`] is a pure, unit-testable function with no env or lock
/// access.
#[derive(Debug, Clone)]
pub struct CustodyInputs {
    /// `CRUX_PASSPORT_REVOCATION` — canonical runtime value off `McpContext`.
    pub revocation_enforced: bool,
    /// `CRUX_AGENT_CARD` — `/.well-known/agent-card` discovery exposed.
    pub agent_card_enabled: bool,
    /// `CORECRUXD_FEATURE_RECEIPT_VERIFY` — the `receipt_verify` tool is live.
    pub receipt_verify_enabled: bool,
    /// `CORECRUXD_FEATURE_AUDIT_EXPORT` — the online `audit_export_bundle` path.
    pub audit_export_online: bool,
    /// An RCX router is wired (token-gated hosted/customer-hosted backends).
    pub router_present: bool,
    /// A remote sync target is configured (else this node is local-only).
    pub sync_remote_configured: bool,
    /// Local fact count — context surface size.
    pub fact_count: usize,
    /// D1: the calling agent's passport standing — REMEMBER is scored for the
    /// caller, not for the daemon.
    pub caller_passport: CallerPassport,
    /// D1: whether an export from this node can be traced to a pinned signer
    /// (the D2 contract) — PROVE is only `strong` when it can.
    pub export_identity: ExportIdentityPostureV1,
}

/// The calling agent's passport standing, judged the way `store_fact` judges it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerPassport {
    /// A live passport that can write.
    Usable,
    /// Anonymous caller, or no passport issued.
    Missing,
    /// The passport has been revoked.
    Revoked,
    /// Agent passports are enforced and no category resolves for this caller,
    /// so `store_fact` refuses every write.
    NoCategory,
}

impl CallerPassport {
    /// Resolve the caller's standing from the fact store.
    pub async fn resolve(ctx: &McpContext) -> Self {
        let Some(scope_id) = ctx.scope_identity() else {
            return Self::Missing;
        };
        let record = get_agent_passport(ctx).await;
        if record.as_ref().is_some_and(|p| p.revoked_at.is_some()) {
            return Self::Revoked;
        }
        if ctx.agent_passports_enabled {
            // The same category lookup store_fact's write enforcement runs.
            let store = ctx.fact_store.read().await;
            return if passport_category_for(&store, &scope_id).is_some() {
                Self::Usable
            } else {
                Self::NoCategory
            };
        }
        if record.is_some() {
            Self::Usable
        } else {
            Self::Missing
        }
    }

    /// Why the caller cannot use its passport, or `None` when it can.
    fn gap(self) -> Option<&'static str> {
        match self {
            Self::Usable => None,
            Self::Missing => Some("this caller has no passport"),
            Self::Revoked => Some("this caller's passport is revoked"),
            Self::NoCategory => Some("this caller's passport carries no category, so store_fact refuses its writes"),
        }
    }
}

impl CustodyInputs {
    /// Gather inputs from process env + the request context.
    pub fn gather(ctx: &McpContext, fact_count: usize, caller_passport: CallerPassport) -> Self {
        Self {
            // Prefer the threaded runtime value over re-reading env, so a
            // test that sets it via `with_revocation_enforced` is honoured.
            revocation_enforced: ctx.revocation_enforced,
            // Use the same resolver as the live gate so the scorecard reflects
            // the launch default (agent-card ON unless CRUX_AGENT_CARD=0).
            agent_card_enabled: crate::server::agent_card_enabled(),
            receipt_verify_enabled: env_flag("CORECRUXD_FEATURE_RECEIPT_VERIFY"),
            audit_export_online: env_flag("CORECRUXD_FEATURE_AUDIT_EXPORT"),
            router_present: ctx.rcx_router.is_some(),
            sync_remote_configured: env_set_nonempty("CORECRUXD_SYNC_REMOTE_URL"),
            fact_count,
            caller_passport,
            export_identity: export_identity_posture_v1(),
        }
    }
}

fn axis(id: &str, question: &str, verdict: &str, evidence: String) -> Value {
    json!({ "axis": id, "question": question, "verdict": verdict, "evidence": evidence })
}

fn on_off(b: bool) -> &'static str {
    if b {
        "ON"
    } else {
        "OFF"
    }
}

/// Build the 10-axis scorecard. Pure: depends only on [`CustodyInputs`].
pub fn build_scorecard(inputs: &CustodyInputs) -> Value {
    // ── The four questions ─────────────────────────────────────────────
    let see = axis(
        "SEE",
        "What context can it reach without me pasting it in?",
        "strong",
        "query / query_scan / query_expand (BM25 + graph fusion); token_budget enforced per call (budget.rs)"
            .to_string(),
    );
    let do_ = axis(
        "DO",
        "What actions can it take where the work happens?",
        "strong",
        "every state mutation emits a CROWN receipt (corecrux-receipts); high-risk actions pre-checked via enrich_action".to_string(),
    );
    // REMEMBER answers for the caller: a daemon that can remember is no use to
    // an agent whose own passport cannot write.
    let caller_gap = inputs.caller_passport.gap();
    let remember = axis(
        "REMEMBER",
        "What does it accumulate, and where does that memory live?",
        if caller_gap.is_none() { "strong" } else { "partial" },
        format!(
            "store_fact / query_facts over {} local fact(s); freshness horizon_class + supersedes keep recall honest; private facts scoped to the agent (fact_store.rs); caller passport: {}",
            inputs.fact_count,
            caller_gap.unwrap_or("usable")
        ),
    );
    let check_verdict = if inputs.receipt_verify_enabled {
        "strong"
    } else {
        "partial"
    };
    let check = axis(
        "CHECK",
        "How do I verify what it actually did?",
        check_verdict,
        format!(
            "CROWN receipts + entity timeline projection; receipt_verify is {} (CORECRUXD_FEATURE_RECEIPT_VERIFY)",
            on_off(inputs.receipt_verify_enabled)
        ),
    );

    // ── The exit test ──────────────────────────────────────────────────
    // EXPORT is structurally strong: the offline path (corecruxctl
    // context-export / memory export) is always available regardless of
    // flags; the online MCP path adds convenience when enabled.
    let export = axis(
        "EXPORT",
        "Can I leave with my context in a usable form?",
        "strong",
        format!(
            "corecruxctl context export — one signed, re-importable bundle of facts + sessions + receipts (offline, always available); online audit_export_bundle is {} (CORECRUXD_FEATURE_AUDIT_EXPORT)",
            on_off(inputs.audit_export_online)
        ),
    );
    let inspect = axis(
        "INSPECT",
        "Can I see everything it holds about me, in full?",
        "strong",
        "memory_view + entity timeline + CROWN receipts expose the full held context".to_string(),
    );
    let revoke_verdict = if inputs.revocation_enforced {
        "strong"
    } else {
        "partial"
    };
    let revoke = axis(
        "REVOKE",
        "Can I cut off its access, auditably?",
        revoke_verdict,
        format!(
            "passport revocation reduces a revoked passport to read-only — CRUX_PASSPORT_REVOCATION is {}; agent-card discovery CRUX_AGENT_CARD is {}",
            on_off(inputs.revocation_enforced),
            on_off(inputs.agent_card_enabled)
        ),
    );
    // ROUTE: even with no hosted router, the substrate is model-agnostic by
    // construction (context-provider: the reasoning LLM is brought per-query),
    // so absence of a router is `partial`, never a lock-in.
    let route_verdict = if inputs.router_present { "strong" } else { "partial" };
    let route = axis(
        "ROUTE",
        "Can I point the same context at a different model?",
        route_verdict,
        format!(
            "substrate is model-agnostic (packed claims + lanes + receipts built once; reasoning LLM brought per-query); RCX router is {}",
            if inputs.router_present { "wired (token-gated hosted/customer-hosted backends)" } else { "absent (local-only — still model-agnostic)" }
        ),
    );
    let keep_local = axis(
        "KEEP-LOCAL",
        "Can sensitive context stay on my machine, provably?",
        "strong",
        format!(
            "private:true facts never push — sync skips them on both promote and pull (sync.rs); this node is {}",
            if inputs.sync_remote_configured {
                "remote-sync configured"
            } else {
                "local-only (no network required)"
            }
        ),
    );
    // PROVE: a signed custody-proof export ships (`corecruxctl context export`
    // → `context verify`), but until an expected export signer is pinned every
    // export verifies against the key embedded in it — internal consistency,
    // not proof of origin — so PROVE is only strong when pinned.
    let export_pinned = inputs.export_identity.is_pinned();
    let prove = axis(
        "PROVE",
        "Can I produce evidence of what it saw and did?",
        if export_pinned { "strong" } else { "partial" },
        format!(
            "corecruxctl context export emits a passport-signed custody proof (manifest binds cruxpack + audit-bundle hashes + an offline audit-verify report); context verify re-checks it offline. Export signer: {} ({EXPORT_VERIFY_PUBLIC_KEY_ENV}). receipt_verify (per-receipt) is {}. Transparency-log witness inclusion stays optional.",
            inputs.export_identity.label(),
            on_off(inputs.receipt_verify_enabled)
        ),
    );

    // ── Summary scores ─────────────────────────────────────────────────
    // Lock-in is about whether you can WALK AWAY with your context. EXPORT and
    // KEEP-LOCAL dominate; ROUTE matters only when the context is welded to one
    // model. REVOKE/PROVE are trust axes (reported separately), not lock-in.
    let mut lock_in: u8 = 1;
    if export["verdict"] != "strong" {
        lock_in += 2;
    }
    if keep_local["verdict"] != "strong" {
        lock_in += 1;
    }
    if route["verdict"] == "none" {
        lock_in += 1;
    }
    let lock_in_risk = lock_in.min(5);
    let lock_in_label = match lock_in_risk {
        1 | 2 => "trivial to leave",
        3 => "moderate",
        _ => "hard / hostage",
    };

    // Trust posture: which production-recommended flags are still OFF + the
    // standing gap. Kept separate from lock-in so a local node that is trivial
    // to leave still gets told to turn on revocation/verification for prod.
    let mut trust_recommendations: Vec<String> = Vec::new();
    if !inputs.revocation_enforced {
        trust_recommendations.push("set CRUX_PASSPORT_REVOCATION=1 to make access revocable".to_string());
    }
    if !inputs.receipt_verify_enabled {
        trust_recommendations.push("set CORECRUXD_FEATURE_RECEIPT_VERIFY=1 to expose receipt_verify".to_string());
    }
    if !inputs.agent_card_enabled {
        trust_recommendations.push("set CRUX_AGENT_CARD=1 for agent-card discovery".to_string());
    }

    let mut gaps: Vec<String> = Vec::new();
    if let Some(gap) = caller_gap {
        gaps.push(gap.to_string());
    }
    if !export_pinned {
        gaps.push(format!(
            "export signer {} — set {EXPORT_VERIFY_PUBLIC_KEY_ENV} to pin it",
            inputs.export_identity.label()
        ));
    }
    let standing_gap = if gaps.is_empty() {
        "none — signed custody-proof export with a pinned signer (corecruxctl context export -> context verify); transparency-log witness inclusion remains optional".to_string()
    } else {
        gaps.join("; ")
    };

    json!({
        "daemon_version": SERVER_VERSION,
        "four_questions": [see, do_, remember, check],
        "exit_test": [export, inspect, revoke, route, keep_local, prove],
        "lock_in_risk": lock_in_risk,
        "lock_in_label": lock_in_label,
        "trust_posture": {
            "recommendations": trust_recommendations,
            "standing_gap": standing_gap
        },
        "thesis": "A substrate you can leave is the product: useful (strong on the four questions) AND low lock-in (you keep custody, can export, and route to any model).",
        "note": "Verdicts reflect this process's RUNTIME flags, not just what exists in code. A flag-gated-OFF capability is reported `partial`. REMEMBER is scored for the calling agent's passport; PROVE for whether the export signer is pinned."
    })
}

/// `context_custody_audit` handler.
pub async fn handle_context_custody_audit(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !audit_enabled() {
        let text = serde_json::to_string_pretty(&json!({
            "enabled": false,
            "note": format!("context-custody audit is disabled; set {FEATURE_FLAG_ENV}=1 to enable"),
        }))
        .unwrap_or_default();
        return Ok(json!({ "content": [{ "type": "text", "text": text }] }));
    }

    let fact_count = ctx.fact_store.read().await.count();
    let caller_passport = CallerPassport::resolve(ctx).await;
    let inputs = CustodyInputs::gather(ctx, fact_count, caller_passport);
    let scorecard = build_scorecard(&inputs);
    let text = serde_json::to_string_pretty(&scorecard).unwrap_or_default();
    Ok(json!({ "content": [{ "type": "text", "text": text }] }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::tools::passport::{handle_issue_passport, handle_revoke_passport};
    use corecrux_memory::fact_store::StoreFact;

    fn inputs(strong: bool) -> CustodyInputs {
        CustodyInputs {
            revocation_enforced: strong,
            agent_card_enabled: strong,
            receipt_verify_enabled: strong,
            audit_export_online: strong,
            router_present: strong,
            sync_remote_configured: false,
            fact_count: 42,
            caller_passport: if strong {
                CallerPassport::Usable
            } else {
                CallerPassport::Missing
            },
            export_identity: if strong {
                ExportIdentityPostureV1::Pinned
            } else {
                ExportIdentityPostureV1::Unpinned
            },
        }
    }

    fn with_agent(ctx: &McpContext, name: &str) -> McpContext {
        ctx.with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        })
    }

    fn find<'a>(card: &'a Value, group: &str, id: &str) -> &'a Value {
        card[group]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["axis"] == id)
            .unwrap_or_else(|| panic!("axis {id} missing from {group}"))
    }

    #[test]
    fn all_flags_on_is_low_lock_in_and_all_exit_axes_strong() {
        let card = build_scorecard(&inputs(true));
        // The four questions are all strong when verification is on.
        for id in ["SEE", "DO", "REMEMBER", "CHECK"] {
            assert_eq!(find(&card, "four_questions", id)["verdict"], "strong", "{id}");
        }
        // Every exit-test axis is strong with flags on, including PROVE now that
        // the signed custody-proof export ships (context-export/context-verify).
        for id in ["EXPORT", "INSPECT", "REVOKE", "ROUTE", "KEEP-LOCAL", "PROVE"] {
            assert_eq!(find(&card, "exit_test", id)["verdict"], "strong", "{id}");
        }
        // Trivial to leave.
        assert_eq!(card["lock_in_risk"], 1);
        assert_eq!(card["lock_in_label"], "trivial to leave");
        // Usable caller passport + pinned export signer: no standing gap.
        let gap = card["trust_posture"]["standing_gap"].as_str().unwrap();
        assert!(gap.starts_with("none"), "{gap}");
    }

    /// D1: a caller that cannot write must not be told REMEMBER is strong, and
    /// the standing gap must say why instead of claiming "none".
    #[test]
    fn caller_without_a_usable_passport_is_not_strong_on_remember() {
        for caller in [
            CallerPassport::Missing,
            CallerPassport::Revoked,
            CallerPassport::NoCategory,
        ] {
            let card = build_scorecard(&CustodyInputs {
                caller_passport: caller,
                ..inputs(true)
            });
            let remember = find(&card, "four_questions", "REMEMBER");
            assert_eq!(remember["verdict"], "partial", "{caller:?}");
            let reason = caller.gap().unwrap();
            assert!(remember["evidence"].as_str().unwrap().contains(reason), "{caller:?}");
            let gap = card["trust_posture"]["standing_gap"].as_str().unwrap();
            assert!(!gap.starts_with("none"), "{caller:?}: {gap}");
            assert!(gap.contains(reason), "{caller:?}: {gap}");
            // The export half of the posture is still pinned, so PROVE holds.
            assert_eq!(find(&card, "exit_test", "PROVE")["verdict"], "strong");
        }
    }

    /// D1 (D2 contract): while no export signer is pinned, every export this
    /// node produces verifies on its own embedded key, so PROVE is not strong.
    #[test]
    fn unpinned_export_signer_downgrades_prove_and_names_the_gap() {
        let card = build_scorecard(&CustodyInputs {
            export_identity: ExportIdentityPostureV1::Unpinned,
            ..inputs(true)
        });
        let prove = find(&card, "exit_test", "PROVE");
        assert_eq!(prove["verdict"], "partial");
        assert!(prove["evidence"].as_str().unwrap().contains("UNPINNED"));
        let gap = card["trust_posture"]["standing_gap"].as_str().unwrap();
        assert!(!gap.starts_with("none"), "{gap}");
        assert!(gap.contains(EXPORT_VERIFY_PUBLIC_KEY_ENV), "{gap}");
        // The caller half is usable, so REMEMBER holds.
        assert_eq!(find(&card, "four_questions", "REMEMBER")["verdict"], "strong");
    }

    #[tokio::test]
    async fn caller_passport_tracks_issue_and_revoke() {
        let ctx = McpContext::new_default("test-node");
        assert_eq!(CallerPassport::resolve(&ctx).await, CallerPassport::Missing);
        let alice = with_agent(&ctx, "alice");
        assert_eq!(CallerPassport::resolve(&alice).await, CallerPassport::Missing);
        handle_issue_passport(&json!({}), &alice).await.unwrap();
        assert_eq!(CallerPassport::resolve(&alice).await, CallerPassport::Usable);
        handle_revoke_passport(&json!({}), &alice).await.unwrap();
        assert_eq!(CallerPassport::resolve(&alice).await, CallerPassport::Revoked);
    }

    #[tokio::test]
    async fn caller_passport_needs_a_category_when_passports_are_enforced() {
        let ctx = McpContext::new_default("test-node")
            .with_agent_passports(true, crate::agent_passport::AgentPassportMap::builtin_default());
        let alice = with_agent(&ctx, "alice");
        // An unmapped agent's passport records no tenant group, hence no category.
        handle_issue_passport(&json!({}), &alice).await.unwrap();
        assert_eq!(CallerPassport::resolve(&alice).await, CallerPassport::NoCategory);

        ctx.fact_store.write().await.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__passport__::alice".to_string(),
            key: "record".to_string(),
            value: json!({"id": "alice", "category": "work"}).to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
        assert_eq!(CallerPassport::resolve(&alice).await, CallerPassport::Usable);
    }

    #[test]
    fn all_flags_off_is_still_trivial_to_leave_but_trust_is_weaker() {
        let card = build_scorecard(&inputs(false));
        // CHECK + REVOKE degrade to partial when their flags are off — the
        // scorecard reports runtime state, not just code existence.
        assert_eq!(find(&card, "four_questions", "CHECK")["verdict"], "partial");
        assert_eq!(find(&card, "exit_test", "REVOKE")["verdict"], "partial");
        assert_eq!(find(&card, "exit_test", "ROUTE")["verdict"], "partial");
        // But you can still walk away: export + keep-local hold ⇒ lock-in 1.
        assert_eq!(card["lock_in_risk"], 1);
        // Trust posture nudges the operator to turn the production flags on.
        let recs = card["trust_posture"]["recommendations"].as_array().unwrap();
        assert_eq!(recs.len(), 3);
    }

    #[test]
    fn local_only_reports_no_network_required() {
        let card = build_scorecard(&inputs(false));
        let keep_local = find(&card, "exit_test", "KEEP-LOCAL");
        assert!(keep_local["evidence"].as_str().unwrap().contains("local-only"));
    }
}
