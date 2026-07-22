// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Local engram catalog — pre-execution prompt overlays resolved by intent.
//!
//! An engram is a small behavioural overlay served to an agent *before* it
//! acts, routed by intent bucket and gated by model capability class. The
//! daemon ships a built-in catalog; operators extend or override it with
//! fact-backed overlays under `__engram__::*` (override wins by matching
//! `(name, version)`).
//!
//! This module owns the catalog logic and pure helpers. Serving surfaces live
//! elsewhere: the HTTP routes in `corecruxd::http::engrams` and the MCP
//! `engram_resolve` tool in `crux-mcp`, both of which operate on the same
//! [`FactStore`] handle.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::fact_store::{dedup_latest, FactQuery, FactStore};

pub const ENGRAM_ENTITY_PREFIX: &str = "__engram__::";
const LOCAL_ENGRAM_MANIFEST_SCHEMA: &str = "crux.local.engram_manifest.v1";
pub const SESSION_PROCEDURE_SCHEMA: &str = "cuecrux.memory.session_procedure.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalEngram {
    pub id: String,
    pub name: String,
    pub version: String,
    pub intent_bucket: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_pattern: Option<String>,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applicable_why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_class_min: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_class_max: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_class: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_chunk_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_chunk_set_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub created_at_unix_ms: u64,
}

fn default_enabled() -> bool {
    true
}

/// Built-in catalog merged with fact-backed overlays under `__engram__::*`.
/// An overlay replaces a builtin with the same `(name, version)`.
pub fn local_catalog_with_overlays(store: &FactStore) -> Vec<LocalEngram> {
    let mut out = builtin_engrams();
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(ENGRAM_ENTITY_PREFIX.trim_end_matches("::").to_string() + "::"),
        top_k: 500,
        token_budget: None,
    });
    for fact in dedup_latest(result.facts) {
        if fact.value.is_empty() {
            continue;
        }
        if let Ok(engram) = serde_json::from_str::<LocalEngram>(&fact.value) {
            out.retain(|e| !(e.name == engram.name && e.version == engram.version));
            out.push(engram);
        }
    }
    out.sort_by(|a, b| a.intent_bucket.cmp(&b.intent_bucket).then_with(|| a.name.cmp(&b.name)));
    out
}

pub fn builtin_engrams() -> Vec<LocalEngram> {
    vec![
        LocalEngram {
            id: "eng_local_investigate_v1".to_string(),
            name: "local-investigation-rhythm".to_string(),
            version: "v1".to_string(),
            intent_bucket: "investigation".to_string(),
            query_pattern: Some("audit|review|investigate|triage|bug|failure".to_string()),
            content: "Before acting, gather the active project context, the latest relevant facts, the route/storyline if code is involved, and the last verification or receipt touching the same object.".to_string(),
            applicable_why: Some("Local daemon baseline for agent investigation sessions.".to_string()),
            capability_class_min: None,
            capability_class_max: None,
            generated_class: None,
            source_chunk_hashes: Vec::new(),
            source_chunk_set_hash: None,
            inherited_reason: None,
            policy_hash: None,
            enabled: true,
            created_at_unix_ms: 1_776_710_400_000,
        },
        LocalEngram {
            id: "eng_route_preflight_v1".to_string(),
            name: "route-impact-preflight".to_string(),
            version: "v1".to_string(),
            intent_bucket: "developer_surface".to_string(),
            query_pattern: Some("route|api|handler|scope|openapi|storyline".to_string()),
            content: "For HTTP/gRPC work, inspect the route storyline, route auth scopes, request/response shape, and nearest tests before editing. Record any scope drift or missing OpenAPI coverage separately from code style cleanup.".to_string(),
            applicable_why: Some("Useful when daemon API work touches handlers or MCP surfaces.".to_string()),
            capability_class_min: None,
            capability_class_max: None,
            generated_class: None,
            source_chunk_hashes: Vec::new(),
            source_chunk_set_hash: None,
            inherited_reason: None,
            policy_hash: None,
            enabled: true,
            created_at_unix_ms: 1_776_710_400_000,
        },
        LocalEngram {
            id: "eng_session_expansion_v1".to_string(),
            name: "aggregation-session-expansion".to_string(),
            version: "v1".to_string(),
            intent_bucket: "aggregation_count".to_string(),
            query_pattern: Some("count|list|how many|aggregate|enumerate".to_string()),
            content: "When multiple chunks from one session match an aggregation question, expand nearby turns from that session before concluding the count or list is complete.".to_string(),
            applicable_why: Some("Matches hosted MemoryCrux aggregation-session-expansion behavior.".to_string()),
            capability_class_min: None,
            capability_class_max: None,
            generated_class: None,
            source_chunk_hashes: Vec::new(),
            source_chunk_set_hash: None,
            inherited_reason: None,
            policy_hash: None,
            enabled: true,
            created_at_unix_ms: 1_776_710_400_000,
        },
        LocalEngram {
            id: "eng_code_minimalism_v1".to_string(),
            name: "code-minimalism".to_string(),
            version: "v1".to_string(),
            intent_bucket: "developer_surface".to_string(),
            query_pattern: Some(
                "implement|add|build|create|write|refactor|scaffold|feature|endpoint|component|module".to_string(),
            ),
            content: "Before writing code, take the highest rung that holds: (1) does this need to exist at all — speculative need is skipped, said in one line; (2) does it already exist in this codebase — search first, reuse the existing helper/type/pattern; (3) stdlib covers it — use it; (4) a native platform feature covers it — prefer it over hand-rolled code; (5) an already-installed dependency covers it — use it, never add a new one for a few lines; (6) it fits in one line — one line; (7) only then write the minimum code that works. Understand the problem before climbing: trace every file the change touches. Never minimise away trust-boundary validation, data-loss error handling, security, accessibility, or anything explicitly requested. Non-trivial logic leaves one runnable check behind. Mark deliberate ceilings with a `crux-min:` comment naming the upgrade trigger.".to_string(),
            applicable_why: Some(
                "The historical v1-profile replay (AuditCrux benchmarks/ponytail, corpus ponytail-fastapi-cd83fc1) observed lower pooled code volume and recorded total-token aggregates on Fable and Opus. All 96 cells left a non-empty diff, but the harness executed no generated patch or task test and one Opus baseline timed out, so it supports no functional-correctness or causal scaling claim.".to_string(),
            ),
            capability_class_min: None,
            capability_class_max: None,
            generated_class: None,
            source_chunk_hashes: Vec::new(),
            source_chunk_set_hash: None,
            inherited_reason: None,
            policy_hash: None,
            enabled: true,
            created_at_unix_ms: 1_784_140_800_000,
        },
    ]
}

pub fn current_session_procedure() -> serde_json::Value {
    json!({
        "steps": [
            "Resolve session procedure and engram manifest before the first retrieval-heavy turn.",
            "Use the daemon-local context first, then cloud mirrors or hosted MemoryCrux only when the task requires shared tenant memory.",
            "Carry returned prompt_hash, engram_set_hash, semantic_profile_id, and receipt ids into any answer replay capsule.",
            "If evidence is stale, superseded, or policy-constrained, report that separately from the historical answer."
        ],
        "delivery": "first_call_or_hash_mismatch",
    })
}

pub fn build_engram_manifest(engrams: &[LocalEngram], tenant_id: &str, capability_class: &str) -> serde_json::Value {
    let rows: Vec<_> = engrams
        .iter()
        .filter(|e| e.enabled && class_allows(capability_class, e))
        .map(|e| {
            json!({
                "name": e.name,
                "version": e.version,
                "intent_bucket": e.intent_bucket,
                "prompt_hash": prompt_hash(&e.content),
                "applicable_why_hash": e.applicable_why.as_deref().map(prompt_hash),
                "generated_class": &e.generated_class,
                "source_chunk_hashes": &e.source_chunk_hashes,
                "source_chunk_set_hash": &e.source_chunk_set_hash,
                "inherited_reason": &e.inherited_reason,
                "policy_hash": &e.policy_hash,
            })
        })
        .collect();
    let payload = json!({
        "schema": LOCAL_ENGRAM_MANIFEST_SCHEMA,
        "tenant_id": tenant_id,
        "capability_class": capability_class,
        "engrams": rows,
    });
    json!({
        "schema": LOCAL_ENGRAM_MANIFEST_SCHEMA,
        "tenant_id": tenant_id,
        "capability_class": capability_class,
        "manifest_hash": hash_json(&payload),
        "engrams": payload["engrams"],
    })
}

pub fn compute_engram_set_hash(engrams: &[LocalEngram]) -> serde_json::Value {
    let rows: Vec<_> = engrams
        .iter()
        .map(|e| {
            json!({
                "name": e.name,
                "version": e.version,
                "prompt_hash": prompt_hash(&e.content),
                "applicable_why_hash": e.applicable_why.as_deref().map(prompt_hash),
            })
        })
        .collect();
    let row_value = serde_json::Value::Array(rows);
    let count = row_value.as_array().map_or(0, Vec::len);
    json!({
        "schema": "crux.local.engram_set_hash.v1",
        "hash": hash_json(&row_value),
        "count": count,
    })
}

// Reuse the crate's existing blake3 helpers rather than adding fresh copies
// (this crate already had several): `prompt_hash` is replay's text hash under
// the name the engram wire format uses; `hash_json` is action_enrichment's.
pub use crate::action_enrichment::hash_json;
pub use crate::replay::hash_text as prompt_hash;

pub fn parse_name_version(value: &str) -> Option<(&str, &str)> {
    let idx = value.rfind('@')?;
    if idx == 0 || idx == value.len() - 1 {
        return None;
    }
    Some((&value[..idx], &value[idx + 1..]))
}

pub fn model_id_to_capability_class(model_id: Option<&str>) -> String {
    let Some(model) = model_id.map(str::to_ascii_lowercase) else {
        return "capable".to_string();
    };
    if model.contains("mini") || model.contains("haiku") || model.contains("flash") {
        "fast".to_string()
    } else if model.contains("opus")
        || model.contains("fable")
        || model.contains("frontier")
        || model.contains("gpt-5.5")
    {
        "frontier".to_string()
    } else {
        "capable".to_string()
    }
}

/// Outcome of resolving `name@version` entries against a catalog under a
/// capability class. `missing` collects every unresolvable entry in request
/// order (malformed, unknown, or class-denied); `malformed` is the subset
/// that failed `name@version` parsing, kept separately so the HTTP surface
/// can preserve its 422-on-malformed contract while MCP reports one merged
/// list.
pub struct ResolveOutcome {
    pub resolved: Vec<LocalEngram>,
    pub missing: Vec<String>,
    pub malformed: Vec<String>,
}

/// Shared resolve loop for the HTTP route and the MCP tool — one place for
/// the enabled-filter and capability gating.
pub fn resolve_from_catalog(catalog: &[LocalEngram], names: &[String], capability_class: &str) -> ResolveOutcome {
    let mut out = ResolveOutcome {
        resolved: Vec::new(),
        missing: Vec::new(),
        malformed: Vec::new(),
    };
    for name in names {
        let Some((want_name, want_version)) = parse_name_version(name) else {
            out.malformed.push(name.clone());
            out.missing.push(name.clone());
            continue;
        };
        let found = catalog
            .iter()
            .find(|e| e.enabled && e.name == want_name && e.version == want_version);
        match found {
            Some(e) if class_allows(capability_class, e) => out.resolved.push(e.clone()),
            _ => out.missing.push(name.clone()),
        }
    }
    out
}

pub fn class_allows(capability_class: &str, engram: &LocalEngram) -> bool {
    const ORDER: &[&str] = &["fast", "capable", "frontier"];
    let rank = |value: &str| ORDER.iter().position(|x| *x == value).unwrap_or(1);
    let actual = rank(capability_class);
    if let Some(min) = engram.capability_class_min.as_deref() {
        if actual < rank(min) {
            return false;
        }
    }
    if let Some(max) = engram.capability_class_max.as_deref() {
        if actual > rank(max) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fact_store::StoreFact;

    #[test]
    fn parse_name_version_requires_at_version() {
        assert_eq!(parse_name_version("a@v1"), Some(("a", "v1")));
        assert_eq!(parse_name_version("a"), None);
        assert_eq!(parse_name_version("@v1"), None);
    }

    #[test]
    fn manifest_hash_changes_with_catalog() {
        let one = builtin_engrams();
        let mut two = one.clone();
        two[0].content.push_str(" changed");
        let a = build_engram_manifest(&one, "t", "capable");
        let b = build_engram_manifest(&two, "t", "capable");
        assert_ne!(a["manifest_hash"], b["manifest_hash"]);
    }

    #[test]
    fn manifest_and_set_hashes_bind_applicable_why() {
        let one = builtin_engrams();
        let mut two = one.clone();
        two[0].applicable_why = Some("corrected rationale".to_string());

        let manifest_a = build_engram_manifest(&one, "t", "capable");
        let manifest_b = build_engram_manifest(&two, "t", "capable");
        assert_ne!(manifest_a["manifest_hash"], manifest_b["manifest_hash"]);
        assert_ne!(
            compute_engram_set_hash(&one)["hash"],
            compute_engram_set_hash(&two)["hash"]
        );
        assert!(manifest_a["engrams"][0]["applicable_why_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("blake3:")));
    }

    #[test]
    fn manifest_round_trips_generated_metadata() {
        let engrams = vec![LocalEngram {
            id: "generated-1".to_string(),
            name: "shared-date-header".to_string(),
            version: "v1".to_string(),
            intent_bucket: "temporal_duration".to_string(),
            query_pattern: None,
            content: "The docs store effective dates in the nearest Date header.".to_string(),
            applicable_why: Some("generated_inheritance=exact_chunk_hash".to_string()),
            capability_class_min: None,
            capability_class_max: None,
            generated_class: Some("chunk_bound".to_string()),
            source_chunk_hashes: vec!["a".repeat(64)],
            source_chunk_set_hash: Some("b".repeat(64)),
            inherited_reason: Some("exact_chunk_hash".to_string()),
            policy_hash: Some("policy-hash-1".to_string()),
            enabled: true,
            created_at_unix_ms: 1,
        }];

        let manifest = build_engram_manifest(&engrams, "tenant-a", "capable");

        assert_eq!(manifest["engrams"][0]["generated_class"], "chunk_bound");
        assert_eq!(manifest["engrams"][0]["source_chunk_hashes"][0], "a".repeat(64));
        assert_eq!(manifest["engrams"][0]["inherited_reason"], "exact_chunk_hash");
    }

    #[test]
    fn builtin_catalog_includes_code_minimalism() {
        let builtins = builtin_engrams();
        let cm = builtins
            .iter()
            .find(|e| e.name == "code-minimalism" && e.version == "v1")
            .expect("the backwards-compatible code-minimalism v1 must ship as a builtin");
        assert_eq!(cm.intent_bucket, "developer_surface");
        assert!(cm.enabled);
        assert!(cm.content.contains("crux-min:"));
        let why = cm.applicable_why.as_deref().expect("bounded rationale");
        assert!(why.contains("All 96 cells"));
        assert!(why.contains("timed out"));
        assert!(why.contains("no functional-correctness or causal scaling claim"));
        assert!(!why.contains("no correctness regression"));
    }

    #[test]
    fn overlay_fact_overrides_builtin_by_name_version() {
        let mut store = FactStore::new();
        let mut custom = builtin_engrams()
            .into_iter()
            .find(|e| e.name == "code-minimalism")
            .unwrap();
        custom.content = "operator-tuned ladder".to_string();
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: format!("{ENGRAM_ENTITY_PREFIX}code-minimalism"),
            key: "engram".to_string(),
            value: serde_json::to_string(&custom).unwrap(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        let catalog = local_catalog_with_overlays(&store);
        let served: Vec<_> = catalog.iter().filter(|e| e.name == "code-minimalism").collect();
        assert_eq!(served.len(), 1, "overlay must replace, not duplicate");
        assert_eq!(served[0].content, "operator-tuned ladder");
    }

    #[test]
    fn class_allows_respects_min_and_max_bounds() {
        let mut e = builtin_engrams().remove(0);
        assert!(class_allows("fast", &e));
        assert!(class_allows("frontier", &e));

        e.capability_class_min = Some("capable".to_string());
        assert!(!class_allows("fast", &e));
        assert!(class_allows("capable", &e));
        assert!(class_allows("frontier", &e));

        e.capability_class_max = Some("capable".to_string());
        assert!(!class_allows("frontier", &e));
        assert!(class_allows("capable", &e));

        // Unknown class ranks as "capable".
        assert!(class_allows("unknown", &e));
    }

    #[test]
    fn resolve_from_catalog_separates_malformed_from_missing() {
        let catalog = builtin_engrams();
        let names = vec![
            "code-minimalism@v1".to_string(),
            "nope@v1".to_string(),
            "malformed".to_string(),
        ];
        let out = resolve_from_catalog(&catalog, &names, "capable");
        assert_eq!(out.resolved.len(), 1);
        assert_eq!(out.missing, vec!["nope@v1".to_string(), "malformed".to_string()]);
        assert_eq!(out.malformed, vec!["malformed".to_string()]);
    }

    #[test]
    fn resolve_denies_below_capability_min() {
        let mut catalog = builtin_engrams();
        for e in &mut catalog {
            if e.name == "code-minimalism" {
                e.capability_class_min = Some("frontier".to_string());
            }
        }
        let names = vec!["code-minimalism@v1".to_string()];
        assert!(!resolve_from_catalog(&catalog, &names, "fast").missing.is_empty());
        assert_eq!(resolve_from_catalog(&catalog, &names, "frontier").resolved.len(), 1);
    }

    /// The wizard profile (crux-config-wizard/profiles/code-minimalism.md) and
    /// this builtin engram are deliberately different renderings (full doc vs
    /// compressed overlay) of the same ruleset. Full single-sourcing is the
    /// wrong depth; what must never drift is the load-bearing `crux-min:`
    /// marker token (harvest tooling greps for it) and the 7-rung ladder.
    #[test]
    fn profile_and_engram_share_marker_and_rungs() {
        let profile_md = include_str!("../../crux-config-wizard/profiles/code-minimalism.md");
        let engram = builtin_engrams()
            .into_iter()
            .find(|e| e.name == "code-minimalism")
            .expect("builtin present");
        for artefact in [profile_md, engram.content.as_str()] {
            assert!(
                artefact.contains("crux-min:"),
                "shortcut marker token must match in both"
            );
        }
        assert!(engram.content.contains("(7)"), "engram ladder must have 7 rungs");
        assert_eq!(
            profile_md.matches("\n1.").count(),
            1,
            "profile ladder must start at rung 1"
        );
        assert!(profile_md.contains("\n7."), "profile ladder must have 7 rungs");
        // Carve-outs that must never be minimised away, present in both.
        for term in ["validation", "security", "accessibility"] {
            assert!(profile_md.to_lowercase().contains(term), "profile carve-out: {term}");
            assert!(engram.content.to_lowercase().contains(term), "engram carve-out: {term}");
        }
    }

    #[test]
    fn model_id_maps_to_capability_class() {
        assert_eq!(model_id_to_capability_class(None), "capable");
        assert_eq!(model_id_to_capability_class(Some("claude-haiku-4-5")), "fast");
        assert_eq!(model_id_to_capability_class(Some("claude-opus-4-8")), "frontier");
        assert_eq!(model_id_to_capability_class(Some("claude-sonnet-4-6")), "capable");
        assert_eq!(model_id_to_capability_class(Some("claude-fable-5")), "frontier");
    }
}
