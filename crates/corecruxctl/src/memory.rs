// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl memory ...` — operator-side CLI for the agent-ux-01
//! readable/editable memory panel.
//!
//! Subcommands (driven from `corecruxctl::main`):
//!
//! - `memory ls --top-k N`            — list visible memory facts (newest first)
//! - `memory show <fact_id>`          — print one fact with full metadata
//! - `memory edit <fact_id> --value …` — update value (passport-attributed)
//! - `memory pin <fact_id> [--off]`    — toggle pin state
//!
//! All subcommands talk to the running daemon via `/v1/facts*` HTTP routes,
//! filter reserved-prefix entities client-side, and require `CRUX_AGENT_TOKEN`
//! (Bearer) when auth is enabled on the daemon.

use serde::{Deserialize, Serialize};

/// Reserved entity prefixes filtered out of the memory panel view. Kept in
/// sync with `crux_mcp::tools::memory::RESERVED_ENTITY_PREFIXES`; we
/// duplicate here so the CLI does not pull `crux-mcp` as a dependency.
pub const RESERVED_ENTITY_PREFIXES: &[&str] = &[
    "__agent::",
    "__ops::",
    "__bootstrap__::",
    "__memory_pin::",
    "__work__::",
    "__decisions__::",
    "__project_layer__::",
    "__tenant_metadata__::",
];

const MEMORY_PIN_PREFIX: &str = "__memory_pin::";

fn entity_is_reserved(entity: &str) -> bool {
    RESERVED_ENTITY_PREFIXES.iter().any(|p| entity.starts_with(p))
}

#[derive(Debug, thiserror::Error)]
pub enum MemoryCliError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("daemon returned status {status}: {body}")]
    UpstreamStatus { status: u16, body: String },
    #[error("response missing field: {0}")]
    MissingField(&'static str),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl MemoryCliError {
    fn transport(err: impl std::fmt::Display) -> Self {
        Self::Transport(err.to_string())
    }
}

/// One contradiction candidate surfaced by the read-only Audit II M1 pass
/// (`GET /v1/console/review/contradictions`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContradictionCandidate {
    pub entity: String,
    pub key: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub polarity_a: String,
    #[serde(default)]
    pub polarity_b: String,
    #[serde(default)]
    pub fact_ids: Vec<String>,
    #[serde(default)]
    pub values: Vec<String>,
}

/// Receipt returned by the safe consolidation pass (Audit II M2,
/// `POST /v1/console/review/consolidations`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsolidationReceipt {
    pub consolidation_id: String,
    pub canonical_fact_id: String,
    #[serde(default)]
    pub superseded_fact_ids: Vec<String>,
    #[serde(default)]
    pub source_fact_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryFact {
    pub fact_id: String,
    pub entity: String,
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub confidence: f32,
    pub stored_at: String,
    #[serde(default)]
    pub source_receipt: Option<String>,
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Debug)]
pub struct MemoryClient {
    base: String,
    bearer: Option<String>,
    agent: ureq::Agent,
}

impl MemoryClient {
    pub fn new(base: &str, bearer: Option<String>) -> Self {
        let base = base.trim_end_matches('/').to_string();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(15)))
            .build()
            .into();
        Self { base, bearer, agent }
    }

    /// Convenience: build a client from env. Honours `CORECRUXD_HTTP_URL` (or
    /// defaults to `http://127.0.0.1:14800`) plus `CRUX_AGENT_TOKEN`.
    pub fn from_env() -> Self {
        let base = std::env::var("CORECRUXD_HTTP_URL").unwrap_or_else(|_| "http://127.0.0.1:14800".to_string());
        let bearer = std::env::var("CRUX_AGENT_TOKEN").ok().filter(|s| !s.is_empty());
        Self::new(&base, bearer)
    }

    fn url(&self, path: &str) -> String {
        let path = path.trim_start_matches('/');
        format!("{}/{}", self.base, path)
    }

    fn apply_auth(
        &self,
        mut req: ureq::RequestBuilder<ureq::typestate::WithoutBody>,
    ) -> ureq::RequestBuilder<ureq::typestate::WithoutBody> {
        if let Some(token) = &self.bearer {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        req
    }

    fn apply_auth_body(
        &self,
        mut req: ureq::RequestBuilder<ureq::typestate::WithBody>,
    ) -> ureq::RequestBuilder<ureq::typestate::WithBody> {
        if let Some(token) = &self.bearer {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        req
    }

    /// Query `/v1/facts` (with the daemon's default visibility filter) and
    /// drop reserved-prefix entities client-side.
    pub fn list(&self, top_k: usize, entity_filter: Option<&str>) -> Result<Vec<MemoryFact>, MemoryCliError> {
        let url = self.url("/v1/facts");
        let mut req = self.agent.get(&url).query("top_k", top_k.to_string());
        if let Some(e) = entity_filter {
            req = req.query("entity", e);
        }
        req = self.apply_auth(req);
        let resp = req.call().map_err(MemoryCliError::transport)?;
        let status = resp.status().as_u16();
        let body = resp.into_body().read_to_string().map_err(MemoryCliError::transport)?;
        if status >= 400 {
            return Err(MemoryCliError::UpstreamStatus { status, body });
        }
        let parsed: serde_json::Value = serde_json::from_str(&body)?;
        let facts_arr = parsed
            .get("facts")
            .and_then(|v| v.as_array())
            .ok_or(MemoryCliError::MissingField("facts"))?;
        let mut out = Vec::new();
        for f in facts_arr {
            let fact: MemoryFact = serde_json::from_value(f.clone())?;
            if fact.deleted || entity_is_reserved(&fact.entity) {
                continue;
            }
            out.push(fact);
            if out.len() >= top_k {
                break;
            }
        }
        Ok(out)
    }

    pub fn show(&self, fact_id: &str) -> Result<MemoryFact, MemoryCliError> {
        let url = self.url(&format!("/v1/facts/{fact_id}"));
        let req = self.apply_auth(self.agent.get(&url));
        let resp = req.call().map_err(MemoryCliError::transport)?;
        let status = resp.status().as_u16();
        let body = resp.into_body().read_to_string().map_err(MemoryCliError::transport)?;
        if status >= 400 {
            return Err(MemoryCliError::UpstreamStatus { status, body });
        }
        let fact: MemoryFact = serde_json::from_str(&body)?;
        if entity_is_reserved(&fact.entity) {
            return Err(MemoryCliError::UpstreamStatus {
                status: 403,
                body: format!(
                    "fact entity '{}' is reserved (not visible through memory panel)",
                    fact.entity
                ),
            });
        }
        Ok(fact)
    }

    /// Edit a fact via PUT /v1/facts with same entity+key+confidence and the
    /// new value. The daemon supersedes the prior version transparently.
    pub fn edit(&self, fact_id: &str, new_value: &str, reason: Option<&str>) -> Result<MemoryFact, MemoryCliError> {
        let existing = self.show(fact_id)?;
        let body = serde_json::json!({
            "entity": existing.entity,
            "key": existing.key,
            "value": new_value,
            "confidence": existing.confidence,
            "source_receipt": reason.map(|r| format!("memory_edit:{r}")),
        });
        let url = self.url("/v1/facts");
        let req = self.apply_auth_body(self.agent.put(&url));
        let resp = req.send_json(body).map_err(MemoryCliError::transport)?;
        let status = resp.status().as_u16();
        let resp_body = resp.into_body().read_to_string().map_err(MemoryCliError::transport)?;
        if status >= 400 {
            return Err(MemoryCliError::UpstreamStatus {
                status,
                body: resp_body,
            });
        }
        let new_fact: MemoryFact = serde_json::from_str(&resp_body)?;
        Ok(new_fact)
    }

    /// Set or clear the pin state for a fact. Stored as a fact under
    /// `__memory_pin::cli::<fact_id>` with key="pinned" value="0"/"1". Note
    /// the operator namespace ("cli") is constant because the HTTP write
    /// path does not carry an agent identity; per-agent pins live behind the
    /// MCP `memory_pin` tool.
    pub fn pin(&self, fact_id: &str, pinned: bool) -> Result<(), MemoryCliError> {
        // Sanity-check the target fact exists + is not reserved.
        let _existing = self.show(fact_id)?;
        let body = serde_json::json!({
            "entity": format!("{MEMORY_PIN_PREFIX}cli::{fact_id}"),
            "key": "pinned",
            "value": if pinned { "1" } else { "0" },
            "confidence": 1.0,
        });
        let url = self.url("/v1/facts");
        let req = self.apply_auth_body(self.agent.put(&url));
        let resp = req.send_json(body).map_err(MemoryCliError::transport)?;
        let status = resp.status().as_u16();
        let resp_body = resp.into_body().read_to_string().map_err(MemoryCliError::transport)?;
        if status >= 400 {
            return Err(MemoryCliError::UpstreamStatus {
                status,
                body: resp_body,
            });
        }
        Ok(())
    }

    /// List contradiction candidates via the read-only review endpoint
    /// (`GET /v1/console/review/contradictions`). Detect-only; the daemon
    /// never mutates state on this path.
    pub fn contradictions(&self, limit: usize) -> Result<Vec<ContradictionCandidate>, MemoryCliError> {
        let url = self.url("/v1/console/review/contradictions");
        let req = self.apply_auth(self.agent.get(&url).query("limit", limit.to_string()));
        let resp = req.call().map_err(MemoryCliError::transport)?;
        let status = resp.status().as_u16();
        let body = resp.into_body().read_to_string().map_err(MemoryCliError::transport)?;
        if status >= 400 {
            return Err(MemoryCliError::UpstreamStatus { status, body });
        }
        let parsed: serde_json::Value = serde_json::from_str(&body)?;
        let arr = parsed
            .get("candidates")
            .and_then(|v| v.as_array())
            .ok_or(MemoryCliError::MissingField("candidates"))?;
        let mut out = Vec::with_capacity(arr.len());
        for c in arr {
            out.push(serde_json::from_value(c.clone())?);
        }
        Ok(out)
    }

    /// Explicitly consolidate target facts into one canonical fact via
    /// `POST /v1/console/review/consolidations`. The daemon runs the M2
    /// protection guards (pinned/receipt-linked/private/high-confidence
    /// targets are refused with a 4xx) and emits a consolidation receipt.
    pub fn consolidate(
        &self,
        entity: &str,
        key: &str,
        canonical_value: &str,
        targets: &[String],
        confidence: f32,
    ) -> Result<ConsolidationReceipt, MemoryCliError> {
        let body = serde_json::json!({
            "consolidation_id": "",
            "entity": entity,
            "key": key,
            "canonical_value": canonical_value,
            "target_fact_ids": targets,
            "confidence": confidence,
        });
        let url = self.url("/v1/console/review/consolidations");
        let req = self.apply_auth_body(self.agent.post(&url));
        let resp = req.send_json(body).map_err(MemoryCliError::transport)?;
        let status = resp.status().as_u16();
        let resp_body = resp.into_body().read_to_string().map_err(MemoryCliError::transport)?;
        if status >= 400 {
            return Err(MemoryCliError::UpstreamStatus {
                status,
                body: resp_body,
            });
        }
        let parsed: serde_json::Value = serde_json::from_str(&resp_body)?;
        let receipt = parsed.get("receipt").ok_or(MemoryCliError::MissingField("receipt"))?;
        Ok(serde_json::from_value(receipt.clone())?)
    }
}

/// Pretty-print contradiction candidates (used by `memory contradictions`).
pub fn render_contradictions(candidates: &[ContradictionCandidate]) -> String {
    use std::fmt::Write as _;
    if candidates.is_empty() {
        return "no contradiction candidates\n".to_string();
    }
    let mut out = String::new();
    for c in candidates {
        let _ = writeln!(
            out,
            "[{}::{}] {} ({} vs {})  facts={}",
            c.entity,
            c.key,
            c.reason,
            c.polarity_a,
            c.polarity_b,
            c.fact_ids.join(","),
        );
    }
    out
}

/// Pretty-print a single fact (used by `show`).
pub fn render_fact(fact: &MemoryFact) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "fact_id   : {}", fact.fact_id);
    let _ = writeln!(out, "entity    : {}", fact.entity);
    let _ = writeln!(out, "key       : {}", fact.key);
    let _ = writeln!(out, "value     : {}", fact.value);
    let _ = writeln!(out, "version   : {}", fact.version);
    let _ = writeln!(out, "confidence: {:.2}", fact.confidence);
    let _ = writeln!(out, "stored_at : {}", fact.stored_at);
    if let Some(r) = &fact.source_receipt {
        let _ = writeln!(out, "receipt   : {r}");
    }
    if fact.deleted {
        out.push_str("status    : DELETED\n");
    }
    out
}

/// Pretty-print a list summary (used by `ls`).
pub fn render_list(facts: &[MemoryFact]) -> String {
    use std::fmt::Write as _;
    if facts.is_empty() {
        return "no memory visible".to_string();
    }
    let mut out = String::new();
    for f in facts {
        let _ = writeln!(
            out,
            "{}  v{}  [{}]  {} = {}",
            f.fact_id, f.version, f.entity, f.key, f.value
        );
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn reserved_filter_catches_all_listed_prefixes() {
        for p in RESERVED_ENTITY_PREFIXES {
            let e = format!("{p}some-suffix");
            assert!(entity_is_reserved(&e), "{e} should be reserved");
        }
        assert!(!entity_is_reserved("person:alice"));
        assert!(!entity_is_reserved("project:beta"));
    }

    #[test]
    fn render_list_handles_empty() {
        assert_eq!(render_list(&[]), "no memory visible");
    }

    #[test]
    fn render_fact_includes_all_fields() {
        let f = MemoryFact {
            fact_id: "f_1".to_string(),
            entity: "person:bob".to_string(),
            key: "city".to_string(),
            value: "NYC".to_string(),
            version: 2,
            confidence: 0.9,
            stored_at: "2026-05-27T00:00:00Z".to_string(),
            source_receipt: Some("memory_edit:moved".to_string()),
            deleted: false,
        };
        let out = render_fact(&f);
        assert!(out.contains("f_1"));
        assert!(out.contains("person:bob"));
        assert!(out.contains("memory_edit:moved"));
    }

    #[test]
    fn render_fact_marks_deleted() {
        let f = MemoryFact {
            fact_id: "f_2".to_string(),
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            version: 1,
            confidence: 1.0,
            stored_at: "t".to_string(),
            source_receipt: None,
            deleted: true,
        };
        let out = render_fact(&f);
        assert!(out.contains("status    : DELETED"));
        assert!(!out.contains("receipt   :"));
    }

    #[test]
    fn render_list_formats_each_fact() {
        let facts = vec![
            MemoryFact {
                fact_id: "f_a".to_string(),
                entity: "person:a".to_string(),
                key: "city".to_string(),
                value: "LDN".to_string(),
                version: 3,
                confidence: 0.5,
                stored_at: "t".to_string(),
                source_receipt: None,
                deleted: false,
            },
            MemoryFact {
                fact_id: "f_b".to_string(),
                entity: "person:b".to_string(),
                key: "lang".to_string(),
                value: "rust".to_string(),
                version: 1,
                confidence: 0.9,
                stored_at: "t".to_string(),
                source_receipt: None,
                deleted: false,
            },
        ];
        let out = render_list(&facts);
        assert!(out.contains("f_a  v3  [person:a]  city = LDN"));
        assert!(out.contains("f_b  v1  [person:b]  lang = rust"));
    }

    // ── MemoryClient (driven against a loopback stub) ───────────────────

    fn fact_json(fact_id: &str, entity: &str) -> serde_json::Value {
        serde_json::json!({
            "fact_id": fact_id,
            "entity": entity,
            "key": "k",
            "value": "v",
            "version": 1,
            "confidence": 1.0,
            "stored_at": "2026-06-17T00:00:00Z",
        })
    }

    #[test]
    fn url_joins_and_normalises_slashes() {
        let c = MemoryClient::new("http://host:1/", None);
        assert_eq!(c.url("/v1/facts"), "http://host:1/v1/facts");
        assert_eq!(c.url("v1/facts"), "http://host:1/v1/facts");
    }

    #[test]
    #[serial_test::serial]
    fn from_env_defaults_and_overrides() {
        std::env::remove_var("CORECRUXD_HTTP_URL");
        std::env::remove_var("CRUX_AGENT_TOKEN");
        let c = MemoryClient::from_env();
        assert_eq!(c.base, "http://127.0.0.1:14800");
        assert!(c.bearer.is_none());

        std::env::set_var("CORECRUXD_HTTP_URL", "http://example:9/");
        std::env::set_var("CRUX_AGENT_TOKEN", "tok123");
        let c = MemoryClient::from_env();
        assert_eq!(c.base, "http://example:9");
        assert_eq!(c.bearer.as_deref(), Some("tok123"));
        std::env::remove_var("CORECRUXD_HTTP_URL");
        std::env::remove_var("CRUX_AGENT_TOKEN");
    }

    #[test]
    fn list_filters_reserved_and_deleted_and_sends_bearer() {
        let body = serde_json::json!({
            "facts": [
                fact_json("f_keep", "person:alice"),
                { "fact_id": "f_del", "entity": "person:bob", "key": "k", "value": "v",
                  "version": 1, "confidence": 1.0, "stored_at": "t", "deleted": true },
                fact_json("f_reserved", "__agent::secret"),
                fact_json("f_keep2", "project:beta"),
            ]
        })
        .to_string();
        let (port, h) = crate::test_support::serve_responses(vec![(200, body)]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), Some("bearer-xyz".to_string()));
        let facts = c.list(10, Some("person:alice")).expect("list ok");
        let reqs = h.join().expect("join");

        assert_eq!(facts.len(), 2);
        assert_eq!(facts[0].fact_id, "f_keep");
        assert_eq!(facts[1].fact_id, "f_keep2");
        assert!(reqs[0].to_lowercase().contains("authorization: bearer bearer-xyz"));
        assert!(reqs[0].contains("entity=person%3Aalice") || reqs[0].contains("entity=person:alice"));
    }

    #[test]
    fn list_respects_top_k_cap() {
        let body = serde_json::json!({
            "facts": [fact_json("f1", "e1"), fact_json("f2", "e2"), fact_json("f3", "e3")]
        })
        .to_string();
        let (port, h) = crate::test_support::serve_responses(vec![(200, body)]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
        let facts = c.list(2, None).expect("list ok");
        h.join().ok();
        assert_eq!(facts.len(), 2);
    }

    #[test]
    fn list_missing_facts_field_errors() {
        let (port, h) = crate::test_support::serve_responses(vec![(200, "{}".to_string())]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
        let err = c.list(5, None).expect_err("must fail");
        h.join().ok();
        assert!(matches!(err, MemoryCliError::MissingField("facts")));
    }

    #[test]
    fn list_upstream_error_status() {
        // This client's agent leaves `http_status_as_error` at its default
        // (true), so a 5xx surfaces as a transport error rather than reaching
        // the `status >= 400` branch.
        let (port, h) = crate::test_support::serve_responses(vec![(503, "down".to_string())]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
        let err = c.list(5, None).expect_err("must fail");
        h.join().ok();
        assert!(matches!(err, MemoryCliError::Transport(_)), "got {err:?}");
    }

    #[test]
    fn show_success() {
        let (port, h) = crate::test_support::serve_responses(vec![(200, fact_json("f_x", "person:a").to_string())]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
        let fact = c.show("f_x").expect("show ok");
        h.join().ok();
        assert_eq!(fact.fact_id, "f_x");
    }

    #[test]
    fn show_rejects_reserved_entity() {
        let (port, h) = crate::test_support::serve_responses(vec![(200, fact_json("f_r", "__ops::x").to_string())]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
        let err = c.show("f_r").expect_err("reserved must fail");
        h.join().ok();
        match err {
            MemoryCliError::UpstreamStatus { status, body } => {
                assert_eq!(status, 403);
                assert!(body.contains("reserved"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn show_upstream_error() {
        let (port, h) = crate::test_support::serve_responses(vec![(404, "nope".to_string())]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
        let err = c.show("missing").expect_err("must fail");
        h.join().ok();
        assert!(matches!(err, MemoryCliError::Transport(_)), "got {err:?}");
    }

    #[test]
    fn edit_reads_then_supersedes() {
        let (port, h) = crate::test_support::serve_responses(vec![
            (200, fact_json("f_e", "person:a").to_string()),
            (200, fact_json("f_e", "person:a").to_string()),
        ]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
        let updated = c.edit("f_e", "new-value", Some("typo")).expect("edit ok");
        let reqs = h.join().expect("join");
        assert_eq!(updated.fact_id, "f_e");
        // Second request is the PUT carrying the new value + receipt reason.
        assert!(reqs[1].contains("new-value"));
        assert!(reqs[1].contains("memory_edit:typo"));
    }

    #[test]
    fn edit_fails_when_show_fails() {
        let (port, h) = crate::test_support::serve_responses(vec![(500, "boom".to_string())]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
        let err = c.edit("f", "v", None).expect_err("must fail");
        h.join().ok();
        assert!(matches!(err, MemoryCliError::Transport(_)), "got {err:?}");
    }

    #[test]
    fn edit_surfaces_put_error() {
        let (port, h) = crate::test_support::serve_responses(vec![
            (200, fact_json("f_e", "person:a").to_string()),
            (409, "conflict".to_string()),
        ]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
        let err = c.edit("f_e", "v", None).expect_err("put fails");
        h.join().ok();
        assert!(matches!(err, MemoryCliError::Transport(_)), "got {err:?}");
    }

    #[test]
    fn pin_on_and_off() {
        for pinned in [true, false] {
            let (port, h) = crate::test_support::serve_responses(vec![
                (200, fact_json("f_p", "person:a").to_string()),
                (200, "{}".to_string()),
            ]);
            let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
            c.pin("f_p", pinned).expect("pin ok");
            let reqs = h.join().expect("join");
            let want = if pinned { "\"1\"" } else { "\"0\"" };
            assert!(reqs[1].contains(want), "value should be {want}: {}", reqs[1]);
            assert!(reqs[1].contains("__memory_pin::cli::f_p"));
        }
    }

    #[test]
    fn pin_surfaces_put_error() {
        let (port, h) = crate::test_support::serve_responses(vec![
            (200, fact_json("f_p", "person:a").to_string()),
            (500, "boom".to_string()),
        ]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
        let err = c.pin("f_p", true).expect_err("must fail");
        h.join().ok();
        assert!(matches!(err, MemoryCliError::Transport(_)), "got {err:?}");
    }

    #[test]
    fn error_display_and_transport_helper() {
        assert_eq!(
            MemoryCliError::transport("dns boom").to_string(),
            "transport error: dns boom"
        );
        assert_eq!(
            MemoryCliError::MissingField("facts").to_string(),
            "response missing field: facts"
        );
        assert_eq!(
            MemoryCliError::UpstreamStatus {
                status: 418,
                body: "tea".to_string()
            }
            .to_string(),
            "daemon returned status 418: tea"
        );
        let json_err: MemoryCliError = serde_json::from_str::<MemoryFact>("not json").unwrap_err().into();
        assert!(json_err.to_string().contains("JSON error"));
    }

    #[test]
    fn render_contradictions_handles_empty_and_rows() {
        assert_eq!(render_contradictions(&[]), "no contradiction candidates\n");
        let cands = vec![ContradictionCandidate {
            entity: "service:api".to_string(),
            key: "enabled".to_string(),
            reason: "opposite_polarity_same_entity_key".to_string(),
            polarity_a: "positive".to_string(),
            polarity_b: "negative".to_string(),
            fact_ids: vec!["f_a".to_string(), "f_b".to_string()],
            values: vec!["enabled".to_string(), "disabled".to_string()],
        }];
        let out = render_contradictions(&cands);
        assert!(out.contains("[service:api::enabled]"));
        assert!(out.contains("positive vs negative"));
        assert!(out.contains("f_a,f_b"));
    }

    #[test]
    fn contradictions_parses_candidates_and_sends_bearer() {
        let body = serde_json::json!({
            "schema": "crux.console.review.contradictions.v1",
            "limit": 50,
            "count": 1,
            "candidates": [{
                "entity": "service:api", "key": "enabled",
                "reason": "opposite_polarity_same_entity_key",
                "polarity_a": "positive", "polarity_b": "negative",
                "fact_ids": ["f_a", "f_b"], "values": ["enabled", "disabled"]
            }]
        })
        .to_string();
        let (port, h) = crate::test_support::serve_responses(vec![(200, body)]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), Some("tok-c".to_string()));
        let cands = c.contradictions(50).expect("contradictions ok");
        let reqs = h.join().expect("join");
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].entity, "service:api");
        assert!(reqs[0].to_lowercase().contains("authorization: bearer tok-c"));
        assert!(reqs[0].contains("limit=50"));
    }

    #[test]
    fn contradictions_missing_field_errors() {
        let (port, h) = crate::test_support::serve_responses(vec![(200, "{}".to_string())]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
        let err = c.contradictions(10).expect_err("must fail");
        h.join().ok();
        assert!(matches!(err, MemoryCliError::MissingField("candidates")));
    }

    #[test]
    fn consolidate_posts_request_and_parses_receipt() {
        let body = serde_json::json!({
            "schema": "crux.console.review.consolidation.v1",
            "status": "consolidated",
            "receipt": {
                "consolidation_id": "con-1",
                "canonical_fact_id": "f_canon",
                "superseded_fact_ids": ["f_old", "f_dup"],
                "source_fact_ids": ["f_old", "f_dup"]
            }
        })
        .to_string();
        let (port, h) = crate::test_support::serve_responses(vec![(200, body)]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), Some("tok-w".to_string()));
        let receipt = c
            .consolidate(
                "proj",
                "status",
                "active",
                &["f_old".to_string(), "f_dup".to_string()],
                0.8,
            )
            .expect("consolidate ok");
        let reqs = h.join().expect("join");
        assert_eq!(receipt.canonical_fact_id, "f_canon");
        assert_eq!(receipt.superseded_fact_ids.len(), 2);
        // The POST body carries entity/key/value/targets (ureq pretty-prints
        // JSON with a space after the colon, so match key + value loosely).
        assert!(reqs[0].contains("\"entity\"") && reqs[0].contains("\"proj\""));
        assert!(reqs[0].contains("\"canonical_value\"") && reqs[0].contains("\"active\""));
        assert!(reqs[0].contains("f_old"));
        assert!(reqs[0].to_lowercase().contains("authorization: bearer tok-w"));
    }

    #[test]
    fn consolidate_surfaces_protection_conflict() {
        // The daemon rejects a protected target with a 409 (CONFLICT).
        let (port, h) = crate::test_support::serve_responses(vec![(409, "target receipt-linked".to_string())]);
        let c = MemoryClient::new(&format!("http://127.0.0.1:{port}"), None);
        let err = c
            .consolidate("proj", "status", "active", &["f_linked".to_string()], 0.8)
            .expect_err("protected target must fail");
        h.join().ok();
        assert!(matches!(err, MemoryCliError::Transport(_)), "got {err:?}");
    }

    #[test]
    fn list_transport_error_on_dead_port() {
        // Nothing listening: ureq fails to connect → Transport error.
        let c = MemoryClient::new("http://127.0.0.1:1", None);
        let err = c.list(5, None).expect_err("must fail");
        assert!(matches!(err, MemoryCliError::Transport(_)));
    }
}
