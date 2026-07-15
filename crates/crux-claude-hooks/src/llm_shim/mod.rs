// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `crux-llm-shim` — opt-in local-LLM context-injection proxy (G17, M4 of
//! ExecPlan `context-mediation-injection-2026-06-11`).
//!
//! The ONE sanctioned proxy in the mediation plane (see
//! `PlanCrux docs/master-plan/shared/Context-Mediation-Points.md` §3): a thin
//! OpenAI-compatible HTTP shim in front of a **local** model server (Ollama,
//! vLLM, llama.cpp server) that:
//!
//! - (a) prepends the rendered `context_bundle/v1` markdown as the FIRST
//!   system message (stable region first — the prompt-cache lever, G21a),
//! - (b) mints mediation receipt records per request (`context_injected`)
//!   and per stream end-state (`stream_completed` / `stream_aborted`),
//! - (c) passes everything else through unmodified — params, tool calls,
//!   streaming bytes, non-chat routes.
//!
//! Guardrails (normative, from the M1 spec):
//! - Default-OFF: refuses to start unless `CRUX_LLM_SHIM=1`.
//! - Upstream allowlist: literal loopback / RFC1918 IPs and `localhost`
//!   ONLY — scope creep toward cloud proxying is structurally blocked.
//! - Listen address must be loopback.
//! - Free-tier functional: zero network beyond the user's own upstream;
//!   daemon receipt posting is best-effort with a local JSONL spool fallback.
//! - Experimental in v1: `Connection: close` per request, no keep-alive,
//!   chunked request bodies are rejected with `411`.
//!
//! Receipt records emitted here are **observational JSON drafts** posted to
//! `POST /v1/mediation/receipts` (and/or spooled locally). Canonical signed
//! receipts (deterministic CBOR + blake3 + Ed25519) are minted daemon-side by
//! `corecrux-receipts::stream_v1`; field names align so the daemon can lift a
//! spooled draft into a signed receipt without remapping.

pub mod allowlist;
pub mod cloud_witness;
pub mod http;
pub mod inject;
pub mod receipts;
pub mod witness;

use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Context as _;

/// Env flag gating the shim (default-OFF per the plan's rollout posture).
pub const ENABLE_ENV: &str = "CRUX_LLM_SHIM";

/// Env flag gating cloud witness mode independently from local injection.
pub const CLOUD_WITNESS_ENABLE_ENV: &str = "CRUX_CLOUD_WITNESS";

/// Optional secret that gates cloud-witness session attribution.
pub const CLOUD_WITNESS_SESSION_TOKEN_ENV: &str = "CRUX_CLOUD_WITNESS_SESSION_TOKEN";

/// Test-only upstream override read by the CLI only when the loud insecure
/// flag is present (or directly by unit tests compiled with `cfg(test)`).
pub const CLOUD_WITNESS_TEST_UPSTREAM_ENV: &str = "CRUX_CLOUD_WITNESS_TEST_UPSTREAM";

/// Schema tag stamped on every shim-emitted receipt record.
pub const SHIM_RECEIPT_SCHEMA: &str = "cuecrux.mediation.shim.v1";

/// Schema tag stamped on cloud witness records before signing.
pub const WITNESS_RECEIPT_SCHEMA: &str = "cuecrux.mediation.witness.v1";

/// Bundle contract version the shim injects (owned by the M1 spec).
pub const BUNDLE_VERSION: &str = "context_bundle/v1";

/// Resolved shim configuration (post-validation).
#[derive(Debug, Clone)]
pub struct ShimConfig {
    /// Upstream base URL, e.g. `http://127.0.0.1:11434`. Already
    /// allowlist-validated (loopback / RFC1918 / `localhost`, http only).
    pub upstream: String,
    /// Loopback listen address, e.g. `127.0.0.1:11435`.
    pub listen: String,
    /// Rendered bundle to inject, with provenance. `None` = passthrough mode
    /// (no `context_injected` receipts; stream receipts still minted).
    pub bundle: Option<BundleSource>,
    /// Session identity stamped on every receipt record.
    pub session_id: String,
    /// JSONL spool path for receipt records (always written on daemon-post
    /// failure; tests point this at a tempdir).
    pub receipts_spool: PathBuf,
    /// Post receipt records to `POST /v1/mediation/receipts` (best-effort).
    pub daemon_receipts: bool,
}

/// Resolved cloud witness configuration (post CLI mode selection).
#[derive(Debug, Clone)]
pub struct CloudWitnessConfig {
    /// Pinned cloud provider whose API origin receives traffic.
    pub provider: allowlist::CloudUpstream,
    /// Loopback listen address used as the SDK base URL.
    pub listen: String,
    /// Persistent Ed25519 witness seed path.
    pub witness_key: PathBuf,
    /// Shared mediation JSONL spool path.
    pub receipts_spool: PathBuf,
    /// Whether to attempt daemon delivery before the JSONL fallback.
    pub daemon_receipts: bool,
    /// Hashed listener credential used only to authenticate session hints.
    session_auth_token: Option<SessionAuthTokenHash>,
    /// Validated loopback HTTP override installed only through the loud
    /// [`CloudWitnessConfig::with_insecure_test_upstream`] opt-in.
    insecure_test_upstream: Option<String>,
}

#[derive(Clone)]
struct SessionAuthTokenHash(blake3::Hash);

impl SessionAuthTokenHash {
    fn from_env() -> Option<Self> {
        std::env::var(CLOUD_WITNESS_SESSION_TOKEN_ENV)
            .ok()
            .filter(|token| !token.is_empty())
            .map(|token| Self(blake3::hash(token.as_bytes())))
    }

    fn matches(&self, presented: &str) -> bool {
        // `blake3::Hash` equality uses a fixed-size constant-time comparison.
        self.0 == blake3::hash(presented.as_bytes())
    }
}

impl std::fmt::Debug for SessionAuthTokenHash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl CloudWitnessConfig {
    /// Build production cloud-witness configuration using the provider's
    /// pinned TLS origin.
    pub fn new(
        provider: allowlist::CloudUpstream,
        listen: String,
        witness_key: PathBuf,
        receipts_spool: PathBuf,
        daemon_receipts: bool,
    ) -> Self {
        Self {
            provider,
            listen,
            witness_key,
            receipts_spool,
            daemon_receipts,
            session_auth_token: SessionAuthTokenHash::from_env(),
            insecure_test_upstream: None,
        }
    }

    /// Return whether `presented` proves permission to stamp a session hint.
    pub(crate) fn session_auth_token_matches(&self, presented: &str) -> bool {
        self.session_auth_token
            .as_ref()
            .is_some_and(|expected| expected.matches(presented))
    }

    /// Replace the pinned TLS origin with a loopback-only HTTP test upstream.
    ///
    /// This is intentionally loud: it validates the URL, prints an
    /// unmistakable warning, and causes every record to carry
    /// `test_upstream:true`. Production callers should never invoke it.
    #[allow(clippy::print_stderr)]
    pub fn with_insecure_test_upstream(mut self, url: &str) -> anyhow::Result<Self> {
        let validated = allowlist::validate_insecure_test_upstream(url)?;
        eprintln!("!!! CRUX CLOUD WITNESS INSECURE TEST UPSTREAM ENABLED: {validated} — TEST RECORDS ONLY !!!");
        self.insecure_test_upstream = Some(validated);
        Ok(self)
    }

    /// Return the insecure test origin when the explicit test opt-in is active.
    pub fn insecure_test_upstream(&self) -> Option<&str> {
        self.insecure_test_upstream.as_deref()
    }
}

/// Where the injected bundle came from, plus its identity fields.
#[derive(Debug, Clone)]
pub struct BundleSource {
    /// Rendered markdown (the boot-banner shape) injected verbatim.
    pub markdown: String,
    /// `stable_hash` from the bundle payload when the context endpoint
    /// supplied one (blake3 of the stable region, per the M1 spec). `None`
    /// for `--bundle-file` sources.
    pub stable_hash: Option<String>,
    /// Algorithm-prefixed digest of the injected bytes as a whole
    /// (`sha256:<hex>`), always present — links stream receipts back to the
    /// injection when `stable_hash` is absent.
    pub bundle_digest: String,
    /// `file:<path>` or `endpoint:<url>`.
    pub origin: String,
}

impl BundleSource {
    /// Build from rendered markdown, computing the transport digest.
    pub fn from_markdown(markdown: String, stable_hash: Option<String>, origin: String) -> Self {
        let bundle_digest = sha256_hex_prefixed(markdown.as_bytes());
        Self {
            markdown,
            stable_hash,
            bundle_digest,
            origin,
        }
    }
}

/// `sha256:<hex>` digest of `bytes`. The shim labels every digest with its
/// algorithm because the canonical daemon-side hash is blake3 — an unlabeled
/// hex string would invite cross-algorithm comparison bugs.
pub fn sha256_hex_prefixed(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for b in digest {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
    }
    out
}

/// Default-OFF gate: `CRUX_LLM_SHIM` must be `1` or `true`.
pub fn ensure_enabled() -> anyhow::Result<()> {
    match std::env::var(ENABLE_ENV) {
        Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") => Ok(()),
        _ => anyhow::bail!(
            "crux-llm-shim is default-OFF (experimental). Set {ENABLE_ENV}=1 to enable. \
             See docs/master-plan/shared/Context-Mediation-Points.md §3."
        ),
    }
}

/// Default-OFF gate: `CRUX_CLOUD_WITNESS` must be `1` or `true`.
pub fn ensure_cloud_witness_enabled() -> anyhow::Result<()> {
    match std::env::var(CLOUD_WITNESS_ENABLE_ENV) {
        Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") => Ok(()),
        _ => anyhow::bail!("cloud witness mode is default-OFF. Set {CLOUD_WITNESS_ENABLE_ENV}=1 to enable"),
    }
}

/// Resolve the insecure loopback test upstream from the environment.
///
/// In production builds `allow_insecure` must come from the loud CLI flag.
/// Unit tests may exercise the environment-only path under `cfg(test)`.
pub fn cloud_test_upstream_from_env(allow_insecure: bool) -> anyhow::Result<Option<String>> {
    let permitted = allow_insecure || cfg!(test);
    if !permitted {
        return Ok(None);
    }
    std::env::var(CLOUD_WITNESS_TEST_UPSTREAM_ENV)
        .ok()
        .map(|url| allowlist::validate_insecure_test_upstream(&url))
        .transpose()
}

/// Load a bundle from a file path (markdown, injected verbatim).
pub fn bundle_from_file(path: &std::path::Path) -> anyhow::Result<BundleSource> {
    let markdown =
        std::fs::read_to_string(path).with_context(|| format!("reading --bundle-file {}", path.display()))?;
    anyhow::ensure!(
        !markdown.trim().is_empty(),
        "--bundle-file is empty: {}",
        path.display()
    );
    Ok(BundleSource::from_markdown(
        markdown,
        None,
        format!("file:{}", path.display()),
    ))
}

/// Fetch a bundle from a context endpoint (plan A's `/v1/context` transport).
///
/// Tolerant payload handling: a JSON object with `markdown` (or
/// `bundle_markdown`) and optional `stable_hash` is preferred; a plain-text
/// body is used verbatim. The endpoint must itself be loopback/RFC1918 (it is
/// the local daemon) — validated with the same allowlist as the upstream.
pub fn bundle_from_endpoint(url: &str) -> anyhow::Result<BundleSource> {
    allowlist::validate_local_url(url).context("--context-endpoint must be local")?;
    let mut request = ureq::get(url).header("Accept", "application/json");
    if let Some(token) = crate::daemon_client::agent_token() {
        request = request.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = request.call().with_context(|| format!("GET {url}"))?;
    let mut body = String::new();
    response
        .body_mut()
        .as_reader()
        .read_to_string(&mut body)
        .context("reading context endpoint body")?;
    let (markdown, stable_hash) = match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(v) if v.is_object() => {
            let md = v
                .get("markdown")
                .or_else(|| v.get("bundle_markdown"))
                .or_else(|| v.get("rendered"))
                .and_then(|m| m.as_str())
                .map(str::to_string);
            let hash = v.get("stable_hash").and_then(|h| h.as_str()).map(str::to_string);
            match md {
                Some(md) => (md, hash),
                None => (body, hash),
            }
        }
        _ => (body, None),
    };
    anyhow::ensure!(!markdown.trim().is_empty(), "context endpoint returned an empty bundle");
    Ok(BundleSource::from_markdown(
        markdown,
        stable_hash,
        format!("endpoint:{url}"),
    ))
}

/// Running shim handle — `addr` is the bound listen address; `shutdown`
/// stops the accept loop (used by tests; the binary runs until killed).
pub struct ShimHandle {
    pub addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl ShimHandle {
    /// Signal the accept loop to stop and join it. A no-op connection is made
    /// to unblock `accept()`.
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.addr);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for ShimHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.addr);
    }
}

/// Validate config and start the shim server on a background accept loop.
///
/// Validation enforced here (not in the CLI) so library users get the same
/// guardrails: enable flag, upstream allowlist, loopback listen address.
pub fn serve(config: ShimConfig) -> anyhow::Result<ShimHandle> {
    ensure_enabled()?;
    allowlist::validate_upstream(&config.upstream)?;
    let listener =
        TcpListener::bind(&config.listen).with_context(|| format!("binding listen address {}", config.listen))?;
    let addr = listener.local_addr().context("resolving bound listen address")?;
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "listen address must be loopback (got {addr}); the shim is a local-only surface"
    );
    let stop = Arc::new(AtomicBool::new(false));
    let stop_accept = Arc::clone(&stop);
    let shared = Arc::new(config);
    let join = std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stop_accept.load(Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = stream else { continue };
            let conn_config = Arc::clone(&shared);
            std::thread::spawn(move || {
                http::handle_connection(stream, &conn_config);
            });
        }
    });
    Ok(ShimHandle {
        addr,
        stop,
        join: Some(join),
    })
}

/// Validate configuration and start cloud witness mode on a background
/// loopback-only accept loop.
///
/// A persistent-key failure is deliberately not a startup failure. The
/// runtime forwards traffic and emits `witness_degraded` records instead.
pub fn serve_cloud_witness(config: CloudWitnessConfig) -> anyhow::Result<ShimHandle> {
    ensure_cloud_witness_enabled()?;
    let runtime = cloud_witness::CloudWitnessRuntime::new(config)?;
    let listener = TcpListener::bind(&runtime.config().listen)
        .with_context(|| format!("binding listen address {}", runtime.config().listen))?;
    let addr = listener.local_addr().context("resolving bound listen address")?;
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "listen address must be loopback (got {addr}); cloud witness is a local-only surface"
    );
    let stop = Arc::new(AtomicBool::new(false));
    let stop_accept = Arc::clone(&stop);
    let shared = Arc::new(runtime);
    let join = std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stop_accept.load(Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = stream else { continue };
            let conn_runtime = Arc::clone(&shared);
            std::thread::spawn(move || {
                cloud_witness::handle_connection(stream, &conn_runtime);
            });
        }
    });
    Ok(ShimHandle {
        addr,
        stop,
        join: Some(join),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_digest_is_prefixed_and_stable() {
        let d = sha256_hex_prefixed(b"hello");
        assert!(d.starts_with("sha256:"));
        assert_eq!(d, sha256_hex_prefixed(b"hello"));
        assert_ne!(d, sha256_hex_prefixed(b"hellp"));
        // Known vector: sha256("hello")
        assert_eq!(
            d,
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn enable_gate_refuses_when_unset() {
        let _guard = crate::test_support::env_guard();
        std::env::remove_var(ENABLE_ENV);
        assert!(ensure_enabled().is_err());
        std::env::set_var(ENABLE_ENV, "0");
        assert!(ensure_enabled().is_err());
        std::env::set_var(ENABLE_ENV, "1");
        assert!(ensure_enabled().is_ok());
        std::env::set_var(ENABLE_ENV, "true");
        assert!(ensure_enabled().is_ok());
        std::env::remove_var(ENABLE_ENV);
    }

    #[test]
    fn cloud_gate_is_independent_from_local_gate() {
        let _guard = crate::test_support::env_guard();
        std::env::remove_var(ENABLE_ENV);
        std::env::remove_var(CLOUD_WITNESS_ENABLE_ENV);
        assert!(ensure_cloud_witness_enabled().is_err());
        std::env::set_var(ENABLE_ENV, "1");
        assert!(ensure_cloud_witness_enabled().is_err());
        std::env::remove_var(ENABLE_ENV);
        std::env::set_var(CLOUD_WITNESS_ENABLE_ENV, "1");
        assert!(ensure_cloud_witness_enabled().is_ok());
        assert!(ensure_enabled().is_err());
        std::env::remove_var(CLOUD_WITNESS_ENABLE_ENV);
    }

    #[test]
    fn unit_tests_may_resolve_loopback_test_upstream_without_cli_flag() {
        let _guard = crate::test_support::env_guard();
        std::env::set_var(CLOUD_WITNESS_TEST_UPSTREAM_ENV, "http://127.0.0.1:8123");
        assert_eq!(
            cloud_test_upstream_from_env(false).unwrap().as_deref(),
            Some("http://127.0.0.1:8123")
        );
        std::env::remove_var(CLOUD_WITNESS_TEST_UPSTREAM_ENV);
    }

    #[test]
    fn cloud_config_is_pinned_until_loud_test_opt_in() {
        let config = CloudWitnessConfig::new(
            allowlist::CloudUpstream::Anthropic,
            "127.0.0.1:0".into(),
            PathBuf::from("witness.key"),
            PathBuf::from("receipts.jsonl"),
            false,
        );
        assert!(config.insecure_test_upstream().is_none());
        assert!(config
            .clone()
            .with_insecure_test_upstream("http://attacker.example")
            .is_err());
        let test_config = config.with_insecure_test_upstream("http://127.0.0.1:8123").unwrap();
        assert_eq!(test_config.insecure_test_upstream(), Some("http://127.0.0.1:8123"));
    }

    #[test]
    fn bundle_from_markdown_carries_digest_and_origin() {
        let b = BundleSource::from_markdown("# bundle".into(), None, "file:/tmp/x.md".into());
        assert!(b.bundle_digest.starts_with("sha256:"));
        assert_eq!(b.origin, "file:/tmp/x.md");
        assert!(b.stable_hash.is_none());
    }
}
