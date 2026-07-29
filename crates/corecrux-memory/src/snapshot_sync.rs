// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Daemon-side client for the hosted compaction-snapshot object store
//! (CruxEngine `apps/api` `PUT/GET /v1/snapshots/:id`), plus the fail-closed Pro
//! gate that guards it (ExecPlan `hosted-compaction-sync-productization-2026-07-17`
//! M2; the object-storage plan's deferred daemon-side snapshot-push client).
//!
//! ## Credential model (investigated, not invented)
//!
//! The CruxEngine snapshot API authenticates each request via `x-api-key` +
//! `x-tenant-id` (CruxEngine `apps/api/src/plugins/auth.ts`, `ApiKeyAuth`), and
//! gates `/v1/snapshots/:id` on the `snapshot_sync` Pro entitlement, failing
//! **closed** with `402` when the tenant lacks it
//! (`apps/api/src/plugins/require-entitlement.ts`).
//!
//! The daemon already reaches CruxEngine `apps/api` with exactly this header pair
//! via the engine-mediation client (`CORECRUXD_ENGINE_BASE_URL` +
//! `CORECRUXD_ENGINE_API_KEY`, injected as `x-api-key`; see
//! `corecruxd::http::engine_console`, grounded from CruxEngine's openapi
//! `securitySchemes.ApiKeyAuth.name`). This client **reuses that existing
//! credential family** and adds only a tenant id (`CORECRUXD_ENGINE_TENANT_ID`)
//! for the per-tenant snapshot object key `tenants/<tenant>/snapshots/<id>`.
//!
//! The fact-sync / mirror path (`CORECRUXD_SYNC_REMOTE_URL` +
//! `CORECRUXD_SYNC_API_KEY`, `Authorization: Bearer`) targets a hosted
//! *corecruxd* (`/v1/facts/bulk`), **not** CruxEngine `apps/api`; its Bearer
//! credential does not satisfy the snapshot API's `x-api-key` / `x-tenant-id`
//! auth and it carries no per-user tenant, so it is deliberately NOT reused here.
//!
//! ## Fail-closed gate (M2)
//!
//! Hosted snapshot egress happens ONLY when all three hold: the `CRUX_COMPACTION_SYNC`
//! opt-in is on, the CruxEngine credential is fully configured, and the tenant
//! carries the Pro entitlement (proven by the server, not asserted locally). A
//! server `402` latches the gate closed for the rest of the process with a single
//! "Pro required" log — no retry loop. When the opt-in is off or the credential
//! is missing, the gate is closed and every call is a zero-work no-op, so the free
//! local compaction path is byte-for-byte unchanged.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::fact_store::{default_tenant_hash, StoreFact};

/// Hard cap on a single snapshot object, mirroring the server's
/// `SNAPSHOT_MAX_BYTES` (`apps/api/src/snapshots/storage.ts`). Enforced
/// client-side *before* the request is sent so an oversized snapshot fails
/// locally instead of round-tripping to a `413`.
pub const SNAPSHOT_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Explicit default-OFF opt-in, shared verbatim with the hook writer
/// (`crux_claude_hooks::snapshot_crypto::hosted_sync_enabled`): only `1`/`on`
/// enable hosted egress; `0`, `off`, and unset are all off.
pub const COMPACTION_SYNC_ENV: &str = "CRUX_COMPACTION_SYNC";

/// CruxEngine base URL — reused from the engine-mediation client.
pub const ENGINE_BASE_URL_ENV: &str = "CORECRUXD_ENGINE_BASE_URL";
/// CruxEngine API key — reused from the engine-mediation client; sent as `x-api-key`.
pub const ENGINE_API_KEY_ENV: &str = "CORECRUXD_ENGINE_API_KEY";
/// The daemon's own CruxEngine tenant id; sent as `x-tenant-id` and the object
/// key prefix. The engine-mediation client's `CORECRUXD_ENGINE_SEARCH_TENANT` is
/// a *corpus* selector (default `wikicrux`) — wrong for the per-user snapshot
/// store — so the tenant is carried in its own var.
pub const ENGINE_TENANT_ID_ENV: &str = "CORECRUXD_ENGINE_TENANT_ID";

/// Grounded from CruxEngine openapi `securitySchemes.ApiKeyAuth.name`.
const API_KEY_HEADER: &str = "x-api-key";
/// Required by CruxEngine's auth middleware for per-tenant routes (`TenantHeader`).
const TENANT_HEADER: &str = "x-tenant-id";

/// Fact entity under which a hosted push/pull receipt is recorded. `__ops::` is a
/// born-private reserved prefix (`crate::fact_privacy`); every fact-store write
/// mints a CROWN receipt by construction, so this IS the "existing receipt path".
pub const RECEIPT_ENTITY: &str = "__ops::compaction-sync";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Whether the `CRUX_COMPACTION_SYNC` opt-in is on.
#[must_use]
pub fn opt_in_enabled() -> bool {
    matches!(std::env::var(COMPACTION_SYNC_ENV).as_deref(), Ok("1" | "on"))
}

/// True iff `id` matches the server's snapshot-id charset `^[A-Za-z0-9._-]{1,128}$`
/// (`apps/api/src/snapshots/storage.ts` `SNAPSHOT_ID_PATTERN`).
#[must_use]
pub fn is_valid_snapshot_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Resolved CruxEngine snapshot-store credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotSyncConfig {
    /// CruxEngine base URL, trailing slash trimmed.
    pub base_url: String,
    /// API key sent as `x-api-key`.
    pub api_key: String,
    /// Tenant id sent as `x-tenant-id` and used as the object key prefix.
    pub tenant_id: String,
}

impl SnapshotSyncConfig {
    /// Resolve the credential from the reused `CORECRUXD_ENGINE_*` env family.
    /// Returns `None` when any of base URL / API key / tenant id is absent or
    /// blank — the gate then stays closed (fail-closed on missing config).
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let base_url = trimmed_env(ENGINE_BASE_URL_ENV)?.trim_end_matches('/').to_string();
        let api_key = trimmed_env(ENGINE_API_KEY_ENV)?;
        let tenant_id = trimmed_env(ENGINE_TENANT_ID_ENV)?;
        if base_url.is_empty() {
            return None;
        }
        Some(Self {
            base_url,
            api_key,
            tenant_id,
        })
    }
}

fn trimmed_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// A hosted-snapshot operation, for receipts and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotOp {
    Push,
    Pull,
}

impl SnapshotOp {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Pull => "pull",
        }
    }
}

/// Transport / policy failures from a snapshot push or pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotSyncError {
    /// The snapshot id is outside the server charset (never sent).
    InvalidId,
    /// The payload exceeds [`SNAPSHOT_MAX_BYTES`] (rejected before sending).
    TooLarge { size: usize, cap: usize },
    /// Server `402` — the tenant lacks the `snapshot_sync` Pro entitlement.
    ProRequired,
    /// Server `401` / `403` — the credential is invalid for this tenant.
    Unauthorized,
    /// Any other non-success status.
    Upstream { status: u16 },
    /// A transport error (connect/read/timeout); carries a terse reason.
    Transport(String),
}

impl std::fmt::Display for SnapshotSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidId => write!(f, "invalid snapshot id"),
            Self::TooLarge { size, cap } => {
                write!(f, "snapshot is {size} bytes, over the {cap} byte cap")
            }
            Self::ProRequired => write!(f, "Pro entitlement required (snapshot_sync)"),
            Self::Unauthorized => write!(f, "snapshot credential rejected"),
            Self::Upstream { status } => write!(f, "snapshot store returned HTTP {status}"),
            Self::Transport(reason) => write!(f, "snapshot store transport error: {reason}"),
        }
    }
}

impl std::error::Error for SnapshotSyncError {}

/// Client for the CruxEngine hosted snapshot object store. Stateless beyond the
/// credential + a configured `ureq` agent; safe to share.
pub struct SnapshotSyncClient {
    config: SnapshotSyncConfig,
    agent: ureq::Agent,
}

impl SnapshotSyncClient {
    /// Build a client for `config` with a bounded-timeout, non-erroring-on-status agent.
    #[must_use]
    pub fn new(config: SnapshotSyncConfig) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .build()
            .into();
        Self { config, agent }
    }

    /// The tenant this client authenticates as.
    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.config.tenant_id
    }

    fn snapshot_url(&self, id: &str) -> String {
        format!("{}/v1/snapshots/{id}", self.config.base_url)
    }

    /// PUT an opaque (client-encrypted) snapshot blob. `204`/`200` ⇒ `Ok`. The
    /// [`SNAPSHOT_MAX_BYTES`] cap is enforced before the request is sent.
    ///
    /// # Errors
    /// See [`SnapshotSyncError`] — notably [`SnapshotSyncError::ProRequired`] on a
    /// `402` (non-Pro tenant, fail-closed at the server).
    pub fn push(&self, id: &str, bytes: &[u8]) -> Result<(), SnapshotSyncError> {
        if !is_valid_snapshot_id(id) {
            return Err(SnapshotSyncError::InvalidId);
        }
        if bytes.len() > SNAPSHOT_MAX_BYTES {
            return Err(SnapshotSyncError::TooLarge {
                size: bytes.len(),
                cap: SNAPSHOT_MAX_BYTES,
            });
        }
        let response = self
            .agent
            .put(&self.snapshot_url(id))
            .header(API_KEY_HEADER, &self.config.api_key)
            .header(TENANT_HEADER, &self.config.tenant_id)
            .header("content-type", "application/octet-stream")
            .send(bytes)
            .map_err(|e| SnapshotSyncError::Transport(e.to_string()))?;
        match response.status().as_u16() {
            200 | 204 => Ok(()),
            402 => Err(SnapshotSyncError::ProRequired),
            401 | 403 => Err(SnapshotSyncError::Unauthorized),
            413 => Err(SnapshotSyncError::TooLarge {
                size: bytes.len(),
                cap: SNAPSHOT_MAX_BYTES,
            }),
            status => Err(SnapshotSyncError::Upstream { status }),
        }
    }

    /// GET a snapshot blob. `200` ⇒ `Ok(Some(bytes))`; `404` ⇒ `Ok(None)`.
    /// The read is capped at [`SNAPSHOT_MAX_BYTES`].
    ///
    /// # Errors
    /// See [`SnapshotSyncError`].
    pub fn pull(&self, id: &str) -> Result<Option<Vec<u8>>, SnapshotSyncError> {
        if !is_valid_snapshot_id(id) {
            return Err(SnapshotSyncError::InvalidId);
        }
        let response = self
            .agent
            .get(&self.snapshot_url(id))
            .header(API_KEY_HEADER, &self.config.api_key)
            .header(TENANT_HEADER, &self.config.tenant_id)
            .call()
            .map_err(|e| SnapshotSyncError::Transport(e.to_string()))?;
        match response.status().as_u16() {
            200 => {
                let bytes = response
                    .into_body()
                    .with_config()
                    .limit(SNAPSHOT_MAX_BYTES as u64 + 1)
                    .read_to_vec()
                    .map_err(|e| SnapshotSyncError::Transport(e.to_string()))?;
                if bytes.len() > SNAPSHOT_MAX_BYTES {
                    return Err(SnapshotSyncError::TooLarge {
                        size: bytes.len(),
                        cap: SNAPSHOT_MAX_BYTES,
                    });
                }
                Ok(Some(bytes))
            }
            404 => Ok(None),
            402 => Err(SnapshotSyncError::ProRequired),
            401 | 403 => Err(SnapshotSyncError::Unauthorized),
            status => Err(SnapshotSyncError::Upstream { status }),
        }
    }
}

/// Outcome of a gated push.
#[derive(Debug)]
pub enum GatePushOutcome {
    /// The gate is closed (opt-in off, no config, or latched after a `402`) —
    /// nothing was sent.
    Skipped,
    /// The snapshot was stored.
    Pushed,
    /// The server returned `402`; the gate is now latched closed for the process.
    ProRequired,
    /// A transient failure (transport / `5xx`); the gate stays open to retry later.
    Failed(SnapshotSyncError),
}

type ReceiptSink = Box<dyn Fn(StoreFact) + Send + Sync>;

/// The M2 fail-closed gate. Holds a client only when the opt-in + config both
/// hold; a `402` latches it closed for the process (single "Pro required" log, no
/// retry loop). When closed, [`SnapshotSyncGate::push`] is a zero-work no-op.
pub struct SnapshotSyncGate {
    client: Option<SnapshotSyncClient>,
    disabled: AtomicBool,
    pro_required_logged: AtomicBool,
    receipt_sink: Option<ReceiptSink>,
}

impl SnapshotSyncGate {
    /// Resolve the gate from the environment: a client is present only when the
    /// opt-in is on AND the credential is fully configured. No receipt sink.
    #[must_use]
    pub fn from_env() -> Self {
        let client = if opt_in_enabled() {
            SnapshotSyncConfig::from_env().map(SnapshotSyncClient::new)
        } else {
            None
        };
        Self::from_client(client)
    }

    /// Build a gate around an explicit (possibly absent) client. `None` ⇒ closed.
    #[must_use]
    pub fn from_client(client: Option<SnapshotSyncClient>) -> Self {
        Self {
            client,
            disabled: AtomicBool::new(false),
            pro_required_logged: AtomicBool::new(false),
            receipt_sink: None,
        }
    }

    /// Attach a sink that receives one born-private receipt [`StoreFact`] per
    /// successful push (the daemon writes it to its fact store → CROWN receipt).
    #[must_use]
    pub fn with_receipt_sink(mut self, sink: ReceiptSink) -> Self {
        self.receipt_sink = Some(sink);
        self
    }

    /// Whether the gate would attempt a push right now.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.client.is_some() && !self.disabled.load(Ordering::Relaxed)
    }

    /// Attempt a gated push. Closed gate ⇒ [`GatePushOutcome::Skipped`] (no work).
    /// A `402` latches the gate closed and logs once; other errors leave it open.
    /// On success a receipt is emitted via the sink, if any.
    pub fn push(&self, id: &str, bytes: &[u8]) -> GatePushOutcome {
        if self.disabled.load(Ordering::Relaxed) {
            return GatePushOutcome::Skipped;
        }
        let Some(client) = self.client.as_ref() else {
            return GatePushOutcome::Skipped;
        };
        match client.push(id, bytes) {
            Ok(()) => {
                if let Some(sink) = self.receipt_sink.as_ref() {
                    sink(receipt_fact(
                        SnapshotOp::Push,
                        id,
                        client.tenant_id(),
                        bytes.len(),
                        now_unix_ms(),
                    ));
                }
                GatePushOutcome::Pushed
            }
            Err(SnapshotSyncError::ProRequired) => {
                self.disabled.store(true, Ordering::Relaxed);
                if !self.pro_required_logged.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        target: "compaction_sync",
                        "hosted compaction snapshot sync disabled for this session: Pro entitlement (snapshot_sync) required"
                    );
                }
                GatePushOutcome::ProRequired
            }
            Err(other) => GatePushOutcome::Failed(other),
        }
    }
}

/// Build the born-private receipt fact for one hosted push/pull. Every fact-store
/// write mints a CROWN receipt by construction, so writing this IS the receipt.
#[must_use]
pub fn receipt_fact(op: SnapshotOp, id: &str, tenant: &str, bytes: usize, at_unix_ms: u64) -> StoreFact {
    let value = serde_json::json!({
        "op": op.as_str(),
        "snapshot_id": id,
        "tenant": tenant,
        "bytes": bytes,
        "at_unix_ms": at_unix_ms,
    })
    .to_string();
    StoreFact {
        tenant_hash: default_tenant_hash(),
        entity: RECEIPT_ENTITY.to_string(),
        key: format!("{}:{id}:{at_unix_ms}", op.as_str()),
        value,
        source_receipt: Some(format!("compaction-sync:{}:{id}", op.as_str())),
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::mpsc;

    // ── One-shot HTTP stub (mirrors engine_console's test stub) ────────────────
    // Captures the request (headers + declared body) and returns a canned status
    // + body. Returns the base URL and a channel carrying the raw request text.
    fn spawn_stub(status_line: &'static str, body: &'static [u8]) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let base_url = format!("http://{}", listener.local_addr().expect("addr"));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut bytes = Vec::new();
            let mut buf = [0u8; 4096];
            let header_end = loop {
                if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break bytes.len(),
                    Ok(n) => bytes.extend_from_slice(&buf[..n]),
                }
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end.min(bytes.len())]).to_string();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.trim()
                        .eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            let want = header_end + content_length;
            while bytes.len() < want {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => bytes.extend_from_slice(&buf[..n]),
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&bytes).to_string());
            let _ = write!(
                stream,
                "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(body);
        });
        (base_url, rx)
    }

    fn client(base_url: &str) -> SnapshotSyncClient {
        SnapshotSyncClient::new(SnapshotSyncConfig {
            base_url: base_url.to_string(),
            api_key: "sk-test-secret".to_string(),
            tenant_id: "tenant-abc".to_string(),
        })
    }

    #[test]
    fn valid_snapshot_id_matches_server_charset() {
        assert!(is_valid_snapshot_id("sess-abc.123_DEF"));
        assert!(!is_valid_snapshot_id(""));
        assert!(!is_valid_snapshot_id("has/slash"));
        assert!(!is_valid_snapshot_id("space here"));
        assert!(!is_valid_snapshot_id(&"x".repeat(129)));
    }

    #[test]
    fn push_sends_octet_stream_with_reused_credential_headers() {
        let (base_url, rx) = spawn_stub("204 No Content", b"");
        let out = client(&base_url).push("sess-1", b"ciphertext-blob");
        assert!(out.is_ok(), "204 must be Ok: {out:?}");
        let req = rx.recv().expect("captured request");
        assert!(req.starts_with("PUT /v1/snapshots/sess-1 "), "req line: {req}");
        let lower = req.to_ascii_lowercase();
        assert!(lower.contains("x-api-key: sk-test-secret"), "x-api-key header: {req}");
        assert!(lower.contains("x-tenant-id: tenant-abc"), "x-tenant-id header: {req}");
        assert!(
            lower.contains("content-type: application/octet-stream"),
            "octet-stream: {req}"
        );
        assert!(req.contains("ciphertext-blob"), "body must be sent: {req}");
    }

    #[test]
    fn push_over_cap_fails_before_sending() {
        // Point at a closed port: if the cap check did NOT short-circuit, the send
        // would produce a Transport error instead of TooLarge.
        let c = client("http://127.0.0.1:1");
        let oversize = vec![0u8; SNAPSHOT_MAX_BYTES + 1];
        match c.push("sess-big", &oversize) {
            Err(SnapshotSyncError::TooLarge { size, cap }) => {
                assert_eq!(size, SNAPSHOT_MAX_BYTES + 1);
                assert_eq!(cap, SNAPSHOT_MAX_BYTES);
            }
            other => panic!("expected TooLarge before send, got {other:?}"),
        }
    }

    #[test]
    fn push_402_maps_to_pro_required() {
        let (base_url, _rx) = spawn_stub(
            "402 Payment Required",
            br#"{"ok":false,"error":{"code":"api.validation.entitlement_required","entitlement":"snapshot_sync"}}"#,
        );
        assert_eq!(client(&base_url).push("s", b"x"), Err(SnapshotSyncError::ProRequired));
    }

    #[test]
    fn pull_200_returns_bytes_404_returns_none() {
        let (ok_url, _rx) = spawn_stub("200 OK", b"opaque-bytes");
        assert_eq!(client(&ok_url).pull("s").unwrap(), Some(b"opaque-bytes".to_vec()));

        let (miss_url, _rx2) = spawn_stub("404 Not Found", b"");
        assert_eq!(client(&miss_url).pull("s").unwrap(), None);
    }

    #[test]
    fn pull_402_maps_to_pro_required() {
        let (base_url, _rx) = spawn_stub("402 Payment Required", b"");
        assert_eq!(client(&base_url).pull("s"), Err(SnapshotSyncError::ProRequired));
    }

    #[test]
    fn gate_closed_when_opt_in_off_is_a_noop() {
        // No client ⇒ closed ⇒ Skipped, no network, free path untouched.
        let gate = SnapshotSyncGate::from_client(None);
        assert!(!gate.is_open());
        assert!(matches!(gate.push("s", b"x"), GatePushOutcome::Skipped));
    }

    #[test]
    fn gate_latches_closed_after_402_and_logs_once() {
        let (base_url, _rx) = spawn_stub("402 Payment Required", b"");
        let gate = SnapshotSyncGate::from_client(Some(client(&base_url)));
        assert!(gate.is_open());
        assert!(matches!(gate.push("s", b"x"), GatePushOutcome::ProRequired));
        // Latched: further pushes are Skipped (no retry loop), gate now closed.
        assert!(!gate.is_open());
        assert!(matches!(gate.push("s", b"x"), GatePushOutcome::Skipped));
        assert!(gate.pro_required_logged.load(Ordering::Relaxed));
    }

    #[test]
    fn gate_emits_born_private_receipt_on_success() {
        let (base_url, _rx) = spawn_stub("204 No Content", b"");
        let sink: std::sync::Arc<std::sync::Mutex<Vec<StoreFact>>> = std::sync::Arc::default();
        let captured = sink.clone();
        let gate = SnapshotSyncGate::from_client(Some(client(&base_url)))
            .with_receipt_sink(Box::new(move |f| captured.lock().unwrap().push(f)));
        assert!(matches!(gate.push("sess-9", b"blob"), GatePushOutcome::Pushed));
        let facts = sink.lock().unwrap();
        assert_eq!(facts.len(), 1);
        let f = &facts[0];
        assert_eq!(f.entity, RECEIPT_ENTITY);
        assert!(f.private, "receipt must be born-private");
        assert!(f.value.contains("\"op\":\"push\""));
        assert!(f.value.contains("sess-9"));
        assert_eq!(f.source_receipt.as_deref(), Some("compaction-sync:push:sess-9"));
    }

    #[test]
    fn receipt_fact_shape_for_pull() {
        let f = receipt_fact(SnapshotOp::Pull, "sess-2", "tenant-x", 42, 1_700_000_000_000);
        assert_eq!(f.entity, RECEIPT_ENTITY);
        assert!(f.private);
        assert_eq!(f.key, "pull:sess-2:1700000000000");
        assert!(f.value.contains("\"bytes\":42"));
        assert!(f.value.contains("\"tenant\":\"tenant-x\""));
    }
}
