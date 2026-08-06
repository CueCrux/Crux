// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl login` — unified, auto-selected auth rails for the Crux Daemon.
//!
//! One command authenticates a client to a daemon wherever it lives, picking
//! the lowest-friction *secure* rail automatically:
//!
//! 1. **discover** the daemon: `--url` → `~/.config/cuecrux/env` → localhost.
//!    (Tailnet MagicDNS discovery arrives with the Tailscale rail, M2.)
//! 2. **probe** `/readyz` + `/v1/version` for reachability + version, then an
//!    authenticated read route to learn the auth posture (off vs required).
//! 3. **select a rail** (highest-preference reachable & secure):
//!    - Rail 1 `loopback` + `auth=off`  → no credential.
//!    - Rail 2 `tailscale` identity      → daemon auto-mints a scoped JWT (M2).
//!    - Rail 3 `device` grant            → device-authorization flow (M3).
//!    - Rail 4 `static_token` (`--token`)→ store a static named token (CI/air-gapped).
//! 4. **persist** the credential → `~/.config/cuecrux/credentials.json` (0600).
//! 5. **register MCP** for the resolved daemon (`~/.config/cuecrux/env`) and
//!    verify `tools/list` + a `store_fact`→`query_facts` round-trip.
//!
//! This module is the M1 scaffold: Rail 1 (loopback) and Rail 4 (`--token`) are
//! wired end-to-end with no daemon changes. The Tailscale and device rails are
//! recognised by the selector but gated to "not yet implemented" until M2/M3.
//! Network I/O is isolated in thin functions; the rail-selection, credential
//! store, URL, and env-file logic is pure and unit-tested.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Default loopback HTTP base for the Crux Daemon. Port 14800 is fixed.
pub const DEFAULT_HTTP_BASE: &str = "http://127.0.0.1:14800";
/// HTTP port (REST API). Never changed.
pub const HTTP_PORT: u16 = 14800;
/// MCP port (agent-facing tools). Never changed.
pub const MCP_PORT: u16 = 14801;
/// Credential store schema version. Bump on incompatible shape changes.
const STORE_SCHEMA_VERSION: u32 = 1;

// ──────────────────────────────────────────────────────────────────────────
// Rails + posture
// ──────────────────────────────────────────────────────────────────────────

/// The auth rail selected for a daemon. Each rail degrades closed: an off-host
/// rail only works over encrypted transport, and every issued credential reuses
/// the daemon's existing scope model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rail {
    /// Rail 1 — loopback trust on a daemon with `auth=off`. No credential.
    Loopback,
    /// Rail 2 — verified tailnet identity → daemon-minted scoped JWT (M2).
    Tailscale,
    /// Rail 3 — RFC 8628 device-authorization grant (M3).
    Device,
    /// Rail 4 — operator-provided static named token (CI / air-gapped).
    StaticToken,
}

impl Rail {
    /// Stable string form persisted in the credential store.
    pub fn as_str(self) -> &'static str {
        match self {
            Rail::Loopback => "loopback",
            Rail::Tailscale => "tailscale",
            Rail::Device => "device",
            Rail::StaticToken => "static_token",
        }
    }

    /// Whether this rail is wired end-to-end in the current build. All four
    /// rails are implemented as of M4 (loopback + static token in M1, tailscale
    /// in M2, device grant in M3).
    pub fn is_implemented(self) -> bool {
        matches!(
            self,
            Rail::Loopback | Rail::StaticToken | Rail::Tailscale | Rail::Device
        )
    }
}

/// The daemon's authentication posture as observed by an unauthenticated probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPosture {
    /// `auth=off` — read routes succeed without a credential.
    Off,
    /// A credential is required (any of `dev_scopes` / `jwt_hs256` / `jwt_jwks`).
    Required,
}

/// Signals fed to rail selection. Kept as a plain struct so the selection table
/// is exhaustively unit-testable without any network or environment access.
#[derive(Debug, Clone, Copy)]
pub struct RailInputs {
    /// The resolved daemon HTTP base is a loopback address.
    pub is_loopback: bool,
    /// An explicit `--token` was supplied (forces the static-token rail).
    pub explicit_token: bool,
    /// An ambient static token is present (e.g. `CRUX_AGENT_TOKEN` in the env
    /// file). Used only as a last-resort fallback — it must NOT override an
    /// explicit `--device`, and (since the MCP agent token lives under the same
    /// var) it must not hijack the loopback/tailnet rails.
    pub ambient_token: bool,
    /// `--device` was requested explicitly.
    pub device_flag: bool,
    /// A verified tailnet identity is present.
    pub tailscale_identity: bool,
    /// The probed auth posture.
    pub posture: AuthPosture,
}

/// Select the highest-preference secure rail for the given signals.
///
/// Order: explicit `--token` → explicit `--device` → loopback (`auth=off`) →
/// tailnet identity → ambient static token (fallback) → error. An *ambient*
/// token (env-file `CRUX_AGENT_TOKEN`, which doubles as the MCP agent token) is
/// deliberately the lowest-priority signal so it never hijacks `--device` or the
/// loopback/tailnet rails.
pub fn select_rail(inputs: RailInputs) -> Result<Rail, String> {
    // Explicit operator intent first.
    if inputs.explicit_token {
        return Ok(Rail::StaticToken);
    }
    if inputs.device_flag {
        return Ok(Rail::Device);
    }
    // Auto-selection: cheapest secure rail first.
    if inputs.posture == AuthPosture::Off {
        return Ok(Rail::Loopback);
    }
    if inputs.tailscale_identity {
        return Ok(Rail::Tailscale);
    }
    // Last resort: an ambient static token, if one is present.
    if inputs.ambient_token {
        return Ok(Rail::StaticToken);
    }
    let transport_note = if inputs.is_loopback {
        ""
    } else {
        " (off-host rails require encrypted transport)"
    };
    Err(format!(
        "daemon requires authentication but no rail is available: pass --token for a static named \
         token (Rail 4), or use --device for the device grant (Rail 3, lands in M3){transport_note}"
    ))
}

// ──────────────────────────────────────────────────────────────────────────
// Credential store  (~/.config/cuecrux/credentials.json, 0600)
// ──────────────────────────────────────────────────────────────────────────

/// One daemon's stored credential, keyed in the store by its HTTP URL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonCredential {
    /// Which rail produced this credential (`as_str` of [`Rail`]).
    pub rail: String,
    /// Short-lived access token (JWT) or static named token. Absent for Rail 1.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub access_token: Option<String>,
    /// Long-lived, named + revocable refresh credential (device rail; M3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_token: Option<String>,
    /// Absolute Unix-seconds expiry of the device refresh credential.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_expiry: Option<u64>,
    /// Unix-seconds expiry of `access_token`, if it is short-lived.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expiry: Option<u64>,
    /// Scopes granted to this credential (informational; the daemon is the gate).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Resolved MCP endpoint for this daemon.
    pub mcp_url: String,
    /// Resolved HTTP base for this daemon.
    pub http_url: String,
}

/// The on-disk credential store, keyed by daemon HTTP URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStore {
    /// Schema version for forward-compatibility.
    #[serde(default = "default_schema_version")]
    pub version: u32,
    /// daemon HTTP URL → credential.
    #[serde(default)]
    pub daemons: BTreeMap<String, DaemonCredential>,
}

fn default_schema_version() -> u32 {
    STORE_SCHEMA_VERSION
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self {
            version: STORE_SCHEMA_VERSION,
            daemons: BTreeMap::new(),
        }
    }
}

impl CredentialStore {
    /// Insert or replace the credential for `http_url`.
    pub fn upsert(&mut self, http_url: &str, cred: DaemonCredential) {
        self.daemons.insert(http_url.to_string(), cred);
    }
}

/// Resolve `~/.config/cuecrux` from `$HOME`. Returns `None` when `$HOME` is unset.
pub fn config_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| Path::new(&home).join(".config").join("cuecrux"))
}

/// Path to the credential store under a given config dir.
pub fn credentials_path(config_dir: &Path) -> PathBuf {
    config_dir.join("credentials.json")
}

/// Path to the shared env file under a given config dir.
pub fn env_path(config_dir: &Path) -> PathBuf {
    config_dir.join("env")
}

/// Load the credential store, returning an empty store if the file is absent.
pub fn load_store(path: &Path) -> Result<CredentialStore, DynErr> {
    match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(CredentialStore::default()),
        Ok(s) => Ok(serde_json::from_str(&s)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CredentialStore::default()),
        Err(e) => Err(Box::new(e)),
    }
}

/// Persist the credential store with owner-only (0600) permissions, creating
/// the parent directory if needed. The directory is created 0700 on unix.
pub fn save_store(path: &Path, store: &CredentialStore) -> Result<(), DynErr> {
    if let Some(parent) = path.parent() {
        create_dir_private(parent)?;
    }
    let json = serde_json::to_string_pretty(store)?;
    write_private(path, json.as_bytes())?;
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────
// Private filesystem helpers (0600 files, 0700 dirs)
// ──────────────────────────────────────────────────────────────────────────

fn create_dir_private(dir: &Path) -> Result<(), DynErr> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dir)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(dir, perms)?;
    }
    Ok(())
}

/// Write `bytes` to `path`, leaving the file 0600. Truncates any existing file.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), DynErr> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    // Re-assert in case the file pre-existed with looser perms (the create-mode
    // does not relax an existing file's bits).
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), DynErr> {
    use std::io::Write as _;
    let mut f = std::fs::File::create(path)?;
    f.write_all(bytes)?;
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────
// URL helpers
// ──────────────────────────────────────────────────────────────────────────

/// Normalise a user-supplied daemon URL into an HTTP base: add `http://` when no
/// scheme is present and strip a trailing slash. Returns an error for input that
/// cannot be parsed as a URL.
pub fn normalize_http_base(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty daemon URL".to_string());
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let parsed = url::Url::parse(&with_scheme).map_err(|e| format!("invalid daemon URL '{input}': {e}"))?;
    if parsed.host_str().is_none() {
        return Err(format!("daemon URL '{input}' has no host"));
    }
    Ok(with_scheme.trim_end_matches('/').to_string())
}

/// Derive the MCP endpoint (`http(s)://host:14801/mcp`) from an HTTP base.
/// The MCP port is fixed at 14801; only the port and path are rewritten.
pub fn derive_mcp_url(http_base: &str) -> Result<String, String> {
    let parsed = url::Url::parse(http_base).map_err(|e| format!("invalid HTTP base '{http_base}': {e}"))?;
    let scheme = parsed.scheme();
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("HTTP base '{http_base}' has no host"))?;
    Ok(format!("{scheme}://{host}:{MCP_PORT}/mcp"))
}

/// Whether an HTTP base points at a loopback address (127.0.0.0/8, ::1, localhost).
pub fn is_loopback_url(http_base: &str) -> bool {
    let Ok(parsed) = url::Url::parse(http_base) else {
        return false;
    };
    match parsed.host_str() {
        Some("localhost") => true,
        Some(host) => {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
                return v4.is_loopback();
            }
            if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
                return v6.is_loopback();
            }
            false
        }
        None => false,
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Env-file parsing + discovery
// ──────────────────────────────────────────────────────────────────────────

/// Parse a dotenv-style `KEY=VALUE` file. Blank lines and `#` comments are
/// skipped; a leading `export ` is tolerated; surrounding quotes are stripped.
pub fn parse_env_file(content: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().to_string();
        if key.is_empty() {
            continue;
        }
        let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
        out.insert(key, val);
    }
    out
}

/// Merge `updates` into the existing env-file `content`, replacing in place where
/// a key already exists and appending new keys at the end. Comments and unrelated
/// lines are preserved. Returns the rendered file content.
pub fn render_env_file(existing: &str, updates: &BTreeMap<String, String>) -> String {
    let mut applied: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut lines: Vec<String> = Vec::new();
    for raw in existing.lines() {
        let trimmed = raw.trim();
        let body = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        if let Some((k, _)) = body.split_once('=') {
            let key = k.trim();
            if let Some(val) = updates.get(key) {
                lines.push(format!("{key}={val}"));
                applied.insert(key.to_string());
                continue;
            }
        }
        lines.push(raw.to_string());
    }
    for (key, val) in updates {
        if !applied.contains(key) {
            lines.push(format!("{key}={val}"));
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Persist a daemon endpoint into `~/.config/cuecrux/env` (0600) so the Claude
/// Code hooks + agent bridges resolve it. Writes `CRUX_HTTP_URL` and the derived
/// `CRUX_MCP_URL`, preserving any other keys (notably `CRUX_AGENT_TOKEN`). The
/// input is normalised (a bare `host:port` gains `http://`). Returns the resolved
/// `(http_base, mcp_url)` and the path written. Shared by `login` and
/// `hooks install --endpoint`.
pub fn save_endpoint(http_base_input: &str) -> Result<(String, String, PathBuf), DynErr> {
    let http_base = normalize_http_base(http_base_input)?;
    let mcp_url = derive_mcp_url(&http_base)?;
    let cfg_dir = config_dir().ok_or("HOME is not set")?;
    let path = env_path(&cfg_dir);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut updates: BTreeMap<String, String> = BTreeMap::new();
    updates.insert("CRUX_MCP_URL".to_string(), mcp_url.clone());
    updates.insert("CRUX_HTTP_URL".to_string(), http_base.clone());
    let rendered = render_env_file(&existing, &updates);
    create_dir_private(&cfg_dir)?;
    write_private(&path, rendered.as_bytes())?;
    Ok((http_base, mcp_url, path))
}

/// Read the daemon HTTP endpoint currently configured in `~/.config/cuecrux/env`,
/// if any. Returns `None` when the file is absent or has no `CRUX_HTTP_URL`.
pub fn configured_endpoint() -> Option<String> {
    let cfg_dir = config_dir()?;
    let content = std::fs::read_to_string(env_path(&cfg_dir)).ok()?;
    parse_env_file(&content).get("CRUX_HTTP_URL").cloned()
}

/// Build the ordered daemon-discovery candidate list from the available signals.
///
/// Order: explicit `--url` → `CRUX_HTTP_URL` / `CORECRUXD_HTTP_URL` from the env
/// file → an HTTP base derived from `CRUX_MCP_URL` in the env file → localhost.
/// Each entry is normalised; duplicates and un-parseable entries are dropped.
pub fn discover_candidates(explicit: Option<&str>, env_vars: &BTreeMap<String, String>) -> Vec<String> {
    let mut raw: Vec<String> = Vec::new();
    if let Some(u) = explicit {
        raw.push(u.to_string());
    }
    for key in ["CRUX_HTTP_URL", "CORECRUXD_HTTP_URL"] {
        if let Some(v) = env_vars.get(key) {
            if !v.trim().is_empty() {
                raw.push(v.clone());
            }
        }
    }
    if let Some(mcp) = env_vars.get("CRUX_MCP_URL") {
        if let Some(base) = http_base_from_mcp_url(mcp) {
            raw.push(base);
        }
    }
    raw.push(DEFAULT_HTTP_BASE.to_string());

    let mut out: Vec<String> = Vec::new();
    for candidate in raw {
        if let Ok(norm) = normalize_http_base(&candidate) {
            if !out.contains(&norm) {
                out.push(norm);
            }
        }
    }
    out
}

/// Derive an HTTP base from an MCP URL by rewriting the port to 14800 and
/// dropping the path. Returns `None` if the MCP URL cannot be parsed.
fn http_base_from_mcp_url(mcp_url: &str) -> Option<String> {
    let parsed = url::Url::parse(mcp_url.trim()).ok()?;
    let scheme = parsed.scheme();
    let host = parsed.host_str()?;
    Some(format!("{scheme}://{host}:{HTTP_PORT}"))
}

// ──────────────────────────────────────────────────────────────────────────
// Network probes (thin wrappers over ureq; not unit-tested without a server)
// ──────────────────────────────────────────────────────────────────────────

/// Outcome of probing a daemon for reachability + version.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub version: String,
}

fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(3)))
        .timeout_global(Some(Duration::from_secs(15)))
        // Treat non-2xx as a normal response (not a transport error) so we can
        // read status codes *and* error bodies — the device-grant poll returns
        // its `authorization_pending`/`slow_down` code in a 400 JSON body.
        .http_status_as_error(false)
        .build()
        .into()
}

/// Current unix time in seconds (CLI context — real clock is appropriate).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Call a GET and reduce it to an HTTP status code, treating a non-2xx response
/// as a status (not a transport error). `Err` means the host was unreachable.
fn get_status(agent: &ureq::Agent, url: &str, bearer: Option<&str>) -> Result<u16, DynErr> {
    let mut req = agent.get(url).header("accept", "application/json");
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    match req.call() {
        Ok(resp) => Ok(resp.status().as_u16()),
        Err(ureq::Error::StatusCode(code)) => Ok(code),
        Err(other) => Err(Box::new(other)),
    }
}

/// GET `/readyz` then `/v1/version`; return the daemon's reported version.
fn probe_reachability(agent: &ureq::Agent, http_base: &str) -> Result<ProbeResult, DynErr> {
    // /readyz — reachability (may be 200 or 503 while warming; either proves the
    // socket is live, so we accept any HTTP status and only fail on transport).
    let _ = get_status(agent, &format!("{http_base}/readyz"), None)?;

    let url = format!("{http_base}/v1/version");
    let body = match agent.get(&url).header("accept", "application/json").call() {
        Ok(resp) => resp.into_body().read_to_string()?,
        Err(ureq::Error::StatusCode(code)) => {
            return Err(format!("/v1/version returned HTTP {code}").into());
        }
        Err(other) => return Err(Box::new(other)),
    };
    let parsed: serde_json::Value = serde_json::from_str(&body)?;
    let version = parsed
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    Ok(ProbeResult { version })
}

/// Probe the auth posture: a Read-classified route returns 200 under `auth=off`
/// and 401/403 when a credential is required. `/v1/projections/entity/count` is
/// a cheap GET with no side effects.
fn probe_posture(agent: &ureq::Agent, http_base: &str, bearer: Option<&str>) -> Result<AuthPosture, DynErr> {
    let url = format!("{http_base}/v1/projections/entity/count");
    let status = get_status(agent, &url, bearer)?;
    match status {
        401 | 403 => Ok(AuthPosture::Required),
        _ => Ok(AuthPosture::Off),
    }
}

/// Why a login self-check did not report success.
///
/// D-28: both self-checks used to collapse into a bare `DynErr`, and the
/// caller printed every one as `"skipped"` — so a daemon that answered
/// `PUT /v1/facts` with a 500, or returned no fact at all, read exactly like
/// a daemon that was not running. A check that RAN AND FAILED must not report
/// the same word as a check that could not run.
#[derive(Debug)]
enum VerifyOutcome {
    /// The check could not run — nothing was reachable to check. Legitimately
    /// skipped: `corecruxctl login` is expected to work offline.
    Unreachable(String),
    /// The check ran against a live daemon and the daemon failed it.
    Failed(String),
}

impl std::fmt::Display for VerifyOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(msg) | Self::Failed(msg) => f.write_str(msg),
        }
    }
}

/// Classify a `ureq` transport error.
///
/// NOTE: `http_agent` sets `http_status_as_error(false)` so the device-grant
/// poll can read its status code out of a 400 body. That means
/// `ureq::Error::StatusCode` is **never produced by this agent** — a non-2xx
/// arrives as `Ok(resp)`. Every caller here must therefore check
/// `resp.status()` itself (see `status_outcome`); reaching this function at all
/// means the request never got an HTTP response. The `StatusCode` arm is kept
/// only so this stays correct if the agent config changes.
fn transport_outcome(err: &ureq::Error, what: &str) -> VerifyOutcome {
    match err {
        ureq::Error::StatusCode(code) => VerifyOutcome::Failed(format!("{what} returned HTTP {code}")),
        other => VerifyOutcome::Unreachable(format!("{what}: {other}")),
    }
}

/// The daemon answered — a non-2xx is a live refusal, never a skip.
fn status_outcome(status: u16, what: &str) -> Option<VerifyOutcome> {
    (!(200..300).contains(&status)).then(|| VerifyOutcome::Failed(format!("{what} returned HTTP {status}")))
}

/// Best-effort verification that the resolved daemon answers MCP `tools/list`.
/// Returns the advertised tool count. Non-fatal on the caller's side.
fn verify_mcp_tools_list(agent: &ureq::Agent, mcp_url: &str, bearer: Option<&str>) -> Result<usize, VerifyOutcome> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });
    let mut req = agent
        .post(mcp_url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let text = match req.send_json(body) {
        Ok(mut resp) => {
            if let Some(failure) = status_outcome(resp.status().as_u16(), "MCP tools/list") {
                return Err(failure);
            }
            resp.body_mut()
                .read_to_string()
                .map_err(|err| VerifyOutcome::Failed(format!("MCP tools/list body unreadable: {err}")))?
        }
        Err(err) => return Err(transport_outcome(&err, "MCP tools/list")),
    };
    // The MCP endpoint may answer as JSON or as an SSE `data:` frame.
    let json_text = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("data:").map(str::trim))
        .unwrap_or(text.as_str());
    // Past this point the daemon answered: every remaining failure is a real
    // failure, never a skip.
    let parsed: serde_json::Value = serde_json::from_str(json_text)
        .map_err(|err| VerifyOutcome::Failed(format!("MCP tools/list response is not JSON: {err}")))?;
    let count = parsed
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .map(|a| a.len())
        .ok_or_else(|| VerifyOutcome::Failed("MCP tools/list response missing result.tools".to_string()))?;
    Ok(count)
}

/// Best-effort end-to-end memory check: `store_fact` (PUT /v1/facts) then read
/// it back (GET /v1/facts?query=). Returns Ok on a successful round-trip.
fn verify_fact_roundtrip(agent: &ureq::Agent, http_base: &str, bearer: Option<&str>) -> Result<(), VerifyOutcome> {
    let entity = "__crux_login_selfcheck";
    let key = "last_login_probe";
    let value = "ok";
    let put_url = format!("{http_base}/v1/facts");
    let put_body = serde_json::json!({
        "entity": entity,
        "key": key,
        "value": value,
        "confidence": 1.0,
    });
    let mut put = agent.put(&put_url).header("content-type", "application/json");
    if let Some(t) = bearer {
        put = put.header("authorization", format!("Bearer {t}"));
    } else {
        put = put.header("x-corecrux-scopes", "facts:write");
    }
    match put.send_json(put_body) {
        Ok(resp) => {
            // The write leg's whole point is to prove the daemon accepts a
            // fact. Without this check a 500 arrived as `Ok` and the round-trip
            // carried on to the read leg as though the write had landed.
            if let Some(failure) = status_outcome(resp.status().as_u16(), "store_fact") {
                return Err(failure);
            }
        }
        Err(err) => return Err(transport_outcome(&err, "store_fact")),
    }

    let get_url = format!("{http_base}/v1/facts");
    let mut get = agent
        .get(&get_url)
        .query("entity", entity)
        .query("top_k", "5")
        .query("token_budget", "500")
        .header("accept", "application/json");
    if let Some(t) = bearer {
        get = get.header("authorization", format!("Bearer {t}"));
    } else {
        get = get.header("x-corecrux-scopes", "query:read");
    }
    // The write already succeeded, so the daemon is demonstrably up: from here
    // every failure is a real failure, never a skip.
    let text = match get.call() {
        Ok(mut resp) => {
            if let Some(failure) = status_outcome(resp.status().as_u16(), "query_facts") {
                return Err(failure);
            }
            resp.body_mut()
                .read_to_string()
                .map_err(|err| VerifyOutcome::Failed(format!("query_facts body unreadable: {err}")))?
        }
        Err(other) => {
            return Err(VerifyOutcome::Failed(format!(
                "query_facts failed after a successful write: {other}"
            )))
        }
    };
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .map_err(|err| VerifyOutcome::Failed(format!("query_facts response is not JSON: {err}")))?;
    let found = parsed
        .get("facts")
        .and_then(|f| f.as_array())
        .is_some_and(|arr| arr.iter().any(|f| f.get("key").and_then(|k| k.as_str()) == Some(key)));
    if found {
        Ok(())
    } else {
        Err(VerifyOutcome::Failed(
            "query_facts did not return the just-written fact".to_string(),
        ))
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Issuance rails (tailscale + device) — daemon token endpoints
// ──────────────────────────────────────────────────────────────────────────

/// A token issued by the daemon (tailscale or device rail).
#[derive(Debug, Clone)]
struct IssuedToken {
    access_token: String,
    refresh_token: Option<String>,
    refresh_expires_in: Option<u64>,
    expires_in: u64,
    scopes: Vec<String>,
    tenant_id: Option<String>,
}

/// Identity echo from `GET /v1/auth/whoami`.
#[derive(Debug, Clone, Default)]
struct WhoAmI {
    trusted: bool,
    login: Option<String>,
    allowlisted: bool,
}

/// Parse an issuance response (`{access_token, refresh_token?, expires_in,
/// scopes, tenant_id?}`) shared by the tailscale + device rails.
fn parse_issued_token(text: &str) -> Result<IssuedToken, DynErr> {
    let v: serde_json::Value = serde_json::from_str(text)?;
    let access_token = v
        .get("access_token")
        .and_then(|x| x.as_str())
        .ok_or("issuance response missing access_token")?
        .to_string();
    Ok(IssuedToken {
        access_token,
        refresh_token: v.get("refresh_token").and_then(|x| x.as_str()).map(str::to_string),
        refresh_expires_in: v.get("refresh_expires_in").and_then(serde_json::Value::as_u64),
        expires_in: v.get("expires_in").and_then(|x| x.as_u64()).unwrap_or(300),
        scopes: v
            .get("scopes")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
        tenant_id: v.get("tenant_id").and_then(|x| x.as_str()).map(str::to_string),
    })
}

/// POST JSON and capture `(status, body)` regardless of HTTP status (the agent is
/// configured with `http_status_as_error(false)`).
fn post_json_capture(agent: &ureq::Agent, url: &str, body: serde_json::Value) -> Result<(u16, String), DynErr> {
    match agent
        .post(url)
        .header("content-type", "application/json")
        .send_json(body)
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.into_body().read_to_string()?;
            Ok((status, text))
        }
        Err(ureq::Error::StatusCode(code)) => Ok((code, String::new())),
        Err(other) => Err(Box::new(other)),
    }
}

/// Probe `GET /v1/auth/whoami`. Returns `None` when the rail is disabled (404) or
/// the daemon is unreachable — i.e. the tailnet rail is not available.
fn probe_whoami(agent: &ureq::Agent, http_base: &str) -> Option<WhoAmI> {
    let url = format!("{http_base}/v1/auth/whoami");
    let resp = agent.get(&url).header("accept", "application/json").call().ok()?;
    if resp.status().as_u16() != 200 {
        return None;
    }
    let text = resp.into_body().read_to_string().ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    Some(WhoAmI {
        trusted: v.get("trusted").and_then(|x| x.as_bool()).unwrap_or(false),
        login: v.get("login").and_then(|x| x.as_str()).map(str::to_string),
        allowlisted: v.get("allowlisted").and_then(|x| x.as_bool()).unwrap_or(false),
    })
}

/// Rail 2 — mint a scoped JWT from the verified tailnet identity.
fn mint_tailscale(agent: &ureq::Agent, http_base: &str) -> Result<IssuedToken, DynErr> {
    let url = format!("{http_base}/v1/auth/tailscale/token");
    let (status, text) = post_json_capture(agent, &url, serde_json::json!({}))?;
    if status != 200 {
        return Err(format!("tailscale token issuance failed (HTTP {status}): {text}").into());
    }
    parse_issued_token(&text)
}

/// Rail 3 — drive the device-authorization grant to completion (start → poll).
fn run_device_flow(agent: &ureq::Agent, http_base: &str) -> Result<IssuedToken, DynErr> {
    let start_url = format!("{http_base}/v1/auth/device/start");
    let (status, text) = post_json_capture(agent, &start_url, serde_json::json!({ "client_name": "corecruxctl" }))?;
    if status != 200 {
        return Err(format!("device/start failed (HTTP {status}): {text}").into());
    }
    let start: serde_json::Value = serde_json::from_str(&text)?;
    let device_code = start
        .get("device_code")
        .and_then(|v| v.as_str())
        .ok_or("device/start missing device_code")?
        .to_string();
    let user_code = start.get("user_code").and_then(|v| v.as_str()).unwrap_or("?");
    let verification_uri = start
        .get("verification_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("/activate");
    let mut interval = start.get("interval").and_then(|v| v.as_u64()).unwrap_or(5).max(1);
    let expires_in = start.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(600);

    println!();
    println!("To authorize this client, open:  {verification_uri}");
    println!("and enter the code:              {user_code}");
    println!("waiting for approval (expires in {expires_in}s) …");

    let deadline = now_unix() + expires_in;
    let token_url = format!("{http_base}/v1/auth/device/token");
    let poll_body = serde_json::json!({ "device_code": device_code });
    loop {
        if now_unix() >= deadline {
            return Err("device authorization timed out before approval".into());
        }
        std::thread::sleep(Duration::from_secs(interval));
        let (status, text) = post_json_capture(agent, &token_url, poll_body.clone())?;
        if status == 200 {
            return parse_issued_token(&text);
        }
        let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
        match v.get("error").and_then(|e| e.as_str()).unwrap_or("") {
            "authorization_pending" => {}
            "slow_down" => interval = interval.saturating_add(5),
            "temporarily_unavailable" => interval = interval.saturating_add(5).min(60),
            "access_denied" => return Err("device authorization was denied by the approver".into()),
            "expired_token" => return Err("device code expired before approval".into()),
            "" => return Err(format!("device/token error (HTTP {status}): {text}").into()),
            other => return Err(format!("device/token error: {other}").into()),
        }
    }
}

/// Refresh a stored credential's access token if it is expired/near-expiry.
/// Returns `Some(updated)` if a refresh happened, `None` if no refresh was needed
/// or possible. Device rails use the refresh credential; the tailnet rail
/// re-mints from the (still-present) identity; static/loopback never refresh.
fn refresh_credential(agent: &ureq::Agent, cred: &DaemonCredential) -> Result<Option<DaemonCredential>, DynErr> {
    // 60 s safety lead so an in-flight request never trips expiry.
    let near_expiry = cred.expiry.is_some_and(|e| now_unix() + 60 >= e);
    if !near_expiry {
        return Ok(None);
    }
    let issued = match cred.rail.as_str() {
        "device" => {
            let Some(refresh) = cred.refresh_token.as_deref() else {
                return Ok(None);
            };
            if cred.refresh_expiry.is_some_and(|expiry| now_unix() >= expiry) {
                return Err(
                    "device refresh credential expired; run `corecruxctl login --device` to authorize this client again"
                        .into(),
                );
            }
            let url = format!("{}/v1/auth/device/refresh", cred.http_url);
            let (status, text) = post_json_capture(agent, &url, serde_json::json!({ "refresh_token": refresh }))?;
            if status != 200 {
                return Err(format!("device refresh failed (HTTP {status}): {text}").into());
            }
            parse_issued_token(&text)?
        }
        "tailscale" => mint_tailscale(agent, &cred.http_url)?,
        _ => return Ok(None),
    };
    let mut updated = cred.clone();
    updated.access_token = Some(issued.access_token);
    if issued.refresh_token.is_some() {
        updated.refresh_token = issued.refresh_token;
    }
    if let Some(refresh_expires_in) = issued.refresh_expires_in {
        updated.refresh_expiry = Some(now_unix().saturating_add(refresh_expires_in));
    }
    updated.expiry = Some(now_unix() + issued.expires_in);
    if !issued.scopes.is_empty() {
        updated.scopes = issued.scopes;
    }
    Ok(Some(updated))
}

// ──────────────────────────────────────────────────────────────────────────
// CLI entry point
// ──────────────────────────────────────────────────────────────────────────

/// Parsed arguments for `corecruxctl login`.
#[derive(Debug, Clone, Default)]
pub struct LoginArgs {
    /// Explicit daemon URL (`--url`). When absent, discovery runs.
    pub url: Option<String>,
    /// Static named token (`--token`) → Rail 4.
    pub token: Option<String>,
    /// Force the device-authorization grant (`--device`) → Rail 3 (M3).
    pub device: bool,
    /// Skip the post-login `tools/list` + fact round-trip verification.
    pub no_verify: bool,
    /// Exit non-zero when a self-check RAN and FAILED.
    ///
    /// Off by default: login itself succeeded — the credential is stored and
    /// usable — so failing the command would break `corecruxctl login && …`
    /// over a transient daemon fault. On for CI and provisioning, which need
    /// every requested check to have actually passed. Same shape as the
    /// evidence plane's `--strict` (see ExecPlan
    /// `crux-pinned-defect-remediation-2026-07-31`, M5): an *unreachable*
    /// daemon is still tolerated, because that check could not run.
    pub strict_verify: bool,
    /// Skip installing the Claude Code hooks (banner + observe capture).
    pub no_hooks: bool,
    /// Skip registering this machine with the daemon.
    pub no_register: bool,
}

/// Run `corecruxctl login`.
pub fn run(args: LoginArgs) -> Result<(), DynErr> {
    let cfg_dir = config_dir().ok_or("HOME is not set; cannot locate ~/.config/cuecrux")?;
    let env_file = env_path(&cfg_dir);
    let env_vars = match std::fs::read_to_string(&env_file) {
        Ok(content) => parse_env_file(&content),
        Err(_) => BTreeMap::new(),
    };

    // 1. discover.
    let candidates = discover_candidates(args.url.as_deref(), &env_vars);
    println!("crux login");
    println!("==========");

    let agent = http_agent();
    // An explicit `--token` forces the static-token rail. An *ambient*
    // `CRUX_AGENT_TOKEN` from the env file is the MCP agent token — keep it
    // separate so it never hijacks `--device`/loopback, and never gets stored as
    // the HTTP credential unless it is genuinely the chosen static token.
    let explicit_token = args
        .token
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let ambient_token = env_vars
        .get("CRUX_AGENT_TOKEN")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let static_token = explicit_token.clone().or_else(|| ambient_token.clone());

    // 2. probe each candidate until one is reachable.
    let mut chosen: Option<(String, ProbeResult)> = None;
    for candidate in &candidates {
        print!("probe {candidate} … ");
        match probe_reachability(&agent, candidate) {
            Ok(probe) => {
                println!("reachable (daemon v{})", probe.version);
                chosen = Some((candidate.clone(), probe));
                break;
            }
            Err(e) => println!("unreachable ({e})"),
        }
    }
    let (http_base, _probe) =
        chosen.ok_or_else(|| format!("no reachable Crux Daemon among candidates: {}", candidates.join(", ")))?;

    let is_loopback = is_loopback_url(&http_base);
    // Posture is "does an unauthenticated read get rejected" — probe with no
    // bearer so an ambient MCP token can't skew the result.
    let posture = probe_posture(&agent, &http_base, None)?;
    println!(
        "auth posture: {}",
        match posture {
            AuthPosture::Off => "off (no credential required)",
            AuthPosture::Required => "credential required",
        }
    );

    // 3. select rail — probe the tailnet identity rail first (cheap GET).
    let whoami = probe_whoami(&agent, &http_base);
    if let Some(w) = whoami.as_ref().filter(|w| w.trusted) {
        if let Some(login) = &w.login {
            println!("tailnet identity: {login} (allowlisted: {})", w.allowlisted);
        }
    }
    let tailscale_identity = whoami.as_ref().is_some_and(|w| w.trusted && w.allowlisted);
    let inputs = RailInputs {
        is_loopback,
        explicit_token: explicit_token.is_some(),
        ambient_token: ambient_token.is_some(),
        device_flag: args.device,
        tailscale_identity,
        posture,
    };
    let rail = select_rail(inputs)?;
    println!("selected rail: {} ({})", rail.as_str(), rail_description(rail));

    // 4. obtain + persist the credential for the rail.
    let mcp_url = derive_mcp_url(&http_base)?;
    let (cred, effective_bearer) = build_credential(&agent, rail, &http_base, &mcp_url, static_token.clone())?;
    let store_path = credentials_path(&cfg_dir);
    let mut store = load_store(&store_path)?;
    store.upsert(&http_base, cred);
    save_store(&store_path, &store)?;
    println!("stored credential → {} (0600)", store_path.display());

    // 5. register MCP + verify.
    // Only the static-token rail's token is an MCP agent token; the device /
    // tailscale rails issue *HTTP* JWTs which must NOT be written over
    // `CRUX_AGENT_TOKEN` (MCP uses a separate static token). Preserve any
    // existing MCP token for those rails.
    let mcp_agent_token = if rail == Rail::StaticToken {
        effective_bearer.clone()
    } else {
        None
    };
    register_mcp(&cfg_dir, &http_base, &mcp_url, mcp_agent_token.as_deref())?;
    println!("registered MCP endpoint {mcp_url} → {}", env_file.display());

    let mut verification_failed = false;
    if args.no_verify {
        println!("verification skipped (--no-verify)");
    } else {
        // MCP authenticates with the agent token (ambient `CRUX_AGENT_TOKEN`),
        // not the HTTP bearer — verify with that.
        let mcp_bearer = mcp_agent_token.or_else(|| ambient_token.clone());
        // D-28: every outcome used to print as "skipped", so a daemon that
        // answered with a 500 — or returned no fact at all — read exactly like
        // a daemon that was not running. Failures now say FAILED and go to
        // stderr; only a genuinely unreachable daemon is "skipped".
        match verify_mcp_tools_list(&agent, &mcp_url, mcp_bearer.as_deref()) {
            Ok(n) => println!("verify: MCP tools/list ok ({n} tools)"),
            Err(VerifyOutcome::Unreachable(e)) => println!("verify: MCP tools/list skipped ({e})"),
            Err(VerifyOutcome::Failed(e)) => {
                verification_failed = true;
                eprintln!("verify: MCP tools/list FAILED ({e})");
            }
        }
        match verify_fact_roundtrip(&agent, &http_base, effective_bearer.as_deref()) {
            Ok(()) => println!("verify: store_fact → query_facts round-trip ok"),
            Err(VerifyOutcome::Unreachable(e)) => println!("verify: fact round-trip skipped ({e})"),
            Err(VerifyOutcome::Failed(e)) => {
                verification_failed = true;
                eprintln!("verify: store_fact → query_facts round-trip FAILED ({e})");
            }
        }
    }

    // 6. orchestrate machine setup: install Claude Code hooks + register the
    //    machine. Both best-effort (non-fatal) so login still succeeds offline.
    if args.no_hooks {
        println!("hooks: skipped (--no-hooks)");
    } else {
        match crate::hooks::install(true, None) {
            Ok(summary) => println!("hooks: {summary}"),
            Err(e) => println!("hooks: skipped ({e})"),
        }
    }
    if args.no_register {
        println!("machine: registration skipped (--no-register)");
    } else {
        match crate::machine::register(&http_base) {
            Ok(s) => println!("machine: {s}"),
            Err(e) => println!("machine: registration skipped ({e})"),
        }
    }

    println!();
    println!("logged in to {http_base} via the {} rail.", rail.as_str());
    // D-28: login itself succeeded — the credential is stored and usable — so
    // this is not an error. But a self-check that RAN AND FAILED is a live
    // daemon problem the operator must not have to notice in the scrollback.
    if verification_failed {
        eprintln!();
        eprintln!(
            "WARNING: login succeeded but one or more self-checks FAILED against the live daemon (see the FAILED lines above). \
             This is not the same as a skipped check: the daemon answered and did not behave."
        );
        if args.strict_verify {
            return Err("post-login self-check failed against the live daemon (--strict-verify)".into());
        }
    }
    Ok(())
}

/// Obtain the credential for the selected rail, returning the stored credential
/// and the bearer token to use immediately (for MCP registration + verification).
fn build_credential(
    agent: &ureq::Agent,
    rail: Rail,
    http_base: &str,
    mcp_url: &str,
    token: Option<String>,
) -> Result<(DaemonCredential, Option<String>), DynErr> {
    let base = |access_token: Option<String>,
                refresh_token: Option<String>,
                refresh_expiry: Option<u64>,
                expiry: Option<u64>,
                scopes: Vec<String>| {
        DaemonCredential {
            rail: rail.as_str().to_string(),
            access_token,
            refresh_token,
            refresh_expiry,
            expiry,
            scopes,
            mcp_url: mcp_url.to_string(),
            http_url: http_base.to_string(),
        }
    };
    match rail {
        Rail::Loopback => Ok((base(None, None, None, None, vec![]), None)),
        Rail::StaticToken => Ok((base(token.clone(), None, None, None, vec![]), token)),
        Rail::Tailscale => {
            let issued = mint_tailscale(agent, http_base)?;
            print_issued("minted scoped token", &issued);
            let bearer = Some(issued.access_token.clone());
            let cred = base(
                Some(issued.access_token),
                None,
                None,
                Some(now_unix() + issued.expires_in),
                issued.scopes,
            );
            Ok((cred, bearer))
        }
        Rail::Device => {
            let issued = run_device_flow(agent, http_base)?;
            print_issued("approved — minted scoped token", &issued);
            let bearer = Some(issued.access_token.clone());
            let cred = base(
                Some(issued.access_token),
                issued.refresh_token,
                issued.refresh_expires_in.map(|ttl| now_unix().saturating_add(ttl)),
                Some(now_unix() + issued.expires_in),
                issued.scopes,
            );
            Ok((cred, bearer))
        }
    }
}

fn print_issued(prefix: &str, issued: &IssuedToken) {
    println!(
        "{prefix} (tenant {}, {} scope(s), ttl {}s)",
        issued.tenant_id.as_deref().unwrap_or("?"),
        issued.scopes.len(),
        issued.expires_in
    );
}

/// Parsed arguments for `corecruxctl logout`.
#[derive(Debug, Clone, Default)]
pub struct LogoutArgs {
    /// Daemon URL to log out of.
    pub url: Option<String>,
    /// Log out of every stored daemon.
    pub all: bool,
}

/// Run `corecruxctl logout` — revoke device refresh credentials (best-effort) and
/// clear the stored credential(s).
pub fn run_logout(args: LogoutArgs) -> Result<(), DynErr> {
    let cfg_dir = config_dir().ok_or("HOME is not set; cannot locate ~/.config/cuecrux")?;
    let store_path = credentials_path(&cfg_dir);
    let mut store = load_store(&store_path)?;
    let agent = http_agent();

    let targets: Vec<String> = if args.all {
        store.daemons.keys().cloned().collect()
    } else if let Some(u) = &args.url {
        vec![normalize_http_base(u)?]
    } else {
        return Err("specify --url <daemon> or --all".into());
    };
    if targets.is_empty() {
        println!("no stored credentials to clear");
        return Ok(());
    }
    for url in targets {
        match store.daemons.remove(&url) {
            Some(cred) => {
                if cred.rail == "device" {
                    if let Some(refresh) = cred.refresh_token.as_deref() {
                        let revoke_url = format!("{url}/v1/auth/device/revoke");
                        match post_json_capture(&agent, &revoke_url, serde_json::json!({ "refresh_token": refresh })) {
                            Ok((200, _)) => println!("revoked device refresh credential at {url}"),
                            Ok((s, t)) => println!("revoke returned HTTP {s} ({t}) — clearing locally anyway"),
                            Err(e) => println!("revoke failed ({e}) — clearing locally anyway"),
                        }
                    }
                }
                println!("cleared credential for {url}");
            }
            None => println!("no stored credential for {url}"),
        }
    }
    save_store(&store_path, &store)?;
    Ok(())
}

/// Parsed arguments for `corecruxctl whoami`.
#[derive(Debug, Clone, Default)]
pub struct WhoamiArgs {
    /// Restrict output to a single daemon URL.
    pub url: Option<String>,
}

/// Run `corecruxctl whoami` — show stored credential posture per daemon.
pub fn run_whoami(args: WhoamiArgs) -> Result<(), DynErr> {
    let cfg_dir = config_dir().ok_or("HOME is not set; cannot locate ~/.config/cuecrux")?;
    let store = load_store(&credentials_path(&cfg_dir))?;
    if store.daemons.is_empty() {
        println!("no stored credentials (run `corecruxctl login`)");
        return Ok(());
    }
    let target = args.url.as_deref().map(normalize_http_base).transpose()?;
    let now = now_unix();
    for (url, cred) in &store.daemons {
        if let Some(t) = &target {
            if t != url {
                continue;
            }
        }
        let expiry = match cred.expiry {
            Some(e) if e > now => format!("{}s remaining", e - now),
            Some(_) => "expired".to_string(),
            None => "n/a".to_string(),
        };
        println!("{url}");
        println!("  rail:   {}", cred.rail);
        println!(
            "  scopes: {}",
            if cred.scopes.is_empty() {
                "(daemon-defined)".to_string()
            } else {
                cred.scopes.join(", ")
            }
        );
        println!(
            "  token:  {}",
            if cred.access_token.is_some() {
                "present"
            } else {
                "none (loopback)"
            }
        );
        println!("  expiry: {expiry}");
    }
    Ok(())
}

/// Resolve a fresh bearer token for `http_url`, transparently refreshing an
/// expired short-lived token and persisting the result. Returns `Ok(None)` when
/// there is no stored credential or the rail carries no token (loopback).
///
/// Reusable refresh entry point for the CLI and the MCP bridge (bridge wiring is
/// tracked as a follow-up — see ExecPlan M4 notes).
pub fn resolve_fresh_bearer(http_url: &str) -> Result<Option<String>, DynErr> {
    let cfg_dir = config_dir().ok_or("HOME is not set; cannot locate ~/.config/cuecrux")?;
    let store_path = credentials_path(&cfg_dir);
    let mut store = load_store(&store_path)?;
    let key = normalize_http_base(http_url)?;
    let Some(cred) = store.daemons.get(&key).cloned() else {
        return Ok(None);
    };
    let agent = http_agent();
    if let Some(updated) = refresh_credential(&agent, &cred)? {
        let bearer = updated.access_token.clone();
        store.upsert(&key, updated);
        save_store(&store_path, &store)?;
        return Ok(bearer);
    }
    Ok(cred.access_token)
}

fn rail_description(rail: Rail) -> &'static str {
    match rail {
        Rail::Loopback => "loopback trust, auth=off — zero friction",
        Rail::Tailscale => "verified tailnet identity",
        Rail::Device => "device-authorization grant",
        Rail::StaticToken => "static named token",
    }
}

/// Register the resolved daemon endpoints in `~/.config/cuecrux/env` so the agent
/// bridges + hooks resolve them. Writes `CRUX_MCP_URL` + `CRUX_HTTP_URL` (and, for
/// the static-token rail, `CRUX_AGENT_TOKEN`) into the 0600 env file, preserving
/// other keys.
fn register_mcp(cfg_dir: &Path, http_url: &str, mcp_url: &str, token: Option<&str>) -> Result<(), DynErr> {
    let path = env_path(cfg_dir);
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut updates: BTreeMap<String, String> = BTreeMap::new();
    updates.insert("CRUX_MCP_URL".to_string(), mcp_url.to_string());
    updates.insert("CRUX_HTTP_URL".to_string(), http_url.to_string());
    if let Some(t) = token {
        updates.insert("CRUX_AGENT_TOKEN".to_string(), t.to_string());
    }
    let rendered = render_env_file(&existing, &updates);
    create_dir_private(cfg_dir)?;
    write_private(&path, rendered.as_bytes())?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use crate::test_support::serve_responses;

    // ── shared helpers ──

    /// A port with nothing listening on it: bind an ephemeral port, read it back,
    /// then drop the listener. Used to drive the transport-error arms.
    fn closed_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    }

    /// Point `$HOME` at a fresh tempdir. The returned guard must stay alive for
    /// the duration of the test; every caller is `#[serial_test::serial]` because
    /// `HOME` is process-global.
    fn temp_home() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", dir.path());
        dir
    }

    /// A credential with only the fields a test cares about set.
    fn test_cred(rail: &str, http_url: &str) -> DaemonCredential {
        DaemonCredential {
            rail: rail.to_string(),
            access_token: None,
            refresh_token: None,
            expiry: None,
            scopes: vec![],
            mcp_url: derive_mcp_url(http_url).unwrap_or_else(|_| "http://x:14801/mcp".to_string()),
            http_url: http_url.to_string(),
        }
    }

    fn write_store(cred_url: &str, cred: DaemonCredential) {
        let mut store = CredentialStore::default();
        store.upsert(cred_url, cred);
        save_store(&credentials_path(&config_dir().unwrap()), &store).unwrap();
    }

    fn read_store() -> CredentialStore {
        load_store(&credentials_path(&config_dir().unwrap())).unwrap()
    }

    // ── rail selection table (matrix cell → expected rail) ──

    // `has_token` here means an *explicit* --token (the historical meaning of
    // these cases); ambient token defaults off.
    fn inputs(is_loopback: bool, has_token: bool, device: bool, ts: bool, posture: AuthPosture) -> RailInputs {
        RailInputs {
            is_loopback,
            explicit_token: has_token,
            ambient_token: false,
            device_flag: device,
            tailscale_identity: ts,
            posture,
        }
    }

    #[test]
    fn ambient_token_does_not_override_device() {
        // Regression: an ambient CRUX_AGENT_TOKEN (the MCP agent token) must not
        // hijack an explicit --device.
        let r = select_rail(RailInputs {
            is_loopback: false,
            explicit_token: false,
            ambient_token: true,
            device_flag: true,
            tailscale_identity: false,
            posture: AuthPosture::Required,
        })
        .unwrap();
        assert_eq!(r, Rail::Device);
    }

    #[test]
    fn ambient_token_does_not_override_loopback() {
        let r = select_rail(RailInputs {
            is_loopback: true,
            explicit_token: false,
            ambient_token: true,
            device_flag: false,
            tailscale_identity: false,
            posture: AuthPosture::Off,
        })
        .unwrap();
        assert_eq!(r, Rail::Loopback);
    }

    #[test]
    fn ambient_token_is_last_resort_fallback() {
        // No explicit flags, auth required, no identity → fall back to the
        // ambient static token rather than erroring.
        let r = select_rail(RailInputs {
            is_loopback: false,
            explicit_token: false,
            ambient_token: true,
            device_flag: false,
            tailscale_identity: false,
            posture: AuthPosture::Required,
        })
        .unwrap();
        assert_eq!(r, Rail::StaticToken);
    }

    #[test]
    fn rail_loopback_auth_off_no_token() {
        // Same host, have host/env access, auth off → Rail 1.
        let r = select_rail(inputs(true, false, false, false, AuthPosture::Off)).unwrap();
        assert_eq!(r, Rail::Loopback);
    }

    #[test]
    fn rail_explicit_token_wins_even_when_auth_off() {
        // Operator intent (--token) is honoured before auto-selection.
        let r = select_rail(inputs(true, true, false, false, AuthPosture::Off)).unwrap();
        assert_eq!(r, Rail::StaticToken);
    }

    #[test]
    fn rail_static_token_remote_auth_required() {
        // Remote (no tailscale), have token → Rail 4.
        let r = select_rail(inputs(false, true, false, false, AuthPosture::Required)).unwrap();
        assert_eq!(r, Rail::StaticToken);
    }

    #[test]
    fn rail_device_flag_selects_device() {
        let r = select_rail(inputs(false, false, true, false, AuthPosture::Required)).unwrap();
        assert_eq!(r, Rail::Device);
    }

    #[test]
    fn rail_tailscale_identity_when_present_and_auth_required() {
        let r = select_rail(inputs(false, false, false, true, AuthPosture::Required)).unwrap();
        assert_eq!(r, Rail::Tailscale);
    }

    #[test]
    fn rail_auth_required_no_credential_is_error() {
        // No host access, remote, no token, no identity → cannot select.
        let err = select_rail(inputs(false, false, false, false, AuthPosture::Required)).unwrap_err();
        assert!(err.contains("--token"), "error should suggest --token: {err}");
    }

    #[test]
    fn all_four_rails_implemented() {
        assert!(Rail::Loopback.is_implemented());
        assert!(Rail::StaticToken.is_implemented());
        assert!(Rail::Tailscale.is_implemented());
        assert!(Rail::Device.is_implemented());
    }

    #[test]
    fn fact_roundtrip_without_bearer_uses_dev_scope_headers_and_budget() {
        let (port, handle) = crate::test_support::serve_responses(vec![
            (200, "{}".to_string()),
            (200, r#"{"facts":[{"key":"last_login_probe"}]}"#.to_string()),
        ]);
        let agent = http_agent();
        verify_fact_roundtrip(&agent, &format!("http://127.0.0.1:{port}"), None).unwrap();

        let captured = handle.join().unwrap();
        assert!(captured[0].contains("PUT /v1/facts"));
        assert!(captured[0]
            .to_ascii_lowercase()
            .contains("x-corecrux-scopes: facts:write"));
        assert!(captured[1].contains("GET /v1/facts?entity=__crux_login_selfcheck"));
        assert!(captured[1].contains("token_budget=500"));
        assert!(captured[1]
            .to_ascii_lowercase()
            .contains("x-corecrux-scopes: query:read"));
    }

    // ── URL helpers ──

    #[test]
    fn normalize_adds_scheme_and_strips_slash() {
        assert_eq!(
            normalize_http_base("127.0.0.1:14800/").unwrap(),
            "http://127.0.0.1:14800"
        );
        assert_eq!(
            normalize_http_base("https://crux.example.com/").unwrap(),
            "https://crux.example.com"
        );
    }

    #[test]
    fn normalize_rejects_empty() {
        assert!(normalize_http_base("   ").is_err());
    }

    #[test]
    fn derive_mcp_url_rewrites_port_and_path() {
        assert_eq!(
            derive_mcp_url("http://127.0.0.1:14800").unwrap(),
            "http://127.0.0.1:14801/mcp"
        );
        assert_eq!(
            derive_mcp_url("https://crux.example.com").unwrap(),
            "https://crux.example.com:14801/mcp"
        );
    }

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_url("http://127.0.0.1:14800"));
        assert!(is_loopback_url("http://localhost:14800"));
        assert!(is_loopback_url("http://[::1]:14800"));
        assert!(!is_loopback_url("http://100.89.67.6:14800"));
        assert!(!is_loopback_url("https://crux.example.com"));
    }

    // ── env-file parse + merge ──

    #[test]
    fn parse_env_handles_comments_export_and_quotes() {
        let content = "# comment\nexport CRUX_MCP_URL=\"http://x:14801/mcp\"\nCRUX_AGENT_TOKEN=abc\n\n";
        let parsed = parse_env_file(content);
        assert_eq!(parsed.get("CRUX_MCP_URL").unwrap(), "http://x:14801/mcp");
        assert_eq!(parsed.get("CRUX_AGENT_TOKEN").unwrap(), "abc");
    }

    #[test]
    fn render_env_replaces_existing_and_appends_new() {
        let existing = "# header\nCRUX_MCP_URL=http://old:14801/mcp\nOTHER=keepme\n";
        let mut updates = BTreeMap::new();
        updates.insert("CRUX_MCP_URL".to_string(), "http://new:14801/mcp".to_string());
        updates.insert("CRUX_AGENT_TOKEN".to_string(), "tok".to_string());
        let out = render_env_file(existing, &updates);
        assert!(out.contains("# header"));
        assert!(out.contains("OTHER=keepme"));
        assert!(out.contains("CRUX_MCP_URL=http://new:14801/mcp"));
        assert!(!out.contains("http://old:14801/mcp"));
        assert!(out.contains("CRUX_AGENT_TOKEN=tok"));
    }

    #[test]
    #[serial_test::serial]
    fn save_endpoint_roundtrips_and_preserves_token() {
        let home = std::env::temp_dir().join(format!("crux-ep-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);

        // Nothing configured yet.
        assert!(configured_endpoint().is_none());

        // A bare host:port is normalised and the MCP url derived.
        let (http, mcp, path) = save_endpoint("100.70.12.73:14800").unwrap();
        assert_eq!(http, "http://100.70.12.73:14800");
        assert_eq!(mcp, "http://100.70.12.73:14801/mcp");
        assert!(path.exists());
        assert_eq!(configured_endpoint().as_deref(), Some("http://100.70.12.73:14800"));

        // An unrelated key (the agent token) must survive a re-save.
        let with_token = format!("{}CRUX_AGENT_TOKEN=secret\n", std::fs::read_to_string(&path).unwrap());
        std::fs::write(&path, with_token).unwrap();
        save_endpoint("http://other:14800").unwrap();
        let after = parse_env_file(&std::fs::read_to_string(&path).unwrap());
        assert_eq!(after.get("CRUX_AGENT_TOKEN").map(String::as_str), Some("secret"));
        assert_eq!(
            after.get("CRUX_HTTP_URL").map(String::as_str),
            Some("http://other:14800")
        );
        assert_eq!(
            after.get("CRUX_MCP_URL").map(String::as_str),
            Some("http://other:14801/mcp")
        );
    }

    // ── discovery ordering ──

    #[test]
    fn discover_prefers_explicit_then_env_then_localhost() {
        let mut env = BTreeMap::new();
        env.insert("CRUX_HTTP_URL".to_string(), "http://envhost:14800".to_string());
        let c = discover_candidates(Some("http://explicit:14800"), &env);
        assert_eq!(c[0], "http://explicit:14800");
        assert_eq!(c[1], "http://envhost:14800");
        assert_eq!(c.last().unwrap(), DEFAULT_HTTP_BASE);
    }

    #[test]
    fn discover_derives_http_base_from_mcp_url() {
        let mut env = BTreeMap::new();
        env.insert("CRUX_MCP_URL".to_string(), "http://tail:14801/mcp".to_string());
        let c = discover_candidates(None, &env);
        assert!(c.contains(&"http://tail:14800".to_string()));
    }

    #[test]
    fn discover_dedupes() {
        let mut env = BTreeMap::new();
        env.insert("CRUX_HTTP_URL".to_string(), DEFAULT_HTTP_BASE.to_string());
        let c = discover_candidates(Some(DEFAULT_HTTP_BASE), &env);
        assert_eq!(c.iter().filter(|x| *x == DEFAULT_HTTP_BASE).count(), 1);
    }

    // ── credential store round-trip + 0600 ──

    #[test]
    fn store_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = credentials_path(dir.path());
        let mut store = CredentialStore::default();
        store.upsert(
            "http://127.0.0.1:14800",
            DaemonCredential {
                rail: "loopback".to_string(),
                access_token: None,
                refresh_token: None,
                refresh_expiry: None,
                expiry: None,
                scopes: vec![],
                mcp_url: "http://127.0.0.1:14801/mcp".to_string(),
                http_url: "http://127.0.0.1:14800".to_string(),
            },
        );
        save_store(&path, &store).unwrap();
        let loaded = load_store(&path).unwrap();
        assert_eq!(loaded.version, STORE_SCHEMA_VERSION);
        assert_eq!(loaded.daemons.len(), 1);
        assert_eq!(loaded.daemons["http://127.0.0.1:14800"].rail, "loopback");
    }

    #[test]
    fn device_issuance_parses_refresh_expiry() {
        let issued = parse_issued_token(
            r#"{
                "access_token":"access",
                "refresh_token":"credential.secret",
                "refresh_expires_in":7776000,
                "expires_in":300,
                "scopes":["query:read"],
                "tenant_id":"tenant-a"
            }"#,
        )
        .unwrap();
        assert_eq!(issued.refresh_token.as_deref(), Some("credential.secret"));
        assert_eq!(issued.refresh_expires_in, Some(7_776_000));
    }

    #[test]
    fn legacy_credential_without_refresh_expiry_still_loads() {
        let credential: DaemonCredential = serde_json::from_str(
            r#"{
                "rail":"device",
                "access_token":"access",
                "refresh_token":"credential.secret",
                "expiry":123,
                "scopes":[],
                "mcp_url":"http://127.0.0.1:14801/mcp",
                "http_url":"http://127.0.0.1:14800"
            }"#,
        )
        .unwrap();
        assert_eq!(credential.refresh_expiry, None);
    }

    #[test]
    fn load_missing_store_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = credentials_path(dir.path());
        let store = load_store(&path).unwrap();
        assert!(store.daemons.is_empty());
    }

    #[test]
    fn upsert_replaces_same_key() {
        let mut store = CredentialStore::default();
        let base = DaemonCredential {
            rail: "loopback".to_string(),
            access_token: None,
            refresh_token: None,
            refresh_expiry: None,
            expiry: None,
            scopes: vec![],
            mcp_url: "m".to_string(),
            http_url: "h".to_string(),
        };
        store.upsert("k", base.clone());
        let mut updated = base;
        updated.rail = "static_token".to_string();
        store.upsert("k", updated);
        assert_eq!(store.daemons.len(), 1);
        assert_eq!(store.daemons["k"].rail, "static_token");
    }

    #[cfg(unix)]
    #[test]
    fn saved_store_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = credentials_path(dir.path());
        save_store(&path, &CredentialStore::default()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "credential store must be owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn rewriting_existing_store_stays_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = credentials_path(dir.path());
        // Pre-create with loose perms.
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_store(&path, &CredentialStore::default()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "rewrite must tighten perms to 0600");
    }

    #[cfg(unix)]
    #[test]
    fn save_store_creates_a_private_parent_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("deep").join("cuecrux");
        let path = credentials_path(&nested);
        save_store(&path, &CredentialStore::default()).unwrap();
        let mode = std::fs::metadata(&nested).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "credential dir must be owner-only");
    }

    // ── malformed / partial stored credentials ──

    #[test]
    fn load_store_rejects_malformed_json() {
        // Regression: a corrupt store must be an error, not silently treated as
        // "no credentials" — that would downgrade an authenticated client to an
        // anonymous one without telling anybody.
        let dir = tempfile::tempdir().unwrap();
        let path = credentials_path(dir.path());
        std::fs::write(&path, "{ this is not json").unwrap();
        assert!(load_store(&path).is_err());
    }

    #[test]
    fn load_store_treats_a_whitespace_only_file_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = credentials_path(dir.path());
        std::fs::write(&path, "   \n\t\n").unwrap();
        assert!(load_store(&path).unwrap().daemons.is_empty());
    }

    #[test]
    fn credential_omits_absent_optional_fields_on_disk() {
        // A loopback credential must not serialise `access_token: null` — the
        // store should contain no token key at all.
        let dir = tempfile::tempdir().unwrap();
        let path = credentials_path(dir.path());
        let mut store = CredentialStore::default();
        store.upsert(
            "http://127.0.0.1:14800",
            test_cred("loopback", "http://127.0.0.1:14800"),
        );
        save_store(&path, &store).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("access_token"), "loopback store leaked a token field");
        assert!(!raw.contains("refresh_token"));
        assert!(!raw.contains("expiry"));
    }

    #[test]
    fn credential_deserializes_with_only_the_required_fields() {
        // Forward/backward compatibility: a store written by an older build (no
        // version, no optional token fields) must still load.
        let dir = tempfile::tempdir().unwrap();
        let path = credentials_path(dir.path());
        std::fs::write(
            &path,
            r#"{"daemons":{"http://h:14800":{"rail":"loopback","mcp_url":"http://h:14801/mcp","http_url":"http://h:14800"}}}"#,
        )
        .unwrap();
        let store = load_store(&path).unwrap();
        assert_eq!(store.version, STORE_SCHEMA_VERSION);
        let c = &store.daemons["http://h:14800"];
        assert!(c.access_token.is_none());
        assert!(c.refresh_token.is_none());
        assert!(c.scopes.is_empty());
    }

    // ── URL + env-file edge cases ──

    #[test]
    fn normalize_rejects_unparsable_and_hostless_urls() {
        assert!(normalize_http_base("http://[oops").is_err());
        let err = normalize_http_base("file:///tmp/daemon").unwrap_err();
        assert!(err.contains("no host"), "{err}");
    }

    #[test]
    fn derive_mcp_url_rejects_unparsable_and_hostless_bases() {
        assert!(derive_mcp_url("not a url").is_err());
        let err = derive_mcp_url("file:///tmp/daemon").unwrap_err();
        assert!(err.contains("no host"), "{err}");
    }

    #[test]
    fn loopback_detection_is_false_for_unparsable_and_hostless_input() {
        assert!(!is_loopback_url("not a url"));
        assert!(!is_loopback_url("file:///tmp/daemon"));
        assert!(!is_loopback_url("http://127.0.0.1.example.com"));
    }

    #[test]
    fn parse_env_skips_lines_without_a_key() {
        let parsed = parse_env_file("NOEQUALS\n=novalue\n  \nexport 'Q'='v'\n");
        assert!(!parsed.contains_key("NOEQUALS"));
        assert!(!parsed.contains_key(""));
        assert_eq!(parsed.get("'Q'").map(String::as_str), Some("v"));
    }

    #[test]
    fn render_env_replaces_an_exported_key_in_place() {
        let mut updates = BTreeMap::new();
        updates.insert("CRUX_HTTP_URL".to_string(), "http://new:14800".to_string());
        let out = render_env_file("export CRUX_HTTP_URL=http://old:14800\n", &updates);
        assert_eq!(out, "CRUX_HTTP_URL=http://new:14800\n");
    }

    #[test]
    fn discover_drops_blank_and_unparsable_entries() {
        let mut env = BTreeMap::new();
        env.insert("CRUX_HTTP_URL".to_string(), "   ".to_string());
        env.insert("CORECRUXD_HTTP_URL".to_string(), "http://other:14800".to_string());
        env.insert("CRUX_MCP_URL".to_string(), "not a url".to_string());
        let c = discover_candidates(None, &env);
        assert_eq!(c, vec!["http://other:14800".to_string(), DEFAULT_HTTP_BASE.to_string()]);
    }

    #[test]
    fn select_rail_error_names_the_transport_constraint_only_when_off_host() {
        let remote = select_rail(inputs(false, false, false, false, AuthPosture::Required)).unwrap_err();
        assert!(remote.contains("encrypted transport"), "{remote}");
        let local = select_rail(inputs(true, false, false, false, AuthPosture::Required)).unwrap_err();
        assert!(!local.contains("encrypted transport"), "{local}");
    }

    #[test]
    fn rail_labels_are_stable() {
        // The `as_str` form is persisted in credentials.json and matched on in
        // refresh/logout — renaming a variant silently breaks stored creds.
        for (rail, s) in [
            (Rail::Loopback, "loopback"),
            (Rail::Tailscale, "tailscale"),
            (Rail::Device, "device"),
            (Rail::StaticToken, "static_token"),
        ] {
            assert_eq!(rail.as_str(), s);
            assert!(!rail_description(rail).is_empty());
        }
    }

    // ── HTTP probes ──

    #[test]
    fn get_status_returns_the_code_and_sends_the_bearer() {
        let (port, handle) = serve_responses(vec![(403, "{}".to_string())]);
        let agent = http_agent();
        let status = get_status(&agent, &format!("http://127.0.0.1:{port}/x"), Some("test-bearer")).unwrap();
        assert_eq!(status, 403);
        let captured = handle.join().unwrap();
        assert!(captured[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer test-bearer"));
    }

    #[test]
    fn get_status_reports_transport_failure_as_an_error() {
        let agent = http_agent();
        let url = format!("http://127.0.0.1:{}/x", closed_port());
        assert!(get_status(&agent, &url, None).is_err());
    }

    #[test]
    fn probe_reachability_reads_the_daemon_version() {
        let (port, handle) = serve_responses(vec![
            (200, "{}".to_string()),
            (200, r#"{"version":"0.9.9"}"#.to_string()),
        ]);
        let agent = http_agent();
        let probe = probe_reachability(&agent, &format!("http://127.0.0.1:{port}")).unwrap();
        assert_eq!(probe.version, "0.9.9");
        let captured = handle.join().unwrap();
        assert!(captured[0].contains("GET /readyz"));
        assert!(captured[1].contains("GET /v1/version"));
    }

    #[test]
    fn probe_reachability_accepts_a_warming_daemon_and_a_versionless_body() {
        // 503 on /readyz still proves the socket is live, and a /v1/version body
        // without the field must degrade to "unknown" rather than fail login.
        let (port, handle) = serve_responses(vec![(503, "{}".to_string()), (200, "{}".to_string())]);
        let agent = http_agent();
        let probe = probe_reachability(&agent, &format!("http://127.0.0.1:{port}")).unwrap();
        assert_eq!(probe.version, "unknown");
        handle.join().unwrap();
    }

    #[test]
    fn probe_reachability_fails_on_a_non_json_version_body() {
        // NOTE: the agent sets `http_status_as_error(false)`, so a 500 arrives as
        // a normal response and is parsed as a body — the `Error::StatusCode` arm
        // in `probe_reachability` is unreachable. The failure still surfaces, but
        // as a JSON parse error rather than "/v1/version returned HTTP 500".
        let (port, handle) = serve_responses(vec![(200, "{}".to_string()), (500, "upstream boom".to_string())]);
        let agent = http_agent();
        assert!(probe_reachability(&agent, &format!("http://127.0.0.1:{port}")).is_err());
        handle.join().unwrap();
    }

    #[test]
    fn probe_reachability_fails_when_the_host_is_unreachable() {
        let agent = http_agent();
        assert!(probe_reachability(&agent, &format!("http://127.0.0.1:{}", closed_port())).is_err());
    }

    #[test]
    fn probe_posture_maps_401_and_403_to_required() {
        for code in [401u16, 403] {
            let (port, handle) = serve_responses(vec![(code, "{}".to_string())]);
            let agent = http_agent();
            let posture = probe_posture(&agent, &format!("http://127.0.0.1:{port}"), None).unwrap();
            assert_eq!(posture, AuthPosture::Required, "HTTP {code}");
            let captured = handle.join().unwrap();
            assert!(captured[0].contains("GET /v1/projections/entity/count"));
        }
    }

    #[test]
    fn probe_posture_maps_200_to_off_and_forwards_the_bearer() {
        let (port, handle) = serve_responses(vec![(200, "{}".to_string())]);
        let agent = http_agent();
        let posture = probe_posture(&agent, &format!("http://127.0.0.1:{port}"), Some("test-bearer")).unwrap();
        assert_eq!(posture, AuthPosture::Off);
        let captured = handle.join().unwrap();
        assert!(captured[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer test-bearer"));
    }

    // ── MCP + fact verification ──

    #[test]
    fn mcp_tools_list_counts_tools_from_a_json_response() {
        let (port, handle) = serve_responses(vec![(
            200,
            r#"{"result":{"tools":[{"name":"a"},{"name":"b"}]}}"#.to_string(),
        )]);
        let agent = http_agent();
        let n = verify_mcp_tools_list(&agent, &format!("http://127.0.0.1:{port}/mcp"), Some("test-bearer")).unwrap();
        assert_eq!(n, 2);
        let captured = handle.join().unwrap();
        assert!(captured[0].contains("tools/list"));
        assert!(captured[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer test-bearer"));
    }

    /// D-28: both self-checks collapsed every outcome into a bare error and
    /// the caller printed all of them as `"skipped"`, so a daemon that
    /// answered `PUT /v1/facts` with a 500 — or returned no fact at all — read
    /// exactly like a daemon that was not running. A check that RAN AND FAILED
    /// must be distinguishable from one that could not run.
    #[test]
    fn a_live_daemon_failure_is_not_reported_as_a_skip() {
        let agent = http_agent();

        // Daemon answers and refuses the write: ran, failed.
        let (port, handle) = serve_responses(vec![(500, "boom".to_string())]);
        let outcome = verify_fact_roundtrip(&agent, &format!("http://127.0.0.1:{port}"), None).unwrap_err();
        assert!(
            matches!(outcome, VerifyOutcome::Failed(_)),
            "a 500 on the write leg is a failure, not a skip: {outcome:?}"
        );
        assert!(outcome.to_string().contains("HTTP 500"), "{outcome}");
        handle.join().unwrap();

        // Write succeeds, read-back returns no matching fact: ran, failed.
        let (port, handle) = serve_responses(vec![
            (200, r#"{"ok":true}"#.to_string()),
            (200, r#"{"facts":[]}"#.to_string()),
        ]);
        let outcome = verify_fact_roundtrip(&agent, &format!("http://127.0.0.1:{port}"), None).unwrap_err();
        assert!(
            matches!(outcome, VerifyOutcome::Failed(_)),
            "a silent read-back miss is a failure, not a skip: {outcome:?}"
        );
        handle.join().unwrap();

        // Nothing listening at all: could not run. `corecruxctl login` is
        // expected to work offline, so this one really is a skip.
        let outcome = verify_fact_roundtrip(&agent, "http://127.0.0.1:9", None).unwrap_err();
        assert!(
            matches!(outcome, VerifyOutcome::Unreachable(_)),
            "an unreachable daemon is a skip, not a failure: {outcome:?}"
        );
    }

    /// OD-4: `--strict-verify` turns a self-check that RAN AND FAILED into a
    /// non-zero exit, while still tolerating one that COULD NOT RUN. That
    /// asymmetry is the whole point — `corecruxctl login` is expected to work
    /// offline, so an unreachable daemon must not fail the command even under
    /// strict. Same shape as the evidence plane's `--strict`.
    #[test]
    fn strict_verify_separates_a_live_failure_from_an_unreachable_daemon() {
        let agent = http_agent();

        // Ran and failed: the daemon answered 500 on the write leg.
        let (port, handle) = serve_responses(vec![(500, "boom".to_string())]);
        let outcome = verify_fact_roundtrip(&agent, &format!("http://127.0.0.1:{port}"), None).unwrap_err();
        assert!(
            matches!(outcome, VerifyOutcome::Failed(_)),
            "--strict-verify must be able to see this as a failure: {outcome:?}"
        );
        handle.join().unwrap();

        // Could not run: nothing listening. Even under strict this is tolerated.
        let outcome = verify_fact_roundtrip(&agent, "http://127.0.0.1:9", None).unwrap_err();
        assert!(
            matches!(outcome, VerifyOutcome::Unreachable(_)),
            "an offline login must stay green even with --strict-verify: {outcome:?}"
        );
    }

    /// Same split on the MCP check.
    #[test]
    fn mcp_tools_list_separates_a_refusal_from_an_unreachable_daemon() {
        let agent = http_agent();

        let (port, handle) = serve_responses(vec![(500, "boom".to_string())]);
        let outcome = verify_mcp_tools_list(&agent, &format!("http://127.0.0.1:{port}/mcp"), None).unwrap_err();
        assert!(matches!(outcome, VerifyOutcome::Failed(_)), "{outcome:?}");
        handle.join().unwrap();

        let (port, handle) = serve_responses(vec![(200, r#"{"error":{"code":-32601}}"#.to_string())]);
        let outcome = verify_mcp_tools_list(&agent, &format!("http://127.0.0.1:{port}/mcp"), None).unwrap_err();
        assert!(
            matches!(outcome, VerifyOutcome::Failed(_)),
            "a daemon that answered without result.tools ran and failed: {outcome:?}"
        );
        handle.join().unwrap();

        let outcome = verify_mcp_tools_list(&agent, "http://127.0.0.1:9/mcp", None).unwrap_err();
        assert!(matches!(outcome, VerifyOutcome::Unreachable(_)), "{outcome:?}");
    }

    #[test]
    fn mcp_tools_list_understands_an_sse_data_frame() {
        // The MCP endpoint may answer as `text/event-stream`; the JSON payload
        // then arrives on a `data:` line rather than as the whole body.
        let (port, handle) = serve_responses(vec![(
            200,
            "event: message\ndata: {\"result\":{\"tools\":[{\"name\":\"a\"}]}}\n\n".to_string(),
        )]);
        let agent = http_agent();
        let n = verify_mcp_tools_list(&agent, &format!("http://127.0.0.1:{port}/mcp"), None).unwrap();
        assert_eq!(n, 1);
        handle.join().unwrap();
    }

    #[test]
    fn mcp_tools_list_rejects_a_response_without_result_tools() {
        let (port, handle) = serve_responses(vec![(200, r#"{"error":{"code":-32601}}"#.to_string())]);
        let agent = http_agent();
        let err = verify_mcp_tools_list(&agent, &format!("http://127.0.0.1:{port}/mcp"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing result.tools"), "{err}");
        handle.join().unwrap();
    }

    #[test]
    fn mcp_tools_list_fails_when_unreachable() {
        let agent = http_agent();
        let url = format!("http://127.0.0.1:{}/mcp", closed_port());
        assert!(verify_mcp_tools_list(&agent, &url, None).is_err());
    }

    #[test]
    fn fact_roundtrip_with_a_bearer_uses_authorization_not_dev_scopes() {
        // Regression: when a real credential exists the self-check must exercise
        // it, not fall back to the dev-scope headers (which would make the probe
        // pass against a daemon the credential cannot actually reach).
        let (port, handle) = serve_responses(vec![
            (200, "{}".to_string()),
            (200, r#"{"facts":[{"key":"last_login_probe"}]}"#.to_string()),
        ]);
        let agent = http_agent();
        verify_fact_roundtrip(&agent, &format!("http://127.0.0.1:{port}"), Some("test-bearer")).unwrap();
        let captured = handle.join().unwrap();
        for req in &captured {
            let lower = req.to_ascii_lowercase();
            assert!(lower.contains("authorization: bearer test-bearer"));
            assert!(!lower.contains("x-corecrux-scopes"), "dev-scope header leaked: {req}");
        }
    }

    #[test]
    fn fact_roundtrip_fails_when_the_written_fact_is_not_returned() {
        let (port, handle) = serve_responses(vec![
            (200, "{}".to_string()),
            (200, r#"{"facts":[{"key":"something_else"}]}"#.to_string()),
        ]);
        let agent = http_agent();
        let err = verify_fact_roundtrip(&agent, &format!("http://127.0.0.1:{port}"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not return the just-written fact"), "{err}");
        handle.join().unwrap();
    }

    #[test]
    fn fact_roundtrip_fails_on_a_non_json_query_body() {
        let (port, handle) = serve_responses(vec![(200, "{}".to_string()), (200, "<html/>".to_string())]);
        let agent = http_agent();
        assert!(verify_fact_roundtrip(&agent, &format!("http://127.0.0.1:{port}"), None).is_err());
        handle.join().unwrap();
    }

    #[test]
    fn fact_roundtrip_fails_when_unreachable() {
        let agent = http_agent();
        let base = format!("http://127.0.0.1:{}", closed_port());
        assert!(verify_fact_roundtrip(&agent, &base, None).is_err());
    }

    // ── issuance parsing ──

    #[test]
    fn parse_issued_token_reads_every_field() {
        let issued = parse_issued_token(
            r#"{"access_token":"test-jwt","refresh_token":"test-refresh","expires_in":900,
                "scopes":["facts:read","facts:write"],"tenant_id":"tenant-a"}"#,
        )
        .unwrap();
        assert_eq!(issued.access_token, "test-jwt");
        assert_eq!(issued.refresh_token.as_deref(), Some("test-refresh"));
        assert_eq!(issued.expires_in, 900);
        assert_eq!(issued.scopes, vec!["facts:read", "facts:write"]);
        assert_eq!(issued.tenant_id.as_deref(), Some("tenant-a"));
    }

    #[test]
    fn parse_issued_token_defaults_a_missing_ttl_to_five_minutes() {
        // A daemon that omits `expires_in` must not yield a credential that is
        // treated as never-expiring; the conservative 300 s default forces a
        // refresh instead.
        let issued = parse_issued_token(r#"{"access_token":"test-jwt"}"#).unwrap();
        assert_eq!(issued.expires_in, 300);
        assert!(issued.refresh_token.is_none());
        assert!(issued.scopes.is_empty());
        assert!(issued.tenant_id.is_none());
    }

    #[test]
    fn parse_issued_token_requires_an_access_token() {
        let err = parse_issued_token(r#"{"expires_in":60}"#).unwrap_err().to_string();
        assert!(err.contains("missing access_token"), "{err}");
        assert!(parse_issued_token("not json").is_err());
    }

    #[test]
    fn print_issued_handles_a_missing_tenant() {
        print_issued("test", &parse_issued_token(r#"{"access_token":"test-jwt"}"#).unwrap());
        print_issued(
            "test",
            &parse_issued_token(r#"{"access_token":"test-jwt","tenant_id":"t"}"#).unwrap(),
        );
    }

    #[test]
    fn post_json_capture_returns_status_and_body() {
        let (port, handle) = serve_responses(vec![(418, r#"{"error":"nope"}"#.to_string())]);
        let agent = http_agent();
        let (status, body) = post_json_capture(
            &agent,
            &format!("http://127.0.0.1:{port}/x"),
            serde_json::json!({"a": 1}),
        )
        .unwrap();
        assert_eq!(status, 418);
        assert_eq!(body, r#"{"error":"nope"}"#);
        let captured = handle.join().unwrap();
        assert!(captured[0].contains("POST /x"));
        assert!(captured[0]
            .to_ascii_lowercase()
            .contains("content-type: application/json"));
        assert!(
            captured[0].contains("\"a\""),
            "request body not captured: {}",
            captured[0]
        );
    }

    #[test]
    fn post_json_capture_fails_when_unreachable() {
        let agent = http_agent();
        let url = format!("http://127.0.0.1:{}/x", closed_port());
        assert!(post_json_capture(&agent, &url, serde_json::json!({})).is_err());
    }

    // ── whoami / tailnet rail ──

    #[test]
    fn whoami_reads_the_tailnet_identity() {
        let (port, handle) = serve_responses(vec![(
            200,
            r#"{"trusted":true,"login":"user@example.com","allowlisted":true}"#.to_string(),
        )]);
        let agent = http_agent();
        let who = probe_whoami(&agent, &format!("http://127.0.0.1:{port}")).unwrap();
        assert!(who.trusted && who.allowlisted);
        assert_eq!(who.login.as_deref(), Some("user@example.com"));
        let captured = handle.join().unwrap();
        assert!(captured[0].contains("GET /v1/auth/whoami"));
    }

    #[test]
    fn whoami_defaults_to_untrusted_when_fields_are_absent() {
        // Fail closed: a daemon that answers 200 with an empty body must not be
        // read as a trusted, allowlisted identity.
        let (port, handle) = serve_responses(vec![(200, "{}".to_string())]);
        let agent = http_agent();
        let who = probe_whoami(&agent, &format!("http://127.0.0.1:{port}")).unwrap();
        assert!(!who.trusted);
        assert!(!who.allowlisted);
        assert!(who.login.is_none());
        handle.join().unwrap();
    }

    #[test]
    fn whoami_is_none_when_the_rail_is_disabled_or_unreachable() {
        let (port, handle) = serve_responses(vec![(404, "{}".to_string())]);
        let agent = http_agent();
        assert!(probe_whoami(&agent, &format!("http://127.0.0.1:{port}")).is_none());
        handle.join().unwrap();

        let (port, handle) = serve_responses(vec![(200, "<html/>".to_string())]);
        assert!(probe_whoami(&agent, &format!("http://127.0.0.1:{port}")).is_none());
        handle.join().unwrap();

        assert!(probe_whoami(&agent, &format!("http://127.0.0.1:{}", closed_port())).is_none());
    }

    #[test]
    fn mint_tailscale_parses_the_issued_token() {
        let (port, handle) = serve_responses(vec![(
            200,
            r#"{"access_token":"test-minted","expires_in":120,"scopes":["facts:read"]}"#.to_string(),
        )]);
        let agent = http_agent();
        let issued = mint_tailscale(&agent, &format!("http://127.0.0.1:{port}")).unwrap();
        assert_eq!(issued.access_token, "test-minted");
        let captured = handle.join().unwrap();
        assert!(captured[0].contains("POST /v1/auth/tailscale/token"));
    }

    #[test]
    fn mint_tailscale_surfaces_a_rejection() {
        let (port, handle) = serve_responses(vec![(403, r#"{"error":"not allowlisted"}"#.to_string())]);
        let agent = http_agent();
        let err = mint_tailscale(&agent, &format!("http://127.0.0.1:{port}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("HTTP 403"), "{err}");
        handle.join().unwrap();
    }

    // ── device-authorization grant ──

    #[test]
    fn device_flow_rejects_a_failed_start() {
        let (port, handle) = serve_responses(vec![(500, "boom".to_string())]);
        let agent = http_agent();
        let err = run_device_flow(&agent, &format!("http://127.0.0.1:{port}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("device/start failed (HTTP 500)"), "{err}");
        let captured = handle.join().unwrap();
        assert!(captured[0].contains("POST /v1/auth/device/start"));
    }

    #[test]
    fn device_flow_requires_a_device_code() {
        let (port, handle) = serve_responses(vec![(200, r#"{"user_code":"ABCD-EFGH"}"#.to_string())]);
        let agent = http_agent();
        let err = run_device_flow(&agent, &format!("http://127.0.0.1:{port}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing device_code"), "{err}");
        handle.join().unwrap();
    }

    #[test]
    fn device_flow_rejects_a_non_json_start_body() {
        let (port, handle) = serve_responses(vec![(200, "<html/>".to_string())]);
        let agent = http_agent();
        assert!(run_device_flow(&agent, &format!("http://127.0.0.1:{port}")).is_err());
        handle.join().unwrap();
    }

    #[test]
    fn device_flow_stops_at_the_expiry_deadline() {
        // `expires_in: 0` puts the deadline in the past, so the flow must abort
        // before its first poll rather than loop forever.
        let (port, handle) = serve_responses(vec![(200, r#"{"device_code":"dc","expires_in":0}"#.to_string())]);
        let agent = http_agent();
        let err = run_device_flow(&agent, &format!("http://127.0.0.1:{port}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("timed out before approval"), "{err}");
        handle.join().unwrap();
    }

    #[test]
    fn device_flow_surfaces_each_poll_error_code() {
        for (body, needle) in [
            (r#"{"error":"access_denied"}"#, "denied by the approver"),
            (r#"{"error":"expired_token"}"#, "device code expired"),
            (r#"{"error":"unknown_thing"}"#, "device/token error: unknown_thing"),
            ("<html/>", "device/token error (HTTP 400)"),
        ] {
            let (port, handle) = serve_responses(vec![
                (200, r#"{"device_code":"dc","interval":1,"expires_in":600}"#.to_string()),
                (400, body.to_string()),
            ]);
            let agent = http_agent();
            let err = run_device_flow(&agent, &format!("http://127.0.0.1:{port}"))
                .unwrap_err()
                .to_string();
            assert!(err.contains(needle), "body {body} → {err}");
            let captured = handle.join().unwrap();
            assert!(captured[1].contains("POST /v1/auth/device/token"));
            assert!(captured[1].contains("dc"));
        }
    }

    #[test]
    fn device_flow_backs_off_on_slow_down() {
        // `slow_down` must widen the poll interval rather than abort. With a 1 s
        // budget the next loop iteration hits the deadline, so the observable
        // outcome is the timeout — proving the back-off arm did not error out.
        let (port, _handle) = serve_responses(vec![
            (200, r#"{"device_code":"dc","interval":1,"expires_in":1}"#.to_string()),
            (400, r#"{"error":"slow_down"}"#.to_string()),
        ]);
        let agent = http_agent();
        let err = run_device_flow(&agent, &format!("http://127.0.0.1:{port}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("timed out before approval"), "{err}");
    }

    // ── credential construction per rail ──

    #[test]
    fn build_credential_loopback_never_persists_a_token() {
        // Even when a static token is available, the loopback rail must store no
        // credential — otherwise a token leaks into an auth=off store.
        let agent = http_agent();
        let (cred, bearer) = build_credential(
            &agent,
            Rail::Loopback,
            "http://127.0.0.1:14800",
            "http://127.0.0.1:14801/mcp",
            Some("test-static-token".to_string()),
        )
        .unwrap();
        assert_eq!(cred.rail, "loopback");
        assert!(cred.access_token.is_none());
        assert!(cred.expiry.is_none());
        assert!(bearer.is_none());
    }

    #[test]
    fn build_credential_static_token_stores_the_token_without_expiry() {
        let agent = http_agent();
        let (cred, bearer) = build_credential(
            &agent,
            Rail::StaticToken,
            "http://h:14800",
            "http://h:14801/mcp",
            Some("test-static-token".to_string()),
        )
        .unwrap();
        assert_eq!(cred.rail, "static_token");
        assert_eq!(cred.access_token.as_deref(), Some("test-static-token"));
        assert!(cred.expiry.is_none(), "a static named token must not carry an expiry");
        assert_eq!(bearer.as_deref(), Some("test-static-token"));
    }

    #[test]
    fn build_credential_tailscale_mints_and_dates_the_token() {
        let (port, handle) = serve_responses(vec![(
            200,
            r#"{"access_token":"test-minted","expires_in":600,"scopes":["facts:read"],"tenant_id":"t"}"#.to_string(),
        )]);
        let base = format!("http://127.0.0.1:{port}");
        let agent = http_agent();
        let (cred, bearer) = build_credential(&agent, Rail::Tailscale, &base, "http://h:14801/mcp", None).unwrap();
        assert_eq!(cred.rail, "tailscale");
        assert_eq!(bearer.as_deref(), Some("test-minted"));
        assert!(cred.refresh_token.is_none(), "tailnet rail re-mints, never refreshes");
        assert!(cred.expiry.unwrap() > now_unix() + 500);
        assert_eq!(cred.scopes, vec!["facts:read"]);
        handle.join().unwrap();
    }

    #[test]
    fn build_credential_propagates_a_mint_failure() {
        let (port, handle) = serve_responses(vec![(500, "boom".to_string())]);
        let agent = http_agent();
        let base = format!("http://127.0.0.1:{port}");
        assert!(build_credential(&agent, Rail::Tailscale, &base, "http://h:14801/mcp", None).is_err());
        handle.join().unwrap();
    }

    #[test]
    fn build_credential_device_keeps_the_refresh_credential() {
        let (port, handle) = serve_responses(vec![
            (200, r#"{"device_code":"dc","interval":1,"expires_in":600}"#.to_string()),
            (
                200,
                r#"{"access_token":"test-jwt","refresh_token":"test-refresh","expires_in":300,"scopes":["facts:read"]}"#
                    .to_string(),
            ),
        ]);
        let base = format!("http://127.0.0.1:{port}");
        let agent = http_agent();
        let (cred, bearer) = build_credential(&agent, Rail::Device, &base, "http://h:14801/mcp", None).unwrap();
        assert_eq!(cred.rail, "device");
        assert_eq!(bearer.as_deref(), Some("test-jwt"));
        assert_eq!(cred.refresh_token.as_deref(), Some("test-refresh"));
        assert!(cred.expiry.unwrap() > now_unix() + 200);
        handle.join().unwrap();
    }

    // ── refresh ──

    #[test]
    fn refresh_is_skipped_when_the_token_is_not_near_expiry() {
        let agent = http_agent();
        let mut cred = test_cred("device", "http://127.0.0.1:1");
        assert!(refresh_credential(&agent, &cred).unwrap().is_none(), "no expiry");
        cred.expiry = Some(now_unix() + 3600);
        assert!(refresh_credential(&agent, &cred).unwrap().is_none(), "far from expiry");
    }

    #[test]
    fn refresh_is_a_no_op_for_rails_without_a_refresh_path() {
        // Static tokens and loopback have nothing to refresh; a device credential
        // that lost its refresh token must degrade quietly, not hit the network.
        let agent = http_agent();
        for rail in ["static_token", "loopback", "device"] {
            let mut cred = test_cred(rail, "http://127.0.0.1:1");
            cred.expiry = Some(now_unix() + 5); // inside the 60 s safety lead
            assert!(refresh_credential(&agent, &cred).unwrap().is_none(), "{rail}");
        }
    }

    #[test]
    fn refresh_uses_the_safety_lead_before_the_token_actually_expires() {
        // A token expiring in 30 s is refreshed now, so an in-flight request can
        // never race the expiry.
        let (port, handle) = serve_responses(vec![(
            200,
            r#"{"access_token":"test-new","expires_in":900,"scopes":["facts:read"]}"#.to_string(),
        )]);
        let base = format!("http://127.0.0.1:{port}");
        let mut cred = test_cred("device", &base);
        cred.access_token = Some("test-old".to_string());
        cred.refresh_token = Some("test-refresh-1".to_string());
        cred.scopes = vec!["stale:scope".to_string()];
        cred.expiry = Some(now_unix() + 30);
        let agent = http_agent();
        let updated = refresh_credential(&agent, &cred).unwrap().unwrap();
        assert_eq!(updated.access_token.as_deref(), Some("test-new"));
        assert_eq!(
            updated.refresh_token.as_deref(),
            Some("test-refresh-1"),
            "a response without a new refresh token must keep the old one"
        );
        assert_eq!(updated.scopes, vec!["facts:read"]);
        assert!(updated.expiry.unwrap() > now_unix() + 800);
        let captured = handle.join().unwrap();
        assert!(captured[0].contains("POST /v1/auth/device/refresh"));
        assert!(captured[0].contains("test-refresh-1"));
    }

    #[test]
    fn refresh_keeps_existing_scopes_when_the_daemon_returns_none() {
        let (port, handle) = serve_responses(vec![(200, r#"{"access_token":"test-new"}"#.to_string())]);
        let base = format!("http://127.0.0.1:{port}");
        let mut cred = test_cred("device", &base);
        cred.refresh_token = Some("test-refresh-1".to_string());
        cred.scopes = vec!["facts:read".to_string()];
        cred.expiry = Some(now_unix());
        let agent = http_agent();
        let updated = refresh_credential(&agent, &cred).unwrap().unwrap();
        assert_eq!(updated.scopes, vec!["facts:read"]);
        handle.join().unwrap();
    }

    #[test]
    fn refresh_surfaces_a_rejected_refresh_token() {
        // A revoked refresh credential must be an error, not a silent fallthrough
        // to the stale (expired) access token.
        let (port, handle) = serve_responses(vec![(401, r#"{"error":"revoked"}"#.to_string())]);
        let base = format!("http://127.0.0.1:{port}");
        let mut cred = test_cred("device", &base);
        cred.refresh_token = Some("test-refresh-1".to_string());
        cred.expiry = Some(now_unix());
        let agent = http_agent();
        let err = refresh_credential(&agent, &cred).unwrap_err().to_string();
        assert!(err.contains("device refresh failed (HTTP 401)"), "{err}");
        handle.join().unwrap();
    }

    #[test]
    fn refresh_re_mints_the_tailnet_rail() {
        let (port, handle) = serve_responses(vec![(
            200,
            r#"{"access_token":"test-reminted","expires_in":600}"#.to_string(),
        )]);
        let base = format!("http://127.0.0.1:{port}");
        let mut cred = test_cred("tailscale", &base);
        cred.expiry = Some(now_unix());
        let agent = http_agent();
        let updated = refresh_credential(&agent, &cred).unwrap().unwrap();
        assert_eq!(updated.access_token.as_deref(), Some("test-reminted"));
        let captured = handle.join().unwrap();
        assert!(captured[0].contains("POST /v1/auth/tailscale/token"));
    }

    // ── HOME-dependent CLI entry points (process-global env → serial) ──

    #[test]
    #[serial_test::serial]
    fn every_entry_point_fails_clearly_without_home() {
        let previous = std::env::var_os("HOME");
        std::env::remove_var("HOME");
        assert!(config_dir().is_none());
        assert!(configured_endpoint().is_none());
        assert!(run(LoginArgs::default()).is_err());
        assert!(run_logout(LogoutArgs::default()).is_err());
        assert!(run_whoami(WhoamiArgs::default()).is_err());
        assert!(resolve_fresh_bearer("http://127.0.0.1:14800").is_err());
        assert!(save_endpoint("http://127.0.0.1:14800").is_err());
        if let Some(home) = previous {
            std::env::set_var("HOME", home);
        }
    }

    #[test]
    #[serial_test::serial]
    fn save_endpoint_rejects_an_empty_url() {
        let _home = temp_home();
        assert!(save_endpoint("   ").is_err());
        assert!(configured_endpoint().is_none());
    }

    #[test]
    #[serial_test::serial]
    fn configured_endpoint_is_none_without_the_key() {
        let _home = temp_home();
        let cfg = config_dir().unwrap();
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(env_path(&cfg), "CRUX_AGENT_TOKEN=test-token\n").unwrap();
        assert!(configured_endpoint().is_none());
    }

    #[test]
    #[serial_test::serial]
    fn login_loopback_rail_stores_no_token_and_registers_the_endpoint() {
        let _home = temp_home();
        let (port, handle) = serve_responses(vec![
            (200, "{}".to_string()),                     // /readyz
            (200, r#"{"version":"9.9.9"}"#.to_string()), // /v1/version
            (200, "{}".to_string()),                     // posture → auth=off
            (404, "{}".to_string()),                     // whoami → rail disabled
        ]);
        let base = format!("http://127.0.0.1:{port}");
        run(LoginArgs {
            url: Some(base.clone()),
            no_verify: true,
            strict_verify: false,
            no_hooks: true,
            no_register: true,
            ..Default::default()
        })
        .unwrap();
        let captured = handle.join().unwrap();
        assert!(captured[0].contains("GET /readyz"));
        assert!(captured[2].contains("GET /v1/projections/entity/count"));
        assert!(
            !captured[2].to_ascii_lowercase().contains("authorization:"),
            "posture must be probed unauthenticated"
        );

        let cred = read_store().daemons.remove(&base).expect("credential stored");
        assert_eq!(cred.rail, "loopback");
        assert!(cred.access_token.is_none());
        assert_eq!(cred.mcp_url, format!("http://127.0.0.1:{MCP_PORT}/mcp"));

        let env = parse_env_file(&std::fs::read_to_string(env_path(&config_dir().unwrap())).unwrap());
        assert_eq!(env.get("CRUX_HTTP_URL").map(String::as_str), Some(base.as_str()));
        assert!(
            !env.contains_key("CRUX_AGENT_TOKEN"),
            "the loopback rail has no token to register"
        );
    }

    #[test]
    #[serial_test::serial]
    fn login_static_token_rail_trims_the_token_and_registers_it_for_mcp() {
        let _home = temp_home();
        let (port, handle) = serve_responses(vec![
            (200, "{}".to_string()),
            (200, r#"{"version":"1.0.0"}"#.to_string()),
            (401, "{}".to_string()), // posture → credential required
            (404, "{}".to_string()), // whoami → rail disabled
        ]);
        let base = format!("http://127.0.0.1:{port}");
        run(LoginArgs {
            url: Some(base.clone()),
            token: Some("  test-static-token  ".to_string()),
            no_verify: true,
            strict_verify: false,
            no_hooks: true,
            no_register: true,
            ..Default::default()
        })
        .unwrap();
        handle.join().unwrap();

        let cred = read_store().daemons.remove(&base).expect("credential stored");
        assert_eq!(cred.rail, "static_token");
        assert_eq!(cred.access_token.as_deref(), Some("test-static-token"));

        let env = parse_env_file(&std::fs::read_to_string(env_path(&config_dir().unwrap())).unwrap());
        assert_eq!(
            env.get("CRUX_AGENT_TOKEN").map(String::as_str),
            Some("test-static-token")
        );
    }

    #[test]
    #[serial_test::serial]
    fn login_tailnet_rail_does_not_overwrite_the_mcp_agent_token() {
        // Regression: the tailnet/device rails issue *HTTP* JWTs. Writing one to
        // CRUX_AGENT_TOKEN would clobber the separate MCP agent token and break
        // every MCP client on the machine.
        let _home = temp_home();
        let cfg = config_dir().unwrap();
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(env_path(&cfg), "CRUX_AGENT_TOKEN=test-preexisting-mcp-token\n").unwrap();

        let (port, handle) = serve_responses(vec![
            (200, "{}".to_string()),
            (200, r#"{"version":"1.2.3"}"#.to_string()),
            (401, "{}".to_string()),
            (
                200,
                r#"{"trusted":true,"login":"user@example.com","allowlisted":true}"#.to_string(),
            ),
            (
                200,
                r#"{"access_token":"test-minted-jwt","expires_in":600,"scopes":["facts:read"],"tenant_id":"t"}"#
                    .to_string(),
            ),
        ]);
        let base = format!("http://127.0.0.1:{port}");
        run(LoginArgs {
            url: Some(base.clone()),
            no_verify: true,
            strict_verify: false,
            no_hooks: true,
            no_register: true,
            ..Default::default()
        })
        .unwrap();
        handle.join().unwrap();

        let cred = read_store().daemons.remove(&base).expect("credential stored");
        assert_eq!(cred.rail, "tailscale");
        assert_eq!(cred.access_token.as_deref(), Some("test-minted-jwt"));
        assert!(cred.expiry.is_some());

        let env = parse_env_file(&std::fs::read_to_string(env_path(&cfg)).unwrap());
        assert_eq!(
            env.get("CRUX_AGENT_TOKEN").map(String::as_str),
            Some("test-preexisting-mcp-token"),
            "an HTTP JWT must never be written over the MCP agent token"
        );
    }

    #[test]
    #[serial_test::serial]
    fn login_refuses_when_auth_is_required_and_no_rail_is_available() {
        // The refusal must happen *before* anything is written to disk.
        let _home = temp_home();
        let (port, handle) = serve_responses(vec![
            (200, "{}".to_string()),
            (200, r#"{"version":"1.0.0"}"#.to_string()),
            (401, "{}".to_string()),
            (404, "{}".to_string()),
        ]);
        let base = format!("http://127.0.0.1:{port}");
        let err = run(LoginArgs {
            url: Some(base),
            no_verify: true,
            strict_verify: false,
            no_hooks: true,
            no_register: true,
            ..Default::default()
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("--token"), "{err}");
        handle.join().unwrap();
        assert!(read_store().daemons.is_empty(), "a failed login must store nothing");
        assert!(!env_path(&config_dir().unwrap()).exists());
    }

    #[test]
    #[serial_test::serial]
    fn whoami_reports_the_empty_store_and_every_credential_shape() {
        let _home = temp_home();
        run_whoami(WhoamiArgs::default()).unwrap();

        let mut store = CredentialStore::default();
        let mut expired = test_cred("device", "http://a.test:14800");
        expired.access_token = Some("test-jwt".to_string());
        expired.expiry = Some(now_unix().saturating_sub(60));
        expired.scopes = vec!["facts:read".to_string()];
        store.upsert("http://a.test:14800", expired);
        let mut live = test_cred("tailscale", "http://b.test:14800");
        live.access_token = Some("test-jwt".to_string());
        live.expiry = Some(now_unix() + 600);
        store.upsert("http://b.test:14800", live);
        store.upsert("http://c.test:14800", test_cred("loopback", "http://c.test:14800"));
        save_store(&credentials_path(&config_dir().unwrap()), &store).unwrap();

        run_whoami(WhoamiArgs::default()).unwrap();
        run_whoami(WhoamiArgs {
            url: Some("b.test:14800".to_string()),
        })
        .unwrap();
        assert!(run_whoami(WhoamiArgs {
            url: Some("http://[oops".to_string()),
        })
        .is_err());
    }

    #[test]
    #[serial_test::serial]
    fn logout_requires_a_target() {
        let _home = temp_home();
        let err = run_logout(LogoutArgs::default()).unwrap_err().to_string();
        assert!(err.contains("--url"), "{err}");
        // `--all` against an empty store is a no-op, not an error.
        run_logout(LogoutArgs {
            all: true,
            ..Default::default()
        })
        .unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn logout_of_an_unknown_daemon_is_not_an_error() {
        let _home = temp_home();
        write_store("http://a.test:14800", test_cred("loopback", "http://a.test:14800"));
        run_logout(LogoutArgs {
            url: Some("http://b.test:14800".to_string()),
            all: false,
        })
        .unwrap();
        assert_eq!(read_store().daemons.len(), 1, "an unrelated credential must survive");
    }

    #[test]
    #[serial_test::serial]
    fn logout_revokes_the_device_refresh_credential_then_clears_it() {
        let _home = temp_home();
        let (port, handle) = serve_responses(vec![(200, "{}".to_string())]);
        let base = format!("http://127.0.0.1:{port}");
        let mut cred = test_cred("device", &base);
        cred.access_token = Some("test-jwt".to_string());
        cred.refresh_token = Some("test-refresh-1".to_string());
        write_store(&base, cred);

        run_logout(LogoutArgs {
            url: Some(base.clone()),
            all: false,
        })
        .unwrap();
        let captured = handle.join().unwrap();
        assert!(captured[0].contains("POST /v1/auth/device/revoke"));
        assert!(captured[0].contains("test-refresh-1"));
        assert!(read_store().daemons.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn logout_clears_locally_even_when_revocation_fails() {
        // Regression: an unreachable or rejecting daemon must not strand a device
        // credential on disk — `logout` is a local guarantee.
        let _home = temp_home();
        let (port, handle) = serve_responses(vec![(500, "boom".to_string())]);
        let rejecting = format!("http://127.0.0.1:{port}");
        let unreachable = format!("http://127.0.0.1:{}", closed_port());

        let mut store = CredentialStore::default();
        for url in [&rejecting, &unreachable] {
            let mut cred = test_cred("device", url);
            cred.refresh_token = Some("test-refresh-1".to_string());
            store.upsert(url, cred);
        }
        save_store(&credentials_path(&config_dir().unwrap()), &store).unwrap();

        run_logout(LogoutArgs { url: None, all: true }).unwrap();
        handle.join().unwrap();
        assert!(read_store().daemons.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn resolve_fresh_bearer_is_none_without_a_stored_credential() {
        let _home = temp_home();
        assert!(resolve_fresh_bearer("http://127.0.0.1:14800").unwrap().is_none());
    }

    #[test]
    #[serial_test::serial]
    fn resolve_fresh_bearer_normalizes_the_lookup_key() {
        // The store is keyed by normalised URL; a bare `host:port` from a caller
        // must still find the credential rather than silently return `None`.
        let _home = temp_home();
        let mut cred = test_cred("static_token", "http://a.test:14800");
        cred.access_token = Some("test-static-token".to_string());
        write_store("http://a.test:14800", cred);
        assert_eq!(
            resolve_fresh_bearer("a.test:14800/").unwrap().as_deref(),
            Some("test-static-token")
        );
        assert!(resolve_fresh_bearer("http://[oops").is_err());
    }

    #[test]
    #[serial_test::serial]
    fn resolve_fresh_bearer_refreshes_and_persists_an_expiring_token() {
        let _home = temp_home();
        let (port, handle) = serve_responses(vec![(
            200,
            r#"{"access_token":"test-refreshed","refresh_token":"test-refresh-2","expires_in":900,"scopes":["facts:read"]}"#
                .to_string(),
        )]);
        let base = format!("http://127.0.0.1:{port}");
        let mut cred = test_cred("device", &base);
        cred.access_token = Some("test-stale".to_string());
        cred.refresh_token = Some("test-refresh-1".to_string());
        cred.expiry = Some(now_unix() + 10);
        write_store(&base, cred);

        let bearer = resolve_fresh_bearer(&base).unwrap();
        assert_eq!(bearer.as_deref(), Some("test-refreshed"));
        handle.join().unwrap();

        // The rotated refresh credential must be written back, or the next
        // refresh would replay a token the daemon has already rotated away.
        let stored = read_store().daemons.remove(&base).unwrap();
        assert_eq!(stored.access_token.as_deref(), Some("test-refreshed"));
        assert_eq!(stored.refresh_token.as_deref(), Some("test-refresh-2"));
        assert!(stored.expiry.unwrap() > now_unix() + 800);
    }

    #[test]
    #[serial_test::serial]
    fn resolve_fresh_bearer_surfaces_a_corrupt_store() {
        let _home = temp_home();
        let cfg = config_dir().unwrap();
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(credentials_path(&cfg), "{ not json").unwrap();
        assert!(resolve_fresh_bearer("http://127.0.0.1:14800").is_err());
    }
}
