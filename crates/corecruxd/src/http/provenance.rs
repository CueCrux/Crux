// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! W1 Provenance Marking Gateway — HTTP surface over the shared C2PA
//! machinery in `corecrux-receipts`. Default-OFF behind
//! `CORECRUXD_FEATURE_PROVENANCE_API` (M9 skeleton, ExecPlan
//! `verifiable-record-products-2026-07-17`).
//!
//! Three endpoints:
//! - `POST /v1/provenance/sign`          — BYOK sign (caller supplies key+cert).
//! - `POST /v1/provenance/verify`        — stateless verify (no key needed).
//! - `POST /v1/provenance/verify-record` — verify + mint a retained, signed
//!   verification record (passport-signed, appended to a local JSONL).
//!
//! **BYOK only.** The caller supplies their claim-signing P-256 key + cert
//! chain per request. We never persist, log, or echo key material or asset
//! bytes. Hosted key custody is a later milestone gated on the M11 trust test.
//!
//! **Metering.** Op codes + OD-38-ratified rates are defined here behind a
//! [`ProvenanceMeter`] trait with a no-op default; rates stay unpublished
//! until the wedge passes its skeleton gate. Wiring the no-op to the real
//! `credit_meter` reserve/spend rail remains a follow-up.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::{Duration, Instant};

use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;

use corecrux_receipts::{
    build_c2pa_manifest_v1, inspect_c2pa_leaf_certificate_v1, parse_jumbf_base64, sign_c2pa_manifest_via_signer,
    verify_c2pa_signed_manifest_es256_v1, ByokP256Signer, C2paManifestInputV1,
};

use super::{problem_response, require_http_any_scope_for_tenant, AppState, HeaderMap, State, StatusCode};

// ── Feature flag ───────────────────────────────────────────────────────────

/// Env flag gating the whole surface. Default OFF.
const FEATURE_ENV: &str = "CORECRUXD_FEATURE_PROVENANCE_API";
/// Required operator assertion when the daemon listener is non-loopback. The
/// daemon does not terminate TLS itself, so a public BYOK surface must sit
/// behind an authenticated TLS proxy before request bodies can be accepted.
const TLS_TERMINATED_ENV: &str = "CORECRUXD_PROVENANCE_TLS_TERMINATED";
/// Optional comma-separated exact leaf-certificate SHA-256 pins. This beta
/// trust list does not claim CA-chain validation; it upgrades identity trust
/// only for a currently-valid exact leaf whose envelope signature verifies.
const TRUSTED_LEAF_SHA256_ENV: &str = "CORECRUXD_PROVENANCE_TRUSTED_LEAF_SHA256";
const MAX_TRUSTED_LEAF_PINS: usize = 1_024;
/// Optional comma-separated SHA-256 pins over exact DER root certificates.
/// Default OFF (unset = no CA-chain trust mode, behaviour unchanged). When
/// set, an es256 envelope whose presented `x5chain` cryptographically
/// validates to one of these operator-pinned self-signed roots under the
/// shared CueCrux C2PA chain profile
/// ([`corecrux_receipts::validate_c2pa_chain_to_anchor_v1`]: per-link
/// signatures, current validity, BasicConstraints/KeyUsage/EKU, path length,
/// fail-closed unsupported critical extensions) earns `chain_validated=true`
/// and — with valid envelope integrity — `identity_trusted=true`. Malformed
/// configuration fails closed before route mount, exactly like the leaf list.
const TRUSTED_ROOT_SHA256_ENV: &str = "CORECRUXD_PROVENANCE_TRUSTED_ROOT_SHA256";
const MAX_TRUSTED_ROOT_PINS: usize = 64;
/// Upper bound on presented `x5chain` certificates considered for CA-chain
/// validation. Defense-in-depth on top of the signer-side `MAX_X5CHAIN_CERTS`
/// cap; longer presented chains fail closed rather than costing unbounded
/// parse/verify work.
const MAX_CHAIN_TRUST_CERTS: usize = 8;
/// Optional verification-record retention window. Unset means no automatic
/// deletion; an operator must choose an explicit 1..=3,650-day lifecycle.
const RETENTION_DAYS_ENV: &str = "CORECRUXD_PROVENANCE_RETENTION_DAYS";
const RETENTION_SIGNER_KEYRING_ENV: &str = "CORECRUXD_PROVENANCE_RECORD_SIGNER_KEYRING_JSON";
const MAX_RETENTION_SIGNER_KEYS: usize = 64;
const MAX_RETENTION_DAYS: u32 = 3_650;
const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);
const RETENTION_SWEEP_MAX_TENANTS: usize = 10_000;
const RETENTION_DISCOVERY_MAX_ENTRIES: usize = 10_000;
const RETENTION_SCHEDULER_ACTOR: &str = "provenance-retention-scheduler";
const RETENTION_SCHEDULER_MAX_BYTES_PER_PASS: u64 = 512 * 1024 * 1024;
const RETENTION_SCHEDULER_MAX_PASS_DURATION: Duration = Duration::from_secs(30);
const RETENTION_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);
const RECORD_TENANT_LOCK_SHARDS: usize = 64;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ProvenanceTrustPolicy {
    trusted_leaf_sha256: HashSet<String>,
    trusted_root_sha256: HashSet<String>,
}

fn parse_sha256_pin_set(raw: Option<&str>, env_name: &str, max_pins: usize) -> Result<HashSet<String>, String> {
    let mut pins = HashSet::new();
    let mut pin_count = 0usize;
    for raw_pin in raw.unwrap_or_default().split(',') {
        let raw_pin = raw_pin.trim();
        if raw_pin.is_empty() {
            continue;
        }
        pin_count += 1;
        if pin_count > max_pins {
            return Err(format!("{env_name} exceeds the {max_pins}-pin limit"));
        }
        let without_prefix = raw_pin
            .strip_prefix("sha256:")
            .or_else(|| raw_pin.strip_prefix("SHA256:"))
            .unwrap_or(raw_pin);
        let normalized = without_prefix.replace(':', "").to_ascii_lowercase();
        if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("{env_name} entries must be 64-hex SHA-256 fingerprints"));
        }
        pins.insert(normalized);
    }
    Ok(pins)
}

impl ProvenanceTrustPolicy {
    fn from_env() -> Result<Self, String> {
        Self::parse(
            std::env::var(TRUSTED_LEAF_SHA256_ENV).ok().as_deref(),
            std::env::var(TRUSTED_ROOT_SHA256_ENV).ok().as_deref(),
        )
    }

    fn parse(leaf_raw: Option<&str>, root_raw: Option<&str>) -> Result<Self, String> {
        Ok(Self {
            trusted_leaf_sha256: parse_sha256_pin_set(leaf_raw, TRUSTED_LEAF_SHA256_ENV, MAX_TRUSTED_LEAF_PINS)?,
            trusted_root_sha256: parse_sha256_pin_set(root_raw, TRUSTED_ROOT_SHA256_ENV, MAX_TRUSTED_ROOT_PINS)?,
        })
    }

    fn trusts_leaf(&self, fingerprint: &str) -> bool {
        self.trusted_leaf_sha256.contains(fingerprint)
    }

    fn trusts_root(&self, fingerprint: &str) -> bool {
        self.trusted_root_sha256.contains(fingerprint)
    }

    /// The CA-chain trust mode is active only when the operator pinned at
    /// least one root. Unset/empty keeps the exact-leaf-only beta behaviour.
    fn chain_trust_enabled(&self) -> bool {
        !self.trusted_root_sha256.is_empty()
    }
}

fn provenance_retention_days_from_env() -> Result<Option<u32>, String> {
    let Some(raw) = std::env::var(RETENTION_DAYS_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let days = raw
        .parse::<u32>()
        .map_err(|_| format!("{RETENTION_DAYS_ENV} must be an integer from 1 to {MAX_RETENTION_DAYS}"))?;
    if !(1..=MAX_RETENTION_DAYS).contains(&days) {
        return Err(format!(
            "{RETENTION_DAYS_ENV} must be an integer from 1 to {MAX_RETENTION_DAYS}"
        ));
    }
    Ok(Some(days))
}

fn retention_sweep_due(tenant: &str, now: Instant) -> bool {
    static LAST_SWEEP: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    let sweeps = LAST_SWEEP.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut sweeps) = sweeps.lock() else {
        tracing::error!("provenance retention cadence lock poisoned; preserving records");
        return false;
    };
    let tenant_hash = tenant_records_hash(tenant);
    if sweeps
        .get(&tenant_hash)
        .and_then(|last| now.checked_duration_since(*last))
        .is_some_and(|elapsed| elapsed < RETENTION_SWEEP_INTERVAL)
    {
        return false;
    }
    if sweeps.len() >= RETENTION_SWEEP_MAX_TENANTS {
        sweeps.retain(|_, last| {
            now.checked_duration_since(*last)
                .is_some_and(|elapsed| elapsed < RETENTION_SWEEP_INTERVAL)
        });
    }
    if sweeps.len() >= RETENTION_SWEEP_MAX_TENANTS {
        tracing::warn!(
            max_tenants = RETENTION_SWEEP_MAX_TENANTS,
            "provenance retention cadence table full; preserving unswept tenant records"
        );
        return false;
    }
    sweeps.insert(tenant_hash, now);
    true
}

/// The M9 skeleton reads the flag from the environment directly rather than
/// threading a bool through `AppState`/`Config`: both structs have dozens of
/// literal construction sites across sibling-owned test files, and an env
/// read (a pattern already used by `gpu1`/`console`/`admin` handlers) keeps
/// this change purely additive. Fold into `Config` at M9-full once the
/// surrounding structs settle.
pub(super) fn provenance_api_enabled() -> bool {
    env_truthy(FEATURE_ENV)
}

fn env_truthy(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("on")
    )
}

fn transport_posture_allowed(auth_mode: crate::auth::AuthMode, http_bind_loopback: bool, tls_terminated: bool) -> bool {
    if auth_mode == crate::auth::AuthMode::Off {
        return false;
    }
    if http_bind_loopback {
        return true;
    }
    matches!(
        auth_mode,
        crate::auth::AuthMode::JwtHs256 | crate::auth::AuthMode::JwtJwks
    ) && tls_terminated
}

/// Router-level posture gate. This runs before routes are mounted, so an
/// unsafe flag/auth/transport combination cannot deserialize a BYOK private
/// key body and then reject it later in the handler.
pub(super) fn provenance_routes_enabled(state: &AppState) -> bool {
    if !provenance_api_enabled() {
        return false;
    }
    let allowed = transport_posture_allowed(
        state.auth.mode(),
        state.http_bind_loopback,
        env_truthy(TLS_TERMINATED_ENV),
    );
    if !allowed {
        tracing::error!(
            auth_mode = state.auth.mode().as_str(),
            http_bind_loopback = state.http_bind_loopback,
            tls_terminated_asserted = env_truthy(TLS_TERMINATED_ENV),
            "provenance API flag is on but routes are not mounted: require non-off auth and either loopback binding or JWT plus TLS termination"
        );
    }
    if allowed {
        if let Err(error) = ProvenanceTrustPolicy::from_env() {
            tracing::error!(%error, "provenance API routes are not mounted: invalid exact-leaf trust list");
            return false;
        }
        if let Err(error) = provenance_retention_days_from_env() {
            tracing::error!(%error, "provenance API routes are not mounted: invalid record-retention policy");
            return false;
        }
    }
    allowed
}

// ── Hardening knobs ────────────────────────────────────────────────────────

/// Per-request body cap (base64 asset bytes travel inside the JSON body, so
/// ~16 MiB of JSON ≈ ~12 MiB of asset). Enforced by a `DefaultBodyLimit`
/// layer on the routes in `mod.rs`; this constant is the single source of
/// truth for that layer.
pub(super) const PROVENANCE_MAX_UPLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Allowlisted asset media families (`<family>/<subtype>`) for `sign`.
const ALLOWED_CONTENT_TYPE_FAMILIES: &[&str] = &["image/", "video/", "audio/", "text/"];
/// Exact-match allowlisted content types (a prefix match would let
/// `application/pdf-evil` through).
const ALLOWED_CONTENT_TYPES_EXACT: &[&str] = &["application/pdf", "application/octet-stream"];

fn content_type_allowed(ct: &str) -> bool {
    let ct = ct.trim().to_ascii_lowercase();
    // Drop any `; charset=...` parameters before matching.
    let base = ct.split(';').next().unwrap_or("").trim();
    ALLOWED_CONTENT_TYPES_EXACT.contains(&base)
        || ALLOWED_CONTENT_TYPE_FAMILIES
            .iter()
            .any(|f| base.starts_with(f) && base.len() > f.len())
}

/// Per-principal fixed-window rate limiter. The verified stable subject or
/// passport identity is tenant-domain-separated and hashed before it becomes
/// a key, so refreshing a JWT cannot reset the budget. The table has a hard
/// cardinality bound so attacker-controlled principal churn cannot grow
/// process memory without limit. The daemon-wide ingress limiter independently
/// supplies the trusted-proxy-aware effective-client-IP bucket.
const RATE_WINDOW: Duration = Duration::from_secs(60);
const RATE_MAX_PER_WINDOW: u32 = 120;
const RATE_MAX_KEYS: usize = 10_000;

struct FixedWindowRateLimiter {
    entries: HashMap<String, (Instant, u32)>,
    window: Duration,
    max_per_window: u32,
    max_keys: usize,
    last_sweep: Option<Instant>,
}

impl FixedWindowRateLimiter {
    fn new(window: Duration, max_per_window: u32, max_keys: usize) -> Self {
        Self {
            entries: HashMap::new(),
            window,
            max_per_window,
            max_keys,
            last_sweep: None,
        }
    }

    fn allow(&mut self, key: &str, now: Instant) -> bool {
        if let Some((started, count)) = self.entries.get_mut(key) {
            if now
                .checked_duration_since(*started)
                .is_some_and(|age| age > self.window)
            {
                *started = now;
                *count = 1;
                return true;
            }
            if *count >= self.max_per_window {
                return false;
            }
            *count += 1;
            return true;
        }

        let sweep_due = self.entries.len() >= self.max_keys
            || self
                .last_sweep
                .is_none_or(|last| now.checked_duration_since(last).is_some_and(|age| age > self.window));
        if sweep_due {
            self.entries.retain(|_, (started, _)| {
                now.checked_duration_since(*started)
                    .is_none_or(|age| age <= self.window)
            });
            self.last_sweep = Some(now);
        }
        if self.entries.len() >= self.max_keys {
            return false;
        }
        self.entries.insert(key.to_string(), (now, 1));
        true
    }
}

fn rate_limiter() -> &'static Mutex<FixedWindowRateLimiter> {
    static LIMITER: OnceLock<Mutex<FixedWindowRateLimiter>> = OnceLock::new();
    LIMITER.get_or_init(|| {
        Mutex::new(FixedWindowRateLimiter::new(
            RATE_WINDOW,
            RATE_MAX_PER_WINDOW,
            RATE_MAX_KEYS,
        ))
    })
}

/// Returns `true` if the call is within budget for `key`, `false` if the
/// per-key window is exhausted.
fn rate_limit_ok(key: &str) -> bool {
    let mut limiter = match rate_limiter().lock() {
        Ok(g) => g,
        // A poisoned limiter must fail closed on the counter, not panic.
        Err(_) => return false,
    };
    limiter.allow(key, Instant::now())
}

// ── Metering (OD-38 ratified; rates not yet published) ────────────────────

/// Metered provenance operations. Rates are in **milli-credits** (1000 =
/// 1 Cr) to represent the sub-credit verify rate faithfully.
///
/// Ratified rates (NOT public until the wedge exits skeleton):
/// sign 20 Cr · verify 0.25 Cr · verify-record 1 Cr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProvenanceOp {
    Sign,
    Verify,
    VerifyRecord,
}

impl ProvenanceOp {
    pub(super) fn op_code(self) -> &'static str {
        match self {
            ProvenanceOp::Sign => "provenance.sign",
            ProvenanceOp::Verify => "provenance.verify",
            ProvenanceOp::VerifyRecord => "provenance.verify_record",
        }
    }

    /// Milli-credits (1000 = 1 Cr). Not yet a public price.
    pub(super) fn milli_credits(self) -> u64 {
        match self {
            ProvenanceOp::Sign => 20_000,
            ProvenanceOp::Verify => 250,
            ProvenanceOp::VerifyRecord => 1_000,
        }
    }
}

/// The metering boundary. A real impl reserves+spends against the tenant
/// wallet; the skeleton ships a no-op so the honest hook exists and is
/// unit-tested without faking a billing integration.
pub(super) trait ProvenanceMeter: Send + Sync {
    fn on_op(&self, op: ProvenanceOp, tenant: &str);
}

/// Default meter: records the op (structured log), charges nothing.
///
/// TODO(M9-metering): replace with a `credit_meter`-backed impl that reserves
/// before work and settles/voids after the result. The existing meter is
/// whole-credit-denominated, while `verify` is ratified at 0.25 Cr; the
/// fractional denomination must be made explicit rather than silently rounded.
pub(super) struct NoopMeter;

impl ProvenanceMeter for NoopMeter {
    fn on_op(&self, op: ProvenanceOp, tenant: &str) {
        tracing::info!(
            target: "provenance.meter",
            op = op.op_code(),
            milli_credits = op.milli_credits(),
            tenant = tenant,
            pricing_public = false,
            "provenance op observed (ratified rate not public; no charge in skeleton)"
        );
    }
}

// ── Structured error (never echoes asset bytes) ────────────────────────────

#[derive(Debug)]
struct ProvErr {
    status: StatusCode,
    message: String,
}

impl ProvErr {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ProvErr {
    fn into_response(self) -> Response {
        problem_response(self.status, self.message)
    }
}

fn decode_b64(field: &str, value: &str) -> Result<Vec<u8>, ProvErr> {
    base64::engine::general_purpose::STANDARD
        .decode(value.trim().as_bytes())
        // Deliberately do not include the offending bytes in the message.
        .map_err(|_| ProvErr::new(StatusCode::BAD_REQUEST, format!("{field} is not valid base64")))
}

// ── Request / response shapes ──────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
pub(super) struct ManifestParams {
    pub claim_generator: Option<String>,
    pub crown_receipt_id: Option<String>,
    pub signer_passport: Option<String>,
    pub manifest_id: Option<String>,
    pub when: Option<String>,
    pub model: Option<String>,
}

/// Parsed secret text whose owned allocation is zeroized on drop. Axum/serde's
/// transient request buffer remains framework-owned, which is why route
/// mounting separately requires loopback or an asserted TLS-terminating proxy.
#[derive(Deserialize)]
#[serde(transparent)]
pub(super) struct SecretPem(zeroize::Zeroizing<String>);

impl SecretPem {
    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
impl From<String> for SecretPem {
    fn from(value: String) -> Self {
        Self(zeroize::Zeroizing::new(value))
    }
}

// NB: deliberately NOT `Debug`/`Serialize` — this struct holds the caller's
// private key PEM, and a derived Debug/echo is the classic way key material
// leaks into a log line or error body. The parsed field zeroizes on drop.
#[derive(Deserialize)]
pub(super) struct SignRequest {
    /// Base64 asset bytes to attest.
    pub content_b64: String,
    /// Asset MIME type (validated against the allowlist).
    pub content_type: Option<String>,
    /// BYOK P-256 private key PEM (PKCS#8 or SEC1). Never stored or echoed.
    pub signing_key_pem: SecretPem,
    /// BYOK cert chain PEM (leaf first, then intermediates).
    pub cert_chain_pem: String,
    #[serde(default)]
    pub manifest: ManifestParams,
    pub tenant_id: Option<String>,
    /// Optional label for the signing key inside the envelope.
    pub key_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct SignResponse {
    pub manifest_envelope_b64: String,
    pub content_hash_blake3_hex: String,
    pub signer_key_id: String,
    pub signature_alg: String,
    pub manifest_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct VerifyRequest {
    /// Sidecar JUMBF envelope (base64). Absent ⇒ asset is unsigned.
    pub manifest_envelope_b64: Option<String>,
    /// Base64 asset bytes to check the content binding against.
    pub content_b64: Option<String>,
    pub tenant_id: Option<String>,
}

/// Manifest values are chosen by the caller at sign time and signed with the
/// caller's own (untrusted) key — they are UNVERIFIED claims, never facts the
/// gateway attests to. Field names carry the `unverified_` prefix so a machine
/// consumer can't mistake them for gateway-established identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ManifestClaims {
    pub manifest_id: String,
    pub claim_generator: String,
    pub content_type: Option<String>,
    pub unverified_crown_receipt_id: String,
    pub unverified_signer_passport: String,
    pub signer_key_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct VerifyResponse {
    /// Was a parseable manifest envelope supplied?
    pub present: bool,
    pub signature_alg: Option<String>,
    // ── Internal consistency (NOT trust) ──
    /// Recomputed BLAKE3 matches the transmitted payload hash.
    pub canonical_hash_match: Option<bool>,
    /// ECDSA-SHA256 signature verifies against the PRESENTED (untrusted) leaf.
    pub signature_valid: Option<bool>,
    /// `canonical_hash_match && signature_valid` — envelope is internally
    /// consistent. Does NOT mean the signer is trusted.
    pub integrity_valid: bool,
    // ── Asset binding ──
    /// Were asset bytes supplied so the content binding could be checked?
    pub asset_binding_checked: bool,
    /// `None` when no content was supplied.
    pub content_hash_match: Option<bool>,
    // ── Trust: operator-pinned policy only, never presented material ──
    /// Machine-readable trust posture. `"trusted_root_chain"` when the
    /// presented `x5chain` cryptographically validated to an operator-pinned
    /// root and envelope integrity holds; `"trusted_leaf_allowlist"` for an
    /// operator-pinned, currently-valid exact leaf. Otherwise
    /// `"untrusted_presented_leaf"`, `"root_chain_integrity_invalid"`,
    /// `"unsigned"`, `"external_key_required"`, or one of the pinned-leaf
    /// failure statuses.
    pub trust_status: String,
    /// SHA-256 of the exact DER leaf embedded in `x5chain`, when present.
    /// Safe to compare with an operator trust list; not a trust claim alone.
    #[serde(default)]
    pub signer_leaf_sha256: Option<String>,
    /// SHA-256 of the exact DER terminal (root-candidate) certificate in the
    /// presented `x5chain`. Populated only while the CA-chain trust mode is
    /// active, as the audit aid for building the pin list; never a trust
    /// claim alone.
    #[serde(default)]
    pub chain_root_sha256: Option<String>,
    /// True only when the CA-chain trust mode is active and the presented
    /// `x5chain` cryptographically validated to an operator-pinned root under
    /// the shared CueCrux C2PA chain profile (per-link signatures, validity,
    /// BC/KU/EKU, path length, fail-closed critical extensions). Always false
    /// while the mode is off.
    pub chain_validated: bool,
    /// True only for valid envelope integrity plus an operator-pinned
    /// identity: either a validated chain to a pinned root, or a
    /// currently-valid exact pinned leaf.
    pub identity_trusted: bool,
    // ── Overall ──
    /// True ONLY when the envelope is internally consistent AND asset bytes
    /// were supplied AND they match the bound hash. Never true on
    /// internal-consistency alone, and never implies trust.
    pub ok: bool,
    pub manifest_claims: Option<ManifestClaims>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ProvenanceReceiptV1 {
    pub alg: String,
    pub signed_by: String,
    pub body_hash: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct VerifyRecordResponse {
    pub verification: VerifyResponse,
    pub record_id: String,
    pub recorded_at: String,
    pub receipt: ProvenanceReceiptV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordIdempotency {
    key_hash: String,
    request_hash: String,
}

impl RecordIdempotency {
    fn from_request(tenant: &str, key: &str, req: &VerifyRequest) -> Self {
        let mut key_hasher = blake3::Hasher::new();
        key_hasher.update(b"cuecrux.provenance.idempotency-key.v1\0");
        key_hasher.update(tenant.as_bytes());
        key_hasher.update(b"\0");
        key_hasher.update(key.as_bytes());

        let mut request_hasher = blake3::Hasher::new();
        request_hasher.update(b"cuecrux.provenance.verify-record-request.v1\0");
        request_hasher.update(tenant.as_bytes());
        hash_optional_text(&mut request_hasher, req.manifest_envelope_b64.as_deref());
        hash_optional_text(&mut request_hasher, req.content_b64.as_deref());

        Self {
            key_hash: format!("blake3:{}", key_hasher.finalize().to_hex()),
            request_hash: format!("blake3:{}", request_hasher.finalize().to_hex()),
        }
    }
}

fn hash_optional_text(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(b"\x01");
            hasher.update(&(value.len() as u64).to_le_bytes());
            hasher.update(value.as_bytes());
        }
        None => {
            hasher.update(b"\x00");
        }
    }
}

fn current_unix_seconds() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[derive(Debug, PartialEq, Eq)]
enum VerifyRecordOutcome {
    Created(VerifyRecordResponse),
    Replayed(VerifyRecordResponse),
}

// ── Inner logic (pure enough to unit-test without axum/auth) ────────────────

fn do_sign(meter: &dyn ProvenanceMeter, tenant: &str, req: &SignRequest) -> Result<SignResponse, ProvErr> {
    // Content-type allowlist first — reject before touching key material.
    if let Some(ct) = req.content_type.as_deref() {
        if !content_type_allowed(ct) {
            return Err(ProvErr::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("content_type {ct:?} is not in the provenance allowlist"),
            ));
        }
    }
    let content = decode_b64("content_b64", &req.content_b64)?;

    let signer = ByokP256Signer::from_pem(
        req.signing_key_pem.expose(),
        &req.cert_chain_pem,
        req.key_id.clone().unwrap_or_else(|| "byok-leaf".to_string()),
    )
    .map_err(|e| ProvErr::new(StatusCode::BAD_REQUEST, format!("BYOK material rejected: {e}")))?;

    let manifest_id = req
        .manifest
        .manifest_id
        .clone()
        .unwrap_or_else(|| format!("urn:cuecrux:c2pa:{}", uuid::Uuid::new_v4()));
    let when = req
        .manifest
        .when
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let claim_generator = req
        .manifest
        .claim_generator
        .clone()
        .unwrap_or_else(|| "cuecrux/provenance-gateway".to_string());
    let crown_receipt_id = req.manifest.crown_receipt_id.clone().unwrap_or_default();
    let signer_passport = req.manifest.signer_passport.clone().unwrap_or_default();

    let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
        content_bytes: &content,
        content_type: req.content_type.as_deref(),
        crown_receipt_id: &crown_receipt_id,
        signer_passport: &signer_passport,
        claim_generator: &claim_generator,
        manifest_id: &manifest_id,
        when: &when,
        model: req.manifest.model.as_deref(),
    });
    let content_hash_blake3_hex = manifest.content_hash_blake3_hex.clone();

    let signed = sign_c2pa_manifest_via_signer(manifest, &signer, &when)
        .map_err(|e| ProvErr::new(StatusCode::BAD_REQUEST, format!("signing failed: {e}")))?;

    meter.on_op(ProvenanceOp::Sign, tenant);

    Ok(SignResponse {
        manifest_envelope_b64: signed.to_jumbf_base64(),
        content_hash_blake3_hex,
        signer_key_id: signed.key_id,
        signature_alg: signed.signature_alg,
        manifest_id,
    })
}

fn verify_inner(req: &VerifyRequest, trust_policy: &ProvenanceTrustPolicy) -> Result<VerifyResponse, ProvErr> {
    let Some(envelope_b64) = req.manifest_envelope_b64.as_deref() else {
        return Ok(VerifyResponse {
            present: false,
            signature_alg: None,
            canonical_hash_match: None,
            signature_valid: None,
            integrity_valid: false,
            asset_binding_checked: false,
            content_hash_match: None,
            trust_status: "unsigned".to_string(),
            signer_leaf_sha256: None,
            chain_root_sha256: None,
            chain_validated: false,
            identity_trusted: false,
            ok: false,
            manifest_claims: None,
            notes: vec!["no C2PA manifest supplied — asset is unsigned / no provenance present".to_string()],
        });
    };

    let parsed = parse_jumbf_base64(envelope_b64)
        .map_err(|_| ProvErr::new(StatusCode::BAD_REQUEST, "manifest envelope did not parse"))?;

    let content = match req.content_b64.as_deref() {
        Some(c) => Some(decode_b64("content_b64", c)?),
        None => None,
    };
    let content_supplied = content.is_some();

    let claims = ManifestClaims {
        manifest_id: parsed.manifest.manifest_id.clone(),
        claim_generator: parsed.manifest.claim_generator.clone(),
        content_type: parsed.manifest.content_type.clone(),
        unverified_crown_receipt_id: parsed.manifest.crown_receipt_id.clone(),
        unverified_signer_passport: parsed.manifest.signer_passport.clone(),
        signer_key_id: parsed.key_id.clone(),
    };

    if parsed.signature_alg == "es256" {
        // BYOK envelopes are internally self-verifying: the leaf key is in the
        // x5chain. This establishes CONSISTENCY only — never trust.
        let report = verify_c2pa_signed_manifest_es256_v1(&parsed, content.as_deref().unwrap_or(&[]))
            .map_err(|_| ProvErr::new(StatusCode::BAD_REQUEST, "es256 verification failed"))?;
        let leaf = inspect_c2pa_leaf_certificate_v1(&parsed)
            .map_err(|_| ProvErr::new(StatusCode::BAD_REQUEST, "es256 leaf certificate did not parse"))?;
        let integrity_valid = report.canonical_hash_match && report.signature_valid;
        let content_hash_match = content_supplied.then_some(report.content_hash_match);
        // Overall ok requires integrity AND a checked+matching asset binding.
        let ok = integrity_valid && content_hash_match == Some(true);
        let now = current_unix_seconds();
        let leaf_current = now.is_some_and(|unix_seconds| leaf.valid_at(unix_seconds));
        let leaf_pinned = trust_policy.trusts_leaf(&leaf.sha256_hex);
        let leaf_identity_trusted = leaf_pinned && leaf_current && integrity_valid;

        // ── CA-chain trust mode (default OFF; active only with pinned roots).
        // Fail-closed throughout: any parse, pin, clock, or validation
        // failure leaves chain_validated=false, never an error response —
        // the envelope stays verifiable, it simply earns no identity trust.
        let mut chain_validated = false;
        let mut chain_root_sha256: Option<String> = None;
        let mut chain_failure: Option<String> = None;
        if trust_policy.chain_trust_enabled() {
            match corecrux_receipts::c2pa_x5chain_der_v1(&parsed) {
                Ok(chain_der) if chain_der.len() > MAX_CHAIN_TRUST_CERTS => {
                    chain_failure = Some(format!(
                        "presented x5chain exceeds the {MAX_CHAIN_TRUST_CERTS}-certificate chain-trust bound"
                    ));
                }
                Ok(chain_der) if chain_der.len() < 2 => {
                    chain_failure = Some(
                        "presented x5chain carries no CA chain: a leaf alone cannot validate to a root".to_string(),
                    );
                }
                Ok(chain_der) => {
                    use sha2::{Digest as _, Sha256};
                    // Terminal presented certificate is the root candidate.
                    // `chain_der.len() >= 2` here, so the terminal exists.
                    let root_der = &chain_der[chain_der.len() - 1];
                    let root_fingerprint = hex::encode(Sha256::digest(root_der));
                    chain_root_sha256 = Some(root_fingerprint.clone());
                    if let Some(now_unix) = now {
                        if trust_policy.trusts_root(&root_fingerprint) {
                            match corecrux_receipts::validate_c2pa_chain_to_anchor_v1(&chain_der, root_der, now_unix) {
                                Ok(()) => chain_validated = true,
                                Err(error) => chain_failure = Some(format!("chain validation failed: {error}")),
                            }
                        } else {
                            chain_failure =
                                Some("the presented terminal certificate is not an operator-pinned root".to_string());
                        }
                    } else {
                        chain_failure =
                            Some("the system clock is before the Unix epoch; chain trust failed closed".to_string());
                    }
                }
                Err(_) => {
                    chain_failure = Some("presented x5chain did not decode into DER certificates".to_string());
                }
            }
        }
        let chain_identity_trusted = chain_validated && integrity_valid;
        let identity_trusted = chain_identity_trusted || leaf_identity_trusted;

        let trust_status = if chain_identity_trusted {
            "trusted_root_chain"
        } else if chain_validated {
            "root_chain_integrity_invalid"
        } else if leaf_identity_trusted {
            "trusted_leaf_allowlist"
        } else if now.is_none() && leaf_pinned {
            "system_clock_invalid"
        } else if leaf_pinned && !leaf_current {
            "expired_pinned_leaf"
        } else if leaf_pinned {
            "pinned_leaf_integrity_invalid"
        } else {
            "untrusted_presented_leaf"
        };
        let mut notes = if chain_identity_trusted {
            vec![
                "the presented certificate chain cryptographically validates to an operator-pinned root \
                 (per-link signatures, current validity, BasicConstraints, key usages, C2PA leaf EKU, path \
                 length, critical extensions) and the envelope signature verifies; revocation and public \
                 C2PA trust-list membership are not evaluated"
                    .to_string(),
            ]
        } else if leaf_identity_trusted {
            vec![
                "the exact currently-valid leaf certificate is operator-pinned and the envelope signature verifies; \
                 CA-chain validation is not performed"
                    .to_string(),
            ]
        } else {
            vec![
                "integrity_valid checks the envelope against the PRESENTED leaf only; the leaf, its chain, \
                 and all manifest_claims are UNTRUSTED unless trust_status says trusted_root_chain or \
                 trusted_leaf_allowlist"
                    .to_string(),
            ]
        };
        if let Some(failure) = chain_failure {
            notes.push(format!(
                "CA-chain trust mode is active but did not grant trust: {failure}"
            ));
        }
        if now.is_none() {
            notes.push("the system clock is before the Unix epoch; exact-leaf trust failed closed".to_string());
        } else if !leaf_current {
            notes.push("the presented leaf certificate is outside its validity interval".to_string());
        }
        if !content_supplied {
            notes.push(
                "asset bytes not supplied — content binding NOT checked, so overall ok is false; \
                 re-verify with the asset bytes to establish binding"
                    .to_string(),
            );
        }
        Ok(VerifyResponse {
            present: true,
            signature_alg: Some("es256".to_string()),
            canonical_hash_match: Some(report.canonical_hash_match),
            signature_valid: Some(report.signature_valid),
            integrity_valid,
            asset_binding_checked: content_supplied,
            content_hash_match,
            trust_status: trust_status.to_string(),
            signer_leaf_sha256: Some(leaf.sha256_hex),
            chain_root_sha256,
            chain_validated,
            identity_trusted,
            ok,
            manifest_claims: Some(claims),
            notes,
        })
    } else {
        // Ed25519 (legacy CROWN) envelopes reference an external verifying
        // key we do not hold here — report honestly rather than claim false.
        Ok(VerifyResponse {
            present: true,
            signature_alg: Some(parsed.signature_alg.clone()),
            canonical_hash_match: None,
            signature_valid: None,
            integrity_valid: false,
            asset_binding_checked: false,
            content_hash_match: None,
            trust_status: "external_key_required".to_string(),
            signer_leaf_sha256: None,
            chain_root_sha256: None,
            chain_validated: false,
            identity_trusted: false,
            ok: false,
            manifest_claims: Some(claims),
            notes: vec!["envelope is not a self-verifying BYOK (es256) envelope; \
                 verify with the external verifying key via `corecruxctl output-verify`"
                .to_string()],
        })
    }
}

#[cfg(test)]
fn do_verify(meter: &dyn ProvenanceMeter, tenant: &str, req: &VerifyRequest) -> Result<VerifyResponse, ProvErr> {
    let resp = verify_inner(req, &ProvenanceTrustPolicy::default())?;
    meter.on_op(ProvenanceOp::Verify, tenant);
    Ok(resp)
}

fn do_verify_with_trust(
    meter: &dyn ProvenanceMeter,
    tenant: &str,
    req: &VerifyRequest,
    trust_policy: &ProvenanceTrustPolicy,
) -> Result<VerifyResponse, ProvErr> {
    let resp = verify_inner(req, trust_policy)?;
    meter.on_op(ProvenanceOp::Verify, tenant);
    Ok(resp)
}

#[derive(Clone, Copy)]
struct VerifyRecordContext<'a> {
    tenant: &'a str,
    idempotency: Option<&'a RecordIdempotency>,
    trust_policy: &'a ProvenanceTrustPolicy,
    passport_key_path: &'a Path,
    passport_fpr: &'a str,
    data_dir: &'a Path,
}

fn do_verify_record(
    meter: &dyn ProvenanceMeter,
    req: &VerifyRequest,
    context: VerifyRecordContext<'_>,
) -> Result<VerifyRecordOutcome, ProvErr> {
    let VerifyRecordContext {
        tenant,
        idempotency,
        trust_policy,
        passport_key_path,
        passport_fpr,
        data_dir,
    } = context;
    let verification = verify_inner(req, trust_policy)?;

    let record_id = format!("prov_vr_{}", uuid::Uuid::new_v4());
    let recorded_at = chrono::Utc::now().to_rfc3339();

    // Canonical record body (everything the receipt binds), sans receipt.
    let record_body = json!({
        "schema": "cuecrux.provenance.verification_record.v1",
        "record_id": record_id,
        "recorded_at": recorded_at,
        "tenant_id": tenant,
        "verification": verification,
    });
    let mut record_body = record_body;
    if let (serde_json::Value::Object(obj), Some(idempotency)) = (&mut record_body, idempotency) {
        obj.insert(
            "idempotency_key_hash".to_string(),
            serde_json::Value::String(idempotency.key_hash.clone()),
        );
        obj.insert(
            "request_hash".to_string(),
            serde_json::Value::String(idempotency.request_hash.clone()),
        );
    }
    let canonical = serde_json::to_vec(&record_body).map_err(|e| {
        tracing::error!(error = %e, "provenance record canonicalise failed");
        ProvErr::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error minting verification record",
        )
    })?;

    // Mint a passport-signed receipt — same pattern as observation minting.
    // Sanitize: never surface the internal key path / IO detail to the caller.
    let key = crux_session::LocalPassportKey::from_path(passport_key_path).map_err(|e| {
        tracing::error!(error = %e, "provenance passport key load failed");
        ProvErr::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error minting verification record",
        )
    })?;
    if key.passport_fpr() != passport_fpr {
        return Err(ProvErr::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "passport signer mismatch between key file and daemon state",
        ));
    }
    let hash = blake3::hash(&canonical);
    let signature = key.sign_hash(hash.as_bytes());
    let receipt = ProvenanceReceiptV1 {
        alg: "ed25519".to_string(),
        signed_by: passport_fpr.to_string(),
        body_hash: format!("blake3:{}", hex::encode(hash.as_bytes())),
        signature: hex::encode(signature),
    };

    // Retain: append one JSONL line (record body + receipt) under data_dir.
    let mut line = record_body;
    if let serde_json::Value::Object(obj) = &mut line {
        obj.insert(
            "receipt".to_string(),
            serde_json::to_value(&receipt).unwrap_or(serde_json::Value::Null),
        );
    }
    // Idempotent retries are bound to the normalized request hash and replay
    // the exact retained response. The remaining flag-enable money gate is to
    // reserve credits BEFORE entering this persistence boundary and settle
    // after a successful append/replay; NoopMeter still charges nothing.
    let append_outcome = retain_verification_record(data_dir, tenant, &line, idempotency).map_err(|e| {
        tracing::error!(error = %e, "provenance record persist failed");
        let (status, message) = match e {
            RecordStoreError::LineTooLarge { .. } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "verification record exceeds the retention size limit",
            ),
            RecordStoreError::TenantQuotaExceeded { .. } | RecordStoreError::TooManyEntries => (
                StatusCode::INSUFFICIENT_STORAGE,
                "verification-record tenant retention quota is full",
            ),
            RecordStoreError::IdempotencyConflict => (
                StatusCode::CONFLICT,
                "Idempotency-Key was already used for a different verification request",
            ),
            RecordStoreError::Io(_)
            | RecordStoreError::Json(_)
            | RecordStoreError::CorruptRecord
            | RecordStoreError::UnsafePath
            | RecordStoreError::LockPoisoned
            | RecordStoreError::InvalidSignerKeyring
            | RecordStoreError::RetentionAuditUnavailable
            | RecordStoreError::RetentionCancelled
            | RecordStoreError::RetentionBudgetExhausted => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "verification record could not be retained",
            ),
        };
        ProvErr::new(status, message)
    })?;

    let response = VerifyRecordResponse {
        verification,
        record_id,
        recorded_at,
        receipt,
    };
    match append_outcome {
        RecordAppendOutcome::Appended => {
            meter.on_op(ProvenanceOp::VerifyRecord, tenant);
            Ok(VerifyRecordOutcome::Created(response))
        }
        RecordAppendOutcome::Existing(existing) => Ok(VerifyRecordOutcome::Replayed(*existing)),
    }
}

const RECORD_MAX_LINE_BYTES: u64 = 128 * 1024;
const RECORD_SEGMENT_MAX_BYTES: u64 = 8 * 1024 * 1024;
const RECORD_TENANT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const RECORD_MAX_DIRECTORY_ENTRIES: usize = 1_024;

#[derive(Clone, Copy)]
struct RecordStoreLimits {
    max_line_bytes: u64,
    segment_max_bytes: u64,
    tenant_max_bytes: u64,
    max_directory_entries: usize,
}

impl Default for RecordStoreLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: RECORD_MAX_LINE_BYTES,
            segment_max_bytes: RECORD_SEGMENT_MAX_BYTES,
            tenant_max_bytes: RECORD_TENANT_MAX_BYTES,
            max_directory_entries: RECORD_MAX_DIRECTORY_ENTRIES,
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum RecordStoreError {
    #[error("record store io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("record serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("verification record is {actual} bytes, above the {max} byte line cap")]
    LineTooLarge { actual: u64, max: u64 },
    #[error("tenant verification-record quota exceeded: need {needed} bytes, cap is {max}")]
    TenantQuotaExceeded { needed: u64, max: u64 },
    #[error("tenant verification-record directory has too many entries")]
    TooManyEntries,
    #[error("idempotency key was already used for a different verification request")]
    IdempotencyConflict,
    #[error("verification-record storage contains an unreadable or incomplete record")]
    CorruptRecord,
    #[error("verification-record storage path is not a regular private file or directory")]
    UnsafePath,
    #[error("record append lock is poisoned")]
    LockPoisoned,
    #[error("verification-record retention signer keyring is invalid")]
    InvalidSignerKeyring,
    #[error("verification-record retention audit intent could not be durably recorded")]
    RetentionAuditUnavailable,
    #[error("verification-record retention pass was cancelled before mutation")]
    RetentionCancelled,
    #[error("verification-record retention pass exhausted its configured resource budget")]
    RetentionBudgetExhausted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordRetentionSweepSummary {
    retention_days: u32,
    cutoff: String,
    tenant_hash: String,
    records_dropped: usize,
    expired_records_held: usize,
    files_rewritten: usize,
    files_removed: usize,
}

#[derive(Debug)]
struct RecordRetentionSweepRun {
    summary: RecordRetentionSweepSummary,
    error: Option<RecordStoreError>,
    audit_intent_recorded: bool,
    bytes_examined: u64,
}

#[derive(Clone)]
struct RetentionSweepControls {
    cancellation: Arc<AtomicBool>,
    deadline: Option<Instant>,
    max_store_bytes: u64,
}

impl RetentionSweepControls {
    fn unbounded() -> Self {
        Self {
            cancellation: Arc::new(AtomicBool::new(false)),
            deadline: None,
            max_store_bytes: u64::MAX,
        }
    }

    fn check(&self) -> Result<(), RecordStoreError> {
        if self.cancellation.load(Ordering::Acquire) {
            return Err(RecordStoreError::RetentionCancelled);
        }
        if self.deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(RecordStoreError::RetentionBudgetExhausted);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct RecordReceiptVerifier {
    verifying_keys: HashMap<String, ed25519_dalek::VerifyingKey>,
}

impl RecordReceiptVerifier {
    fn from_parts(expected_signer: &str, public_key_hex: &str) -> Result<Self, RecordStoreError> {
        let public_key: [u8; 32] = hex::decode(public_key_hex)
            .map_err(|_| RecordStoreError::InvalidSignerKeyring)?
            .try_into()
            .map_err(|_: Vec<u8>| RecordStoreError::InvalidSignerKeyring)?;
        if corecrux_memory::cruxpack::passport_fpr_from_public_key(&public_key) != expected_signer {
            return Err(RecordStoreError::InvalidSignerKeyring);
        }
        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(&public_key).map_err(|_| RecordStoreError::InvalidSignerKeyring)?;
        Ok(Self {
            verifying_keys: HashMap::from([(expected_signer.to_string(), verifying_key)]),
        })
    }

    fn from_state(state: &AppState) -> Result<Self, RecordStoreError> {
        let mut verifier = Self::from_parts(&state.passport_fpr, &state.passport_public_key_hex)?;
        let Some(raw_keyring) = std::env::var(RETENTION_SIGNER_KEYRING_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            return Ok(verifier);
        };
        let historical: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&raw_keyring).map_err(|_| RecordStoreError::InvalidSignerKeyring)?;
        if historical.len() > MAX_RETENTION_SIGNER_KEYS {
            return Err(RecordStoreError::InvalidSignerKeyring);
        }
        for (signer, value) in historical {
            let public_key_hex = value.as_str().ok_or(RecordStoreError::InvalidSignerKeyring)?;
            let historical_verifier = Self::from_parts(&signer, public_key_hex)?;
            let historical_key = historical_verifier
                .verifying_keys
                .get(&signer)
                .ok_or(RecordStoreError::InvalidSignerKeyring)?;
            if let Some(existing) = verifier.verifying_keys.get(&signer) {
                if existing.to_bytes() != historical_key.to_bytes() {
                    return Err(RecordStoreError::InvalidSignerKeyring);
                }
            } else {
                verifier.verifying_keys.insert(signer, *historical_key);
            }
        }
        Ok(verifier)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ScheduledRetentionReport {
    tenants_discovered: usize,
    tenants_selected: usize,
    tenants_swept: usize,
    tenants_failed: usize,
    records_dropped: usize,
    expired_records_held: usize,
    receipts_pending: usize,
    cancelled: bool,
    budget_exhausted: bool,
    bytes_examined: u64,
    empty_directories_removed: usize,
}

#[derive(Clone, Copy)]
struct ScheduledRetentionLimits {
    max_bytes: u64,
    max_duration: Duration,
}

impl Default for ScheduledRetentionLimits {
    fn default() -> Self {
        Self {
            max_bytes: RETENTION_SCHEDULER_MAX_BYTES_PER_PASS,
            max_duration: RETENTION_SCHEDULER_MAX_PASS_DURATION,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetainedTenantCandidate {
    tenant: String,
    tenant_hash: String,
    store_bytes: u64,
    next_cursor: usize,
}

struct ScheduledRetentionDiscovery {
    tenants_discovered: usize,
    tenants_selected: usize,
    candidates: Vec<RetainedTenantCandidate>,
    failures: Vec<(String, RecordStoreError)>,
    next_cursor: usize,
    empty_directories_removed: usize,
    bytes_examined: u64,
    cancelled: bool,
    budget_exhausted: bool,
}

#[derive(Serialize)]
struct RecordRetentionReceiptV1<'a> {
    schema: &'a str,
    op: &'a str,
    reason_code: &'a str,
    sweep_id: &'a str,
    tenant_hash: &'a str,
    retention_days: u32,
    cutoff: &'a str,
    records_dropped: usize,
    expired_records_held: usize,
    files_rewritten: usize,
    files_removed: usize,
    status: &'a str,
    trigger: &'a str,
    recorded_at: String,
}

struct RetentionAudit {
    summary: RecordRetentionSweepSummary,
    receipt_id: Option<String>,
}

struct RecordRewritePlan {
    path: PathBuf,
    identity: RecordFileIdentity,
    retained_bytes: Vec<u8>,
    records_dropped: usize,
    expired_records_held: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    len: u64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
}

impl RecordFileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Result<Self, RecordStoreError> {
        if !metadata.is_file() {
            return Err(RecordStoreError::UnsafePath);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.nlink() != 1 {
                return Err(RecordStoreError::UnsafePath);
            }
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
            })
        }
    }

    fn matches_path(&self, path: &Path) -> Result<bool, RecordStoreError> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Ok(false);
        }
        Ok(*self == Self::from_metadata(&metadata)?)
    }
}

fn tenant_records_hash(tenant: &str) -> String {
    blake3::hash(tenant.as_bytes()).to_hex().to_string()
}

fn tenant_records_dir(data_dir: &Path, tenant: &str) -> PathBuf {
    let tenant_hash = tenant_records_hash(tenant);
    data_dir
        .join("provenance")
        .join("tenants")
        .join(format!("t_{tenant_hash}"))
}

struct AnchoredDirectory {
    file: std::fs::File,
    path: PathBuf,
}

impl AnchoredDirectory {
    #[cfg(target_os = "linux")]
    fn open_path(path: &Path) -> Result<Self, RecordStoreError> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(path)?;
        if !file.metadata()?.is_dir() {
            return Err(RecordStoreError::UnsafePath);
        }
        let anchor = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        let file_metadata = file.metadata()?;
        let anchor_metadata = std::fs::metadata(&anchor)?;
        if file_metadata.dev() != anchor_metadata.dev() || file_metadata.ino() != anchor_metadata.ino() {
            return Err(RecordStoreError::UnsafePath);
        }
        Ok(Self { file, path: anchor })
    }

    #[cfg(not(target_os = "linux"))]
    fn open_path(path: &Path) -> Result<Self, RecordStoreError> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RecordStoreError::UnsafePath);
        }
        let file = std::fs::File::open(path)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    #[cfg(target_os = "linux")]
    fn open_child(&self, name: &str) -> Result<Self, RecordStoreError> {
        if name.is_empty() || name.contains('/') {
            return Err(RecordStoreError::UnsafePath);
        }
        let descriptor = rustix::fs::openat(
            &self.file,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        let file = std::fs::File::from(descriptor);
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;
        let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        let file_metadata = file.metadata()?;
        let anchor_metadata = std::fs::metadata(&path)?;
        if !file_metadata.is_dir()
            || file_metadata.dev() != anchor_metadata.dev()
            || file_metadata.ino() != anchor_metadata.ino()
        {
            return Err(RecordStoreError::UnsafePath);
        }
        Ok(Self { file, path })
    }

    #[cfg(not(target_os = "linux"))]
    fn open_child(&self, name: &str) -> Result<Self, RecordStoreError> {
        Self::open_path(&self.path.join(name))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn sync_all(&self) -> Result<(), RecordStoreError> {
        self.file.sync_all().map_err(Into::into)
    }

    #[cfg(target_os = "linux")]
    fn same_directory(&self, other: &Self) -> Result<bool, RecordStoreError> {
        use std::os::unix::fs::MetadataExt as _;

        let left = self.file.metadata()?;
        let right = other.file.metadata()?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }

    #[cfg(target_os = "linux")]
    fn unlink_child(&self, name: &str, remove_directory: bool) -> Result<(), RecordStoreError> {
        if name.is_empty() || name.contains('/') {
            return Err(RecordStoreError::UnsafePath);
        }
        let flags = if remove_directory {
            rustix::fs::AtFlags::REMOVEDIR
        } else {
            rustix::fs::AtFlags::empty()
        };
        rustix::fs::unlinkat(&self.file, name, flags)
            .map_err(std::io::Error::from)
            .map_err(Into::into)
    }
}

fn open_existing_tenants_root(data_dir: &Path) -> Result<Option<AnchoredDirectory>, RecordStoreError> {
    let data_root = match AnchoredDirectory::open_path(data_dir) {
        Ok(root) => root,
        Err(RecordStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let provenance_root = match data_root.open_child("provenance") {
        Ok(root) => root,
        Err(RecordStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    match provenance_root.open_child("tenants") {
        Ok(root) => Ok(Some(root)),
        Err(RecordStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn open_existing_tenant_directory(
    data_dir: &Path,
    tenant_hash: &str,
) -> Result<Option<AnchoredDirectory>, RecordStoreError> {
    let Some(tenants_root) = open_existing_tenants_root(data_dir)? else {
        return Ok(None);
    };
    match tenants_root.open_child(&format!("t_{tenant_hash}")) {
        Ok(directory) => Ok(Some(directory)),
        Err(RecordStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn cleanup_empty_tenant_directory(data_dir: &Path, tenant_hash: &str) -> Result<bool, RecordStoreError> {
    cleanup_empty_tenant_directory_with_controls(data_dir, tenant_hash, &RetentionSweepControls::unbounded())
}

#[cfg(target_os = "linux")]
fn cleanup_empty_tenant_directory_with_controls(
    data_dir: &Path,
    tenant_hash: &str,
    controls: &RetentionSweepControls,
) -> Result<bool, RecordStoreError> {
    let _process_guard = lock_tenant_for_retention(tenant_hash, controls)?;
    let Some(tenant_anchor) = open_existing_tenant_directory(data_dir, tenant_hash)? else {
        return Ok(false);
    };
    let lock_path = tenant_anchor.path().join(".append.lock");
    let lock_file = match open_private_existing_lock(&lock_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    validate_and_harden_open_file(&lock_file)?;
    lock_file_for_retention(&lock_file, controls)?;
    controls.check()?;
    cleanup_retention_temp_files(tenant_anchor.path())?;
    for entry in std::fs::read_dir(tenant_anchor.path())? {
        controls.check()?;
        let entry = entry?;
        if entry.file_name() != ".append.lock" {
            return Ok(false);
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(RecordStoreError::UnsafePath);
        }
    }

    let Some(tenants_root) = open_existing_tenants_root(data_dir)? else {
        return Err(RecordStoreError::UnsafePath);
    };
    let directory_name = format!("t_{tenant_hash}");
    let current = tenants_root.open_child(&directory_name)?;
    if !tenant_anchor.same_directory(&current)? {
        return Err(RecordStoreError::UnsafePath);
    }
    tenant_anchor.unlink_child(".append.lock", false)?;
    tenant_anchor.sync_all()?;
    tenants_root.unlink_child(&directory_name, true)?;
    tenants_root.sync_all()?;
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
fn cleanup_empty_tenant_directory(_data_dir: &Path, _tenant_hash: &str) -> Result<bool, RecordStoreError> {
    Err(RecordStoreError::UnsafePath)
}

#[cfg(not(target_os = "linux"))]
fn cleanup_empty_tenant_directory_with_controls(
    _data_dir: &Path,
    _tenant_hash: &str,
    _controls: &RetentionSweepControls,
) -> Result<bool, RecordStoreError> {
    Err(RecordStoreError::UnsafePath)
}

#[cfg(test)]
fn records_path(data_dir: &Path, tenant: &str) -> PathBuf {
    tenant_records_dir(data_dir, tenant).join("verification-records.jsonl")
}

fn record_tenant_lock(tenant_hash: &str) -> &'static Mutex<()> {
    static LOCKS: OnceLock<Box<[Mutex<()>]>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| {
        (0..RECORD_TENANT_LOCK_SHARDS)
            .map(|_| Mutex::new(()))
            .collect::<Vec<_>>()
            .into_boxed_slice()
    });
    let digest = blake3::hash(tenant_hash.as_bytes());
    let shard = usize::from(digest.as_bytes()[0]) % locks.len();
    &locks[shard]
}

fn lock_tenant_for_retention<'a>(
    tenant_hash: &str,
    controls: &RetentionSweepControls,
) -> Result<std::sync::MutexGuard<'a, ()>, RecordStoreError> {
    let lock: &'a Mutex<()> = record_tenant_lock(tenant_hash);
    loop {
        controls.check()?;
        match lock.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::WouldBlock) => std::thread::sleep(RETENTION_LOCK_POLL_INTERVAL),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(RecordStoreError::LockPoisoned),
        }
    }
}

fn lock_file_for_retention(file: &std::fs::File, controls: &RetentionSweepControls) -> Result<(), RecordStoreError> {
    use fs2::FileExt as _;

    loop {
        controls.check()?;
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(RETENTION_LOCK_POLL_INTERVAL);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn is_retention_temp_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(".verification-records-retention-"))
        && path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("tmp"))
}

fn is_verification_record_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if name == "verification-records.jsonl" {
        return true;
    }
    let Some(archive) = name
        .strip_prefix("verification-records-")
        .and_then(|name| name.strip_suffix(".jsonl"))
    else {
        return false;
    };
    let Some((timestamp, uuid)) = archive.split_once('-') else {
        return false;
    };
    timestamp.parse::<i64>().is_ok() && uuid::Uuid::parse_str(uuid).is_ok()
}

fn cleanup_retention_temp_files(tenant_dir: &Path) -> Result<(), RecordStoreError> {
    let mut removed = false;
    for entry in std::fs::read_dir(tenant_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !is_retention_temp_file(&path) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(RecordStoreError::UnsafePath);
        }
        let identity = RecordFileIdentity::from_metadata(&entry.metadata()?)?;
        if !identity.matches_path(&path)? {
            return Err(RecordStoreError::UnsafePath);
        }
        std::fs::remove_file(path)?;
        removed = true;
    }
    if removed {
        sync_directory(tenant_dir)?;
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum RecordAppendOutcome {
    Appended,
    Existing(Box<VerifyRecordResponse>),
}

#[cfg(test)]
fn append_record(data_dir: &Path, tenant: &str, line: &serde_json::Value) -> Result<(), RecordStoreError> {
    append_record_with_limits(data_dir, tenant, line, RecordStoreLimits::default())
}

#[cfg(test)]
fn append_record_with_limits(
    data_dir: &Path,
    tenant: &str,
    line: &serde_json::Value,
    limits: RecordStoreLimits,
) -> Result<(), RecordStoreError> {
    match retain_record_with_limits(data_dir, tenant, line, limits, None)? {
        RecordAppendOutcome::Appended => Ok(()),
        RecordAppendOutcome::Existing(_) => Err(RecordStoreError::CorruptRecord),
    }
}

fn retain_verification_record(
    data_dir: &Path,
    tenant: &str,
    line: &serde_json::Value,
    idempotency: Option<&RecordIdempotency>,
) -> Result<RecordAppendOutcome, RecordStoreError> {
    retain_record_with_limits(data_dir, tenant, line, RecordStoreLimits::default(), idempotency)
}

fn retain_record_with_limits(
    data_dir: &Path,
    tenant: &str,
    line: &serde_json::Value,
    limits: RecordStoreLimits,
    idempotency: Option<&RecordIdempotency>,
) -> Result<RecordAppendOutcome, RecordStoreError> {
    use fs2::FileExt as _;
    use std::io::Write as _;

    let mut serialized = serde_json::to_vec(line)?;
    serialized.push(b'\n');
    let line_bytes = u64::try_from(serialized.len()).unwrap_or(u64::MAX);
    let effective_line_cap = limits.max_line_bytes.min(limits.segment_max_bytes);
    if line_bytes > effective_line_cap {
        return Err(RecordStoreError::LineTooLarge {
            actual: line_bytes,
            max: effective_line_cap,
        });
    }

    let tenant_hash = tenant_records_hash(tenant);
    let _process_guard = record_tenant_lock(&tenant_hash)
        .lock()
        .map_err(|_| RecordStoreError::LockPoisoned)?;
    let tenant_dir_path = tenant_records_dir(data_dir, tenant);
    let tenant_dir_preexisting = tenant_dir_path.exists();
    std::fs::create_dir_all(&tenant_dir_path)?;
    let tenant_anchor = open_existing_tenant_directory(data_dir, &tenant_hash)?.ok_or(RecordStoreError::UnsafePath)?;
    let tenant_dir = tenant_anchor.path();
    set_private_directory_permissions(tenant_dir)?;

    let lock_path = tenant_dir.join(".append.lock");
    reject_symlink_or_non_file(&lock_path)?;
    let lock_file = open_private_append_lock(&lock_path)?;
    validate_and_harden_open_file(&lock_file)?;
    lock_file.lock_exclusive()?;
    cleanup_retention_temp_files(tenant_dir)?;

    let active_path = tenant_dir.join("verification-records.jsonl");
    let mut total_bytes = 0_u64;
    let mut directory_entries = 0_usize;
    let mut active_bytes = None;
    let mut jsonl_paths = Vec::new();
    for entry in std::fs::read_dir(tenant_dir)? {
        let entry = entry?;
        directory_entries = directory_entries.saturating_add(1);
        if directory_entries > limits.max_directory_entries {
            return Err(RecordStoreError::TooManyEntries);
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(RecordStoreError::UnsafePath);
        }
        if !file_type.is_file() {
            return Err(RecordStoreError::UnsafePath);
        }
        let entry_path = entry.path();
        let is_jsonl = is_verification_record_file(&entry_path);
        if entry.file_name() != ".append.lock" && !is_jsonl {
            return Err(RecordStoreError::UnsafePath);
        }
        if is_jsonl {
            let bytes = entry.metadata()?.len();
            total_bytes = total_bytes.saturating_add(bytes);
            if entry_path == active_path {
                active_bytes = Some(bytes);
            }
            jsonl_paths.push(entry_path);
        }
    }
    if let Some(idempotency) = idempotency {
        if let Some(existing) = find_idempotent_record(&jsonl_paths, idempotency)? {
            return Ok(RecordAppendOutcome::Existing(Box::new(existing)));
        }
    }
    let needed = total_bytes.saturating_add(line_bytes);
    if needed > limits.tenant_max_bytes {
        return Err(RecordStoreError::TenantQuotaExceeded {
            needed,
            max: limits.tenant_max_bytes,
        });
    }

    reject_symlink_or_non_file(&active_path)?;
    let rotate =
        active_bytes.is_some_and(|bytes| bytes > 0 && bytes.saturating_add(line_bytes) > limits.segment_max_bytes);
    if (active_bytes.is_none() || rotate) && directory_entries >= limits.max_directory_entries {
        return Err(RecordStoreError::TooManyEntries);
    }
    if rotate {
        let archive_path = tenant_dir.join(format!(
            "verification-records-{}-{}.jsonl",
            chrono::Utc::now().timestamp_millis(),
            uuid::Uuid::new_v4()
        ));
        std::fs::rename(&active_path, archive_path)?;
        tenant_anchor.sync_all()?;
    }

    let mut file = open_private_append_file(&active_path)?;
    validate_and_harden_open_file(&file)?;
    file.write_all(&serialized)?;
    file.sync_all()?;
    tenant_anchor.sync_all()?;
    if !tenant_dir_preexisting {
        sync_directory_chain(&tenant_dir_path, data_dir)?;
    }
    Ok(RecordAppendOutcome::Appended)
}

struct ValidatedStoredRecord<'a> {
    record_id: &'a str,
    recorded_at: chrono::DateTime<chrono::Utc>,
}

fn read_bounded_retention_line(
    reader: &mut impl std::io::BufRead,
    max_line_bytes: u64,
    remaining_budget: u64,
) -> Result<Option<Vec<u8>>, RecordStoreError> {
    use std::io::{BufRead as _, Read as _};

    if remaining_budget == 0 {
        return Err(RecordStoreError::RetentionBudgetExhausted);
    }
    let read_cap = remaining_budget.min(max_line_bytes.saturating_add(1));
    let mut encoded_line = Vec::new();
    let line_bytes = reader.take(read_cap).read_until(b'\n', &mut encoded_line)?;
    if line_bytes == 0 {
        return Ok(None);
    }
    let line_bytes = u64::try_from(line_bytes).unwrap_or(u64::MAX);
    if line_bytes > max_line_bytes {
        return Err(RecordStoreError::CorruptRecord);
    }
    if !encoded_line.ends_with(b"\n") {
        if line_bytes >= remaining_budget && remaining_budget <= max_line_bytes {
            return Err(RecordStoreError::RetentionBudgetExhausted);
        }
        return Err(RecordStoreError::CorruptRecord);
    }
    Ok(Some(encoded_line))
}

fn validate_retained_record_for_retention<'a>(
    stored: &'a serde_json::Value,
    tenant: &str,
    verifier: &RecordReceiptVerifier,
) -> Result<ValidatedStoredRecord<'a>, RecordStoreError> {
    use ed25519_dalek::Verifier as _;

    let mut body = stored.as_object().cloned().ok_or(RecordStoreError::CorruptRecord)?;
    let receipt: ProvenanceReceiptV1 =
        serde_json::from_value(body.remove("receipt").ok_or(RecordStoreError::CorruptRecord)?)
            .map_err(|_| RecordStoreError::CorruptRecord)?;
    if body.get("schema").and_then(serde_json::Value::as_str) != Some("cuecrux.provenance.verification_record.v1")
        || body.get("tenant_id").and_then(serde_json::Value::as_str) != Some(tenant)
        || receipt.alg != "ed25519"
    {
        return Err(RecordStoreError::CorruptRecord);
    }
    let verifying_key = verifier
        .verifying_keys
        .get(&receipt.signed_by)
        .ok_or(RecordStoreError::CorruptRecord)?;
    let canonical = serde_json::to_vec(&serde_json::Value::Object(body)).map_err(RecordStoreError::Json)?;
    let hash = blake3::hash(&canonical);
    if receipt.body_hash != format!("blake3:{}", hex::encode(hash.as_bytes())) {
        return Err(RecordStoreError::CorruptRecord);
    }
    let signature = ed25519_dalek::Signature::from_slice(
        &hex::decode(&receipt.signature).map_err(|_| RecordStoreError::CorruptRecord)?,
    )
    .map_err(|_| RecordStoreError::CorruptRecord)?;
    verifying_key
        .verify(hash.as_bytes(), &signature)
        .map_err(|_| RecordStoreError::CorruptRecord)?;

    let record_id = stored
        .get("record_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(RecordStoreError::CorruptRecord)?;
    let recorded_at = stored
        .get("recorded_at")
        .and_then(serde_json::Value::as_str)
        .ok_or(RecordStoreError::CorruptRecord)?;
    let recorded_at = chrono::DateTime::parse_from_rfc3339(recorded_at)
        .map_err(|_| RecordStoreError::CorruptRecord)?
        .with_timezone(&chrono::Utc);
    Ok(ValidatedStoredRecord { record_id, recorded_at })
}

#[cfg(test)]
fn sweep_expired_verification_records(
    data_dir: &Path,
    tenant: &str,
    retention_days: u32,
    now: chrono::DateTime<chrono::Utc>,
    legal_holds: &[corecrux_memory::LegalHold],
    verifier: &RecordReceiptVerifier,
) -> RecordRetentionSweepRun {
    sweep_expired_verification_records_with_audit_intent(
        data_dir,
        tenant,
        retention_days,
        now,
        legal_holds,
        verifier,
        |_| Ok(()),
    )
}

fn sweep_expired_verification_records_with_audit_intent(
    data_dir: &Path,
    tenant: &str,
    retention_days: u32,
    now: chrono::DateTime<chrono::Utc>,
    legal_holds: &[corecrux_memory::LegalHold],
    verifier: &RecordReceiptVerifier,
    record_audit_intent: impl FnMut(&RecordRetentionSweepSummary) -> Result<(), RecordStoreError>,
) -> RecordRetentionSweepRun {
    sweep_expired_verification_records_with_controls(
        data_dir,
        RetentionSweepRequest {
            tenant,
            retention_days,
            now,
            legal_holds,
            verifier,
            controls: &RetentionSweepControls::unbounded(),
        },
        record_audit_intent,
    )
}

struct RetentionSweepRequest<'a> {
    tenant: &'a str,
    retention_days: u32,
    now: chrono::DateTime<chrono::Utc>,
    legal_holds: &'a [corecrux_memory::LegalHold],
    verifier: &'a RecordReceiptVerifier,
    controls: &'a RetentionSweepControls,
}

struct RetentionSweepContext<'a> {
    tenant: &'a str,
    cutoff: chrono::DateTime<chrono::Utc>,
    legal_holds: &'a [corecrux_memory::LegalHold],
    verifier: &'a RecordReceiptVerifier,
    controls: &'a RetentionSweepControls,
}

#[cfg_attr(not(target_os = "linux"), allow(unreachable_code, unused_variables, unused_mut))]
fn sweep_expired_verification_records_with_controls(
    data_dir: &Path,
    request: RetentionSweepRequest<'_>,
    mut record_audit_intent: impl FnMut(&RecordRetentionSweepSummary) -> Result<(), RecordStoreError>,
) -> RecordRetentionSweepRun {
    let cutoff = request.now - chrono::Duration::days(i64::from(request.retention_days));
    let mut summary = RecordRetentionSweepSummary {
        retention_days: request.retention_days,
        cutoff: cutoff.to_rfc3339(),
        tenant_hash: tenant_records_hash(request.tenant),
        records_dropped: 0,
        expired_records_held: 0,
        files_rewritten: 0,
        files_removed: 0,
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = &mut record_audit_intent;
        return RecordRetentionSweepRun {
            summary,
            error: Some(RecordStoreError::UnsafePath),
            audit_intent_recorded: false,
            bytes_examined: 0,
        };
    }

    let context = RetentionSweepContext {
        tenant: request.tenant,
        cutoff,
        legal_holds: request.legal_holds,
        verifier: request.verifier,
        controls: request.controls,
    };
    let mut audit_intent_recorded = false;
    let mut tracked_audit_intent = |planned: &RecordRetentionSweepSummary| {
        record_audit_intent(planned)?;
        audit_intent_recorded = true;
        Ok(())
    };
    let mut bytes_examined = 0;
    let error = sweep_expired_verification_records_inner(
        data_dir,
        &context,
        &mut summary,
        &mut bytes_examined,
        &mut tracked_audit_intent,
    )
    .err();
    RecordRetentionSweepRun {
        summary,
        error,
        audit_intent_recorded,
        bytes_examined,
    }
}

fn sweep_expired_verification_records_inner(
    data_dir: &Path,
    context: &RetentionSweepContext<'_>,
    summary: &mut RecordRetentionSweepSummary,
    bytes_examined: &mut u64,
    record_audit_intent: &mut impl FnMut(&RecordRetentionSweepSummary) -> Result<(), RecordStoreError>,
) -> Result<(), RecordStoreError> {
    let limits = RecordStoreLimits::default();
    context.controls.check()?;
    let tenant_hash = tenant_records_hash(context.tenant);
    let _process_guard = lock_tenant_for_retention(&tenant_hash, context.controls)?;
    let Some(tenant_anchor) = open_existing_tenant_directory(data_dir, &tenant_hash)? else {
        return Ok(());
    };
    let tenant_dir = tenant_anchor.path();
    set_private_directory_permissions(tenant_dir)?;

    let lock_path = tenant_dir.join(".append.lock");
    reject_symlink_or_non_file(&lock_path)?;
    let lock_file = open_private_append_lock(&lock_path)?;
    validate_and_harden_open_file(&lock_file)?;
    lock_file_for_retention(&lock_file, context.controls)?;
    context.controls.check()?;
    cleanup_retention_temp_files(tenant_dir)?;

    // Validate and plan the complete tenant rewrite before deleting anything.
    // The store is already capped at 64 MiB per tenant, which bounds this
    // retained-byte plan while allowing atomic per-file replacement.
    let mut plans = Vec::new();
    let mut directory_entries = 0usize;
    let mut total_bytes = 0u64;
    for entry in std::fs::read_dir(tenant_dir)? {
        context.controls.check()?;
        let entry = entry?;
        directory_entries = directory_entries.saturating_add(1);
        if directory_entries > limits.max_directory_entries {
            return Err(RecordStoreError::TooManyEntries);
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(RecordStoreError::UnsafePath);
        }
        let path = entry.path();
        if entry.file_name() == ".append.lock" {
            continue;
        }
        if !is_verification_record_file(&path) {
            return Err(RecordStoreError::UnsafePath);
        }
        let next_total = total_bytes.saturating_add(entry.metadata()?.len());
        if next_total > context.controls.max_store_bytes {
            return Err(RecordStoreError::RetentionBudgetExhausted);
        }
        total_bytes = next_total;
        *bytes_examined = total_bytes;
        if total_bytes > limits.tenant_max_bytes {
            return Err(RecordStoreError::TenantQuotaExceeded {
                needed: total_bytes,
                max: limits.tenant_max_bytes,
            });
        }

        reject_symlink_or_non_file(&path)?;
        let file = open_private_read_file(&path)?;
        validate_and_harden_open_file(&file)?;
        let identity = RecordFileIdentity::from_metadata(&file.metadata()?)?;
        let mut reader = std::io::BufReader::new(file);
        let mut retained_bytes = Vec::new();
        let mut records_dropped = 0usize;
        let mut expired_records_held = 0usize;
        loop {
            context.controls.check()?;
            let Some(encoded_line) = read_bounded_retention_line(
                &mut reader,
                limits.max_line_bytes,
                limits.max_line_bytes.saturating_add(1),
            )?
            else {
                break;
            };
            let json_bytes = &encoded_line[..encoded_line.len() - 1];
            if json_bytes.iter().all(u8::is_ascii_whitespace) {
                retained_bytes.extend_from_slice(&encoded_line);
                continue;
            }
            let stored: serde_json::Value =
                serde_json::from_slice(json_bytes).map_err(|_| RecordStoreError::CorruptRecord)?;
            let validated = validate_retained_record_for_retention(&stored, context.tenant, context.verifier)?;
            if validated.recorded_at >= context.cutoff {
                retained_bytes.extend_from_slice(&encoded_line);
                continue;
            }

            let entity = format!("provenance::verification_record::{}", validated.record_id);
            if context
                .legal_holds
                .iter()
                .any(|hold| hold.covers(context.tenant, &entity))
            {
                retained_bytes.extend_from_slice(&encoded_line);
                expired_records_held = expired_records_held.saturating_add(1);
            } else {
                records_dropped = records_dropped.saturating_add(1);
            }
        }
        if records_dropped > 0 {
            plans.push(RecordRewritePlan {
                path,
                identity,
                retained_bytes,
                records_dropped,
                expired_records_held,
            });
        } else {
            summary.expired_records_held = summary.expired_records_held.saturating_add(expired_records_held);
        }
    }

    let mut planned_summary = summary.clone();
    for plan in &plans {
        planned_summary.records_dropped = planned_summary.records_dropped.saturating_add(plan.records_dropped);
        planned_summary.expired_records_held = planned_summary
            .expired_records_held
            .saturating_add(plan.expired_records_held);
        if plan.retained_bytes.is_empty() {
            planned_summary.files_removed = planned_summary.files_removed.saturating_add(1);
        } else {
            planned_summary.files_rewritten = planned_summary.files_rewritten.saturating_add(1);
        }
    }
    if planned_summary.records_dropped > 0 {
        context.controls.check()?;
        record_audit_intent(&planned_summary)?;
    }

    for plan in plans {
        if !plan.identity.matches_path(&plan.path)? {
            return Err(RecordStoreError::UnsafePath);
        }
        if plan.retained_bytes.is_empty() {
            std::fs::remove_file(&plan.path)?;
            summary.records_dropped = summary.records_dropped.saturating_add(plan.records_dropped);
            summary.expired_records_held = summary.expired_records_held.saturating_add(plan.expired_records_held);
            summary.files_removed = summary.files_removed.saturating_add(1);
            tenant_anchor.sync_all()?;
            continue;
        }

        let temp_path = tenant_dir.join(format!(".verification-records-retention-{}.tmp", uuid::Uuid::new_v4()));
        let rewrite_result = (|| -> Result<(), RecordStoreError> {
            use std::io::Write as _;

            let mut temp_file = open_private_new_file(&temp_path)?;
            validate_and_harden_open_file(&temp_file)?;
            temp_file.write_all(&plan.retained_bytes)?;
            temp_file.sync_all()?;
            if !plan.identity.matches_path(&plan.path)? {
                return Err(RecordStoreError::UnsafePath);
            }
            std::fs::rename(&temp_path, &plan.path)?;
            summary.records_dropped = summary.records_dropped.saturating_add(plan.records_dropped);
            summary.expired_records_held = summary.expired_records_held.saturating_add(plan.expired_records_held);
            summary.files_rewritten = summary.files_rewritten.saturating_add(1);
            tenant_anchor.sync_all()?;
            Ok(())
        })();
        if rewrite_result.is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
        rewrite_result?;
    }
    Ok(())
}

fn retention_terminal_status(run: &RecordRetentionSweepRun) -> Option<&'static str> {
    run.audit_intent_recorded
        .then_some(if run.error.is_some() { "failed" } else { "completed" })
}

#[cfg(test)]
fn provenance_tenants_root(data_dir: &Path) -> PathBuf {
    data_dir.join("provenance").join("tenants")
}

fn tenant_hash_from_directory_name(name: &str) -> Result<String, RecordStoreError> {
    let hash = name.strip_prefix("t_").ok_or(RecordStoreError::UnsafePath)?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RecordStoreError::UnsafePath);
    }
    Ok(hash.to_string())
}

#[cfg(test)]
fn list_retained_tenant_directories_with_limit(
    data_dir: &Path,
    max_entries: usize,
) -> Result<Vec<String>, RecordStoreError> {
    list_retained_tenant_directories_with_controls(data_dir, max_entries, &RetentionSweepControls::unbounded())
}

fn list_retained_tenant_directories_with_controls(
    data_dir: &Path,
    max_entries: usize,
    controls: &RetentionSweepControls,
) -> Result<Vec<String>, RecordStoreError> {
    controls.check()?;
    let Some(tenants_root) = open_existing_tenants_root(data_dir)? else {
        return Ok(Vec::new());
    };

    let mut paths = Vec::new();
    for entry in std::fs::read_dir(tenants_root.path())? {
        controls.check()?;
        let entry = entry?;
        if paths.len() >= max_entries {
            return Err(RecordStoreError::TooManyEntries);
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(RecordStoreError::UnsafePath);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RecordStoreError::UnsafePath)?;
        tenant_hash_from_directory_name(&name)?;
        paths.push(name);
    }
    paths.sort();
    Ok(paths)
}

fn selected_tenant_directories(paths: &[String], cursor: &mut usize, limit: usize) -> Vec<String> {
    if paths.is_empty() || limit == 0 {
        *cursor = 0;
        return Vec::new();
    }
    let start = *cursor % paths.len();
    let count = limit.min(paths.len());
    let selected = (0..count)
        .map(|offset| paths[(start + offset) % paths.len()].clone())
        .collect();
    *cursor = (start + count) % paths.len();
    selected
}

fn recover_retained_tenant(
    data_dir: &Path,
    tenant_hash: &str,
    verifier: &RecordReceiptVerifier,
    controls: &RetentionSweepControls,
    bytes_examined: &mut u64,
) -> Result<Option<RetainedTenantCandidate>, RecordStoreError> {
    controls.check()?;
    let _process_guard = lock_tenant_for_retention(tenant_hash, controls)?;
    let Some(tenant_anchor) = open_existing_tenant_directory(data_dir, tenant_hash)? else {
        return Ok(None);
    };
    let tenant_dir = tenant_anchor.path();
    let lock_path = tenant_dir.join(".append.lock");
    let lock_metadata = std::fs::symlink_metadata(&lock_path)?;
    if lock_metadata.file_type().is_symlink() || !lock_metadata.is_file() {
        return Err(RecordStoreError::UnsafePath);
    }
    let lock_file = open_private_existing_lock(&lock_path)?;
    validate_and_harden_open_file(&lock_file)?;
    lock_file_for_retention(&lock_file, controls)?;

    let mut jsonl_paths = Vec::new();
    let mut directory_entries = 0usize;
    let mut total_bytes = 0u64;
    for entry in std::fs::read_dir(tenant_dir)? {
        controls.check()?;
        let entry = entry?;
        directory_entries = directory_entries.saturating_add(1);
        if directory_entries > RECORD_MAX_DIRECTORY_ENTRIES {
            return Err(RecordStoreError::TooManyEntries);
        }
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(RecordStoreError::UnsafePath);
        }
        let path = entry.path();
        if entry.file_name() == ".append.lock" || is_retention_temp_file(&path) {
            continue;
        }
        if !is_verification_record_file(&path) {
            return Err(RecordStoreError::UnsafePath);
        }
        let file_bytes = entry.metadata()?.len();
        let next_examined = (*bytes_examined).saturating_add(file_bytes);
        if next_examined > controls.max_store_bytes {
            return Err(RecordStoreError::RetentionBudgetExhausted);
        }
        *bytes_examined = next_examined;
        total_bytes = total_bytes.saturating_add(file_bytes);
        if total_bytes > RECORD_TENANT_MAX_BYTES {
            return Err(RecordStoreError::TenantQuotaExceeded {
                needed: total_bytes,
                max: RECORD_TENANT_MAX_BYTES,
            });
        }
        jsonl_paths.push(path);
    }
    jsonl_paths.sort();

    let had_jsonl = !jsonl_paths.is_empty();
    for path in jsonl_paths {
        controls.check()?;
        reject_symlink_or_non_file(&path)?;
        let file = open_private_read_file(&path)?;
        validate_and_harden_open_file(&file)?;
        let mut reader = std::io::BufReader::new(file);
        loop {
            controls.check()?;
            let Some(encoded_line) = read_bounded_retention_line(
                &mut reader,
                RECORD_MAX_LINE_BYTES,
                RECORD_MAX_LINE_BYTES.saturating_add(1),
            )?
            else {
                break;
            };
            let json_bytes = &encoded_line[..encoded_line.len() - 1];
            if json_bytes.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let stored: serde_json::Value =
                serde_json::from_slice(json_bytes).map_err(|_| RecordStoreError::CorruptRecord)?;
            let tenant = stored
                .get("tenant_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(RecordStoreError::CorruptRecord)?;
            if tenant_records_hash(tenant) != tenant_hash {
                return Err(RecordStoreError::CorruptRecord);
            }
            validate_retained_record_for_retention(&stored, tenant, verifier)?;
            return Ok(Some(RetainedTenantCandidate {
                tenant: tenant.to_string(),
                tenant_hash: tenant_hash.to_string(),
                store_bytes: total_bytes,
                next_cursor: 0,
            }));
        }
    }
    if had_jsonl {
        Err(RecordStoreError::CorruptRecord)
    } else {
        Ok(None)
    }
}

fn with_active_tenant_legal_holds<R>(
    fact_store: &tokio::sync::RwLock<corecrux_memory::FactStore>,
    tenant: &str,
    apply: impl FnOnce(&[corecrux_memory::LegalHold]) -> R,
) -> R {
    let store = fact_store.blocking_read();
    let legal_holds: Vec<_> = store
        .active_legal_holds()
        .into_iter()
        .filter(|hold| hold.tenant_id == tenant)
        .collect();
    let result = apply(&legal_holds);
    drop(store);
    result
}

fn with_active_tenant_legal_holds_controlled<R>(
    fact_store: &tokio::sync::RwLock<corecrux_memory::FactStore>,
    tenant: &str,
    controls: &RetentionSweepControls,
    apply: impl FnOnce(&[corecrux_memory::LegalHold]) -> R,
) -> Result<R, RecordStoreError> {
    let store = loop {
        controls.check()?;
        if let Ok(store) = fact_store.try_read() {
            break store;
        }
        std::thread::sleep(RETENTION_LOCK_POLL_INTERVAL);
    };
    let legal_holds: Vec<_> = store
        .active_legal_holds()
        .into_iter()
        .filter(|hold| hold.tenant_id == tenant)
        .collect();
    let result = apply(&legal_holds);
    drop(store);
    Ok(result)
}

#[cfg(test)]
async fn run_scheduled_retention_once(
    state: &AppState,
    retention_days: u32,
    max_tenants: usize,
    now: chrono::DateTime<chrono::Utc>,
    cursor: &mut usize,
) -> Result<ScheduledRetentionReport, RecordStoreError> {
    run_scheduled_retention_once_with_limits(
        state,
        retention_days,
        max_tenants,
        now,
        cursor,
        Arc::new(AtomicBool::new(false)),
        ScheduledRetentionLimits::default(),
    )
    .await
}

async fn run_scheduled_retention_once_with_cancel(
    state: &AppState,
    retention_days: u32,
    max_tenants: usize,
    now: chrono::DateTime<chrono::Utc>,
    cursor: &mut usize,
    cancellation: Arc<AtomicBool>,
) -> Result<ScheduledRetentionReport, RecordStoreError> {
    run_scheduled_retention_once_with_limits(
        state,
        retention_days,
        max_tenants,
        now,
        cursor,
        cancellation,
        ScheduledRetentionLimits::default(),
    )
    .await
}

async fn run_scheduled_retention_once_with_limits(
    state: &AppState,
    retention_days: u32,
    max_tenants: usize,
    now: chrono::DateTime<chrono::Utc>,
    cursor: &mut usize,
    cancellation: Arc<AtomicBool>,
    limits: ScheduledRetentionLimits,
) -> Result<ScheduledRetentionReport, RecordStoreError> {
    let pass_started = Instant::now();
    let pass_controls = RetentionSweepControls {
        cancellation: cancellation.clone(),
        deadline: pass_started.checked_add(limits.max_duration),
        max_store_bytes: limits.max_bytes,
    };
    let verifier = RecordReceiptVerifier::from_state(state)?;
    let data_dir = state.data_dir.clone();
    let discovery_verifier = verifier.clone();
    let discovery_controls = pass_controls.clone();
    let mut discovery_cursor = *cursor;
    let discovery_result = tokio::task::spawn_blocking(move || {
        let paths = match list_retained_tenant_directories_with_controls(
            &data_dir,
            RETENTION_DISCOVERY_MAX_ENTRIES,
            &discovery_controls,
        ) {
            Ok(paths) => paths,
            Err(RecordStoreError::RetentionCancelled) => {
                return Ok(ScheduledRetentionDiscovery {
                    tenants_discovered: 0,
                    tenants_selected: 0,
                    candidates: Vec::new(),
                    failures: Vec::new(),
                    next_cursor: discovery_cursor,
                    empty_directories_removed: 0,
                    bytes_examined: 0,
                    cancelled: true,
                    budget_exhausted: false,
                });
            }
            Err(RecordStoreError::RetentionBudgetExhausted) => {
                return Ok(ScheduledRetentionDiscovery {
                    tenants_discovered: 0,
                    tenants_selected: 0,
                    candidates: Vec::new(),
                    failures: Vec::new(),
                    next_cursor: discovery_cursor.saturating_add(max_tenants),
                    empty_directories_removed: 0,
                    bytes_examined: 0,
                    cancelled: false,
                    budget_exhausted: true,
                });
            }
            Err(error) => return Err(error),
        };
        let discovered = paths.len();
        let selection_start = if paths.is_empty() {
            0
        } else {
            discovery_cursor % paths.len()
        };
        let selected = selected_tenant_directories(&paths, &mut discovery_cursor, max_tenants);
        let selected_count = selected.len();
        let mut candidates = Vec::new();
        let mut failures = Vec::new();
        let mut empty_directories_removed = 0usize;
        let mut bytes_examined = 0u64;
        let mut cancelled = false;
        let mut budget_exhausted = false;
        let mut next_cursor = selection_start;
        for (offset, directory_name) in selected.into_iter().enumerate() {
            match discovery_controls.check() {
                Ok(()) => {}
                Err(RecordStoreError::RetentionCancelled) => {
                    cancelled = true;
                    break;
                }
                Err(RecordStoreError::RetentionBudgetExhausted) => {
                    budget_exhausted = true;
                    break;
                }
                Err(error) => return Err(error),
            }
            let directory_next_cursor = (selection_start + offset + 1) % paths.len();
            next_cursor = directory_next_cursor;
            let tenant_hash = tenant_hash_from_directory_name(&directory_name)?;
            match recover_retained_tenant(
                &data_dir,
                &tenant_hash,
                &discovery_verifier,
                &discovery_controls,
                &mut bytes_examined,
            ) {
                Ok(Some(mut candidate)) => {
                    candidate.next_cursor = directory_next_cursor;
                    candidates.push(candidate);
                }
                Ok(None) => {
                    match cleanup_empty_tenant_directory_with_controls(&data_dir, &tenant_hash, &discovery_controls) {
                        Ok(true) => empty_directories_removed = empty_directories_removed.saturating_add(1),
                        Ok(false) => {}
                        Err(RecordStoreError::RetentionCancelled) => {
                            cancelled = true;
                            break;
                        }
                        Err(RecordStoreError::RetentionBudgetExhausted) => {
                            budget_exhausted = true;
                            break;
                        }
                        Err(error) => failures.push((tenant_hash, error)),
                    }
                }
                Err(RecordStoreError::RetentionCancelled) => {
                    cancelled = true;
                    break;
                }
                Err(RecordStoreError::RetentionBudgetExhausted) => {
                    budget_exhausted = true;
                    break;
                }
                Err(error) => failures.push((tenant_hash, error)),
            }
        }
        Ok::<_, RecordStoreError>(ScheduledRetentionDiscovery {
            tenants_discovered: discovered,
            tenants_selected: selected_count,
            candidates,
            failures,
            next_cursor,
            empty_directories_removed,
            bytes_examined,
            cancelled,
            budget_exhausted,
        })
    })
    .await
    .map_err(|error| RecordStoreError::Io(std::io::Error::other(format!("retention discovery task: {error}"))))?;
    let discovery = discovery_result?;
    *cursor = discovery.next_cursor;
    let mut report = ScheduledRetentionReport {
        tenants_discovered: discovery.tenants_discovered,
        tenants_selected: discovery.tenants_selected,
        tenants_failed: discovery.failures.len(),
        empty_directories_removed: discovery.empty_directories_removed,
        bytes_examined: discovery.bytes_examined,
        cancelled: discovery.cancelled,
        budget_exhausted: discovery.budget_exhausted,
        ..ScheduledRetentionReport::default()
    };
    for (tenant_hash, error) in discovery.failures {
        tracing::error!(%tenant_hash, %error, "provenance retention tenant discovery failed closed");
    }
    if report.cancelled || report.budget_exhausted {
        return Ok(report);
    }

    for candidate in discovery.candidates {
        *cursor = candidate.next_cursor;
        match pass_controls.check() {
            Ok(()) => {}
            Err(RecordStoreError::RetentionCancelled) => {
                report.cancelled = true;
                break;
            }
            Err(RecordStoreError::RetentionBudgetExhausted) => {
                report.budget_exhausted = true;
                break;
            }
            Err(error) => return Err(error),
        }
        let remaining_bytes = limits.max_bytes.saturating_sub(report.bytes_examined);
        if remaining_bytes == 0 || candidate.store_bytes > remaining_bytes {
            report.budget_exhausted = true;
            break;
        }
        if !retention_sweep_due(&candidate.tenant, Instant::now()) {
            continue;
        }
        let sweep_controls = RetentionSweepControls {
            max_store_bytes: remaining_bytes,
            ..pass_controls.clone()
        };
        let fact_store = state.fact_store.clone();
        let receipt_state = state.clone();
        let sweep_data_dir = state.data_dir.clone();
        let sweep_tenant = candidate.tenant;
        let tenant_hash = candidate.tenant_hash;
        let sweep_verifier = verifier.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<_, RecordStoreError> {
            let sweep_id = new_retention_sweep_id();
            let mut run = with_active_tenant_legal_holds_controlled(
                &fact_store,
                &sweep_tenant,
                &sweep_controls,
                |legal_holds| {
                    sweep_expired_verification_records_with_controls(
                        &sweep_data_dir,
                        RetentionSweepRequest {
                            tenant: &sweep_tenant,
                            retention_days,
                            now,
                            legal_holds,
                            verifier: &sweep_verifier,
                            controls: &sweep_controls,
                        },
                        |planned| {
                            let intent = mint_record_retention_intent_controlled(
                                &receipt_state,
                                RETENTION_SCHEDULER_ACTOR,
                                planned.clone(),
                                &sweep_id,
                                "scheduled",
                                &sweep_controls,
                            )?;
                            intent
                                .receipt_id
                                .map(|_| ())
                                .ok_or(RecordStoreError::RetentionAuditUnavailable)
                        },
                    )
                },
            )?;
            let empty_directory_removed = if run.error.is_none() {
                match cleanup_empty_tenant_directory_with_controls(
                    &sweep_data_dir,
                    &tenant_records_hash(&sweep_tenant),
                    &sweep_controls,
                ) {
                    Ok(removed) => removed,
                    Err(error) => {
                        run.error = Some(error);
                        false
                    }
                }
            } else {
                false
            };
            let audit = retention_terminal_status(&run).map(|status| {
                mint_record_retention_receipt(
                    &receipt_state,
                    RETENTION_SCHEDULER_ACTOR,
                    run.summary.clone(),
                    &sweep_id,
                    status,
                    "scheduled",
                )
            });
            Ok((run, audit, empty_directory_removed))
        })
        .await;
        let (run, audit, empty_directory_removed) = match result {
            Ok(Ok(result)) => result,
            Ok(Err(RecordStoreError::RetentionCancelled)) => {
                report.cancelled = true;
                break;
            }
            Ok(Err(RecordStoreError::RetentionBudgetExhausted)) => {
                report.budget_exhausted = true;
                break;
            }
            Ok(Err(error)) => {
                report.tenants_failed = report.tenants_failed.saturating_add(1);
                tracing::error!(%tenant_hash, %error, "provenance retention tenant task failed closed");
                continue;
            }
            Err(error) => {
                report.tenants_failed = report.tenants_failed.saturating_add(1);
                tracing::error!(%tenant_hash, %error, "provenance retention tenant task failed");
                continue;
            }
        };
        report.bytes_examined = report.bytes_examined.saturating_add(run.bytes_examined);
        report.records_dropped = report.records_dropped.saturating_add(run.summary.records_dropped);
        if empty_directory_removed {
            report.empty_directories_removed = report.empty_directories_removed.saturating_add(1);
        }
        report.expired_records_held = report
            .expired_records_held
            .saturating_add(run.summary.expired_records_held);
        if audit.as_ref().is_some_and(|audit| audit.receipt_id.is_none()) {
            report.receipts_pending = report.receipts_pending.saturating_add(1);
        }
        match run.error {
            Some(RecordStoreError::RetentionCancelled) => {
                report.cancelled = true;
                break;
            }
            Some(RecordStoreError::RetentionBudgetExhausted) => {
                report.budget_exhausted = true;
                break;
            }
            Some(error) => {
                report.tenants_failed = report.tenants_failed.saturating_add(1);
                tracing::error!(%tenant_hash, %error, "provenance scheduled retention sweep failed closed");
            }
            None => report.tenants_swept = report.tenants_swept.saturating_add(1),
        }
    }
    report.cancelled |= cancellation.load(Ordering::Acquire);
    Ok(report)
}

pub(crate) fn spawn_provenance_retention_scheduler(
    enabled: bool,
    interval_secs: u64,
    max_tenants: usize,
    state: AppState,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !(60..=86_400).contains(&interval_secs) || !(1..=1_000).contains(&max_tenants) {
        if enabled {
            tracing::error!(
                interval_secs,
                max_tenants,
                "invalid provenance retention scheduler bounds; scheduler disabled"
            );
        }
        return None;
    }
    spawn_provenance_retention_scheduler_with_interval(
        enabled,
        Duration::from_secs(interval_secs),
        max_tenants,
        state,
        shutdown,
    )
}

#[cfg_attr(not(target_os = "linux"), allow(unreachable_code, unused_mut))]
fn spawn_provenance_retention_scheduler_with_interval(
    enabled: bool,
    interval: Duration,
    max_tenants: usize,
    state: AppState,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !enabled {
        return None;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (interval, max_tenants, state, shutdown);
        tracing::error!(
            "provenance retention scheduler requires descriptor-anchored Linux filesystem operations; scheduler disabled"
        );
        return None;
    }
    let retention_days = match provenance_retention_days_from_env() {
        Ok(Some(days)) => days,
        Ok(None) => {
            tracing::error!(
                "provenance retention scheduler enabled without an explicit retention-days policy; scheduler disabled"
            );
            return None;
        }
        Err(error) => {
            tracing::error!(%error, "invalid provenance retention scheduler policy; scheduler disabled");
            return None;
        }
    };
    if max_tenants == 0 || RecordReceiptVerifier::from_state(&state).is_err() {
        tracing::error!("invalid provenance retention scheduler bounds or passport verifier; scheduler disabled");
        return None;
    }
    tracing::info!(
        retention_days,
        interval_secs = interval.as_secs(),
        max_tenants,
        max_bytes_per_pass = RETENTION_SCHEDULER_MAX_BYTES_PER_PASS,
        max_pass_seconds = RETENTION_SCHEDULER_MAX_PASS_DURATION.as_secs(),
        "provenance retention scheduler armed; first pass deferred until the configured interval"
    );

    Some(tokio::spawn(async move {
        let mut interval = tokio::time::interval(interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        let mut cursor = 0usize;
        loop {
            tokio::select! {
                biased;
                _ = shutdown.recv() => break,
                _ = interval.tick() => {
                    let cancellation = Arc::new(AtomicBool::new(false));
                    let pass = run_scheduled_retention_once_with_cancel(
                        &state,
                        retention_days,
                        max_tenants,
                        chrono::Utc::now(),
                        &mut cursor,
                        cancellation.clone(),
                    );
                    tokio::pin!(pass);
                    tokio::select! {
                        biased;
                        _ = shutdown.recv() => {
                            cancellation.store(true, Ordering::Release);
                            log_scheduled_retention_result(pass.await);
                            break;
                        }
                        result = &mut pass => log_scheduled_retention_result(result),
                    }
                }
            }
        }
    }))
}

fn log_scheduled_retention_result(result: Result<ScheduledRetentionReport, RecordStoreError>) {
    match result {
        Ok(report) => {
            tracing::info!(
                tenants_discovered = report.tenants_discovered,
                tenants_selected = report.tenants_selected,
                tenants_swept = report.tenants_swept,
                tenants_failed = report.tenants_failed,
                records_dropped = report.records_dropped,
                expired_records_held = report.expired_records_held,
                receipts_pending = report.receipts_pending,
                cancelled = report.cancelled,
                budget_exhausted = report.budget_exhausted,
                bytes_examined = report.bytes_examined,
                "provenance scheduled retention pass completed"
            );
        }
        Err(error) => tracing::error!(%error, "provenance scheduled retention pass failed closed"),
    }
}

fn find_idempotent_record(
    jsonl_paths: &[PathBuf],
    idempotency: &RecordIdempotency,
) -> Result<Option<VerifyRecordResponse>, RecordStoreError> {
    use std::io::BufRead as _;

    let mut matched = None;
    for path in jsonl_paths {
        reject_symlink_or_non_file(path)?;
        let file = open_private_read_file(path)?;
        validate_and_harden_open_file(&file)?;
        for line in std::io::BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if u64::try_from(line.len()).unwrap_or(u64::MAX) > RECORD_MAX_LINE_BYTES {
                return Err(RecordStoreError::CorruptRecord);
            }
            let stored: serde_json::Value = serde_json::from_str(&line).map_err(|_| RecordStoreError::CorruptRecord)?;
            let Some(stored_key_hash) = stored.get("idempotency_key_hash") else {
                continue;
            };
            let Some(stored_key_hash) = stored_key_hash.as_str() else {
                return Err(RecordStoreError::CorruptRecord);
            };
            if stored_key_hash != idempotency.key_hash {
                continue;
            }
            if stored.get("request_hash").and_then(serde_json::Value::as_str) != Some(idempotency.request_hash.as_str())
            {
                return Err(RecordStoreError::IdempotencyConflict);
            }
            let response = verification_response_from_stored_line(&stored)?;
            if matched.as_ref().is_some_and(|existing| existing != &response) {
                return Err(RecordStoreError::CorruptRecord);
            }
            matched = Some(response);
        }
    }
    Ok(matched)
}

fn verification_response_from_stored_line(
    stored: &serde_json::Value,
) -> Result<VerifyRecordResponse, RecordStoreError> {
    serde_json::from_value(json!({
        "verification": stored.get("verification"),
        "record_id": stored.get("record_id"),
        "recorded_at": stored.get("recorded_at"),
        "receipt": stored.get("receipt"),
    }))
    .map_err(|_| RecordStoreError::CorruptRecord)
}

fn reject_symlink_or_non_file(path: &Path) -> Result<(), RecordStoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(RecordStoreError::UnsafePath),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn open_private_append_lock(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true);
    set_private_file_mode(&mut options);
    options.open(path)
}

fn open_private_existing_lock(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    set_private_file_mode(&mut options);
    options.open(path)
}

fn open_private_append_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    set_private_file_mode(&mut options);
    options.open(path)
}

fn open_private_new_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    set_private_file_mode(&mut options);
    options.open(path)
}

fn open_private_read_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    set_private_file_mode(&mut options);
    options.open(path)
}

fn validate_and_harden_open_file(file: &std::fs::File) -> Result<(), RecordStoreError> {
    RecordFileIdentity::from_metadata(&file.metadata()?)?;
    set_open_file_private(file)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_file_mode(options: &mut std::fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn set_private_file_mode(_options: &mut std::fs::OpenOptions) {}

#[cfg(unix)]
fn set_open_file_private(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_open_file_private(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn sync_directory_chain(start: &Path, stop: &Path) -> std::io::Result<()> {
    let mut current = Some(start);
    while let Some(path) = current {
        sync_directory(path)?;
        if path == stop {
            break;
        }
        current = path.parent();
    }
    Ok(())
}

// ── Axum handlers (flag → transport → auth/tenant → rate-limit → inner) ───

fn requested_tenant(headers: &HeaderMap, body_tenant: Option<&str>) -> Result<String, ProvErr> {
    let header_tenant = match headers.get("x-corecrux-tenant-id") {
        Some(value) => Some(
            value
                .to_str()
                .map_err(|_| ProvErr::new(StatusCode::BAD_REQUEST, "x-corecrux-tenant-id is not valid text"))?
                .trim(),
        )
        .filter(|value| !value.is_empty()),
        None => None,
    };
    let body_tenant = body_tenant.map(str::trim).filter(|value| !value.is_empty());

    if let (Some(header), Some(body)) = (header_tenant, body_tenant) {
        if header != body {
            return Err(ProvErr::new(
                StatusCode::BAD_REQUEST,
                "tenant_id does not match x-corecrux-tenant-id",
            ));
        }
    }

    header_tenant
        .or(body_tenant)
        .map(str::to_string)
        .ok_or_else(|| ProvErr::new(StatusCode::BAD_REQUEST, "tenant_id or x-corecrux-tenant-id is required"))
}

#[allow(clippy::result_large_err)]
fn stable_rate_principal(state: &AppState, headers: &HeaderMap) -> Result<String, Response> {
    let evidence = crate::auth::describe_http_evidence(&state.auth, headers).map_err(IntoResponse::into_response)?;
    if let Some(subject) = evidence.subject.filter(|subject| !subject.trim().is_empty()) {
        return Ok(format!("subject:{subject}"));
    }
    let scope_context = crate::auth::http_scope_context(&state.auth, headers).map_err(IntoResponse::into_response)?;
    if let Some(passport_id) = scope_context.passport_id.filter(|passport| !passport.trim().is_empty()) {
        return Ok(format!("passport:{passport_id}"));
    }
    if matches!(
        state.auth.mode(),
        crate::auth::AuthMode::JwtHs256 | crate::auth::AuthMode::JwtJwks
    ) {
        return Err(problem_response(
            StatusCode::UNAUTHORIZED,
            "provenance access token must include a stable sub or passport_id claim",
        ));
    }

    // Loopback-only dev scopes do not carry verified identity claims. Preserve
    // their existing per-credential isolation without weakening hosted JWT
    // posture; the digest never exposes the development credential itself.
    let credential = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            headers
                .get("x-corecrux-passport-id")
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or("authenticated-no-credential-id");
    let credential_hash = blake3::hash(credential.as_bytes()).to_hex();
    Ok(format!("dev-credential:{credential_hash}"))
}

#[allow(clippy::result_large_err)]
fn credential_rate_key(state: &AppState, headers: &HeaderMap, tenant: &str) -> Result<String, Response> {
    let principal = stable_rate_principal(state, headers)?;
    let mut material = Vec::with_capacity(tenant.len() + principal.len() + 32);
    material.extend_from_slice(b"cuecrux.provenance.rate-key.v1\0");
    material.extend_from_slice(tenant.as_bytes());
    material.push(0);
    material.extend_from_slice(principal.as_bytes());
    Ok(blake3::hash(&material).to_hex().to_string())
}

fn rate_limited_response() -> Response {
    let mut response = problem_response(
        StatusCode::TOO_MANY_REQUESTS,
        "per-principal provenance rate limit exceeded; retry after the current window",
    );
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_static("60"),
    );
    response
}

fn record_idempotency(
    headers: &HeaderMap,
    tenant: &str,
    req: &VerifyRequest,
) -> Result<Option<RecordIdempotency>, ProvErr> {
    let mut values = headers.get_all("idempotency-key").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ProvErr::new(
            StatusCode::BAD_REQUEST,
            "exactly one Idempotency-Key header is allowed",
        ));
    }
    let key = value.to_str().map_err(|_| {
        ProvErr::new(
            StatusCode::BAD_REQUEST,
            "Idempotency-Key must contain visible ASCII characters",
        )
    })?;
    if key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ProvErr::new(
            StatusCode::BAD_REQUEST,
            "Idempotency-Key must be 1-128 characters from [A-Za-z0-9._:-]",
        ));
    }
    Ok(Some(RecordIdempotency::from_request(tenant, key, req)))
}

fn not_enabled() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        format!("provenance API disabled (set {FEATURE_ENV}=1)"),
    )
}

fn blocking_task_failed(operation: &'static str, err: tokio::task::JoinError) -> Response {
    tracing::error!(operation, error = %err, "provenance blocking task failed");
    problem_response(StatusCode::INTERNAL_SERVER_ERROR, "internal provenance worker failure")
}

#[allow(clippy::result_large_err)]
fn retention_actor(state: &AppState, headers: &HeaderMap) -> Result<String, Response> {
    let scope_context = crate::auth::http_scope_context(&state.auth, headers).map_err(IntoResponse::into_response)?;
    if let Some(passport_id) = scope_context.passport_id {
        return Ok(passport_id);
    }
    let evidence = crate::auth::describe_http_evidence(&state.auth, headers).map_err(IntoResponse::into_response)?;
    Ok(evidence
        .subject
        .unwrap_or_else(|| format!("authenticated:{}", state.auth.mode().as_str())))
}

fn mint_record_retention_receipt(
    state: &AppState,
    actor: &str,
    summary: RecordRetentionSweepSummary,
    sweep_id: &str,
    status: &'static str,
    trigger: &'static str,
) -> RetentionAudit {
    let payload = build_record_retention_receipt(&summary, sweep_id, status, trigger);
    let receipt_id = super::observations::mint_governance_receipt(
        state,
        "__governance__::retention",
        actor,
        "retention.provenance_records",
        &payload,
    );
    RetentionAudit { summary, receipt_id }
}

fn mint_record_retention_intent_controlled(
    state: &AppState,
    actor: &str,
    summary: RecordRetentionSweepSummary,
    sweep_id: &str,
    trigger: &'static str,
    controls: &RetentionSweepControls,
) -> Result<RetentionAudit, RecordStoreError> {
    let payload = build_record_retention_receipt(&summary, sweep_id, "planned", trigger);
    match super::observations::mint_governance_receipt_controlled(
        state,
        "__governance__::retention",
        actor,
        "retention.provenance_records",
        &payload,
        || controls.check().is_ok(),
    ) {
        super::observations::ControlledGovernanceReceiptMint::Recorded(receipt_id) => Ok(RetentionAudit {
            summary,
            receipt_id: Some(receipt_id),
        }),
        super::observations::ControlledGovernanceReceiptMint::Pending => Ok(RetentionAudit {
            summary,
            receipt_id: None,
        }),
        super::observations::ControlledGovernanceReceiptMint::Interrupted => match controls.check() {
            Err(error) => Err(error),
            Ok(()) => Err(RecordStoreError::RetentionCancelled),
        },
    }
}

fn new_retention_sweep_id() -> String {
    format!("prov_ret_{}", uuid::Uuid::new_v4())
}

fn build_record_retention_receipt<'a>(
    summary: &'a RecordRetentionSweepSummary,
    sweep_id: &'a str,
    status: &'a str,
    trigger: &'a str,
) -> RecordRetentionReceiptV1<'a> {
    RecordRetentionReceiptV1 {
        schema: "cuecrux.provenance.record_retention.v1",
        op: "provenance_record_retention",
        reason_code: "configured_retention_window",
        sweep_id,
        tenant_hash: &summary.tenant_hash,
        retention_days: summary.retention_days,
        cutoff: &summary.cutoff,
        records_dropped: summary.records_dropped,
        expired_records_held: summary.expired_records_held,
        files_rewritten: summary.files_rewritten,
        files_removed: summary.files_removed,
        status,
        trigger,
        recorded_at: chrono::Utc::now().to_rfc3339(),
    }
}

fn attach_retention_audit_headers(mut response: Response, audit: Option<&RetentionAudit>) -> Response {
    let Some(audit) = audit else {
        return response;
    };
    let status = if audit.receipt_id.is_some() {
        "recorded"
    } else {
        "pending"
    };
    response.headers_mut().insert(
        axum::http::HeaderName::from_static("x-cuecrux-retention-receipt-status"),
        axum::http::HeaderValue::from_static(status),
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&audit.summary.records_dropped.to_string()) {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static("x-cuecrux-retention-records-dropped"),
            value,
        );
    }
    if let Some(receipt_id) = audit.receipt_id.as_deref() {
        if let Ok(value) = axum::http::HeaderValue::from_str(receipt_id) {
            response.headers_mut().insert(
                axum::http::HeaderName::from_static("x-cuecrux-retention-receipt-id"),
                value,
            );
        }
    }
    response
}

/// Any-of scopes accepted across the whole provenance surface. Kept in sync
/// with the `route_auth::classify_route` contract for `/v1/provenance`.
const PROVENANCE_SCOPES: &[&str] = &["provenance:write", "admin:write"];

/// Common pre-handler gate. The selected tenant is accepted only when the
/// verified token's `tenant_id`/`tenants` claim authorizes it (admin scope is
/// the explicit bypass). The returned tenant is therefore safe to use for
/// persistence and metering; the body/header value alone never grants access.
#[allow(clippy::result_large_err)]
fn guard(state: &AppState, headers: &HeaderMap, body_tenant: Option<&str>) -> Result<String, Response> {
    if !provenance_api_enabled() {
        return Err(not_enabled());
    }
    if !transport_posture_allowed(
        state.auth.mode(),
        state.http_bind_loopback,
        env_truthy(TLS_TERMINATED_ENV),
    ) {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "provenance API requires non-off auth and a safe transport posture",
        ));
    }
    let tenant = requested_tenant(headers, body_tenant).map_err(IntoResponse::into_response)?;
    if let Err(problem) = require_http_any_scope_for_tenant(&state.auth, headers, PROVENANCE_SCOPES, &tenant) {
        return Err(problem.into_response());
    }
    let rate_key = credential_rate_key(state, headers, &tenant)?;
    if !rate_limit_ok(&rate_key) {
        return Err(rate_limited_response());
    }
    Ok(tenant)
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_provenance_sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SignRequest>,
) -> Response {
    let tenant = match guard(&state, &headers, body.tenant_id.as_deref()) {
        Ok(tenant) => tenant,
        Err(resp) => return resp,
    };
    match tokio::task::spawn_blocking(move || do_sign(&NoopMeter, &tenant, &body)).await {
        Ok(Ok(resp)) => (StatusCode::CREATED, Json(resp)).into_response(),
        Ok(Err(err)) => err.into_response(),
        Err(err) => blocking_task_failed("sign", err),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_provenance_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> Response {
    let tenant = match guard(&state, &headers, body.tenant_id.as_deref()) {
        Ok(tenant) => tenant,
        Err(resp) => return resp,
    };
    let trust_policy = match ProvenanceTrustPolicy::from_env() {
        Ok(policy) => policy,
        Err(error) => {
            tracing::error!(%error, "invalid provenance exact-leaf trust list");
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid provenance trust configuration",
            );
        }
    };
    match tokio::task::spawn_blocking(move || do_verify_with_trust(&NoopMeter, &tenant, &body, &trust_policy)).await {
        Ok(Ok(resp)) => (StatusCode::OK, Json(resp)).into_response(),
        Ok(Err(err)) => err.into_response(),
        Err(err) => blocking_task_failed("verify", err),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_provenance_verify_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> Response {
    let tenant = match guard(&state, &headers, body.tenant_id.as_deref()) {
        Ok(tenant) => tenant,
        Err(resp) => return resp,
    };
    let idempotency = match record_idempotency(&headers, &tenant, &body) {
        Ok(idempotency) => idempotency,
        Err(err) => return err.into_response(),
    };
    let trust_policy = match ProvenanceTrustPolicy::from_env() {
        Ok(policy) => policy,
        Err(error) => {
            tracing::error!(%error, "invalid provenance exact-leaf trust list");
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid provenance trust configuration",
            );
        }
    };
    let retention_days = match provenance_retention_days_from_env() {
        Ok(days) => days,
        Err(error) => {
            tracing::error!(%error, "invalid provenance record-retention policy");
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid provenance retention configuration",
            );
        }
    };
    let mut retention_audit = None;
    let retention_receipt_actor = match retention_days {
        Some(_) => match retention_actor(&state, &headers) {
            Ok(actor) => Some(actor),
            Err(response) => return response,
        },
        None => None,
    };
    let retention_verifier = match retention_days {
        Some(_) => match RecordReceiptVerifier::from_state(&state) {
            Ok(verifier) => Some(verifier),
            Err(error) => {
                tracing::error!(%error, "invalid provenance record-retention verifier");
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid provenance retention verifier",
                );
            }
        },
        None => None,
    };
    if let Some(retention_days) = retention_days.filter(|_| retention_sweep_due(&tenant, Instant::now())) {
        // Resolve a durable actor before reserving the cadence slot or doing
        // destructive lifecycle work. The legal-hold read lock remains held
        // through the sweep so a hold cannot be placed concurrently between
        // the check and file replacement.
        let actor = match retention_receipt_actor {
            Some(actor) => actor,
            None => {
                tracing::error!("provenance retention cadence reserved without a receipt actor");
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "verification-record retention sweep failed",
                );
            }
        };
        let fact_store = state.fact_store.clone();
        let receipt_state = state.clone();
        let sweep_data_dir = state.data_dir.clone();
        let sweep_tenant = tenant.clone();
        let sweep_verifier = match retention_verifier {
            Some(verifier) => verifier,
            None => {
                tracing::error!("provenance retention cadence reserved without a record verifier");
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "verification-record retention sweep failed",
                );
            }
        };
        let sweep = tokio::task::spawn_blocking(move || {
            let sweep_id = new_retention_sweep_id();
            let mut run = with_active_tenant_legal_holds(&fact_store, &sweep_tenant, |legal_holds| {
                sweep_expired_verification_records_with_audit_intent(
                    &sweep_data_dir,
                    &sweep_tenant,
                    retention_days,
                    chrono::Utc::now(),
                    legal_holds,
                    &sweep_verifier,
                    |planned| {
                        let intent = mint_record_retention_receipt(
                            &receipt_state,
                            &actor,
                            planned.clone(),
                            &sweep_id,
                            "planned",
                            "request",
                        );
                        intent
                            .receipt_id
                            .map(|_| ())
                            .ok_or(RecordStoreError::RetentionAuditUnavailable)
                    },
                )
            });
            if run.error.is_none() {
                if let Err(error) = cleanup_empty_tenant_directory(&sweep_data_dir, &tenant_records_hash(&sweep_tenant))
                {
                    run.error = Some(error);
                }
            }
            let audit = retention_terminal_status(&run).map(|status| {
                mint_record_retention_receipt(
                    &receipt_state,
                    &actor,
                    run.summary.clone(),
                    &sweep_id,
                    status,
                    "request",
                )
            });
            (run, audit)
        })
        .await;
        let (sweep, audit) = match sweep {
            Ok(result) => result,
            Err(error) => return blocking_task_failed("verify-record-retention", error),
        };
        retention_audit = audit;
        if sweep.summary.expired_records_held > 0 {
            tracing::info!(
                tenant_hash = %sweep.summary.tenant_hash,
                expired_records_held = sweep.summary.expired_records_held,
                "provenance retention preserved records covered by active legal holds"
            );
        }
        if let Some(error) = sweep.error {
            tracing::error!(%error, "provenance record-retention sweep failed");
            let response = problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "verification-record retention sweep failed",
            );
            return attach_retention_audit_headers(response, retention_audit.as_ref());
        }
    }
    let passport_key_path = state.passport_key_path.clone();
    let passport_fpr = state.passport_fpr.clone();
    let data_dir = state.data_dir.clone();
    let response = match tokio::task::spawn_blocking(move || {
        do_verify_record(
            &NoopMeter,
            &body,
            VerifyRecordContext {
                tenant: &tenant,
                idempotency: idempotency.as_ref(),
                trust_policy: &trust_policy,
                passport_key_path: &passport_key_path,
                passport_fpr: &passport_fpr,
                data_dir: &data_dir,
            },
        )
    })
    .await
    {
        Ok(Ok(VerifyRecordOutcome::Created(resp))) => (StatusCode::CREATED, Json(resp)).into_response(),
        Ok(Ok(VerifyRecordOutcome::Replayed(resp))) => (StatusCode::OK, Json(resp)).into_response(),
        Ok(Err(err)) => err.into_response(),
        Err(err) => blocking_task_failed("verify-record", err),
    };
    attach_retention_audit_headers(response, retention_audit.as_ref())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── Test fixtures ──────────────────────────────────────────────────────

    /// Self-signed P-256 leaf + PKCS#8 private key PEM (customer BYOK stand-in).
    fn byok_material() -> (String, String) {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
        let mut params = CertificateParams::new(vec!["byok.test".to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "provenance byok TEST");
        let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        (kp.serialize_pem(), cert.pem())
    }

    fn expired_byok_material() -> (String, String) {
        use rcgen::{date_time_ymd, CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
        let mut params = CertificateParams::new(vec!["expired-byok.test".to_string()]).unwrap();
        params.not_before = date_time_ymd(2019, 1, 1);
        params.not_after = date_time_ymd(2020, 1, 1);
        let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        (kp.serialize_pem(), cert.pem())
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// Meter double that records every op it is handed.
    #[derive(Default)]
    struct RecordingMeter {
        calls: Mutex<Vec<(String, String)>>,
    }
    impl ProvenanceMeter for RecordingMeter {
        fn on_op(&self, op: ProvenanceOp, tenant: &str) {
            self.calls
                .lock()
                .unwrap()
                .push((op.op_code().to_string(), tenant.to_string()));
        }
    }

    fn sign_req(content: &[u8], content_type: Option<&str>) -> SignRequest {
        let (key_pem, cert_pem) = byok_material();
        SignRequest {
            content_b64: b64(content),
            content_type: content_type.map(str::to_string),
            signing_key_pem: key_pem.into(),
            cert_chain_pem: cert_pem,
            manifest: ManifestParams::default(),
            tenant_id: Some("tenant-a".to_string()),
            key_id: Some("leaf-1".to_string()),
        }
    }

    // ── op-code + rate table ───────────────────────────────────────────────

    #[test]
    fn op_codes_and_rates_are_pinned() {
        assert_eq!(ProvenanceOp::Sign.op_code(), "provenance.sign");
        assert_eq!(ProvenanceOp::Verify.op_code(), "provenance.verify");
        assert_eq!(ProvenanceOp::VerifyRecord.op_code(), "provenance.verify_record");
        assert_eq!(ProvenanceOp::Sign.milli_credits(), 20_000); // 20 Cr
        assert_eq!(ProvenanceOp::Verify.milli_credits(), 250); // 0.25 Cr
        assert_eq!(ProvenanceOp::VerifyRecord.milli_credits(), 1_000); // 1 Cr
    }

    #[test]
    #[serial_test::serial]
    fn flag_defaults_off() {
        std::env::remove_var(FEATURE_ENV);
        assert!(!provenance_api_enabled());
    }

    #[test]
    fn transport_posture_requires_real_auth_and_tls_off_loopback() {
        use crate::auth::AuthMode;

        assert!(!transport_posture_allowed(AuthMode::Off, true, false));
        assert!(transport_posture_allowed(AuthMode::DevScopes, true, false));
        assert!(!transport_posture_allowed(AuthMode::DevScopes, false, true));
        assert!(!transport_posture_allowed(AuthMode::JwtHs256, false, false));
        assert!(transport_posture_allowed(AuthMode::JwtHs256, false, true));
        assert!(transport_posture_allowed(AuthMode::JwtJwks, false, true));
    }

    #[test]
    fn private_key_field_deserializes_into_zeroizing_wrapper() {
        let req: SignRequest = serde_json::from_value(json!({
            "content_b64": b64(b"asset"),
            "signing_key_pem": "test-secret-key",
            "cert_chain_pem": "test-cert"
        }))
        .unwrap();
        assert_eq!(req.signing_key_pem.expose(), "test-secret-key");
    }

    // ── sign → verify round trip (HTTP glue level) ─────────────────────────

    #[test]
    fn sign_then_verify_round_trip_and_meters_both_ops() {
        let content = b"hello-provenance";
        let meter = RecordingMeter::default();
        let signed = do_sign(&meter, "tenant-a", &sign_req(content, Some("image/png"))).unwrap();
        assert_eq!(signed.signature_alg, "es256");

        let verify = do_verify(
            &meter,
            "tenant-a",
            &VerifyRequest {
                manifest_envelope_b64: Some(signed.manifest_envelope_b64.clone()),
                content_b64: Some(b64(content)),
                tenant_id: None,
            },
        )
        .unwrap();
        assert!(verify.present);
        assert_eq!(verify.signature_alg.as_deref(), Some("es256"));
        assert_eq!(verify.signature_valid, Some(true));
        assert!(verify.integrity_valid);
        assert!(verify.asset_binding_checked);
        assert_eq!(verify.content_hash_match, Some(true));
        assert!(verify.ok);
        // Honesty: internal consistency is NOT trust.
        assert_eq!(verify.trust_status, "untrusted_presented_leaf");
        assert!(verify.signer_leaf_sha256.is_some());
        assert!(!verify.chain_validated);
        assert!(!verify.identity_trusted);
        // Manifest values are surfaced as UNVERIFIED claims.
        assert!(verify.manifest_claims.is_some());

        let calls = meter.calls.lock().unwrap();
        assert_eq!(calls[0], ("provenance.sign".to_string(), "tenant-a".to_string()));
        assert_eq!(calls[1], ("provenance.verify".to_string(), "tenant-a".to_string()));
    }

    #[test]
    fn exact_leaf_allowlist_requires_current_cert_and_valid_envelope_integrity() {
        let content = b"trusted-leaf-content";
        let meter = RecordingMeter::default();
        let signed = do_sign(&meter, "tenant-trust", &sign_req(content, Some("image/png"))).unwrap();
        let parsed = parse_jumbf_base64(&signed.manifest_envelope_b64).unwrap();
        let leaf = inspect_c2pa_leaf_certificate_v1(&parsed).unwrap();
        let colon_fingerprint = leaf
            .sha256_hex
            .as_bytes()
            .chunks(2)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        let policy = ProvenanceTrustPolicy::parse(Some(&format!("SHA256:{colon_fingerprint}")), None).unwrap();
        let request = VerifyRequest {
            manifest_envelope_b64: Some(signed.manifest_envelope_b64),
            content_b64: Some(b64(content)),
            tenant_id: None,
        };

        let verified = do_verify_with_trust(&meter, "tenant-trust", &request, &policy).unwrap();

        assert!(verified.ok);
        assert!(verified.identity_trusted);
        assert!(!verified.chain_validated);
        assert_eq!(verified.trust_status, "trusted_leaf_allowlist");
        assert_eq!(verified.signer_leaf_sha256.as_deref(), Some(leaf.sha256_hex.as_str()));

        let (key_pem, cert_pem) = expired_byok_material();
        let expired_request = SignRequest {
            content_b64: b64(content),
            content_type: Some("image/png".to_string()),
            signing_key_pem: key_pem.into(),
            cert_chain_pem: cert_pem,
            manifest: ManifestParams::default(),
            tenant_id: None,
            key_id: Some("expired-leaf".to_string()),
        };
        let expired_signed = do_sign(&meter, "tenant-trust", &expired_request).unwrap();
        let expired_parsed = parse_jumbf_base64(&expired_signed.manifest_envelope_b64).unwrap();
        let expired_leaf = inspect_c2pa_leaf_certificate_v1(&expired_parsed).unwrap();
        let expired_policy = ProvenanceTrustPolicy {
            trusted_leaf_sha256: HashSet::from([expired_leaf.sha256_hex]),
            trusted_root_sha256: HashSet::new(),
        };
        let expired_verified = do_verify_with_trust(
            &meter,
            "tenant-trust",
            &VerifyRequest {
                manifest_envelope_b64: Some(expired_signed.manifest_envelope_b64),
                content_b64: Some(b64(content)),
                tenant_id: None,
            },
            &expired_policy,
        )
        .unwrap();
        assert!(expired_verified.integrity_valid);
        assert!(!expired_verified.identity_trusted);
        assert_eq!(expired_verified.trust_status, "expired_pinned_leaf");
    }

    #[test]
    fn exact_leaf_allowlist_parser_is_bounded_and_fail_closed() {
        assert_eq!(
            ProvenanceTrustPolicy::parse(None, None).unwrap(),
            ProvenanceTrustPolicy::default()
        );
        assert_eq!(
            ProvenanceTrustPolicy::parse(Some("not-a-fingerprint"), None).unwrap_err(),
            format!("{TRUSTED_LEAF_SHA256_ENV} entries must be 64-hex SHA-256 fingerprints")
        );
        let too_many = (0..=MAX_TRUSTED_LEAF_PINS)
            .map(|index| format!("{index:064x}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            ProvenanceTrustPolicy::parse(Some(&too_many), None).unwrap_err(),
            format!("{TRUSTED_LEAF_SHA256_ENV} exceeds the {MAX_TRUSTED_LEAF_PINS}-pin limit")
        );
        let duplicate_overflow = std::iter::repeat_n("0".repeat(64), MAX_TRUSTED_LEAF_PINS + 1)
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            ProvenanceTrustPolicy::parse(Some(&duplicate_overflow), None).unwrap_err(),
            format!("{TRUSTED_LEAF_SHA256_ENV} exceeds the {MAX_TRUSTED_LEAF_PINS}-pin limit")
        );
    }

    // ── CA-chain trust mode (operator-pinned roots; M9 CA-chain) ───────────

    /// Test CA that mirrors the Vault role's strict C2PA profile: a
    /// self-signed root (CA=true, keyCertSign) issuing leaves with
    /// CA=false + digitalSignature + the CueCrux emailProtection EKU.
    struct ChainTestPki {
        root_issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
        root_pem: String,
        root_sha256_hex: String,
    }

    impl ChainTestPki {
        fn new(common_name: &str) -> Self {
            Self::with_validity(common_name, None)
        }

        /// `validity` = optional `(not_before_year, not_after_year)`.
        fn with_validity(common_name: &str, validity: Option<(i32, i32)>) -> Self {
            use rcgen::{date_time_ymd, CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
            use sha2::{Digest as _, Sha256};
            let mut params = CertificateParams::new(vec![common_name.to_string()]).unwrap();
            params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
            if let Some((not_before_year, not_after_year)) = validity {
                params.not_before = date_time_ymd(not_before_year, 1, 1);
                params.not_after = date_time_ymd(not_after_year, 1, 1);
            }
            let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = params.self_signed(&kp).unwrap();
            let root_pem = cert.pem();
            let root_sha256_hex = hex::encode(Sha256::digest(cert.der()));
            let root_issuer = rcgen::Issuer::new(params, kp);
            Self {
                root_issuer,
                root_pem,
                root_sha256_hex,
            }
        }

        /// Issue a currently-valid C2PA-profile leaf. Returns
        /// `(leaf_key_pem, leaf_cert_pem)`.
        fn issue_leaf(&self, common_name: &str) -> (String, String) {
            use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
            let mut params = CertificateParams::new(vec![common_name.to_string()]).unwrap();
            params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
            params.is_ca = rcgen::IsCa::ExplicitNoCa;
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::EmailProtection];
            let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = params.signed_by(&kp, &self.root_issuer).unwrap();
            (kp.serialize_pem(), cert.pem())
        }
    }

    fn chain_signed_envelope(pki: &ChainTestPki, content: &[u8]) -> String {
        let (leaf_key_pem, leaf_cert_pem) = pki.issue_leaf("chain leaf TEST");
        let req = SignRequest {
            content_b64: b64(content),
            content_type: Some("image/png".to_string()),
            signing_key_pem: leaf_key_pem.into(),
            cert_chain_pem: format!("{leaf_cert_pem}{}", pki.root_pem),
            manifest: ManifestParams::default(),
            tenant_id: None,
            key_id: Some("chain-leaf".to_string()),
        };
        do_sign(&RecordingMeter::default(), "tenant-chain", &req)
            .unwrap()
            .manifest_envelope_b64
    }

    fn root_pinned_policy(root_sha256_hex: &str) -> ProvenanceTrustPolicy {
        ProvenanceTrustPolicy::parse(None, Some(root_sha256_hex)).unwrap()
    }

    fn verify_with_policy(envelope_b64: String, content: &[u8], policy: &ProvenanceTrustPolicy) -> VerifyResponse {
        do_verify_with_trust(
            &RecordingMeter::default(),
            "tenant-chain",
            &VerifyRequest {
                manifest_envelope_b64: Some(envelope_b64),
                content_b64: Some(b64(content)),
                tenant_id: None,
            },
            policy,
        )
        .unwrap()
    }

    #[test]
    fn pinned_root_valid_chain_grants_chain_validated_identity_trust() {
        let content = b"chain-trusted-content";
        let pki = ChainTestPki::new("CueCrux Chain Root TEST");
        let envelope = chain_signed_envelope(&pki, content);
        let verified = verify_with_policy(envelope, content, &root_pinned_policy(&pki.root_sha256_hex));

        assert!(verified.ok);
        assert!(verified.integrity_valid);
        assert!(verified.chain_validated, "notes: {:?}", verified.notes);
        assert!(verified.identity_trusted);
        assert_eq!(verified.trust_status, "trusted_root_chain");
        assert_eq!(
            verified.chain_root_sha256.as_deref(),
            Some(pki.root_sha256_hex.as_str())
        );
        // Chain trust must not depend on any leaf pin.
        assert!(!verified.notes.iter().any(|note| note.contains("did not grant trust")));
    }

    #[test]
    fn chain_mode_off_keeps_prior_behaviour_for_chain_signed_envelopes() {
        let content = b"chain-mode-off";
        let pki = ChainTestPki::new("CueCrux Chain Root TEST");
        let envelope = chain_signed_envelope(&pki, content);
        let verified = verify_with_policy(envelope, content, &ProvenanceTrustPolicy::default());

        assert!(verified.ok, "integrity + binding stay independent of trust");
        assert!(!verified.chain_validated);
        assert!(!verified.identity_trusted);
        assert_eq!(verified.trust_status, "untrusted_presented_leaf");
        assert_eq!(verified.chain_root_sha256, None, "no audit field while the mode is off");
    }

    #[test]
    fn wrong_key_same_dn_root_fails_closed() {
        let content = b"decoy-root-content";
        let genuine = ChainTestPki::new("CueCrux Chain Root TEST");
        let decoy = ChainTestPki::new("CueCrux Chain Root TEST");

        // Leaf issued by the DECOY, presented with the GENUINE root cert:
        // names link (same DN) but the link signature cannot verify.
        let (leaf_key_pem, leaf_cert_pem) = decoy.issue_leaf("chain leaf TEST");
        let req = SignRequest {
            content_b64: b64(content),
            content_type: Some("image/png".to_string()),
            signing_key_pem: leaf_key_pem.into(),
            cert_chain_pem: format!("{leaf_cert_pem}{}", genuine.root_pem),
            manifest: ManifestParams::default(),
            tenant_id: None,
            key_id: Some("decoy-leaf".to_string()),
        };
        let envelope = do_sign(&RecordingMeter::default(), "tenant-chain", &req)
            .unwrap()
            .manifest_envelope_b64;
        let verified = verify_with_policy(envelope, content, &root_pinned_policy(&genuine.root_sha256_hex));
        assert!(verified.integrity_valid, "the envelope stays self-consistent");
        assert!(!verified.chain_validated);
        assert!(!verified.identity_trusted);
        assert_eq!(verified.trust_status, "untrusted_presented_leaf");
        assert!(
            verified
                .notes
                .iter()
                .any(|note| note.contains("signature verification failed")),
            "unexpected notes: {:?}",
            verified.notes
        );

        // Decoy root presented outright: its fingerprint is not pinned.
        let envelope = chain_signed_envelope(&decoy, content);
        let verified = verify_with_policy(envelope, content, &root_pinned_policy(&genuine.root_sha256_hex));
        assert!(!verified.chain_validated);
        assert!(!verified.identity_trusted);
        assert_eq!(
            verified.chain_root_sha256.as_deref(),
            Some(decoy.root_sha256_hex.as_str()),
            "audit field must expose the presented terminal certificate"
        );
        assert!(
            verified
                .notes
                .iter()
                .any(|note| note.contains("not an operator-pinned root")),
            "unexpected notes: {:?}",
            verified.notes
        );
    }

    #[test]
    fn missing_root_in_presented_chain_fails_closed() {
        let content = b"leaf-only-content";
        let pki = ChainTestPki::new("CueCrux Chain Root TEST");
        let (leaf_key_pem, leaf_cert_pem) = pki.issue_leaf("chain leaf TEST");
        let req = SignRequest {
            content_b64: b64(content),
            content_type: Some("image/png".to_string()),
            signing_key_pem: leaf_key_pem.into(),
            cert_chain_pem: leaf_cert_pem,
            manifest: ManifestParams::default(),
            tenant_id: None,
            key_id: Some("rootless-leaf".to_string()),
        };
        let envelope = do_sign(&RecordingMeter::default(), "tenant-chain", &req)
            .unwrap()
            .manifest_envelope_b64;
        let verified = verify_with_policy(envelope, content, &root_pinned_policy(&pki.root_sha256_hex));
        assert!(!verified.chain_validated);
        assert!(!verified.identity_trusted);
        assert_eq!(verified.chain_root_sha256, None);
        assert!(
            verified.notes.iter().any(|note| note.contains("carries no CA chain")),
            "unexpected notes: {:?}",
            verified.notes
        );
    }

    #[test]
    fn expired_link_fails_closed_even_when_root_is_pinned() {
        let content = b"expired-root-content";
        let pki = ChainTestPki::with_validity("CueCrux Chain Root TEST", Some((2019, 2020)));
        let envelope = chain_signed_envelope(&pki, content);
        let verified = verify_with_policy(envelope, content, &root_pinned_policy(&pki.root_sha256_hex));
        assert!(verified.integrity_valid);
        assert!(!verified.chain_validated);
        assert!(!verified.identity_trusted);
        assert!(
            verified.notes.iter().any(|note| note.contains("not currently valid")),
            "unexpected notes: {:?}",
            verified.notes
        );
    }

    #[test]
    fn root_pin_parser_is_bounded_and_fail_closed() {
        assert!(
            !ProvenanceTrustPolicy::parse(None, None).unwrap().chain_trust_enabled(),
            "unset roots keep the CA-chain mode off"
        );
        // Prefixed/colon-separated fingerprints normalize like leaf pins.
        let normalized = ProvenanceTrustPolicy::parse(None, Some(&format!("SHA256:{}AB", "AB:".repeat(31)))).unwrap();
        assert!(normalized.chain_trust_enabled());
        assert!(normalized.trusts_root(&"ab".repeat(32)));
        assert_eq!(
            ProvenanceTrustPolicy::parse(None, Some("not-a-fingerprint")).unwrap_err(),
            format!("{TRUSTED_ROOT_SHA256_ENV} entries must be 64-hex SHA-256 fingerprints")
        );
        let too_many = (0..=MAX_TRUSTED_ROOT_PINS)
            .map(|index| format!("{index:064x}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            ProvenanceTrustPolicy::parse(None, Some(&too_many)).unwrap_err(),
            format!("{TRUSTED_ROOT_SHA256_ENV} exceeds the {MAX_TRUSTED_ROOT_PINS}-pin limit")
        );
    }

    #[test]
    fn retained_pre_chain_mode_records_stay_readable() {
        // A record persisted before the CA-chain mode existed (and before the
        // M9e signer_leaf_sha256 field) must still deserialize: the additive
        // fields carry serde defaults, exactly like signer_leaf_sha256 did.
        let legacy_verification = json!({
            "present": true,
            "signature_alg": "es256",
            "canonical_hash_match": true,
            "signature_valid": true,
            "integrity_valid": true,
            "asset_binding_checked": true,
            "content_hash_match": true,
            "trust_status": "untrusted_presented_leaf",
            "chain_validated": false,
            "identity_trusted": false,
            "ok": true,
            "manifest_claims": null,
            "notes": []
        });
        let parsed: VerifyResponse = serde_json::from_value(legacy_verification.clone()).unwrap();
        assert_eq!(parsed.signer_leaf_sha256, None);
        assert_eq!(parsed.chain_root_sha256, None);
        assert!(!parsed.chain_validated);

        let stored_line = json!({
            "record_id": "legacy-1",
            "recorded_at": "2026-07-21T00:00:00Z",
            "verification": legacy_verification,
            "receipt": {
                "alg": "ed25519",
                "signed_by": "fpr",
                "body_hash": "blake3:00",
                "signature": "00"
            }
        });
        let replayed = verification_response_from_stored_line(&stored_line).unwrap();
        assert_eq!(replayed.record_id, "legacy-1");
        assert_eq!(replayed.verification.chain_root_sha256, None);
    }

    #[test]
    fn verify_of_valid_envelope_without_asset_is_not_ok() {
        // #1/#2: a valid envelope for ANY asset must NOT yield ok:true when no
        // asset bytes are supplied — integrity ≠ overall success.
        let content = b"bound-asset";
        let meter = RecordingMeter::default();
        let signed = do_sign(&meter, "t", &sign_req(content, None)).unwrap();
        let resp = do_verify(
            &meter,
            "t",
            &VerifyRequest {
                manifest_envelope_b64: Some(signed.manifest_envelope_b64),
                content_b64: None,
                tenant_id: None,
            },
        )
        .unwrap();
        assert!(resp.integrity_valid, "envelope is internally consistent");
        assert!(!resp.asset_binding_checked, "no asset supplied");
        assert_eq!(resp.content_hash_match, None);
        assert!(!resp.ok, "must NOT be ok without a checked+matching asset binding");
    }

    #[test]
    fn verify_of_unsigned_asset_reports_not_present() {
        let meter = RecordingMeter::default();
        let resp = do_verify(
            &meter,
            "t",
            &VerifyRequest {
                manifest_envelope_b64: None,
                content_b64: Some(b64(b"just some bytes")),
                tenant_id: None,
            },
        )
        .unwrap();
        assert!(!resp.present);
        assert!(!resp.ok);
        assert!(resp.notes.iter().any(|n| n.contains("unsigned")));
        // Metering still fires for a verify call (compute was spent).
        assert_eq!(meter.calls.lock().unwrap()[0].0, "provenance.verify");
    }

    #[test]
    fn verify_of_tampered_content_fails_binding() {
        let content = b"original-asset";
        let meter = RecordingMeter::default();
        let signed = do_sign(&meter, "t", &sign_req(content, None)).unwrap();
        let resp = do_verify(
            &meter,
            "t",
            &VerifyRequest {
                manifest_envelope_b64: Some(signed.manifest_envelope_b64),
                content_b64: Some(b64(b"TAMPERED-asset")),
                tenant_id: None,
            },
        )
        .unwrap();
        assert_eq!(resp.signature_valid, Some(true), "manifest signature stays valid");
        assert_eq!(resp.content_hash_match, Some(false), "tampered content must not bind");
        assert!(!resp.ok);
    }

    #[test]
    fn sign_rejects_disallowed_content_type_before_parsing_key() {
        let meter = RecordingMeter::default();
        // Garbage key material, but content-type check must fire first.
        let req = SignRequest {
            content_b64: b64(b"x"),
            content_type: Some("application/x-evil".to_string()),
            signing_key_pem: "garbage".to_string().into(),
            cert_chain_pem: "garbage".to_string(),
            manifest: ManifestParams::default(),
            tenant_id: None,
            key_id: None,
        };
        let err = do_sign(&meter, "t", &req).unwrap_err();
        assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        // No metering on a rejected op.
        assert!(meter.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn sign_rejects_bad_base64_content() {
        let meter = RecordingMeter::default();
        let mut req = sign_req(b"x", Some("image/png"));
        req.content_b64 = "!!!not-base64!!!".to_string();
        let err = do_sign(&meter, "t", &req).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("not valid base64"));
    }

    // ── verify-record: mints + retains a signed record ─────────────────────

    #[test]
    fn verify_record_mints_signed_record_and_persists_jsonl() {
        use std::io::Read as _;
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        // Passport signing key file + its fingerprint (from_path inits if absent).
        let key_path = data_dir.join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let fpr = key.passport_fpr().to_string();

        let content = b"record-me";
        let meter = RecordingMeter::default();
        let signed = do_sign(&meter, "tenant-r", &sign_req(content, None)).unwrap();
        let trust_policy = ProvenanceTrustPolicy::default();

        let resp = do_verify_record(
            &meter,
            &VerifyRequest {
                manifest_envelope_b64: Some(signed.manifest_envelope_b64),
                content_b64: Some(b64(content)),
                tenant_id: None,
            },
            VerifyRecordContext {
                tenant: "tenant-r",
                idempotency: None,
                trust_policy: &trust_policy,
                passport_key_path: &key_path,
                passport_fpr: &fpr,
                data_dir,
            },
        )
        .unwrap();
        let VerifyRecordOutcome::Created(resp) = resp else {
            panic!("first write must create a verification record");
        };

        assert!(resp.verification.ok);
        assert!(resp.record_id.starts_with("prov_vr_"));
        assert_eq!(resp.receipt.alg, "ed25519");
        assert_eq!(resp.receipt.signed_by, fpr);
        assert!(resp.receipt.body_hash.starts_with("blake3:"));
        assert!(!resp.receipt.signature.is_empty());

        // The JSONL line is retained on disk.
        let mut buf = String::new();
        std::fs::File::open(records_path(data_dir, "tenant-r"))
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();
        assert!(buf.contains(&resp.record_id));
        assert!(buf.contains("verification_record.v1"));

        // verify-record meters exactly the verify_record op (the last call).
        let calls = meter.calls.lock().unwrap();
        assert_eq!(calls.last().unwrap().0, "provenance.verify_record");
    }

    #[test]
    fn verify_record_without_asset_cannot_mint_overall_success() {
        // #1: minting a signed record without the asset must record ok:false,
        // so a passport-signed record never asserts overall success on
        // internal-consistency alone.
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let key_path = data_dir.join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let fpr = key.passport_fpr().to_string();

        let meter = RecordingMeter::default();
        let signed = do_sign(&meter, "t", &sign_req(b"asset", None)).unwrap();
        let trust_policy = ProvenanceTrustPolicy::default();
        let resp = do_verify_record(
            &meter,
            &VerifyRequest {
                manifest_envelope_b64: Some(signed.manifest_envelope_b64),
                content_b64: None, // no asset supplied
                tenant_id: None,
            },
            VerifyRecordContext {
                tenant: "t",
                idempotency: None,
                trust_policy: &trust_policy,
                passport_key_path: &key_path,
                passport_fpr: &fpr,
                data_dir,
            },
        )
        .unwrap();
        let VerifyRecordOutcome::Created(resp) = resp else {
            panic!("first write must create a verification record");
        };
        assert!(
            !resp.verification.ok,
            "record must not claim overall success without asset match"
        );
        assert!(!resp.verification.asset_binding_checked);
    }

    #[test]
    fn verify_record_idempotency_replays_exact_record_and_conflicts_on_payload_change() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let fpr = key.passport_fpr().to_string();
        let meter = RecordingMeter::default();
        let signed = do_sign(&meter, "tenant-idem", &sign_req(b"bound-asset", None)).unwrap();
        let req = VerifyRequest {
            manifest_envelope_b64: Some(signed.manifest_envelope_b64),
            content_b64: Some(b64(b"bound-asset")),
            tenant_id: None,
        };
        let idempotency = RecordIdempotency::from_request("tenant-idem", "request-123", &req);
        let trust_policy = ProvenanceTrustPolicy::default();

        let first = do_verify_record(
            &meter,
            &req,
            VerifyRecordContext {
                tenant: "tenant-idem",
                idempotency: Some(&idempotency),
                trust_policy: &trust_policy,
                passport_key_path: &key_path,
                passport_fpr: &fpr,
                data_dir: tmp.path(),
            },
        )
        .unwrap();
        let VerifyRecordOutcome::Created(first) = first else {
            panic!("first idempotent request must create");
        };
        let retry = do_verify_record(
            &meter,
            &req,
            VerifyRecordContext {
                tenant: "tenant-idem",
                idempotency: Some(&idempotency),
                trust_policy: &trust_policy,
                passport_key_path: &key_path,
                passport_fpr: &fpr,
                data_dir: tmp.path(),
            },
        )
        .unwrap();
        let VerifyRecordOutcome::Replayed(retry) = retry else {
            panic!("retry must replay the retained record");
        };
        assert_eq!(retry, first);

        let stored = std::fs::read_to_string(records_path(tmp.path(), "tenant-idem")).unwrap();
        assert_eq!(stored.lines().count(), 1);
        assert!(
            !stored.contains("request-123"),
            "raw idempotency keys must not be persisted"
        );
        assert!(stored.contains(&idempotency.key_hash));
        assert_eq!(
            meter
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(op, _)| op == "provenance.verify_record")
                .count(),
            1,
            "an idempotent replay must not meter a second operation"
        );

        let changed_req = VerifyRequest {
            content_b64: Some(b64(b"different-asset")),
            ..req
        };
        let changed_idempotency = RecordIdempotency::from_request("tenant-idem", "request-123", &changed_req);
        let err = do_verify_record(
            &meter,
            &changed_req,
            VerifyRecordContext {
                tenant: "tenant-idem",
                idempotency: Some(&changed_idempotency),
                trust_policy: &trust_policy,
                passport_key_path: &key_path,
                passport_fpr: &fpr,
                data_dir: tmp.path(),
            },
        )
        .unwrap_err();
        assert_eq!(err.status, StatusCode::CONFLICT);
        let after_conflict = std::fs::read_to_string(records_path(tmp.path(), "tenant-idem")).unwrap();
        assert_eq!(after_conflict.lines().count(), 1);
    }

    #[test]
    fn idempotency_header_is_strict_and_tenant_scoped() {
        let req = VerifyRequest {
            manifest_envelope_b64: None,
            content_b64: None,
            tenant_id: None,
        };
        let mut headers = HeaderMap::new();
        assert_eq!(record_idempotency(&headers, "tenant-a", &req).unwrap(), None);

        headers.insert("idempotency-key", "safe.key:123".parse().unwrap());
        let tenant_a = record_idempotency(&headers, "tenant-a", &req).unwrap().unwrap();
        let tenant_b = record_idempotency(&headers, "tenant-b", &req).unwrap().unwrap();
        assert_ne!(tenant_a.key_hash, tenant_b.key_hash);

        headers.insert("idempotency-key", "unsafe/key".parse().unwrap());
        assert_eq!(
            record_idempotency(&headers, "tenant-a", &req).unwrap_err().status,
            StatusCode::BAD_REQUEST
        );

        headers.clear();
        headers.append("idempotency-key", "one".parse().unwrap());
        headers.append("idempotency-key", "two".parse().unwrap());
        assert_eq!(
            record_idempotency(&headers, "tenant-a", &req).unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn record_store_is_tenant_partitioned_private_and_durable() {
        let tmp = tempfile::tempdir().unwrap();
        let line_a = json!({"tenant_id": "tenant-a", "record_id": "a"});
        let line_b = json!({"tenant_id": "tenant-b", "record_id": "b"});
        append_record(tmp.path(), "tenant-a", &line_a).unwrap();
        append_record(tmp.path(), "tenant-b", &line_b).unwrap();

        let path_a = records_path(tmp.path(), "tenant-a");
        let path_b = records_path(tmp.path(), "tenant-b");
        assert_ne!(path_a, path_b);
        let stored_a = std::fs::read_to_string(&path_a).unwrap();
        let stored_b = std::fs::read_to_string(&path_b).unwrap();
        assert!(stored_a.contains("tenant-a"));
        assert!(!stored_a.contains("tenant-b"));
        assert!(stored_b.contains("tenant-b"));
        assert!(!stored_b.contains("tenant-a"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&path_a).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(
                std::fs::metadata(tenant_records_dir(tmp.path(), "tenant-a"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn record_store_rotates_segments_and_enforces_total_quota() {
        let tmp = tempfile::tempdir().unwrap();
        let line = json!({"payload": "x".repeat(40)});
        let encoded_len = u64::try_from(serde_json::to_vec(&line).unwrap().len() + 1).unwrap();
        let rotating = RecordStoreLimits {
            max_line_bytes: 512,
            segment_max_bytes: encoded_len + 1,
            tenant_max_bytes: 1_024,
            max_directory_entries: 16,
        };
        append_record_with_limits(tmp.path(), "tenant-rotate", &line, rotating).unwrap();
        append_record_with_limits(tmp.path(), "tenant-rotate", &line, rotating).unwrap();
        let jsonl_files: Vec<PathBuf> = std::fs::read_dir(tenant_records_dir(tmp.path(), "tenant-rotate"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("jsonl"))
            .collect();
        assert_eq!(jsonl_files.len(), 2, "one archive plus one active segment");

        let quota = RecordStoreLimits {
            tenant_max_bytes: encoded_len + 1,
            segment_max_bytes: 512,
            ..rotating
        };
        append_record_with_limits(tmp.path(), "tenant-quota", &line, quota).unwrap();
        let before = std::fs::read(records_path(tmp.path(), "tenant-quota")).unwrap();
        let err = append_record_with_limits(tmp.path(), "tenant-quota", &line, quota).unwrap_err();
        assert!(matches!(err, RecordStoreError::TenantQuotaExceeded { .. }));
        let after = std::fs::read(records_path(tmp.path(), "tenant-quota")).unwrap();
        assert_eq!(after, before, "quota rejection must not partially append");

        let entry_limited = RecordStoreLimits {
            max_directory_entries: 2, // lock file plus active segment
            tenant_max_bytes: 1_024,
            ..rotating
        };
        append_record_with_limits(tmp.path(), "tenant-entry-cap", &line, entry_limited).unwrap();
        let before = std::fs::read(records_path(tmp.path(), "tenant-entry-cap")).unwrap();
        let err = append_record_with_limits(tmp.path(), "tenant-entry-cap", &line, entry_limited).unwrap_err();
        assert!(matches!(err, RecordStoreError::TooManyEntries));
        let after = std::fs::read(records_path(tmp.path(), "tenant-entry-cap")).unwrap();
        assert_eq!(after, before, "entry-cap rejection must precede rotation or append");
    }

    fn retention_test_key() -> crux_session::LocalPassportKey {
        crux_session::LocalPassportKey::from_seed([0x5a; 32]).unwrap()
    }

    fn retention_test_verifier() -> RecordReceiptVerifier {
        let key = retention_test_key();
        RecordReceiptVerifier::from_parts(key.passport_fpr(), key.public_key_hex()).unwrap()
    }

    fn retention_test_state() -> (AppState, crux_session::LocalPassportKey) {
        let mut state = crate::http::tests::test_app_state_with_auth(1, crate::auth::AuthMode::Off);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).unwrap();
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();
        (state, key)
    }

    fn signed_retention_record_line(
        key: &crux_session::LocalPassportKey,
        tenant: &str,
        record_id: &str,
        recorded_at: &str,
    ) -> serde_json::Value {
        let mut body = json!({
            "schema": "cuecrux.provenance.verification_record.v1",
            "tenant_id": tenant,
            "record_id": record_id,
            "recorded_at": recorded_at,
        });
        let canonical = serde_json::to_vec(&body).unwrap();
        let hash = blake3::hash(&canonical);
        let receipt = ProvenanceReceiptV1 {
            alg: "ed25519".to_string(),
            signed_by: key.passport_fpr().to_string(),
            body_hash: format!("blake3:{}", hex::encode(hash.as_bytes())),
            signature: hex::encode(key.sign_hash(hash.as_bytes())),
        };
        body.as_object_mut()
            .unwrap()
            .insert("receipt".to_string(), serde_json::to_value(receipt).unwrap());
        body
    }

    fn retention_record_line(tenant: &str, record_id: &str, recorded_at: &str) -> serde_json::Value {
        signed_retention_record_line(&retention_test_key(), tenant, record_id, recorded_at)
    }

    fn active_record_hold(tenant: &str, entity_prefixes: Vec<String>) -> corecrux_memory::LegalHold {
        corecrux_memory::LegalHold {
            schema: corecrux_memory::LEGAL_HOLD_SCHEMA_V1.to_string(),
            hold_id: "hold-provenance-test".to_string(),
            tenant_id: tenant.to_string(),
            entity_prefixes,
            reason: "fixture legal hold".to_string(),
            placed_at: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            placed_by: "passport:test-reviewer".to_string(),
            place_receipt_id: "receipt:test-hold".to_string(),
            released_at: None,
            released_by: None,
            release_receipt_id: None,
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn record_retention_drops_only_expired_unheld_records_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant = "tenant-retention";
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "old-drop", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "old-held", "2026-01-02T00:00:00Z"),
        )
        .unwrap();
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "fresh-keep", "2026-07-20T00:00:00Z"),
        )
        .unwrap();
        let hold = active_record_hold(tenant, vec!["provenance::verification_record::old-held".to_string()]);
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let verifier = retention_test_verifier();
        let first = sweep_expired_verification_records(tmp.path(), tenant, 30, now, &[hold.clone()], &verifier);
        assert!(first.error.is_none());
        assert_eq!(first.summary.records_dropped, 1);
        assert_eq!(first.summary.expired_records_held, 1);
        assert_eq!(first.summary.files_rewritten, 1);
        assert_eq!(first.summary.files_removed, 0);
        assert_eq!(first.summary.tenant_hash, tenant_records_hash(tenant));
        let stored = std::fs::read_to_string(records_path(tmp.path(), tenant)).unwrap();
        assert!(!stored.contains("old-drop"));
        assert!(stored.contains("old-held"));
        assert!(stored.contains("fresh-keep"));

        let second = sweep_expired_verification_records(tmp.path(), tenant, 30, now, &[hold], &verifier);
        assert!(second.error.is_none());
        assert_eq!(second.summary.records_dropped, 0);
        assert_eq!(second.summary.expired_records_held, 1);
        assert_eq!(second.summary.files_rewritten, 0);
        assert_eq!(
            std::fs::read_to_string(records_path(tmp.path(), tenant)).unwrap(),
            stored
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn record_retention_preserves_every_record_under_a_tenant_wide_hold() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant = "tenant-retention-wide-hold";
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "old-one", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "old-two", "2026-01-02T00:00:00Z"),
        )
        .unwrap();
        let before = std::fs::read(records_path(tmp.path(), tenant)).unwrap();
        let hold = active_record_hold(tenant, Vec::new());
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let sweep =
            sweep_expired_verification_records(tmp.path(), tenant, 30, now, &[hold], &retention_test_verifier());

        assert!(sweep.error.is_none());
        assert_eq!(sweep.summary.records_dropped, 0);
        assert_eq!(sweep.summary.expired_records_held, 2);
        assert_eq!(sweep.summary.files_rewritten, 0);
        assert_eq!(std::fs::read(records_path(tmp.path(), tenant)).unwrap(), before);
    }

    #[test]
    fn record_store_cleans_a_crash_leftover_retention_temp_before_append() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant = "tenant-retention-temp-cleanup";
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "first", "2026-07-20T00:00:00Z"),
        )
        .unwrap();
        let temp_path =
            tenant_records_dir(tmp.path(), tenant).join(".verification-records-retention-crash-fixture.tmp");
        std::fs::write(&temp_path, b"incomplete rewrite").unwrap();

        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "second", "2026-07-21T00:00:00Z"),
        )
        .unwrap();

        assert!(!temp_path.exists());
        let retained = std::fs::read_to_string(records_path(tmp.path(), tenant)).unwrap();
        assert!(retained.contains("\"record_id\":\"first\""));
        assert!(retained.contains("\"record_id\":\"second\""));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn record_retention_fails_closed_before_deleting_when_any_line_is_corrupt() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant = "tenant-retention-corrupt";
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "old-valid", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "bad-time", "not-rfc3339"),
        )
        .unwrap();
        let before = std::fs::read(records_path(tmp.path(), tenant)).unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let sweep = sweep_expired_verification_records(tmp.path(), tenant, 30, now, &[], &retention_test_verifier());

        assert!(matches!(sweep.error, Some(RecordStoreError::CorruptRecord)));
        assert_eq!(sweep.summary.records_dropped, 0);
        assert_eq!(std::fs::read(records_path(tmp.path(), tenant)).unwrap(), before);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn record_retention_removes_an_all_expired_segment() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant = "tenant-retention-empty";
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "old-only", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let sweep = sweep_expired_verification_records(tmp.path(), tenant, 30, now, &[], &retention_test_verifier());

        assert!(sweep.error.is_none());
        assert_eq!(sweep.summary.records_dropped, 1);
        assert_eq!(sweep.summary.files_removed, 1);
        assert!(!records_path(tmp.path(), tenant).exists());
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "new-after-sweep", "2026-07-21T00:00:00Z"),
        )
        .unwrap();
        assert!(records_path(tmp.path(), tenant).exists());
    }

    #[test]
    #[serial_test::serial]
    fn retention_policy_parser_is_explicit_bounded_and_fail_closed() {
        std::env::remove_var(RETENTION_DAYS_ENV);
        assert_eq!(provenance_retention_days_from_env().unwrap(), None);
        std::env::set_var(RETENTION_DAYS_ENV, "90");
        assert_eq!(provenance_retention_days_from_env().unwrap(), Some(90));
        for invalid in ["0", "3651", "1.5", "forever"] {
            std::env::set_var(RETENTION_DAYS_ENV, invalid);
            assert!(provenance_retention_days_from_env().is_err());
        }
        std::env::remove_var(RETENTION_DAYS_ENV);
    }

    #[test]
    fn record_retention_cadence_bounds_full_tenant_scans() {
        let tenant = format!("tenant-retention-cadence-{}", uuid::Uuid::new_v4());
        let start = Instant::now();
        assert!(retention_sweep_due(&tenant, start));
        assert!(!retention_sweep_due(&tenant, start + RETENTION_SWEEP_INTERVAL / 2));
        assert!(retention_sweep_due(
            &tenant,
            start + RETENTION_SWEEP_INTERVAL + Duration::from_secs(1)
        ));
    }

    #[test]
    fn record_retention_receipt_is_count_only_and_excludes_raw_tenant_and_record_ids() {
        let summary = RecordRetentionSweepSummary {
            retention_days: 90,
            cutoff: "2026-04-22T00:00:00+00:00".to_string(),
            tenant_hash: tenant_records_hash("customer-tenant-secret"),
            records_dropped: 3,
            expired_records_held: 2,
            files_rewritten: 1,
            files_removed: 1,
        };
        let encoded = serde_json::to_string(&build_record_retention_receipt(
            &summary,
            "prov_ret_fixture",
            "completed",
            "scheduled",
        ))
        .unwrap();

        assert!(encoded.contains("configured_retention_window"));
        assert!(encoded.contains("\"trigger\":\"scheduled\""));
        assert!(encoded.contains("\"records_dropped\":3"));
        assert!(encoded.contains(&summary.tenant_hash));
        assert!(!encoded.contains("customer-tenant-secret"));
        assert!(!encoded.contains("provenance::verification_record::"));
        assert!(!encoded.contains("old-drop"));
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg(target_os = "linux")]
    async fn verify_record_retention_mints_governance_receipt_and_surfaces_headers() {
        use crate::auth::AuthMode;

        std::env::set_var(FEATURE_ENV, "1");
        std::env::set_var(RETENTION_DAYS_ENV, "30");
        std::env::remove_var(TRUSTED_LEAF_SHA256_ENV);
        let mut state = crate::http::tests::test_app_state_with_auth(1, AuthMode::DevScopes);
        let passport_key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).unwrap();
        state.passport_fpr = passport_key.passport_fpr().to_string();
        state.passport_public_key_hex = passport_key.public_key_hex().to_string();
        let tenant = format!("tenant-retention-http-{}", uuid::Uuid::new_v4());
        append_record(
            &state.data_dir,
            &tenant,
            &signed_retention_record_line(&passport_key, &tenant, "expired-http-record", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "provenance:write".parse().unwrap());
        headers.insert("x-corecrux-tenant-id", tenant.parse().unwrap());
        headers.insert("x-corecrux-passport-id", "passport:retention-test".parse().unwrap());

        let response = post_provenance_verify_record(
            State(state.clone()),
            headers,
            Json(VerifyRequest {
                manifest_envelope_b64: None,
                content_b64: None,
                tenant_id: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers().get("x-cuecrux-retention-receipt-status").unwrap(),
            "recorded"
        );
        assert_eq!(
            response.headers().get("x-cuecrux-retention-records-dropped").unwrap(),
            "1"
        );
        assert!(response.headers().get("x-cuecrux-retention-receipt-id").is_some());
        let retained = std::fs::read_to_string(records_path(&state.data_dir, &tenant)).unwrap();
        assert!(!retained.contains("expired-http-record"));
        assert_eq!(retained.lines().count(), 1, "the new verification record remains");
        let receipt_file =
            super::super::observations::observation_file_path(&state.data_dir, "__governance__::retention");
        let receipt_line = std::fs::read_to_string(receipt_file).unwrap();
        assert!(receipt_line.contains("retention.provenance_records"));
        assert!(
            !receipt_line.contains(&tenant),
            "governance payload must not expose raw tenant ids"
        );

        std::env::remove_var(RETENTION_DAYS_ENV);
        std::env::remove_var(FEATURE_ENV);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn record_retention_rejects_a_tampered_signed_timestamp_before_deletion() {
        let tmp = tempfile::tempdir().unwrap();
        let key = retention_test_key();
        let tenant = "tenant-retention-signed-time";
        let mut tampered = signed_retention_record_line(&key, tenant, "fresh-record", "2026-07-20T00:00:00Z");
        tampered["recorded_at"] = serde_json::Value::String("2026-01-01T00:00:00Z".to_string());
        append_record(tmp.path(), tenant, &tampered).unwrap();
        let before = std::fs::read(records_path(tmp.path(), tenant)).unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let verifier = RecordReceiptVerifier::from_parts(key.passport_fpr(), key.public_key_hex()).unwrap();

        let sweep = sweep_expired_verification_records(tmp.path(), tenant, 30, now, &[], &verifier);

        assert!(matches!(sweep.error, Some(RecordStoreError::CorruptRecord)));
        assert_eq!(sweep.summary.records_dropped, 0);
        assert_eq!(std::fs::read(records_path(tmp.path(), tenant)).unwrap(), before);
    }

    #[test]
    #[serial_test::serial]
    #[cfg(target_os = "linux")]
    fn record_retention_requires_a_trusted_current_or_historical_signer() {
        std::env::remove_var(RETENTION_SIGNER_KEYRING_ENV);
        let (state, _) = retention_test_state();
        let historical_key = crux_session::LocalPassportKey::from_seed([0x6b; 32]).unwrap();
        let tenant = "tenant-historical-retention-signer";
        append_record(
            &state.data_dir,
            tenant,
            &signed_retention_record_line(&historical_key, tenant, "historical-record", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        let before = std::fs::read(records_path(&state.data_dir, tenant)).unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let current_only = RecordReceiptVerifier::from_state(&state).unwrap();
        let rejected = sweep_expired_verification_records(&state.data_dir, tenant, 30, now, &[], &current_only);
        assert!(matches!(rejected.error, Some(RecordStoreError::CorruptRecord)));
        assert_eq!(std::fs::read(records_path(&state.data_dir, tenant)).unwrap(), before);

        std::env::set_var(
            RETENTION_SIGNER_KEYRING_ENV,
            serde_json::json!({ (historical_key.passport_fpr()): historical_key.public_key_hex() }).to_string(),
        );
        let with_history = RecordReceiptVerifier::from_state(&state).unwrap();
        let accepted = sweep_expired_verification_records(&state.data_dir, tenant, 30, now, &[], &with_history);
        assert!(accepted.error.is_none());
        assert_eq!(accepted.summary.records_dropped, 1);
        assert!(!records_path(&state.data_dir, tenant).exists());
        std::env::remove_var(RETENTION_SIGNER_KEYRING_ENV);
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn scheduled_retention_expires_an_inactive_tenant_and_mints_redacted_intent_and_result() {
        let (state, key) = retention_test_state();
        let tenant = format!("inactive-tenant-secret-{}", uuid::Uuid::new_v4());
        append_record(
            &state.data_dir,
            &tenant,
            &signed_retention_record_line(&key, &tenant, "inactive-expired-secret", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        append_record(
            &state.data_dir,
            &tenant,
            &signed_retention_record_line(&key, &tenant, "inactive-fresh-secret", "2026-07-20T00:00:00Z"),
        )
        .unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut cursor = 0usize;

        let first = run_scheduled_retention_once(&state, 30, 10, now, &mut cursor)
            .await
            .unwrap();

        assert_eq!(first.tenants_discovered, 1);
        assert_eq!(first.tenants_selected, 1);
        assert_eq!(first.tenants_swept, 1);
        assert_eq!(first.tenants_failed, 0);
        assert_eq!(first.records_dropped, 1);
        assert_eq!(first.receipts_pending, 0);
        let retained = std::fs::read_to_string(records_path(&state.data_dir, &tenant)).unwrap();
        assert!(!retained.contains("inactive-expired-secret"));
        assert!(retained.contains("inactive-fresh-secret"));

        let receipt_path =
            super::super::observations::observation_file_path(&state.data_dir, "__governance__::retention");
        let receipt_before = std::fs::read_to_string(&receipt_path).unwrap();
        assert!(receipt_before.contains(RETENTION_SCHEDULER_ACTOR));
        assert!(receipt_before.contains("scheduled"));
        assert!(receipt_before.contains("planned"));
        assert!(receipt_before.contains("completed"));
        assert_eq!(receipt_before.lines().count(), 2);
        assert!(!receipt_before.contains(&tenant));
        assert!(!receipt_before.contains("inactive-expired-secret"));
        assert!(!receipt_before.contains("inactive-fresh-secret"));

        let second = run_scheduled_retention_once(&state, 30, 10, now, &mut cursor)
            .await
            .unwrap();
        assert_eq!(second.records_dropped, 0);
        assert_eq!(std::fs::read_to_string(receipt_path).unwrap(), receipt_before);
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn scheduled_retention_aborts_before_deletion_when_audit_intent_cannot_be_minted() {
        let (mut state, key) = retention_test_state();
        let tenant = format!("tenant-audit-intent-failure-{}", uuid::Uuid::new_v4());
        append_record(
            &state.data_dir,
            &tenant,
            &signed_retention_record_line(&key, &tenant, "must-remain", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        let before = std::fs::read(records_path(&state.data_dir, &tenant)).unwrap();
        state.passport_key_path = state.data_dir.clone();
        let debt_before = super::super::observations::receipt_mint_failures();
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut cursor = 0usize;

        let report = run_scheduled_retention_once(&state, 30, 10, now, &mut cursor)
            .await
            .unwrap();

        assert_eq!(report.records_dropped, 0);
        assert_eq!(report.tenants_failed, 1);
        assert!(super::super::observations::receipt_mint_failures() > debt_before);
        assert_eq!(std::fs::read(records_path(&state.data_dir, &tenant)).unwrap(), before);
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn scheduled_retention_validates_later_lines_before_deleting_earlier_records() {
        let (state, key) = retention_test_state();
        let tenant = format!("tenant-later-corrupt-{}", uuid::Uuid::new_v4());
        append_record(
            &state.data_dir,
            &tenant,
            &signed_retention_record_line(&key, &tenant, "old-valid", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        append_record(
            &state.data_dir,
            &tenant,
            &signed_retention_record_line(&key, &tenant, "bad-time", "not-rfc3339"),
        )
        .unwrap();
        let before = std::fs::read(records_path(&state.data_dir, &tenant)).unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut cursor = 0usize;

        let report = run_scheduled_retention_once(&state, 30, 10, now, &mut cursor)
            .await
            .unwrap();

        assert_eq!(report.records_dropped, 0);
        assert_eq!(report.tenants_failed, 1);
        assert_eq!(std::fs::read(records_path(&state.data_dir, &tenant)).unwrap(), before);
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn scheduled_retention_honours_scoped_and_malformed_fail_closed_legal_holds() {
        use corecrux_memory::fact_store::StoreFact;
        use corecrux_memory::HorizonClass;

        let (state, key) = retention_test_state();
        let scoped_tenant = format!("tenant-scheduled-scoped-{}", uuid::Uuid::new_v4());
        append_record(
            &state.data_dir,
            &scoped_tenant,
            &signed_retention_record_line(&key, &scoped_tenant, "drop-me", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        append_record(
            &state.data_dir,
            &scoped_tenant,
            &signed_retention_record_line(&key, &scoped_tenant, "held-record", "2026-01-02T00:00:00Z"),
        )
        .unwrap();
        let malformed_tenant = format!("tenant-scheduled-malformed-{}", uuid::Uuid::new_v4());
        append_record(
            &state.data_dir,
            &malformed_tenant,
            &signed_retention_record_line(&key, &malformed_tenant, "must-survive", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        {
            let mut store = state.fact_store.write().await;
            store
                .place_legal_hold(corecrux_memory::PlaceLegalHold {
                    tenant_id: scoped_tenant.clone(),
                    entity_prefixes: vec!["provenance::verification_record::held-record".to_string()],
                    reason: "fixture scoped hold".to_string(),
                    actor: Some("passport:test-reviewer".to_string()),
                })
                .unwrap();
            store
                .try_store(StoreFact {
                    tenant_hash: malformed_tenant.clone(),
                    entity: "__legal_hold__::malformed-scheduler-fixture".to_string(),
                    key: "state".to_string(),
                    value: "{malformed-json".to_string(),
                    source_receipt: None,
                    confidence: 1.0,
                    private: true,
                    horizon_class: Some(HorizonClass::None),
                    actor: Some("fixture-bypass".to_string()),
                })
                .unwrap();
        }
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut cursor = 0usize;

        let report = run_scheduled_retention_once(&state, 30, 10, now, &mut cursor)
            .await
            .unwrap();

        assert_eq!(report.records_dropped, 1);
        assert_eq!(report.expired_records_held, 2);
        let scoped = std::fs::read_to_string(records_path(&state.data_dir, &scoped_tenant)).unwrap();
        assert!(!scoped.contains("drop-me"));
        assert!(scoped.contains("held-record"));
        let malformed = std::fs::read_to_string(records_path(&state.data_dir, &malformed_tenant)).unwrap();
        assert!(malformed.contains("must-survive"));
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn scheduled_retention_rejects_hash_mismatches_without_touching_the_record() {
        let (state, key) = retention_test_state();
        let stored_tenant = "tenant-signed-inside-mismatched-directory";
        let directory_tenant = "different-directory-tenant";
        let tenant_dir = tenant_records_dir(&state.data_dir, directory_tenant);
        std::fs::create_dir_all(&tenant_dir).unwrap();
        std::fs::write(tenant_dir.join(".append.lock"), b"").unwrap();
        let line = signed_retention_record_line(&key, stored_tenant, "preserve-me", "2026-01-01T00:00:00Z");
        let mut encoded = serde_json::to_vec(&line).unwrap();
        encoded.push(b'\n');
        let path = tenant_dir.join("verification-records.jsonl");
        std::fs::write(&path, &encoded).unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut cursor = 0usize;

        let report = run_scheduled_retention_once(&state, 30, 10, now, &mut cursor)
            .await
            .unwrap();

        assert_eq!(report.tenants_failed, 1);
        assert_eq!(report.tenants_swept, 0);
        assert_eq!(report.records_dropped, 0);
        assert_eq!(std::fs::read(path).unwrap(), encoded);
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn scheduled_retention_batches_rotate_fairly_across_tenants() {
        let (state, key) = retention_test_state();
        let mut tenants = Vec::new();
        for index in 0..3 {
            let tenant = format!("tenant-fair-batch-{index}");
            append_record(
                &state.data_dir,
                &tenant,
                &signed_retention_record_line(&key, &tenant, &format!("expired-{index}"), "2026-01-01T00:00:00Z"),
            )
            .unwrap();
            tenants.push(tenant);
        }
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut cursor = 0usize;
        let mut dropped = 0usize;
        for _ in 0..3 {
            let report = run_scheduled_retention_once(&state, 30, 1, now, &mut cursor)
                .await
                .unwrap();
            assert_eq!(report.tenants_selected, 1);
            dropped = dropped.saturating_add(report.records_dropped);
        }
        assert_eq!(dropped, 3);
        for tenant in tenants {
            assert!(!records_path(&state.data_dir, &tenant).exists());
            assert!(!tenant_records_dir(&state.data_dir, &tenant).exists());
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg(target_os = "linux")]
    async fn retention_scheduler_is_default_off_and_shutdown_preempts_the_first_pass() {
        std::env::remove_var(RETENTION_DAYS_ENV);
        let (state, key) = retention_test_state();
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        assert!(spawn_provenance_retention_scheduler_with_interval(
            false,
            Duration::from_millis(10),
            1,
            state.clone(),
            shutdown_rx,
        )
        .is_none());
        let (_, shutdown_rx) = tokio::sync::broadcast::channel(1);
        assert!(spawn_provenance_retention_scheduler_with_interval(
            true,
            Duration::from_millis(10),
            1,
            state.clone(),
            shutdown_rx,
        )
        .is_none());

        let tenant = "tenant-shutdown-before-first-retention-pass";
        append_record(
            &state.data_dir,
            tenant,
            &signed_retention_record_line(&key, tenant, "must-remain", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        std::env::set_var(RETENTION_DAYS_ENV, "30");
        let handle = spawn_provenance_retention_scheduler_with_interval(
            true,
            Duration::from_millis(50),
            1,
            state.clone(),
            shutdown_tx.subscribe(),
        )
        .unwrap();
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("scheduler exits promptly")
            .unwrap();
        assert!(std::fs::read_to_string(records_path(&state.data_dir, tenant))
            .unwrap()
            .contains("must-remain"));
        std::env::remove_var(RETENTION_DAYS_ENV);
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg(target_os = "linux")]
    async fn retention_scheduler_waits_for_its_interval_then_runs() {
        let (state, key) = retention_test_state();
        let tenant = format!("tenant-live-scheduler-{}", uuid::Uuid::new_v4());
        append_record(
            &state.data_dir,
            &tenant,
            &signed_retention_record_line(&key, &tenant, "expired-live", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        std::env::set_var(RETENTION_DAYS_ENV, "30");
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let handle = spawn_provenance_retention_scheduler_with_interval(
            true,
            Duration::from_millis(80),
            1,
            state.clone(),
            shutdown_rx,
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            records_path(&state.data_dir, &tenant).exists(),
            "boot tick must be skipped"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while tenant_records_dir(&state.data_dir, &tenant).exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("scheduled pass runs after its interval");
        shutdown_tx.send(()).unwrap();
        handle.await.unwrap();
        std::env::remove_var(RETENTION_DAYS_ENV);
    }

    #[tokio::test]
    #[serial_test::serial]
    #[cfg(target_os = "linux")]
    async fn retention_scheduler_shutdown_before_audit_intent_preserves_all_tenants() {
        let (state, key) = retention_test_state();
        let tenants = [
            format!("tenant-shutdown-inflight-a-{}", uuid::Uuid::new_v4()),
            format!("tenant-shutdown-inflight-b-{}", uuid::Uuid::new_v4()),
        ];
        for tenant in &tenants {
            append_record(
                &state.data_dir,
                tenant,
                &signed_retention_record_line(&key, tenant, "expired", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
        }
        std::env::set_var(RETENTION_DAYS_ENV, "30");
        let fact_store_guard = state.fact_store.write().await;
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let handle = spawn_provenance_retention_scheduler_with_interval(
            true,
            Duration::from_millis(20),
            2,
            state.clone(),
            shutdown_rx,
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("scheduler cancels while legal-hold authority is unavailable")
            .unwrap();
        drop(fact_store_guard);

        assert!(tenants
            .iter()
            .all(|tenant| records_path(&state.data_dir, tenant).exists()));
        std::env::remove_var(RETENTION_DAYS_ENV);
    }

    #[test]
    fn retention_discovery_entry_bound_fails_closed_before_any_sweep() {
        let tmp = tempfile::tempdir().unwrap();
        for tenant in ["tenant-bound-a", "tenant-bound-b"] {
            append_record(
                tmp.path(),
                tenant,
                &retention_record_line(tenant, "must-remain", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
        }

        assert!(matches!(
            list_retained_tenant_directories_with_limit(tmp.path(), 1),
            Err(RecordStoreError::TooManyEntries)
        ));
        for tenant in ["tenant-bound-a", "tenant-bound-b"] {
            assert!(records_path(tmp.path(), tenant).exists());
        }
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn scheduled_retention_byte_and_time_budgets_preserve_unswept_tenants() {
        let (state, key) = retention_test_state();
        let tenants = [
            format!("tenant-byte-budget-a-{}", uuid::Uuid::new_v4()),
            format!("tenant-byte-budget-b-{}", uuid::Uuid::new_v4()),
        ];
        for tenant in &tenants {
            append_record(
                &state.data_dir,
                tenant,
                &signed_retention_record_line(&key, tenant, "must-remain", "2026-01-01T00:00:00Z"),
            )
            .unwrap();
        }
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut cursor = 0usize;
        let report = run_scheduled_retention_once_with_limits(
            &state,
            30,
            2,
            now,
            &mut cursor,
            Arc::new(AtomicBool::new(false)),
            ScheduledRetentionLimits {
                max_bytes: 1,
                max_duration: Duration::from_secs(5),
            },
        )
        .await
        .unwrap();
        assert!(report.budget_exhausted);
        assert_eq!(report.records_dropped, 0);
        assert_eq!(cursor, 1, "a budget-hit tenant must not starve the next directory");
        for tenant in &tenants {
            assert!(records_path(&state.data_dir, tenant).exists());
        }

        let mut cursor = 0usize;
        let report = run_scheduled_retention_once_with_limits(
            &state,
            30,
            2,
            now,
            &mut cursor,
            Arc::new(AtomicBool::new(false)),
            ScheduledRetentionLimits {
                max_bytes: RETENTION_SCHEDULER_MAX_BYTES_PER_PASS,
                max_duration: Duration::ZERO,
            },
        )
        .await
        .unwrap();
        assert!(report.budget_exhausted);
        assert_eq!(report.records_dropped, 0);
        for tenant in &tenants {
            assert!(records_path(&state.data_dir, tenant).exists());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sweep_rechecks_the_byte_budget_under_the_tenant_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant = "tenant-locked-byte-budget";
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "must-remain", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        let before = std::fs::read(records_path(tmp.path(), tenant)).unwrap();
        let controls = RetentionSweepControls {
            cancellation: Arc::new(AtomicBool::new(false)),
            deadline: None,
            max_store_bytes: before.len().saturating_sub(1) as u64,
        };
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let sweep = sweep_expired_verification_records_with_controls(
            tmp.path(),
            RetentionSweepRequest {
                tenant,
                retention_days: 30,
                now,
                legal_holds: &[],
                verifier: &retention_test_verifier(),
                controls: &controls,
            },
            |_| Ok(()),
        );

        assert!(matches!(sweep.error, Some(RecordStoreError::RetentionBudgetExhausted)));
        assert!(!sweep.audit_intent_recorded);
        assert_eq!(std::fs::read(records_path(tmp.path(), tenant)).unwrap(), before);
    }

    #[test]
    fn retention_line_reader_rejects_a_no_newline_blob_without_scanning_the_file() {
        let blob_len = usize::try_from(RECORD_MAX_LINE_BYTES).unwrap() * 8;
        let cursor = std::io::Cursor::new(vec![b'x'; blob_len]);
        let mut reader = std::io::BufReader::new(cursor);

        let result = read_bounded_retention_line(
            &mut reader,
            RECORD_MAX_LINE_BYTES,
            RECORD_MAX_LINE_BYTES.saturating_add(1),
        );

        assert!(matches!(result, Err(RecordStoreError::CorruptRecord)));
        assert!(reader.get_ref().position() <= RECORD_MAX_LINE_BYTES.saturating_add(8 * 1024));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn empty_directory_cleanup_observes_cancellation_while_the_tenant_lock_is_held() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant = "tenant-cancelled-empty-cleanup";
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "fixture", "2026-07-20T00:00:00Z"),
        )
        .unwrap();
        std::fs::remove_file(records_path(tmp.path(), tenant)).unwrap();
        let tenant_hash = tenant_records_hash(tenant);
        let _guard = record_tenant_lock(&tenant_hash).lock().unwrap();
        let cancellation = Arc::new(AtomicBool::new(true));
        let controls = RetentionSweepControls {
            cancellation,
            deadline: None,
            max_store_bytes: RETENTION_SCHEDULER_MAX_BYTES_PER_PASS,
        };

        assert!(matches!(
            cleanup_empty_tenant_directory_with_controls(tmp.path(), &tenant_hash, &controls),
            Err(RecordStoreError::RetentionCancelled)
        ));
        assert!(tenant_records_dir(tmp.path(), tenant).exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn legal_hold_read_authority_spans_the_retention_mutation_callback() {
        let fact_store = Arc::new(tokio::sync::RwLock::new(corecrux_memory::FactStore::new()));
        let worker_store = fact_store.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let worker = tokio::task::spawn_blocking(move || {
            with_active_tenant_legal_holds(&worker_store, "tenant-lock-span", |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            });
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        assert!(
            fact_store.try_write().is_err(),
            "a concurrent hold writer must not interleave with the mutation callback"
        );
        release_tx.send(()).unwrap();
        worker.await.unwrap();
        assert!(fact_store.try_write().is_ok());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn anchored_tenant_directory_cannot_be_redirected_by_a_parent_swap() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let tenant = "tenant-parent-swap";
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "anchored-record", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        let original = tenant_records_dir(tmp.path(), tenant);
        let moved = tmp.path().join("moved-original-tenant");
        let victim = tmp.path().join("outside-victim-directory");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("verification-records.jsonl"), b"victim-must-remain").unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let sweep = sweep_expired_verification_records_with_audit_intent(
            tmp.path(),
            tenant,
            30,
            now,
            &[],
            &retention_test_verifier(),
            |_| {
                std::fs::rename(&original, &moved)?;
                symlink(&victim, &original)?;
                Ok(())
            },
        );

        assert!(sweep.error.is_none());
        assert!(sweep.audit_intent_recorded);
        assert_eq!(sweep.summary.records_dropped, 1);
        assert_eq!(
            std::fs::read(victim.join("verification-records.jsonl")).unwrap(),
            b"victim-must-remain"
        );
        assert!(!moved.join("verification-records.jsonl").exists());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn automatic_retention_preserves_records_on_platforms_without_descriptor_anchoring() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant = "tenant-non-linux-preservation";
        let path = records_path(tmp.path(), tenant);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"preserve-without-parsing\n").unwrap();
        let before = std::fs::read(&path).unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let sweep = sweep_expired_verification_records(tmp.path(), tenant, 30, now, &[], &retention_test_verifier());

        assert!(matches!(sweep.error, Some(RecordStoreError::UnsafePath)));
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn retention_scheduler_stays_disabled_without_descriptor_anchoring() {
        let (state, _) = retention_test_state();
        let (_, shutdown_rx) = tokio::sync::broadcast::channel(1);
        assert!(spawn_provenance_retention_scheduler_with_interval(
            true,
            Duration::from_secs(60),
            1,
            state,
            shutdown_rx,
        )
        .is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn post_intent_identity_failure_requires_a_terminal_failed_receipt() {
        let tmp = tempfile::tempdir().unwrap();
        let tenant = "tenant-post-intent-identity-failure";
        append_record(
            tmp.path(),
            tenant,
            &retention_record_line(tenant, "expired-original", "2026-01-01T00:00:00Z"),
        )
        .unwrap();
        let active = records_path(tmp.path(), tenant);
        let displaced = active.with_extension("displaced");
        let replacement = serde_json::to_vec(&retention_record_line(
            tenant,
            "replacement-must-remain",
            "2026-07-20T00:00:00Z",
        ))
        .unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let sweep = sweep_expired_verification_records_with_audit_intent(
            tmp.path(),
            tenant,
            30,
            now,
            &[],
            &retention_test_verifier(),
            |_| {
                std::fs::rename(&active, &displaced)?;
                let mut encoded = replacement.clone();
                encoded.push(b'\n');
                std::fs::write(&active, encoded)?;
                Ok(())
            },
        );

        assert!(matches!(sweep.error, Some(RecordStoreError::UnsafePath)));
        assert!(sweep.audit_intent_recorded);
        assert_eq!(retention_terminal_status(&sweep), Some("failed"));
        assert_eq!(sweep.summary.records_dropped, 0);
        assert!(std::fs::read_to_string(&active)
            .unwrap()
            .contains("replacement-must-remain"));
        assert!(std::fs::read_to_string(displaced).unwrap().contains("expired-original"));
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn scheduled_retention_rejects_symlinked_tenant_entries_without_touching_the_target() {
        use std::os::unix::fs::symlink;

        let (state, _) = retention_test_state();
        let tenants_root = provenance_tenants_root(&state.data_dir);
        std::fs::create_dir_all(&tenants_root).unwrap();
        let victim = state.data_dir.join("outside-retention-victim");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("marker"), b"unchanged").unwrap();
        symlink(&victim, tenants_root.join(format!("t_{}", "a".repeat(64)))).unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-21T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut cursor = 0usize;

        let result = run_scheduled_retention_once(&state, 30, 10, now, &mut cursor).await;

        assert!(matches!(result, Err(RecordStoreError::UnsafePath)));
        assert_eq!(std::fs::read(victim.join("marker")).unwrap(), b"unchanged");
    }

    #[test]
    fn concurrent_record_appends_never_interleave_json_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::sync::Arc::new(tmp.path().to_path_buf());
        let mut workers = Vec::new();
        for index in 0..8_u32 {
            let root = std::sync::Arc::clone(&root);
            workers.push(std::thread::spawn(move || {
                append_record(&root, "tenant-concurrent", &json!({"record": index}))
            }));
        }
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        let stored = std::fs::read_to_string(records_path(&root, "tenant-concurrent")).unwrap();
        let lines: Vec<&str> = stored.lines().collect();
        assert_eq!(lines.len(), 8);
        for line in lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    #[cfg(unix)]
    fn record_store_rejects_symlinked_active_file() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let tenant_dir = tenant_records_dir(tmp.path(), "tenant-symlink");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        let victim = tmp.path().join("victim.txt");
        std::fs::write(&victim, b"unchanged").unwrap();
        symlink(&victim, records_path(tmp.path(), "tenant-symlink")).unwrap();

        let err = append_record(tmp.path(), "tenant-symlink", &json!({"record": "attack"})).unwrap_err();
        assert!(matches!(err, RecordStoreError::UnsafePath));
        assert_eq!(std::fs::read(&victim).unwrap(), b"unchanged");
    }

    #[test]
    #[cfg(unix)]
    fn record_store_hardens_preexisting_file_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let tenant_dir = tenant_records_dir(tmp.path(), "tenant-permissions");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        let active_path = records_path(tmp.path(), "tenant-permissions");
        let lock_path = tenant_dir.join(".append.lock");
        std::fs::write(&active_path, b"").unwrap();
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&tenant_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&active_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o666)).unwrap();

        append_record(tmp.path(), "tenant-permissions", &json!({"record": "private"})).unwrap();

        assert_eq!(
            std::fs::metadata(&tenant_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&active_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // ── flag-off returns 404 at the axum handler ───────────────────────────

    #[tokio::test]
    #[serial_test::serial]
    async fn handlers_404_when_flag_off() {
        std::env::remove_var(FEATURE_ENV);
        let state = crate::http::tests::test_app_state(1);
        let body = VerifyRequest {
            manifest_envelope_b64: None,
            content_b64: None,
            tenant_id: None,
        };
        let resp = post_provenance_verify(State(state), HeaderMap::new(), Json(body)).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn router_flag_off_never_mounts_or_reads_body() {
        use tower::ServiceExt as _;
        // Flag OFF at router build → routes not mounted → 404 before any body
        // extraction, even for a MALFORMED body (which would 400 if extracted).
        std::env::remove_var(FEATURE_ENV);
        let state = crate::http::tests::test_app_state(1);
        let app = crate::http::router(
            state,
            std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::CaseStore::new())),
        );
        for path in [
            "/v1/provenance/sign",
            "/v1/provenance/verify",
            "/v1/provenance/verify-record",
        ] {
            let req = axum::http::Request::post(path)
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{ this is not json"))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "{path} must 404 (unmounted) when the flag is off, not 400 from body parsing"
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn router_flag_on_with_auth_off_still_never_mounts_or_reads_body() {
        use tower::ServiceExt as _;

        std::env::set_var(FEATURE_ENV, "1");
        let state = crate::http::tests::test_app_state(1);
        let app = crate::http::router(
            state,
            std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::CaseStore::new())),
        );
        let req = axum::http::Request::post("/v1/provenance/sign")
            .header("content-type", "application/json")
            .body(axum::body::Body::from("{ this contains key material but is not json"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        std::env::remove_var(FEATURE_ENV);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn invalid_retention_policy_keeps_all_provenance_routes_unmounted() {
        use crate::auth::AuthMode;
        use tower::ServiceExt as _;

        std::env::set_var(FEATURE_ENV, "1");
        std::env::set_var(RETENTION_DAYS_ENV, "0");
        let state = crate::http::tests::test_app_state_with_auth(1, AuthMode::DevScopes);
        let app = crate::http::router(
            state,
            std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::CaseStore::new())),
        );
        for path in [
            "/v1/provenance/sign",
            "/v1/provenance/verify",
            "/v1/provenance/verify-record",
        ] {
            let request = axum::http::Request::post(path)
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{ malformed key-bearing request"))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        std::env::remove_var(RETENTION_DAYS_ENV);
        std::env::remove_var(FEATURE_ENV);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn handler_rejects_missing_or_conflicting_tenant_selector() {
        use crate::auth::AuthMode;

        std::env::set_var(FEATURE_ENV, "1");
        let state = crate::http::tests::test_app_state_with_auth(1, AuthMode::DevScopes);
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "provenance:write".parse().unwrap());

        let missing = post_provenance_verify(
            State(state.clone()),
            headers.clone(),
            Json(VerifyRequest {
                manifest_envelope_b64: None,
                content_b64: None,
                tenant_id: None,
            }),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

        headers.insert("x-corecrux-tenant-id", "tenant-a".parse().unwrap());
        let conflicting = post_provenance_verify(
            State(state.clone()),
            headers.clone(),
            Json(VerifyRequest {
                manifest_envelope_b64: None,
                content_b64: None,
                tenant_id: Some("tenant-b".to_string()),
            }),
        )
        .await;
        assert_eq!(conflicting.status(), StatusCode::BAD_REQUEST);

        headers.insert(
            "x-corecrux-tenant-id",
            axum::http::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        let invalid_header = post_provenance_verify(
            State(state),
            headers,
            Json(VerifyRequest {
                manifest_envelope_b64: None,
                content_b64: None,
                tenant_id: Some("tenant-a".to_string()),
            }),
        )
        .await;
        assert_eq!(invalid_header.status(), StatusCode::BAD_REQUEST);
        std::env::remove_var(FEATURE_ENV);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn handler_binds_selected_tenant_to_verified_jwt_claim() {
        use crate::auth::AuthMode;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        const SECRET: &str = "0123456789abcdef0123456789abcdef";
        std::env::set_var(FEATURE_ENV, "1");
        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", SECRET);
        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");
        let state = crate::http::tests::test_app_state_with_auth(1, AuthMode::JwtHs256);

        #[derive(serde::Serialize)]
        struct Claims<'a> {
            exp: usize,
            iss: &'a str,
            aud: &'a str,
            sub: &'a str,
            scope: &'a str,
            tenant_id: &'a str,
        }
        let claims = Claims {
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3_600) as usize,
            iss: "corecrux-test",
            aud: "corecrux",
            sub: "customer-user-a",
            scope: "provenance:write",
            tenant_id: "tenant-a",
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );

        let denied = post_provenance_verify(
            State(state.clone()),
            headers.clone(),
            Json(VerifyRequest {
                manifest_envelope_b64: None,
                content_b64: None,
                tenant_id: Some("tenant-b".to_string()),
            }),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let allowed = post_provenance_verify(
            State(state),
            headers,
            Json(VerifyRequest {
                manifest_envelope_b64: None,
                content_b64: None,
                tenant_id: Some("tenant-a".to_string()),
            }),
        )
        .await;
        assert_eq!(allowed.status(), StatusCode::OK);

        for name in [
            FEATURE_ENV,
            "CORECRUXD_JWT_HS256_SECRET",
            "CORECRUXD_JWT_ISS",
            "CORECRUXD_JWT_AUD",
        ] {
            std::env::remove_var(name);
        }
    }

    #[test]
    #[serial_test::serial]
    fn jwt_rate_keys_survive_token_rotation_and_require_a_stable_principal() {
        use crate::auth::AuthMode;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        const SECRET: &str = "0123456789abcdef0123456789abcdef";
        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", SECRET);
        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-rate-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");
        let state = crate::http::tests::test_app_state_with_auth(1, AuthMode::JwtHs256);

        #[derive(serde::Serialize)]
        struct Claims<'a> {
            exp: usize,
            iss: &'a str,
            aud: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            sub: Option<&'a str>,
            scope: &'a str,
            tenant_id: &'a str,
            jti: &'a str,
        }
        let expiry = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3_600) as usize;
        let token = |sub, jti| {
            encode(
                &Header::new(Algorithm::HS256),
                &Claims {
                    exp: expiry,
                    iss: "corecrux-rate-test",
                    aud: "corecrux",
                    sub,
                    scope: "provenance:write",
                    tenant_id: "tenant-rate",
                    jti,
                },
                &EncodingKey::from_secret(SECRET.as_bytes()),
            )
            .unwrap()
        };
        let headers = |token: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
            headers
        };

        let first =
            credential_rate_key(&state, &headers(&token(Some("stable-user"), "token-a")), "tenant-rate").unwrap();
        let rotated =
            credential_rate_key(&state, &headers(&token(Some("stable-user"), "token-b")), "tenant-rate").unwrap();
        assert_eq!(first, rotated, "rotating a JWT must not reset the principal budget");
        assert_ne!(
            first,
            credential_rate_key(&state, &headers(&token(Some("stable-user"), "token-c")), "other-tenant").unwrap(),
            "rate budgets remain tenant-scoped"
        );
        assert!(
            credential_rate_key(&state, &headers(&token(None, "token-without-principal")), "tenant-rate").is_err(),
            "hosted JWTs without sub/passport_id must fail closed"
        );

        for name in ["CORECRUXD_JWT_HS256_SECRET", "CORECRUXD_JWT_ISS", "CORECRUXD_JWT_AUD"] {
            std::env::remove_var(name);
        }
    }

    #[test]
    fn content_type_allowlist_matches_expected() {
        assert!(content_type_allowed("image/png"));
        assert!(content_type_allowed("video/mp4"));
        assert!(content_type_allowed("image/png; charset=binary")); // params stripped
        assert!(content_type_allowed("application/pdf"));
        assert!(!content_type_allowed("application/x-msdownload"));
        // #11: exact-match for application/pdf — a prefix would let this through.
        assert!(!content_type_allowed("application/pdf-evil"));
        // Family prefix requires a non-empty subtype.
        assert!(!content_type_allowed("image/"));
    }

    #[test]
    fn rate_limiter_blocks_after_window_budget() {
        let key = format!("rl-test-{}", uuid::Uuid::new_v4());
        for _ in 0..RATE_MAX_PER_WINDOW {
            assert!(rate_limit_ok(&key));
        }
        assert!(!rate_limit_ok(&key), "budget exhausted within the window");
        let response = rate_limited_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(axum::http::header::RETRY_AFTER).unwrap(), "60");
    }

    #[test]
    fn rate_limiter_bounds_key_cardinality_and_reclaims_expired_entries() {
        let start = Instant::now();
        let mut limiter = FixedWindowRateLimiter::new(Duration::from_secs(10), 2, 2);
        assert!(limiter.allow("credential-a", start));
        assert!(limiter.allow("credential-a", start));
        assert!(!limiter.allow("credential-a", start), "per-key budget must fail closed");
        assert!(limiter.allow("credential-b", start));
        assert!(
            !limiter.allow("credential-c", start),
            "new keys must fail closed at the cap"
        );
        assert!(
            limiter.allow("credential-c", start + Duration::from_secs(11)),
            "expired entries must be reclaimed"
        );
        assert_eq!(limiter.entries.len(), 1);
    }
}
