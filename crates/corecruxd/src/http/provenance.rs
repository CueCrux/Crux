// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
use std::sync::{Mutex, OnceLock};
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
/// Optional verification-record retention window. Unset means no automatic
/// deletion; an operator must choose an explicit 1..=3,650-day lifecycle.
const RETENTION_DAYS_ENV: &str = "CORECRUXD_PROVENANCE_RETENTION_DAYS";
const MAX_RETENTION_DAYS: u32 = 3_650;
const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);
const RETENTION_SWEEP_MAX_TENANTS: usize = 10_000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ProvenanceTrustPolicy {
    trusted_leaf_sha256: HashSet<String>,
}

impl ProvenanceTrustPolicy {
    fn from_env() -> Result<Self, String> {
        Self::parse(std::env::var(TRUSTED_LEAF_SHA256_ENV).ok().as_deref())
    }

    fn parse(raw: Option<&str>) -> Result<Self, String> {
        let mut trusted_leaf_sha256 = HashSet::new();
        let mut pin_count = 0usize;
        for raw_pin in raw.unwrap_or_default().split(',') {
            let raw_pin = raw_pin.trim();
            if raw_pin.is_empty() {
                continue;
            }
            pin_count += 1;
            if pin_count > MAX_TRUSTED_LEAF_PINS {
                return Err(format!(
                    "{TRUSTED_LEAF_SHA256_ENV} exceeds the {MAX_TRUSTED_LEAF_PINS}-pin limit"
                ));
            }
            let without_prefix = raw_pin
                .strip_prefix("sha256:")
                .or_else(|| raw_pin.strip_prefix("SHA256:"))
                .unwrap_or(raw_pin);
            let normalized = without_prefix.replace(':', "").to_ascii_lowercase();
            if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!(
                    "{TRUSTED_LEAF_SHA256_ENV} entries must be 64-hex SHA-256 fingerprints"
                ));
            }
            trusted_leaf_sha256.insert(normalized);
        }
        Ok(Self { trusted_leaf_sha256 })
    }

    fn trusts_leaf(&self, fingerprint: &str) -> bool {
        self.trusted_leaf_sha256.contains(fingerprint)
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

/// Per-credential fixed-window rate limiter. The credential itself is hashed
/// before it becomes a key, and the table has a hard cardinality bound so
/// attacker-controlled tenant/token churn cannot grow process memory without
/// limit. A later hosted pass can add a trusted-proxy-aware client-IP bucket.
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
    // ── Trust: NOT established by this BYOK skeleton ──
    /// Machine-readable trust posture. An operator-pinned, currently-valid
    /// exact leaf can be `"trusted_leaf_allowlist"`; CA-chain validation is
    /// still absent. Otherwise `"untrusted_presented_leaf"`, `"unsigned"`,
    /// or `"external_key_required"`.
    pub trust_status: String,
    /// SHA-256 of the exact DER leaf embedded in `x5chain`, when present.
    /// Safe to compare with an operator trust list; not a trust claim alone.
    #[serde(default)]
    pub signer_leaf_sha256: Option<String>,
    /// Always false here — no chain-to-root validation.
    pub chain_validated: bool,
    /// True only for a valid exact leaf pinned by the operator and a valid
    /// signature over the canonical envelope body.
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
        let identity_trusted = leaf_pinned && leaf_current && integrity_valid;
        let trust_status = if identity_trusted {
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
        let mut notes = if identity_trusted {
            vec![
                "the exact currently-valid leaf certificate is operator-pinned and the envelope signature verifies; \
                 CA-chain validation is not performed"
                    .to_string(),
            ]
        } else {
            vec![
                "integrity_valid checks the envelope against the PRESENTED leaf only; the leaf, its chain, \
                 and all manifest_claims are UNTRUSTED unless trust_status says trusted_leaf_allowlist"
                    .to_string(),
            ]
        };
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
            chain_validated: false,
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
            | RecordStoreError::LockPoisoned => (
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
    recorded_at: String,
}

struct RetentionAudit {
    summary: RecordRetentionSweepSummary,
    receipt_id: Option<String>,
}

struct RecordRewritePlan {
    path: PathBuf,
    retained_bytes: Vec<u8>,
    records_dropped: usize,
    expired_records_held: usize,
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

fn records_path(data_dir: &Path, tenant: &str) -> PathBuf {
    tenant_records_dir(data_dir, tenant).join("verification-records.jsonl")
}

fn record_append_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn is_retention_temp_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(".verification-records-retention-"))
        && path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("tmp"))
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

    let _process_guard = record_append_lock()
        .lock()
        .map_err(|_| RecordStoreError::LockPoisoned)?;
    let tenant_dir = tenant_records_dir(data_dir, tenant);
    let tenant_dir_preexisting = tenant_dir.exists();
    std::fs::create_dir_all(&tenant_dir)?;
    let tenant_dir_metadata = std::fs::symlink_metadata(&tenant_dir)?;
    if tenant_dir_metadata.file_type().is_symlink() || !tenant_dir_metadata.is_dir() {
        return Err(RecordStoreError::UnsafePath);
    }
    set_private_directory_permissions(&tenant_dir)?;

    let lock_path = tenant_dir.join(".append.lock");
    reject_symlink_or_non_file(&lock_path)?;
    let lock_file = open_private_append_lock(&lock_path)?;
    validate_and_harden_open_file(&lock_file)?;
    lock_file.lock_exclusive()?;
    cleanup_retention_temp_files(&tenant_dir)?;

    let active_path = records_path(data_dir, tenant);
    let mut total_bytes = 0_u64;
    let mut directory_entries = 0_usize;
    let mut active_bytes = None;
    let mut jsonl_paths = Vec::new();
    for entry in std::fs::read_dir(&tenant_dir)? {
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
        let is_jsonl = entry_path.extension().and_then(|ext| ext.to_str()) == Some("jsonl");
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
        sync_directory(&tenant_dir)?;
    }

    let mut file = open_private_append_file(&active_path)?;
    validate_and_harden_open_file(&file)?;
    file.write_all(&serialized)?;
    file.sync_all()?;
    sync_directory(&tenant_dir)?;
    if !tenant_dir_preexisting {
        sync_directory_chain(&tenant_dir, data_dir)?;
    }
    Ok(RecordAppendOutcome::Appended)
}

fn sweep_expired_verification_records(
    data_dir: &Path,
    tenant: &str,
    retention_days: u32,
    now: chrono::DateTime<chrono::Utc>,
    legal_holds: &[corecrux_memory::LegalHold],
) -> RecordRetentionSweepRun {
    let cutoff = now - chrono::Duration::days(i64::from(retention_days));
    let mut summary = RecordRetentionSweepSummary {
        retention_days,
        cutoff: cutoff.to_rfc3339(),
        tenant_hash: tenant_records_hash(tenant),
        records_dropped: 0,
        expired_records_held: 0,
        files_rewritten: 0,
        files_removed: 0,
    };
    let error = sweep_expired_verification_records_inner(
        data_dir,
        tenant,
        cutoff,
        legal_holds,
        RecordStoreLimits::default(),
        &mut summary,
    )
    .err();
    RecordRetentionSweepRun { summary, error }
}

fn sweep_expired_verification_records_inner(
    data_dir: &Path,
    tenant: &str,
    cutoff: chrono::DateTime<chrono::Utc>,
    legal_holds: &[corecrux_memory::LegalHold],
    limits: RecordStoreLimits,
    summary: &mut RecordRetentionSweepSummary,
) -> Result<(), RecordStoreError> {
    use fs2::FileExt as _;
    use std::io::BufRead as _;

    let _process_guard = record_append_lock()
        .lock()
        .map_err(|_| RecordStoreError::LockPoisoned)?;
    let tenant_dir = tenant_records_dir(data_dir, tenant);
    let tenant_dir_metadata = match std::fs::symlink_metadata(&tenant_dir) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    if tenant_dir_metadata.file_type().is_symlink() || !tenant_dir_metadata.is_dir() {
        return Err(RecordStoreError::UnsafePath);
    }
    set_private_directory_permissions(&tenant_dir)?;

    let lock_path = tenant_dir.join(".append.lock");
    reject_symlink_or_non_file(&lock_path)?;
    let lock_file = open_private_append_lock(&lock_path)?;
    validate_and_harden_open_file(&lock_file)?;
    lock_file.lock_exclusive()?;
    cleanup_retention_temp_files(&tenant_dir)?;

    // Validate and plan the complete tenant rewrite before deleting anything.
    // The store is already capped at 64 MiB per tenant, which bounds this
    // retained-byte plan while allowing atomic per-file replacement.
    let mut plans = Vec::new();
    let mut directory_entries = 0usize;
    let mut total_bytes = 0u64;
    for entry in std::fs::read_dir(&tenant_dir)? {
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
        if path.extension().and_then(|extension| extension.to_str()) != Some("jsonl") {
            return Err(RecordStoreError::UnsafePath);
        }
        total_bytes = total_bytes.saturating_add(entry.metadata()?.len());
        if total_bytes > limits.tenant_max_bytes {
            return Err(RecordStoreError::TenantQuotaExceeded {
                needed: total_bytes,
                max: limits.tenant_max_bytes,
            });
        }

        reject_symlink_or_non_file(&path)?;
        let file = open_private_read_file(&path)?;
        validate_and_harden_open_file(&file)?;
        let mut reader = std::io::BufReader::new(file);
        let mut retained_bytes = Vec::new();
        let mut records_dropped = 0usize;
        let mut expired_records_held = 0usize;
        loop {
            let mut encoded_line = Vec::new();
            let bytes_read = reader.read_until(b'\n', &mut encoded_line)?;
            if bytes_read == 0 {
                break;
            }
            if !encoded_line.ends_with(b"\n")
                || u64::try_from(encoded_line.len()).unwrap_or(u64::MAX) > limits.max_line_bytes
            {
                return Err(RecordStoreError::CorruptRecord);
            }
            let json_bytes = &encoded_line[..encoded_line.len() - 1];
            if json_bytes.iter().all(u8::is_ascii_whitespace) {
                retained_bytes.extend_from_slice(&encoded_line);
                continue;
            }
            let stored: serde_json::Value =
                serde_json::from_slice(json_bytes).map_err(|_| RecordStoreError::CorruptRecord)?;
            if stored.get("schema").and_then(serde_json::Value::as_str)
                != Some("cuecrux.provenance.verification_record.v1")
                || stored.get("tenant_id").and_then(serde_json::Value::as_str) != Some(tenant)
            {
                return Err(RecordStoreError::CorruptRecord);
            }
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
            if recorded_at >= cutoff {
                retained_bytes.extend_from_slice(&encoded_line);
                continue;
            }

            let entity = format!("provenance::verification_record::{record_id}");
            if legal_holds.iter().any(|hold| hold.covers(tenant, &entity)) {
                retained_bytes.extend_from_slice(&encoded_line);
                expired_records_held = expired_records_held.saturating_add(1);
            } else {
                records_dropped = records_dropped.saturating_add(1);
            }
        }
        if records_dropped > 0 {
            plans.push(RecordRewritePlan {
                path,
                retained_bytes,
                records_dropped,
                expired_records_held,
            });
        } else {
            summary.expired_records_held = summary.expired_records_held.saturating_add(expired_records_held);
        }
    }

    for plan in plans {
        if plan.retained_bytes.is_empty() {
            std::fs::remove_file(&plan.path)?;
            summary.records_dropped = summary.records_dropped.saturating_add(plan.records_dropped);
            summary.expired_records_held = summary.expired_records_held.saturating_add(plan.expired_records_held);
            summary.files_removed = summary.files_removed.saturating_add(1);
            sync_directory(&tenant_dir)?;
            continue;
        }

        let temp_path = tenant_dir.join(format!(".verification-records-retention-{}.tmp", uuid::Uuid::new_v4()));
        let rewrite_result = (|| -> Result<(), RecordStoreError> {
            use std::io::Write as _;

            let mut temp_file = open_private_new_file(&temp_path)?;
            validate_and_harden_open_file(&temp_file)?;
            temp_file.write_all(&plan.retained_bytes)?;
            temp_file.sync_all()?;
            std::fs::rename(&temp_path, &plan.path)?;
            summary.records_dropped = summary.records_dropped.saturating_add(plan.records_dropped);
            summary.expired_records_held = summary.expired_records_held.saturating_add(plan.expired_records_held);
            summary.files_rewritten = summary.files_rewritten.saturating_add(1);
            sync_directory(&tenant_dir)?;
            Ok(())
        })();
        if rewrite_result.is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
        rewrite_result?;
    }
    Ok(())
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
    if !file.metadata()?.is_file() {
        return Err(RecordStoreError::UnsafePath);
    }
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

fn credential_rate_key(headers: &HeaderMap, tenant: &str) -> String {
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
    format!("{tenant}:{credential_hash}")
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
    status: &'static str,
) -> RetentionAudit {
    let sweep_id = format!("prov_ret_{}", uuid::Uuid::new_v4());
    let payload = build_record_retention_receipt(&summary, &sweep_id, status);
    let receipt_id = super::observations::mint_governance_receipt(
        state,
        "__governance__::retention",
        actor,
        "retention.provenance_records",
        &payload,
    );
    RetentionAudit { summary, receipt_id }
}

fn build_record_retention_receipt<'a>(
    summary: &'a RecordRetentionSweepSummary,
    sweep_id: &'a str,
    status: &'a str,
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
    if !rate_limit_ok(&credential_rate_key(headers, &tenant)) {
        return Err(problem_response(
            StatusCode::TOO_MANY_REQUESTS,
            "per-key rate limit exceeded; retry after the current window",
        ));
    }
    Ok(tenant)
}

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
        let sweep = tokio::task::spawn_blocking(move || {
            let store = fact_store.blocking_read();
            let legal_holds: Vec<_> = store
                .active_legal_holds()
                .into_iter()
                .filter(|hold| hold.tenant_id == sweep_tenant)
                .collect();
            let run = sweep_expired_verification_records(
                &sweep_data_dir,
                &sweep_tenant,
                retention_days,
                chrono::Utc::now(),
                &legal_holds,
            );
            drop(store);
            let status = if run.error.is_some() { "failed" } else { "completed" };
            let audit = (run.summary.records_dropped > 0)
                .then(|| mint_record_retention_receipt(&receipt_state, &actor, run.summary.clone(), status));
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
        let policy = ProvenanceTrustPolicy::parse(Some(&format!("SHA256:{colon_fingerprint}"))).unwrap();
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
            ProvenanceTrustPolicy::parse(None).unwrap(),
            ProvenanceTrustPolicy::default()
        );
        assert_eq!(
            ProvenanceTrustPolicy::parse(Some("not-a-fingerprint")).unwrap_err(),
            format!("{TRUSTED_LEAF_SHA256_ENV} entries must be 64-hex SHA-256 fingerprints")
        );
        let too_many = (0..=MAX_TRUSTED_LEAF_PINS)
            .map(|index| format!("{index:064x}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            ProvenanceTrustPolicy::parse(Some(&too_many)).unwrap_err(),
            format!("{TRUSTED_LEAF_SHA256_ENV} exceeds the {MAX_TRUSTED_LEAF_PINS}-pin limit")
        );
        let duplicate_overflow = std::iter::repeat_n("0".repeat(64), MAX_TRUSTED_LEAF_PINS + 1)
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            ProvenanceTrustPolicy::parse(Some(&duplicate_overflow)).unwrap_err(),
            format!("{TRUSTED_LEAF_SHA256_ENV} exceeds the {MAX_TRUSTED_LEAF_PINS}-pin limit")
        );
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

    fn retention_record_line(tenant: &str, record_id: &str, recorded_at: &str) -> serde_json::Value {
        json!({
            "schema": "cuecrux.provenance.verification_record.v1",
            "tenant_id": tenant,
            "record_id": record_id,
            "recorded_at": recorded_at,
        })
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

        let first = sweep_expired_verification_records(tmp.path(), tenant, 30, now, &[hold.clone()]);
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

        let second = sweep_expired_verification_records(tmp.path(), tenant, 30, now, &[hold]);
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

        let sweep = sweep_expired_verification_records(tmp.path(), tenant, 30, now, &[hold]);

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

        let sweep = sweep_expired_verification_records(tmp.path(), tenant, 30, now, &[]);

        assert!(matches!(sweep.error, Some(RecordStoreError::CorruptRecord)));
        assert_eq!(sweep.summary.records_dropped, 0);
        assert_eq!(std::fs::read(records_path(tmp.path(), tenant)).unwrap(), before);
    }

    #[test]
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

        let sweep = sweep_expired_verification_records(tmp.path(), tenant, 30, now, &[]);

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
        ))
        .unwrap();

        assert!(encoded.contains("configured_retention_window"));
        assert!(encoded.contains("\"records_dropped\":3"));
        assert!(encoded.contains(&summary.tenant_hash));
        assert!(!encoded.contains("customer-tenant-secret"));
        assert!(!encoded.contains("provenance::verification_record::"));
        assert!(!encoded.contains("old-drop"));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verify_record_retention_mints_governance_receipt_and_surfaces_headers() {
        use crate::auth::AuthMode;

        std::env::set_var(FEATURE_ENV, "1");
        std::env::set_var(RETENTION_DAYS_ENV, "30");
        std::env::remove_var(TRUSTED_LEAF_SHA256_ENV);
        let mut state = crate::http::tests::test_app_state_with_auth(1, AuthMode::DevScopes);
        let passport_key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).unwrap();
        state.passport_fpr = passport_key.passport_fpr().to_string();
        let tenant = format!("tenant-retention-http-{}", uuid::Uuid::new_v4());
        append_record(
            &state.data_dir,
            &tenant,
            &retention_record_line(&tenant, "expired-http-record", "2026-01-01T00:00:00Z"),
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
