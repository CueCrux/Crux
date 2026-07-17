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
//! **Metering.** Op codes + rates are defined here behind a
//! [`ProvenanceMeter`] trait with a no-op default; rates are NOT public
//! pending OD-38 ratification. Wiring the no-op to the real `credit_meter`
//! reserve/spend rail is the follow-up (see `TODO(OD-38)`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;

use corecrux_receipts::{
    build_c2pa_manifest_v1, parse_jumbf_base64, sign_c2pa_manifest_via_signer, verify_c2pa_signed_manifest_es256_v1,
    ByokP256Signer, C2paManifestInputV1,
};

use super::{problem_response, require_http_any_scope, AppState, HeaderMap, State, StatusCode};

// ── Feature flag ───────────────────────────────────────────────────────────

/// Env flag gating the whole surface. Default OFF.
const FEATURE_ENV: &str = "CORECRUXD_FEATURE_PROVENANCE_API";

/// The M9 skeleton reads the flag from the environment directly rather than
/// threading a bool through `AppState`/`Config`: both structs have dozens of
/// literal construction sites across sibling-owned test files, and an env
/// read (a pattern already used by `gpu1`/`console`/`admin` handlers) keeps
/// this change purely additive. Fold into `Config` at M9-full once the
/// surrounding structs settle.
pub(super) fn provenance_api_enabled() -> bool {
    matches!(
        std::env::var(FEATURE_ENV).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("on")
    )
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

/// Naive per-key fixed-window rate limiter.
///
// ponytail: global-lock fixed-window counter; swap for the shared
// `crux_router::quota::QuotaLedger` (already in `AppState`) if throughput or
// fairness matters. Adequate for a BYOK beta gate.
const RATE_WINDOW: Duration = Duration::from_secs(60);
const RATE_MAX_PER_WINDOW: u32 = 120;

fn rate_limiter() -> &'static Mutex<HashMap<String, (Instant, u32)>> {
    static LIMITER: OnceLock<Mutex<HashMap<String, (Instant, u32)>>> = OnceLock::new();
    LIMITER.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns `true` if the call is within budget for `key`, `false` if the
/// per-key window is exhausted.
fn rate_limit_ok(key: &str) -> bool {
    let now = Instant::now();
    let mut map = match rate_limiter().lock() {
        Ok(g) => g,
        // A poisoned limiter must fail closed on the counter, not panic.
        Err(_) => return false,
    };
    let entry = map.entry(key.to_string()).or_insert((now, 0));
    if now.duration_since(entry.0) > RATE_WINDOW {
        *entry = (now, 0);
    }
    if entry.1 >= RATE_MAX_PER_WINDOW {
        return false;
    }
    entry.1 += 1;
    true
}

// ── Metering (OD-38 pending; rates NOT public) ─────────────────────────────

/// Metered provenance operations. Rates are in **milli-credits** (1000 =
/// 1 Cr) to represent the sub-credit verify rate faithfully.
///
/// Rates (NOT public — pending OD-38 ratification, no pricing-page use):
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

    /// Milli-credits (1000 = 1 Cr). NOT a public price (OD-38).
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
/// TODO(OD-38): replace with a `credit_meter`-backed impl that reserves +
/// spends `op.milli_credits()` against `state.credit_meter` for `tenant`
/// (rounding sub-credit ops per the ratified rounding rule), once OD-38 sets
/// the public rates. The trait boundary means the handlers do not change.
pub(super) struct NoopMeter;

impl ProvenanceMeter for NoopMeter {
    fn on_op(&self, op: ProvenanceOp, tenant: &str) {
        tracing::info!(
            target: "provenance.meter",
            op = op.op_code(),
            milli_credits = op.milli_credits(),
            tenant = tenant,
            pricing_public = false,
            "provenance op metered (OD-38 pending — rate not public, no charge in skeleton)"
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

// NB: deliberately NOT `Debug`/`Serialize` — this struct holds the caller's
// private key PEM, and a derived Debug/echo is the classic way key material
// leaks into a log line or error body.
// TODO(flag-enable, key-hardening): deserialize `signing_key_pem` into a
// zeroizing secret wrapper and require loopback or authenticated-TLS
// termination (startup validation) before the flag may enable, so the raw PEM
// never rests un-wiped in the Axum JSON buffer. See PR body §remaining.
#[derive(Deserialize)]
pub(super) struct SignRequest {
    /// Base64 asset bytes to attest.
    pub content_b64: String,
    /// Asset MIME type (validated against the allowlist).
    pub content_type: Option<String>,
    /// BYOK P-256 private key PEM (PKCS#8 or SEC1). Never stored or echoed.
    pub signing_key_pem: String,
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

#[derive(Debug, Deserialize)]
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
#[derive(Debug, Serialize)]
pub(super) struct ManifestClaims {
    pub manifest_id: String,
    pub claim_generator: String,
    pub content_type: Option<String>,
    pub unverified_crown_receipt_id: String,
    pub unverified_signer_passport: String,
    pub signer_key_id: String,
}

#[derive(Debug, Serialize)]
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
    /// Machine-readable trust posture. The skeleton never validates the cert
    /// chain to a root/trust-list, so this is `"untrusted_presented_leaf"`
    /// (or `"unsigned"` / `"external_key_required"`).
    pub trust_status: String,
    /// Always false here — no chain-to-root validation.
    pub chain_validated: bool,
    /// Always false here — no identity/trust-list validation.
    pub identity_trusted: bool,
    // ── Overall ──
    /// True ONLY when the envelope is internally consistent AND asset bytes
    /// were supplied AND they match the bound hash. Never true on
    /// internal-consistency alone, and never implies trust.
    pub ok: bool,
    pub manifest_claims: Option<ManifestClaims>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ProvenanceReceiptV1 {
    pub alg: String,
    pub signed_by: String,
    pub body_hash: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub(super) struct VerifyRecordResponse {
    pub verification: VerifyResponse,
    pub record_id: String,
    pub recorded_at: String,
    pub receipt: ProvenanceReceiptV1,
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
        &req.signing_key_pem,
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

fn verify_inner(req: &VerifyRequest) -> Result<VerifyResponse, ProvErr> {
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
        let integrity_valid = report.canonical_hash_match && report.signature_valid;
        let content_hash_match = content_supplied.then_some(report.content_hash_match);
        // Overall ok requires integrity AND a checked+matching asset binding.
        let ok = integrity_valid && content_hash_match == Some(true);
        let mut notes = vec![
            "integrity_valid checks the envelope against the PRESENTED leaf only; the leaf, its chain, \
             and all manifest_claims are UNTRUSTED — no chain-to-root/identity validation is performed"
                .to_string(),
        ];
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
            trust_status: "untrusted_presented_leaf".to_string(),
            chain_validated: false,
            identity_trusted: false,
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

fn do_verify(meter: &dyn ProvenanceMeter, tenant: &str, req: &VerifyRequest) -> Result<VerifyResponse, ProvErr> {
    let resp = verify_inner(req)?;
    meter.on_op(ProvenanceOp::Verify, tenant);
    Ok(resp)
}

fn do_verify_record(
    meter: &dyn ProvenanceMeter,
    tenant: &str,
    req: &VerifyRequest,
    passport_key_path: &Path,
    passport_fpr: &str,
    data_dir: &Path,
) -> Result<VerifyRecordResponse, ProvErr> {
    let verification = verify_inner(req)?;

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
    // TODO(flag-enable, #9): reserve credits BEFORE persisting (idempotent,
    // keyed by op-id + payload hash) and settle after returning success, so a
    // retained record can never be minted unpaid. NoopMeter charges nothing,
    // so append-then-meter is inert in the skeleton.
    append_record(data_dir, &line).map_err(|e| {
        tracing::error!(error = %e, "provenance record persist failed");
        ProvErr::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error persisting verification record",
        )
    })?;

    meter.on_op(ProvenanceOp::VerifyRecord, tenant);

    Ok(VerifyRecordResponse {
        verification,
        record_id,
        recorded_at,
        receipt,
    })
}

fn records_path(data_dir: &Path) -> PathBuf {
    data_dir.join("provenance").join("verification-records.jsonl")
}

// TODO(flag-enable, #10): this is an unbounded, un-rotated, un-quota'd global
// JSONL with a non-exclusive append. Before flag-enable add per-tenant quota,
// rotation, an exclusive/durable append (lock + fsync) or reuse the signed
// append-only substrate, and run the CPU/file work under spawn_blocking.
fn append_record(data_dir: &Path, line: &serde_json::Value) -> std::io::Result<()> {
    use std::io::Write as _;
    let path = records_path(data_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut serialized = serde_json::to_vec(line)?;
    serialized.push(b'\n');
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
    file.write_all(&serialized)?;
    Ok(())
}

// ── Axum handlers (flag → auth → rate-limit → inner) ───────────────────────

fn tenant_from(headers: &HeaderMap, body_tenant: Option<&str>) -> String {
    headers
        .get("x-corecrux-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| body_tenant.map(str::to_string))
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "byok-anonymous".to_string())
}

fn not_enabled() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        format!("provenance API disabled (set {FEATURE_ENV}=1)"),
    )
}

/// Any-of scopes accepted across the whole provenance surface. Kept in sync
/// with the `route_auth::classify_route` contract for `/v1/provenance`.
const PROVENANCE_SCOPES: &[&str] = &["provenance:write", "admin:write"];

/// Common pre-handler gate: flag → refuse spoofable auth → scope → rate limit.
/// Returns `Some(response)` to short-circuit, `None` to proceed. (`Option`
/// rather than `Result<(), Response>` — the axum `Response` error variant is
/// large enough to trip `clippy::result_large_err`.)
///
/// The global `route_auth` middleware also enforces the classify_route
/// contract before body extraction in `enforce` mode; this in-handler guard is
/// defence-in-depth (and the sole gate when route_auth is not in enforce mode).
// TODO(flag-enable, #7): resolve `tenant` from authenticated token claims
// (require_http_any_scope_for_tenant) rather than trusting the header/body,
// and key the rate limiter on the authenticated subject + client IP with a
// bounded/evicting map — the current global map trusts a caller-controlled
// string and never evicts.
fn guard(state: &AppState, headers: &HeaderMap, tenant: &str) -> Option<Response> {
    if !provenance_api_enabled() {
        return Some(not_enabled());
    }
    // A metered, key-custody-adjacent surface must not run without real auth.
    if state.auth.mode() == crate::auth::AuthMode::Off {
        return Some(problem_response(
            StatusCode::FORBIDDEN,
            "provenance API requires an authenticated auth mode (refusing AuthMode::Off)",
        ));
    }
    if let Err(problem) = require_http_any_scope(&state.auth, headers, PROVENANCE_SCOPES) {
        return Some(problem.into_response());
    }
    if !rate_limit_ok(tenant) {
        return Some(problem_response(
            StatusCode::TOO_MANY_REQUESTS,
            "per-key rate limit exceeded; retry after the current window",
        ));
    }
    None
}

pub(super) async fn post_provenance_sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SignRequest>,
) -> Response {
    let tenant = tenant_from(&headers, body.tenant_id.as_deref());
    if let Some(resp) = guard(&state, &headers, &tenant) {
        return resp;
    }
    match do_sign(&NoopMeter, &tenant, &body) {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err(e) => e.into_response(),
    }
}

pub(super) async fn post_provenance_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> Response {
    let tenant = tenant_from(&headers, body.tenant_id.as_deref());
    if let Some(resp) = guard(&state, &headers, &tenant) {
        return resp;
    }
    match do_verify(&NoopMeter, &tenant, &body) {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => e.into_response(),
    }
}

pub(super) async fn post_provenance_verify_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VerifyRequest>,
) -> Response {
    let tenant = tenant_from(&headers, body.tenant_id.as_deref());
    if let Some(resp) = guard(&state, &headers, &tenant) {
        return resp;
    }
    match do_verify_record(
        &NoopMeter,
        &tenant,
        &body,
        &state.passport_key_path,
        &state.passport_fpr,
        &state.data_dir,
    ) {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err(e) => e.into_response(),
    }
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
            signing_key_pem: key_pem,
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
    fn flag_defaults_off() {
        std::env::remove_var(FEATURE_ENV);
        assert!(!provenance_api_enabled());
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
        assert!(!verify.chain_validated);
        assert!(!verify.identity_trusted);
        // Manifest values are surfaced as UNVERIFIED claims.
        assert!(verify.manifest_claims.is_some());

        let calls = meter.calls.lock().unwrap();
        assert_eq!(calls[0], ("provenance.sign".to_string(), "tenant-a".to_string()));
        assert_eq!(calls[1], ("provenance.verify".to_string(), "tenant-a".to_string()));
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
            signing_key_pem: "garbage".to_string(),
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

        let resp = do_verify_record(
            &meter,
            "tenant-r",
            &VerifyRequest {
                manifest_envelope_b64: Some(signed.manifest_envelope_b64),
                content_b64: Some(b64(content)),
                tenant_id: None,
            },
            &key_path,
            &fpr,
            data_dir,
        )
        .unwrap();

        assert!(resp.verification.ok);
        assert!(resp.record_id.starts_with("prov_vr_"));
        assert_eq!(resp.receipt.alg, "ed25519");
        assert_eq!(resp.receipt.signed_by, fpr);
        assert!(resp.receipt.body_hash.starts_with("blake3:"));
        assert!(!resp.receipt.signature.is_empty());

        // The JSONL line is retained on disk.
        let mut buf = String::new();
        std::fs::File::open(records_path(data_dir))
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
        let resp = do_verify_record(
            &meter,
            "t",
            &VerifyRequest {
                manifest_envelope_b64: Some(signed.manifest_envelope_b64),
                content_b64: None, // no asset supplied
                tenant_id: None,
            },
            &key_path,
            &fpr,
            data_dir,
        )
        .unwrap();
        assert!(
            !resp.verification.ok,
            "record must not claim overall success without asset match"
        );
        assert!(!resp.verification.asset_binding_checked);
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
}
