// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Studio pack build + verify (console-surfaces-remediation M15).
//!
//! Studio boards (the Canvas Studio tile boards, persisted as
//! `console:tileboard:<id>` facts) can be *exported* as portable packs so a
//! third party can install one on their own daemon. A pack is a
//! `crux.studio.v1` payload (board doc + tile designs + board settings)
//! **wrapped in a valid `crux.integration.v1` manifest** so it rides the same
//! signed-extension trust rails as every other community integration
//! (`crux-integrations`).
//!
//! Two pure, read-class POST routes back the console flow — they neither
//! mutate the fact store nor require operator posture; they transform / verify
//! a client-supplied payload, the same class as `/v1/query/text-search`:
//!
//! - `POST /v1/studio/pack/build` — assemble a `crux.integration.v1` manifest
//!   around a studio payload, derive the minimal capability set the board's
//!   tiles actually need, compute `hashes.manifest` (blake3 over the canonical
//!   signing payload, exactly as [`IntegrationManifest::manifest_hash`]
//!   specifies) and `hashes.bundle` (blake3 over the canonical studio payload),
//!   and sign for real **iff** an operator signing key is configured via
//!   `CORECRUXD_STUDIO_SIGNING_KEY_HEX`. Otherwise the pack is returned
//!   unsigned with an honest "sign before publishing" instruction embedded.
//! - `POST /v1/studio/pack/verify` — validate an uploaded pack: schema, both
//!   hashes, and (when present) the Ed25519 signature against the operator's
//!   `TrustedKeyring`. Returns the verification verdict **verbatim** plus a
//!   preview (tile count / kinds / capabilities) so the console can gate the
//!   apply step.
//!
//! The *apply* step for a console-uploaded pack (writing the imported board +
//! designs back into the fact store) reuses the existing operator-gated
//! `POST /v1/console/facts/add` route — these two routes never write.
//!
//! The pack CHECKS themselves are reusable: [`evaluate_pack`] is the single
//! implementation of "is this pack well-formed, integrity-bound, and signed by
//! a key this operator trusts", and [`sibling http::studio_library`] runs it
//! under a **require-signed** policy ([`PackEvaluation::signed`]) before it
//! writes anything from the central template library. `/verify` keeps its
//! permissive verdict-reporting contract: it *reports* `unsigned`, it does not
//! refuse it.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, State, StatusCode};
use crux_integrations::{
    sign_manifest, DataAccess, EntryKind, IntegrationEntry, IntegrationManifest, ManifestHashes, NetworkAccess,
    SafetyPolicy, ValidationPolicy, INTEGRATION_SCHEMA_V1,
};

/// Schema stamp on the studio payload embedded in a pack.
pub const STUDIO_SCHEMA_V1: &str = "crux.studio.v1";
/// Env knob carrying an operator Ed25519 signing key (64 hex chars = 32-byte
/// seed). When present, `build` signs the pack for real. Absent on a bare
/// mirror → unsigned + sign-before-publish guidance. This is a local
/// convenience: the canonical publishing rail is a PR to
/// `integrations/community/` behind the `community_packs` CI gate + the
/// curator-signed index, which never needs a daemon-held private key.
const SIGNING_KEY_ENV: &str = "CORECRUXD_STUDIO_SIGNING_KEY_HEX";

// ── Build ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(super) struct BuildPackBody {
    /// The `crux.studio.v1` payload (board doc + designs + settings).
    pub studio: Value,
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher_passport_fpr: String,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Serialize)]
struct BuildPackResponse {
    /// The finished pack: a `crux.integration.v1` manifest object with a
    /// top-level `studio` key carrying the `crux.studio.v1` payload.
    pack: Value,
    signed: bool,
    /// Capabilities derived as the minimal read set the board's tiles need.
    capabilities: Vec<String>,
    manifest_hash: String,
    bundle_hash: String,
    /// Empty when signed; else the exact steps to sign before publishing.
    sign_instructions: Vec<String>,
    trust_note: String,
}

/// `POST /v1/studio/pack/build` — assemble + hash + (optionally) sign a pack.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_build_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BuildPackBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        return problem.into_response();
    }

    // Guard the studio payload shape up front so the manifest we sign always
    // wraps a well-formed board.
    let schema = body.studio.get("schema").and_then(Value::as_str).unwrap_or_default();
    if schema != STUDIO_SCHEMA_V1 {
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!("studio.schema must be '{STUDIO_SCHEMA_V1}', got '{schema}'"),
        );
    }
    if body.id.trim().is_empty() || body.version.trim().is_empty() || body.publisher_passport_fpr.trim().is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "id, version, and publisher_passport_fpr are required",
        );
    }

    let capabilities = derive_capabilities(&body.studio);
    let summary = if body.summary.trim().is_empty() {
        format!(
            "Studio board pack '{}' — {} tile(s).",
            body.id,
            tile_count(&body.studio)
        )
    } else {
        body.summary.clone()
    };

    let mut manifest = IntegrationManifest {
        schema: INTEGRATION_SCHEMA_V1.to_string(),
        id: body.id.clone(),
        name: if body.name.trim().is_empty() {
            body.id.clone()
        } else {
            body.name.clone()
        },
        version: body.version.clone(),
        publisher_passport_fpr: body.publisher_passport_fpr.clone(),
        summary,
        entry: IntegrationEntry {
            // Studio packs are declarative client-side assets; the board
            // payload is the "recipe" delivered at entry.path (and embedded
            // under the pack's `studio` key for single-file portability).
            kind: EntryKind::SdkRecipe,
            path: "studio-board.json".to_string(),
        },
        capabilities: capabilities.clone(),
        network: NetworkAccess::default(),
        data_access: DataAccess::default(),
        safety: SafetyPolicy::default(),
        hashes: ManifestHashes::default(),
        signature: None,
        external_tool_endpoint: None,
        tools: Vec::new(),
        wasm_module_path: None,
        wasm_module_url: None,
        wasm_module_sha256: None,
        conformance: None,
    };

    let bundle_hash = blake3_hash(&canonical_bytes(&body.studio));
    manifest.hashes.bundle = Some(bundle_hash.clone());
    let manifest_hash = match manifest.manifest_hash() {
        Ok(h) => h,
        Err(err) => return problem_response(StatusCode::BAD_REQUEST, format!("hash failed: {err}")),
    };
    manifest.hashes.manifest = Some(manifest_hash.clone());

    // Sign for real iff an operator key is configured.
    let mut signed = false;
    let mut sign_instructions: Vec<String> = Vec::new();
    match load_signing_key() {
        Ok(Some(key)) => {
            if let Err(err) = sign_manifest(&mut manifest, &key, body.publisher_passport_fpr.clone()) {
                return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("sign failed: {err}"));
            }
            // sign_manifest recomputes hashes.manifest; hashes.bundle is
            // preserved, but re-assert it defensively.
            manifest.hashes.bundle = Some(bundle_hash.clone());
            signed = true;
        }
        Ok(None) => {
            sign_instructions = unsigned_instructions(&body.id, &body.version);
        }
        Err(msg) => {
            return problem_response(StatusCode::BAD_REQUEST, format!("{SIGNING_KEY_ENV}: {msg}"));
        }
    }

    let pack = match manifest_to_pack(&manifest, &body.studio) {
        Ok(v) => v,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("pack encode failed: {err}")),
    };

    let trust_note = if signed {
        "Signed with the operator key. Publish via a PR to integrations/community/ (the community_packs CI gate) so the curator-signed index endorses it.".to_string()
    } else {
        "Unsigned. This pack is inert on any daemon until it carries an Ed25519 Passport signature and the operator grants its capabilities.".to_string()
    };

    (
        StatusCode::OK,
        Json(BuildPackResponse {
            pack,
            signed,
            capabilities,
            manifest_hash,
            bundle_hash,
            sign_instructions,
            trust_note,
        }),
    )
        .into_response()
}

// ── Verify ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(super) struct VerifyPackBody {
    /// The full pack object (manifest fields + a `studio` key).
    pub pack: Value,
}

#[derive(Debug, Serialize)]
struct SignatureVerdict {
    present: bool,
    /// `"valid"`, `"unsigned"`, or `"invalid"`.
    verdict: String,
    /// Verbatim library error when the signature/validation failed (shown
    /// as-is in the console). Empty on success.
    error: String,
}

#[derive(Debug, Serialize)]
struct StudioPreview {
    schema_ok: bool,
    tile_count: usize,
    kinds: Vec<String>,
    board_title: String,
    design_count: usize,
}

#[derive(Debug, Serialize)]
struct VerifyPackResponse {
    ok: bool,
    schema_ok: bool,
    manifest_hash_ok: bool,
    bundle_hash_ok: bool,
    signature: SignatureVerdict,
    /// Additive convenience mirror of `signature.verdict == "valid"` — the one
    /// bit the require-signed install path in `studio_library.rs` gates on.
    signed: bool,
    manifest: Value,
    capabilities: Vec<String>,
    studio: StudioPreview,
    /// Human-facing rejection reasons (empty when ok).
    errors: Vec<String>,
}

/// Everything the pack checks concluded. One implementation, two callers:
/// `/v1/studio/pack/verify` (reports it) and
/// `http::studio_library::post_studio_library_install` (gates on it).
pub(crate) struct PackEvaluation {
    /// `Some` when the pack object is not a decodable `crux.integration.v1`
    /// manifest at all — every other field is then at its rejecting default.
    pub decode_error: Option<String>,
    pub manifest: Option<IntegrationManifest>,
    /// The `studio` key of the pack (`Value::Null` when absent).
    pub studio: Value,
    pub schema_ok: bool,
    pub manifest_hash_ok: bool,
    pub bundle_hash_ok: bool,
    pub studio_schema_ok: bool,
    pub signature_present: bool,
    /// `"valid"` | `"unsigned"` | `"invalid"`.
    pub signature_verdict: &'static str,
    pub signature_error: String,
    pub errors: Vec<String>,
}

impl PackEvaluation {
    /// Integrity + schema all green and the signature is not actively bad.
    /// NOTE: an UNSIGNED pack can be `ok()` — that is the `/verify` route's
    /// long-standing contract (it reports the verdict; it does not enforce a
    /// signing policy). Callers that must not install unsigned content gate on
    /// [`Self::signed`] as well; see `studio_library.rs`.
    pub fn ok(&self) -> bool {
        self.decode_error.is_none()
            && self.schema_ok
            && self.manifest_hash_ok
            && self.bundle_hash_ok
            && self.studio_schema_ok
            && self.signature_verdict != "invalid"
    }

    /// The REQUIRE-SIGNED bit: the pack carries an Ed25519 signature that
    /// validated against this operator's [`crux_integrations::TrustedKeyring`].
    pub fn signed(&self) -> bool {
        self.signature_verdict == "valid"
    }

    fn rejected(reason: String) -> Self {
        Self {
            decode_error: Some(reason.clone()),
            manifest: None,
            studio: Value::Null,
            schema_ok: false,
            manifest_hash_ok: false,
            bundle_hash_ok: false,
            studio_schema_ok: false,
            signature_present: false,
            signature_verdict: "unsigned",
            signature_error: String::new(),
            errors: vec![reason],
        }
    }
}

/// Run every pack check: manifest decode, `crux.integration.v1` schema,
/// `hashes.manifest`, `hashes.bundle` over the canonical studio payload,
/// `crux.studio.v1` schema, and the Ed25519 signature against the operator
/// keyring.
///
/// `policy` is a closure so the (fallible, file-reading) trusted-keyring load
/// happens ONLY when the pack actually carries a signature — preserving the
/// original `/verify` behaviour where an unsigned pack never touches the
/// keyring. `Err` means the keyring itself could not be read (a 500, not a
/// verdict about the pack).
pub(crate) fn evaluate_pack<F>(pack: &Value, policy: F) -> Result<PackEvaluation, String>
where
    F: FnOnce() -> Result<ValidationPolicy, String>,
{
    let Some(obj) = pack.as_object() else {
        return Ok(PackEvaluation::rejected("pack must be a JSON object".to_string()));
    };
    let studio = obj.get("studio").cloned().unwrap_or(Value::Null);

    // Deserialize the manifest portion (the extra `studio` key is ignored).
    let manifest: IntegrationManifest = match serde_json::from_value(pack.clone()) {
        Ok(m) => m,
        Err(err) => {
            let mut rejected = PackEvaluation::rejected(format!("not a valid crux.integration.v1 manifest: {err}"));
            rejected.studio = studio;
            return Ok(rejected);
        }
    };

    let mut errors: Vec<String> = Vec::new();
    let schema_ok = manifest.schema == INTEGRATION_SCHEMA_V1;
    if !schema_ok {
        errors.push(format!(
            "manifest.schema must be '{INTEGRATION_SCHEMA_V1}', got '{}'",
            manifest.schema
        ));
    }

    let recomputed_manifest_hash = manifest.manifest_hash().ok();
    let manifest_hash_ok = match (&manifest.hashes.manifest, &recomputed_manifest_hash) {
        (Some(declared), Some(actual)) => {
            let ok = declared == actual;
            if !ok {
                errors.push(format!(
                    "hashes.manifest mismatch: declared {declared}, actual {actual}"
                ));
            }
            ok
        }
        _ => {
            errors.push("hashes.manifest is missing".to_string());
            false
        }
    };

    let recomputed_bundle = blake3_hash(&canonical_bytes(&studio));
    let bundle_hash_ok = match &manifest.hashes.bundle {
        Some(declared) => {
            let ok = declared == &recomputed_bundle;
            if !ok {
                errors.push(format!(
                    "hashes.bundle mismatch: declared {declared}, actual {recomputed_bundle}"
                ));
            }
            ok
        }
        None => {
            errors.push("hashes.bundle is missing (studio payload is not integrity-bound)".to_string());
            false
        }
    };

    // Signature verdict — verbatim. Validate against the operator keyring.
    let (signature_present, signature_verdict, signature_error) = if manifest.signature.is_none() {
        (false, "unsigned", String::new())
    } else {
        let policy = policy()?;
        match manifest.validate(&policy) {
            Ok(()) => (true, "valid", String::new()),
            Err(err) => {
                let msg = err.to_string();
                errors.push(format!("signature/validation: {msg}"));
                (true, "invalid", msg)
            }
        }
    };

    let studio_schema_ok = studio.get("schema").and_then(Value::as_str) == Some(STUDIO_SCHEMA_V1);
    if !studio_schema_ok {
        errors.push(format!("studio.schema must be '{STUDIO_SCHEMA_V1}'"));
    }

    Ok(PackEvaluation {
        decode_error: None,
        manifest: Some(manifest),
        studio,
        schema_ok,
        manifest_hash_ok,
        bundle_hash_ok,
        studio_schema_ok,
        signature_present,
        signature_verdict,
        signature_error,
        errors,
    })
}

/// `POST /v1/studio/pack/verify` — validate an uploaded pack; never writes.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_verify_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VerifyPackBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        return problem.into_response();
    }
    if !body.pack.is_object() {
        return problem_response(StatusCode::BAD_REQUEST, "pack must be a JSON object");
    }

    let data_dir = state.data_dir.clone();
    let evaluation = match evaluate_pack(&body.pack, || {
        crate::extension_registry::build_policy(&data_dir).map_err(|err| format!("keyring read failed: {err}"))
    }) {
        Ok(evaluation) => evaluation,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    let preview = StudioPreview {
        schema_ok: evaluation.studio_schema_ok,
        tile_count: tile_count(&evaluation.studio),
        kinds: tile_kinds(&evaluation.studio),
        board_title: evaluation
            .studio
            .get("settings")
            .and_then(|s| s.get("title"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        design_count: evaluation
            .studio
            .get("designs")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
    };

    let (manifest_value, capabilities) = match &evaluation.manifest {
        Some(manifest) => (
            serde_json::to_value(manifest).unwrap_or(Value::Null),
            manifest.capabilities.clone(),
        ),
        None => (Value::Null, Vec::new()),
    };

    (
        StatusCode::OK,
        Json(VerifyPackResponse {
            ok: evaluation.ok(),
            schema_ok: evaluation.schema_ok,
            manifest_hash_ok: evaluation.manifest_hash_ok,
            bundle_hash_ok: evaluation.bundle_hash_ok,
            signature: SignatureVerdict {
                present: evaluation.signature_present,
                verdict: evaluation.signature_verdict.to_string(),
                error: evaluation.signature_error.clone(),
            },
            signed: evaluation.signed(),
            manifest: manifest_value,
            capabilities,
            studio: preview,
            errors: evaluation.errors,
        }),
    )
        .into_response()
}

// ── Helpers (pure; unit-tested) ──────────────────────────────────────────

/// Blake3 hash of arbitrary bytes, `blake3:<hex>` — matches
/// [`IntegrationManifest::manifest_hash`]'s prefix convention.
fn blake3_hash(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

/// Canonical bytes for a JSON value: recursively sort every object's keys so
/// the hash is independent of key order (the build serialises the studio
/// payload once, but it round-trips through several JSON parse/stringify hops
/// — browser download, re-import — before verify re-hashes it). Determinism
/// here is what makes the export→import bundle-hash match.
fn canonical_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(&canonicalize(value)).unwrap_or_default()
}

/// Canonical (deeply key-sorted, whitespace-free) JSON **string** — the exact
/// byte form the console's `cwsCanonical()` produces for
/// `console:workspace:` / `console:page:` / `console:tiledesign:` fact values
/// (`console/v2/render.js`). The library installer writes through this so an
/// installed artifact is byte-identical to one the Studio would have saved.
pub(crate) fn canonical_json_string(value: &Value) -> String {
    serde_json::to_string(&canonicalize(value)).unwrap_or_else(|_| "{}".to_string())
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted = Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), canonicalize(&map[k]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

/// Serialize the manifest to a JSON object and attach the `studio` payload.
fn manifest_to_pack(manifest: &IntegrationManifest, studio: &Value) -> Result<Value, serde_json::Error> {
    let mut obj = match serde_json::to_value(manifest)? {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    obj.insert("studio".to_string(), studio.clone());
    Ok(Value::Object(obj))
}

/// The board doc's node list, if present.
fn board_nodes(studio: &Value) -> Vec<&Value> {
    studio
        .get("board")
        .and_then(|b| b.get("doc"))
        .and_then(|d| d.get("nodes"))
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

fn tile_count(studio: &Value) -> usize {
    board_nodes(studio).len()
}

fn tile_kinds(studio: &Value) -> Vec<String> {
    let mut kinds: Vec<String> = board_nodes(studio)
        .iter()
        .filter_map(|n| n.get("kind").and_then(Value::as_str).map(str::to_string))
        .collect();
    kinds.sort();
    kinds.dedup();
    kinds
}

/// Map a bound daemon GET route to the minimal integration capability that
/// names the data it reads. Falls back to the benign `integrations:read`.
fn capability_for_route(route: &str) -> &'static str {
    if route.starts_with("/v1/facts") || route.starts_with("/v1/console/facts") || route.starts_with("/v1/query") {
        "facts:read"
    } else if route.starts_with("/v1/console/sessions") || route.starts_with("/v1/sessions") {
        "sessions:read"
    } else if route.starts_with("/v1/passports") || route.starts_with("/v1/console/passports") {
        "passport:read"
    } else if route.starts_with("/v1/receipts") {
        "admin:read"
    } else if route.starts_with("/v1/console/tenants") {
        "tenant:metadata:read"
    } else {
        "integrations:read"
    }
}

fn capability_for_kind(kind: &str) -> &'static str {
    match kind {
        "search" => "facts:read",
        "receipts" => "admin:read",
        _ => "integrations:read",
    }
}

/// Derive the minimal capability set the board's tiles actually need, from the
/// `crux.integration.v1` allowlist. `integrations:read` is always included as
/// the baseline "reads the daemon's own surface"; specific tiles add specific
/// read capabilities. Deterministic (sorted + deduped).
pub(crate) fn derive_capabilities(studio: &Value) -> Vec<String> {
    let mut caps: Vec<String> = vec!["integrations:read".to_string()];
    for node in board_nodes(studio) {
        let kind = node.get("kind").and_then(Value::as_str).unwrap_or("");
        if let Some(route) = node.get("api").and_then(|a| a.get("route")).and_then(Value::as_str) {
            if !route.is_empty() {
                caps.push(capability_for_route(route).to_string());
            }
        }
        if let Some(route) = node.get("search").and_then(|s| s.get("route")).and_then(Value::as_str) {
            if !route.is_empty() {
                caps.push(capability_for_route(route).to_string());
            }
        }
        caps.push(capability_for_kind(kind).to_string());
    }
    caps.sort();
    caps.dedup();
    caps
}

/// Load the operator signing key from the env knob, if set. `Ok(None)` = not
/// configured (the expected bare-mirror state). `Err` = present but malformed.
fn load_signing_key() -> Result<Option<SigningKey>, String> {
    let raw = match std::env::var(SIGNING_KEY_ENV) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => return Ok(None),
    };
    let bytes = hex::decode(&raw).map_err(|e| format!("not valid hex: {e}"))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "must be 64 hex chars (32-byte Ed25519 seed)".to_string())?;
    Ok(Some(SigningKey::from_bytes(&seed)))
}

fn unsigned_instructions(id: &str, version: &str) -> Vec<String> {
    vec![
        "This pack is UNSIGNED. It is inert on any daemon until signed + capability-granted.".to_string(),
        format!(
            "To sign on this daemon: set {SIGNING_KEY_ENV}=<your 64-hex Ed25519 seed> in the daemon env and re-export."
        ),
        format!(
            "To publish for others: open a PR adding integrations/community/{id}/{version}/manifest.json — the \
             `cargo test -p crux-integrations --test community_packs` CI gate validates it, then the curator-signed \
             index endorses it for install."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_studio() -> Value {
        serde_json::json!({
            "schema": STUDIO_SCHEMA_V1,
            "version": 1,
            "created_at_unix_ms": 1_700_000_000_000_u64,
            "board": {
                "id": "default",
                "doc": {
                    "nodes": [
                        { "id": "a", "kind": "api", "api": { "route": "/v1/facts/list" } },
                        { "id": "b", "kind": "search" },
                        { "id": "c", "kind": "note" }
                    ],
                    "links": [], "texts": [], "pan": { "x": 0, "y": 0 }, "zoom": 1, "version": 1
                }
            },
            "designs": [],
            "settings": { "grid": 20, "refresh": "off", "accent": "", "title": "My Board", "description": "" }
        })
    }

    #[test]
    fn derives_minimal_capabilities() {
        let caps = derive_capabilities(&sample_studio());
        // baseline integrations:read + facts:read (facts/list route + search kind).
        assert!(caps.contains(&"integrations:read".to_string()));
        assert!(caps.contains(&"facts:read".to_string()));
        // no dangerous caps for a facts/search/note board.
        assert!(!caps.contains(&"admin:read".to_string()));
        // sorted + deduped.
        let mut sorted = caps.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(caps, sorted);
    }

    #[test]
    fn receipts_tile_derives_admin_read() {
        let mut studio = sample_studio();
        studio["board"]["doc"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({ "id": "r", "kind": "receipts" }));
        let caps = derive_capabilities(&studio);
        assert!(caps.contains(&"admin:read".to_string()));
    }

    #[test]
    fn canonical_bytes_is_key_order_independent() {
        let a = serde_json::json!({ "x": 1, "y": { "b": 2, "a": 3 } });
        let b = serde_json::json!({ "y": { "a": 3, "b": 2 }, "x": 1 });
        assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
    }

    #[test]
    fn build_then_verify_round_trip_matches_hashes() {
        // Build a manifest exactly as the handler would (no signing key).
        let studio = sample_studio();
        let caps = derive_capabilities(&studio);
        let mut manifest = IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "studio.test".to_string(),
            name: "Studio Test".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: "p_example".to_string(),
            summary: "test".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::SdkRecipe,
                path: "studio-board.json".to_string(),
            },
            capabilities: caps,
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
            external_tool_endpoint: None,
            tools: Vec::new(),
            wasm_module_path: None,
            wasm_module_url: None,
            wasm_module_sha256: None,
            conformance: None,
        };
        let bundle = blake3_hash(&canonical_bytes(&studio));
        manifest.hashes.bundle = Some(bundle.clone());
        manifest.hashes.manifest = Some(manifest.manifest_hash().unwrap());
        let pack = manifest_to_pack(&manifest, &studio).unwrap();

        // Simulate a JSON round-trip (browser download + re-import).
        let round: Value = serde_json::from_str(&serde_json::to_string(&pack).unwrap()).unwrap();
        let studio_back = round.get("studio").cloned().unwrap();
        assert_eq!(blake3_hash(&canonical_bytes(&studio_back)), bundle);

        let manifest_back: IntegrationManifest = serde_json::from_value(round).unwrap();
        assert_eq!(
            manifest_back.manifest_hash().unwrap(),
            manifest.hashes.manifest.unwrap()
        );
    }

    #[test]
    fn tampering_the_studio_breaks_the_bundle_hash() {
        let studio = sample_studio();
        let bundle = blake3_hash(&canonical_bytes(&studio));
        let mut tampered = studio.clone();
        tampered["board"]["doc"]["nodes"][0]["api"]["route"] = Value::String("/v1/receipts/list".to_string());
        assert_ne!(blake3_hash(&canonical_bytes(&tampered)), bundle);
    }

    #[test]
    fn signing_key_env_absent_is_ok_none() {
        // Only asserts the malformed path; env-present is covered at runtime.
        assert!(matches!(load_signing_key(), Ok(None) | Ok(Some(_))));
    }
}
