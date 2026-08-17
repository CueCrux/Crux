// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Central Studio template library — daemon half (L2 of the ExecPlan
//! `crux-integrations-and-template-library-2026-07-25`).
//!
//! Two routes, mirroring the community-extensions registry pair in
//! [`super::extensions`] rail-for-rail:
//!
//! - `GET  /v1/studio/library` — browse the VERIFIED cached catalog
//!   (`<data_dir>/studio/library/index.json`, populated by
//!   `corecruxctl studio sync`), joined against what is already installed.
//!   Read class, no network.
//! - `POST /v1/studio/library/{id}/install` — operator-gated mutation. Load +
//!   re-verify the signed index, find the entry, fetch `pack_url`, pin
//!   `pack_sha256`, run the `studio_pack` verification pipeline under a
//!   **require-signed** policy, then write the pack's artifacts as console
//!   facts.
//!
//! # Install invariants
//!
//! * **Never overwrite.** Every artifact id/uid that collides with a live
//!   console fact is REMAPPED to a free `-2`/`-3`/… suffix, and the remap is
//!   reported in the response. An install can only ever add.
//! * **Consistent remaps.** Page uid remaps are applied through the installed
//!   workspaces' `dests[].pages[]` references, so a remapped workspace still
//!   points at its own pages and never at a pre-existing operator page.
//! * **Provenance on every write.** Each written def/doc gains an
//!   `installed_from` object. The console's tolerant readers preserve unknown
//!   keys (`cwsReadWorkspaceDef` spreads before coercing), so provenance
//!   survives Studio round-trips, and `GET /v1/studio/library` reads it back to
//!   compute the installed join.
//! * **Signature required.** A pack that is unsigned, or whose signature does
//!   not validate against the operator's
//!   [`crux_integrations::TrustedKeyring`], is refused with 403 unless the
//!   operator sets `CORECRUXD_STUDIO_ALLOW_UNSIGNED=1` (dev bypass; the error
//!   detail names the variable).
//!
//! # `required_tier` is ADVISORY here — deliberately
//!
//! Catalog entries may declare a `required_tier` ([`crux_integrations::RcxTier`]
//! — the RCX vocabulary, not a fork). **The daemon does not enforce it.** This
//! is an open-source daemon: any operator can rebuild it with the check
//! removed, so a local tier gate would be security theatre that only
//! inconveniences honest users. The enforcement point is the **catalog server**,
//! which decides whether to serve the signed index row and the `pack_url` bytes
//! to a given subscriber at all. The daemon therefore *echoes* the entry's
//! `required_tier` for display and stamps every response with
//! `tier_enforcement: "advisory"` so no client mistakes the echo for a gate.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path as FsPath, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::Digest as _;

use super::{problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, State, StatusCode};
use crux_integrations::{StudioLibraryEntry, StudioLibraryIndex};

/// Dev bypass for the require-signed install policy. Named verbatim in the 403
/// detail so an operator never has to grep source to find it.
const ALLOW_UNSIGNED_ENV: &str = "CORECRUXD_STUDIO_ALLOW_UNSIGNED";
/// Cache path, relative to `data_dir`. Written by `corecruxctl studio sync`.
const LIBRARY_INDEX_REL_PATH: &str = "studio/library/index.json";
/// Same 2 MiB cap the extension-manifest fetch applies.
const PACK_DOWNLOAD_LIMIT_BYTES: usize = 2 * 1024 * 1024;
/// How many `-N` suffixes to try before giving up on a colliding id.
const MAX_COLLISION_SUFFIX: u32 = 64;

const BOARD_ENTITY_PREFIX: &str = "console:tileboard:";
const DESIGN_ENTITY_PREFIX: &str = "console:tiledesign:";
const WORKSPACE_ENTITY_PREFIX: &str = "console:workspace:";
const PAGE_ENTITY_PREFIX: &str = "console:page:";
const BOARD_KEY: &str = "doc";
const DEF_KEY: &str = "def";
/// The provenance field injected into every written def/doc.
const PROVENANCE_FIELD: &str = "installed_from";

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn allow_unsigned_dev() -> bool {
    std::env::var(ALLOW_UNSIGNED_ENV)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

// ── GET /v1/studio/library ───────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub(super) struct InstallFromLibraryBody {
    /// Optional alternate cached index path. Relative paths resolve under
    /// `data_dir`; absolute paths are accepted for operator-controlled tests
    /// and private mirrors. Mirrors `InstallFromRegistryBody::index_path`.
    #[serde(default)]
    pub index_path: Option<PathBuf>,
}

/// `GET /v1/studio/library` — the verified cached catalog plus a per-entry
/// installed join.
///
/// Read class + `query:read`, the same tier as the sibling
/// `/v1/studio/pack/*` routes: this reads the cached index and the console's
/// own fact artifacts, and mutates nothing.
///
/// Honest failure modes, mirroring [`super::extensions::list_registry_entries`]:
/// 404 naming `corecruxctl studio sync` when no index is cached, 403 when the
/// cached index does not verify against the operator keyring.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_studio_library(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        return problem.into_response();
    }
    let index_path = library_index_path(&state.data_dir, None);
    let index = match load_and_verify_library_index(&state.data_dir, &index_path) {
        Ok(index) => index,
        // The no-cache case is the common one on a fresh daemon; name the
        // command that populates it rather than leaking a bare io error.
        Err((StatusCode::NOT_FOUND, msg)) => {
            return problem_response(
                StatusCode::NOT_FOUND,
                format!("{msg} (run `corecruxctl studio sync` to populate the cached Studio library index)"),
            );
        }
        Err((status, msg)) => return problem_response(status, msg),
    };

    let store = state.fact_store.read().await;
    let installed = installed_library_artifacts(&store);
    drop(store);

    let entries: Vec<Value> = index
        .entries
        .iter()
        .map(|entry| {
            let mut value = serde_json::to_value(entry).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(obj) = value.as_object_mut() {
                let record = installed.get(&entry.id);
                obj.insert("installed".to_string(), Value::Bool(record.is_some()));
                obj.insert(
                    "installed_version".to_string(),
                    record.map_or(Value::Null, |r| Value::String(r.version.clone())),
                );
                obj.insert(
                    "installed_entities".to_string(),
                    Value::Array(
                        record
                            .map(|r| r.entities.iter().cloned().map(Value::String).collect())
                            .unwrap_or_default(),
                    ),
                );
                obj.insert(
                    "installed_at_unix_ms".to_string(),
                    record.map_or(Value::Null, |r| Value::from(r.installed_at_unix_ms)),
                );
            }
            value
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": "crux.studio.library_list.v1",
            "curator_passport_fpr": index.curator_passport_fpr,
            "updated_at_unix_ms": index.updated_at_unix_ms,
            "entries": entries,
            // See the module docs: the catalog server is the tier gate.
            "tier_enforcement": "advisory",
        })),
    )
        .into_response()
}

/// What an already-installed library entry left behind in the fact store.
struct InstalledRecord {
    version: String,
    installed_at_unix_ms: u64,
    entities: BTreeSet<String>,
}

/// Scan the console artifact prefixes for facts carrying an `installed_from`
/// provenance stamp, and group them by `library_id`. Bounded by the console
/// fact count (tens, not millions) — the console artifacts are operator-authored
/// dashboards, not ingest.
fn installed_library_artifacts(store: &corecrux_memory::fact_store::FactStore) -> BTreeMap<String, InstalledRecord> {
    let mut out: BTreeMap<String, InstalledRecord> = BTreeMap::new();
    for entity in store.entities() {
        let key = match console_prefix_key(&entity) {
            Some(key) => key,
            None => continue,
        };
        let Some(fact) = latest_fact(store, &entity, key) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&fact.value) else {
            continue;
        };
        let Some(provenance) = value.get(PROVENANCE_FIELD).and_then(Value::as_object) else {
            continue;
        };
        let Some(library_id) = provenance.get("library_id").and_then(Value::as_str) else {
            continue;
        };
        let version = provenance
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let installed_at = provenance
            .get("installed_at_unix_ms")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let record = out.entry(library_id.to_string()).or_insert_with(|| InstalledRecord {
            version: version.clone(),
            installed_at_unix_ms: installed_at,
            entities: BTreeSet::new(),
        });
        record.entities.insert(entity.clone());
        // Report the most recent install of this library id.
        if installed_at >= record.installed_at_unix_ms {
            record.installed_at_unix_ms = installed_at;
            record.version = version;
        }
    }
    out
}

/// The artifact key a console entity stores its definition under, or `None`
/// when the entity is not a console artifact.
fn console_prefix_key(entity: &str) -> Option<&'static str> {
    if entity.starts_with(BOARD_ENTITY_PREFIX) {
        Some(BOARD_KEY)
    } else if entity.starts_with(DESIGN_ENTITY_PREFIX)
        || entity.starts_with(WORKSPACE_ENTITY_PREFIX)
        || entity.starts_with(PAGE_ENTITY_PREFIX)
    {
        Some(DEF_KEY)
    } else {
        None
    }
}

/// Highest-`version` live fact for `(entity, key)` — the console's own
/// "latest wins" rule (`tstudioLatestFact` in `render.js`).
fn latest_fact<'a>(
    store: &'a corecrux_memory::fact_store::FactStore,
    entity: &str,
    key: &str,
) -> Option<&'a corecrux_memory::fact_store::Fact> {
    store
        .get_by_entity(entity)
        .into_iter()
        .filter(|fact| fact.key == key)
        .max_by_key(|fact| fact.version)
}

// ── POST /v1/studio/library/{id}/install ─────────────────────────────────────

#[derive(Debug, Serialize)]
struct WrittenArtifact {
    /// `board` | `design` | `workspace` | `page`.
    artifact: &'static str,
    entity: String,
    key: &'static str,
    fact_id: String,
}

#[derive(Debug, Serialize)]
struct AppliedRemap {
    artifact: &'static str,
    from: String,
    to: String,
}

/// `POST /v1/studio/library/{id}/install` — install one catalog entry.
///
/// Operator-gated: `admin:read` + `facts:write`, the same posture as
/// [`super::extensions::install_from_registry`], because this writes durable
/// console artifacts.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_studio_library_install(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<InstallFromLibraryBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let ctx = match crate::auth::http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };

    // 1. Load + re-verify the cached, curator-signed index.
    let index_path = library_index_path(&state.data_dir, body.index_path.as_deref());
    let index = match load_and_verify_library_index(&state.data_dir, &index_path) {
        Ok(index) => index,
        Err((StatusCode::NOT_FOUND, msg)) => {
            return problem_response(
                StatusCode::NOT_FOUND,
                format!("{msg} (run `corecruxctl studio sync` to populate the cached Studio library index)"),
            );
        }
        Err((status, msg)) => return problem_response(status, msg),
    };

    // 2. Find the entry.
    let Some(entry) = index.entries.iter().find(|entry| entry.id == id).cloned() else {
        return problem_response(
            StatusCode::NOT_FOUND,
            format!("template '{id}' not found in the Studio library index"),
        );
    };

    // 3. Fetch the pack (https-or-loopback, capped, off the async runtime).
    let pack_bytes = match fetch_pack(entry.pack_url.clone()).await {
        Ok(bytes) => bytes,
        Err((status, msg)) => return problem_response(status, msg),
    };

    // 4. Pin the curator-published sha256 BEFORE parsing anything.
    let actual_sha256 = sha256_hex(&pack_bytes);
    if !actual_sha256.eq_ignore_ascii_case(entry.pack_sha256.trim()) {
        return problem_response(
            StatusCode::CONFLICT,
            format!(
                "pack_sha256 mismatch for '{}': index={}, downloaded={actual_sha256}",
                entry.id, entry.pack_sha256
            ),
        );
    }

    let pack: Value = match serde_json::from_slice(&pack_bytes) {
        Ok(pack) => pack,
        Err(err) => return problem_response(StatusCode::BAD_GATEWAY, format!("pack JSON decode failed: {err}")),
    };

    // 5. Run the studio_pack verification pipeline under a REQUIRE-SIGNED policy.
    let data_dir = state.data_dir.clone();
    let evaluation = match super::studio_pack::evaluate_pack(&pack, || {
        crate::extension_registry::build_policy(&data_dir).map_err(|err| format!("keyring read failed: {err}"))
    }) {
        Ok(evaluation) => evaluation,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    if !evaluation.ok() {
        return problem_response(
            StatusCode::CONFLICT,
            format!(
                "pack for '{}' failed verification: {}",
                entry.id,
                evaluation.errors.join("; ")
            ),
        );
    }
    let bypass = allow_unsigned_dev();
    if !evaluation.signed() && !bypass {
        let why = if evaluation.signature_present {
            format!("signature did not validate: {}", evaluation.signature_error)
        } else {
            "pack is unsigned".to_string()
        };
        return problem_response(
            StatusCode::FORBIDDEN,
            format!(
                "refusing to install '{}': {why}. Add the publisher's key to the trusted keyring \
                 (POST /v1/extensions/keys), or set {ALLOW_UNSIGNED_ENV}=1 to bypass the \
                 require-signed policy in dev.",
                entry.id
            ),
        );
    }

    // The manifest must be the one the curator endorsed, not a different pack
    // served from the same URL under a matching hash.
    if let Some(manifest) = &evaluation.manifest {
        if manifest.id != entry.id || manifest.version != entry.version {
            return problem_response(
                StatusCode::CONFLICT,
                format!(
                    "library entry mismatch: expected {}@{}, pack manifest is {}@{}",
                    entry.id, entry.version, manifest.id, manifest.version
                ),
            );
        }
    }

    // 6. Plan the writes (collision remaps computed against the live store).
    let installed_at_unix_ms = now_unix_ms();
    let provenance = provenance_object(&entry, &actual_sha256, installed_at_unix_ms);

    let mut store = state.fact_store.write().await;
    let live: BTreeSet<String> = store.entities().into_iter().collect();
    let plan = match plan_install(&entry, &evaluation.studio, &live, &provenance) {
        Ok(plan) => plan,
        Err(msg) => {
            drop(store);
            return problem_response(StatusCode::CONFLICT, msg);
        }
    };
    if plan.writes.is_empty() {
        drop(store);
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!(
                "pack for '{}' carries no installable artifacts (no board tiles, designs, workspaces, or pages)",
                entry.id
            ),
        );
    }

    // 7. Apply. Same write discipline as console.rs::post_console_fact_add:
    //    category enforcement against the calling passport, then the global
    //    privacy gate, then the store.
    let mut written = Vec::with_capacity(plan.writes.len());
    for planned in &plan.writes {
        if let Err(err) = crux_mcp::category_enforce::check_passport_can_write_entity(
            &store,
            ctx.passport_id.as_deref(),
            &planned.entity,
        ) {
            drop(store);
            return problem_response(StatusCode::FORBIDDEN, err.to_string());
        }
        let mut sf = corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: planned.entity.clone(),
            key: planned.key.to_string(),
            value: super::studio_pack::canonical_json_string(&planned.value),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        crate::fact_privacy::enforce_global(&mut sf);
        let stored = store.store(sf);
        written.push(WrittenArtifact {
            artifact: planned.artifact,
            entity: planned.entity.clone(),
            key: planned.key,
            fact_id: stored.fact_id,
        });
    }
    drop(store);

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "schema": "crux.studio.library_install.v1",
            "library_id": entry.id,
            "version": entry.version,
            "kind": entry.kind.as_str(),
            "pack_sha256": actual_sha256,
            "publisher_passport_fpr": entry.publisher_passport_fpr,
            "signed": evaluation.signed(),
            "allow_unsigned_dev": bypass,
            "required_tier": entry.required_tier_str(),
            // NOT locally enforced — see the module docs.
            "tier_enforcement": "advisory",
            "provenance": provenance,
            "written": written,
            "remaps": plan.remaps,
            "entry": entry,
        })),
    )
        .into_response()
}

// ── Install planning (pure; unit-tested) ─────────────────────────────────────

struct PlannedWrite {
    artifact: &'static str,
    entity: String,
    key: &'static str,
    value: Value,
}

struct InstallPlan {
    writes: Vec<PlannedWrite>,
    remaps: Vec<AppliedRemap>,
}

/// The provenance object stamped into every written def/doc.
fn provenance_object(entry: &StudioLibraryEntry, pack_sha256: &str, installed_at_unix_ms: u64) -> Value {
    serde_json::json!({
        "library_id": entry.id,
        "version": entry.version,
        "pack_sha256": pack_sha256,
        "publisher_passport_fpr": entry.publisher_passport_fpr,
        "installed_at_unix_ms": installed_at_unix_ms,
    })
}

/// Allocate a free artifact id under `prefix`, never colliding with a live
/// entity or with another id allocated in this same install. `base` wins when
/// free; otherwise `base-2`, `base-3`, … up to [`MAX_COLLISION_SUFFIX`].
fn allocate_id(base: &str, prefix: &str, live: &BTreeSet<String>, taken: &mut BTreeSet<String>) -> Option<String> {
    for n in 1..=MAX_COLLISION_SUFFIX {
        let candidate = if n == 1 {
            base.to_string()
        } else {
            format!("{base}-{n}")
        };
        let entity = format!("{prefix}{candidate}");
        if !live.contains(&entity) && !taken.contains(&entity) {
            taken.insert(entity);
            return Some(candidate);
        }
    }
    None
}

/// Console slug rule, ported from `tstudioSlugify` / `cwsSlugify` in
/// `console/v2/render.js`: lowercase, non-alphanumerics collapsed to `-`,
/// trimmed, capped at 48 chars.
fn slugify(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.extend(ch.to_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    let capped: String = trimmed.chars().take(48).collect();
    let capped = capped.trim_end_matches('-').to_string();
    if capped.is_empty() {
        "item".to_string()
    } else {
        capped
    }
}

/// Merge the provenance stamp into an object value (creating the object if the
/// pack shipped something else). Existing keys are preserved — provenance is
/// additive, and the console's tolerant readers carry it through edits.
fn with_provenance(value: &Value, provenance: &Value) -> Value {
    let mut obj = match value {
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    };
    obj.insert(PROVENANCE_FIELD.to_string(), provenance.clone());
    Value::Object(obj)
}

/// True when a board doc actually carries content worth installing.
fn board_doc_has_content(doc: &Value) -> bool {
    ["nodes", "links", "texts"]
        .iter()
        .any(|k| doc.get(*k).and_then(Value::as_array).is_some_and(|a| !a.is_empty()))
}

/// Turn a verified `crux.studio.v1` payload into the exact set of console-fact
/// writes, with all collision remaps resolved.
///
/// Remap rules:
/// * board  — target id is the LIBRARY ENTRY id (`<entry.id>`), suffixed `-2`…
///   on collision. A board with an empty doc (the shape a workspace-only pack
///   ships) is skipped rather than written as an empty board.
/// * design — target slug is the pack's `slug`, console-slugified, suffixed on
///   collision.
/// * page   — target uid is the pack's `uid`, suffixed on collision.
/// * workspace — target uid is the pack's `uid`, suffixed on collision. Every
///   `dests[].pages[]` reference is rewritten through the page remap so an
///   installed workspace points at ITS pages; a reference to a uid the pack
///   does not carry (e.g. the built-in `explorer` page) is left untouched.
fn plan_install(
    entry: &StudioLibraryEntry,
    studio: &Value,
    live: &BTreeSet<String>,
    provenance: &Value,
) -> Result<InstallPlan, String> {
    let mut taken: BTreeSet<String> = BTreeSet::new();
    let mut writes: Vec<PlannedWrite> = Vec::new();
    let mut remaps: Vec<AppliedRemap> = Vec::new();

    // ── board ────────────────────────────────────────────────────────────
    if let Some(doc) = studio.get("board").and_then(|b| b.get("doc")) {
        if board_doc_has_content(doc) {
            let base = entry.id.clone();
            let board_id = allocate_id(&base, BOARD_ENTITY_PREFIX, live, &mut taken)
                .ok_or_else(|| format!("no free board id for '{base}' after {MAX_COLLISION_SUFFIX} attempts"))?;
            if board_id != base {
                remaps.push(AppliedRemap {
                    artifact: "board",
                    from: base,
                    to: board_id.clone(),
                });
            }
            writes.push(PlannedWrite {
                artifact: "board",
                entity: format!("{BOARD_ENTITY_PREFIX}{board_id}"),
                key: BOARD_KEY,
                value: with_provenance(doc, provenance),
            });
        }
    }

    // ── designs ──────────────────────────────────────────────────────────
    for design in studio.get("designs").and_then(Value::as_array).unwrap_or(&Vec::new()) {
        let Some(raw_slug) = design
            .get("slug")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
        else {
            continue;
        };
        let base = slugify(raw_slug);
        let slug = allocate_id(&base, DESIGN_ENTITY_PREFIX, live, &mut taken)
            .ok_or_else(|| format!("no free design slug for '{base}' after {MAX_COLLISION_SUFFIX} attempts"))?;
        if slug != base {
            remaps.push(AppliedRemap {
                artifact: "design",
                from: base,
                to: slug.clone(),
            });
        }
        // Preserve every key the pack shipped except `slug` (which is the
        // entity suffix, not part of the stored def — see tstudioSaveDesign).
        let mut def = match design {
            Value::Object(map) => map.clone(),
            _ => Map::new(),
        };
        def.remove("slug");
        def.entry("name".to_string())
            .or_insert_with(|| Value::String(slug.clone()));
        writes.push(PlannedWrite {
            artifact: "design",
            entity: format!("{DESIGN_ENTITY_PREFIX}{slug}"),
            key: DEF_KEY,
            value: with_provenance(&Value::Object(def), provenance),
        });
    }

    // ── pages (allocated first so workspace refs can be rewritten) ────────
    let mut page_remap: BTreeMap<String, String> = BTreeMap::new();
    let mut page_defs: Vec<(String, Value)> = Vec::new();
    for page in studio.get("pages").and_then(Value::as_array).unwrap_or(&Vec::new()) {
        let Some(uid) = page.get("uid").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) else {
            continue;
        };
        let new_uid = allocate_id(uid, PAGE_ENTITY_PREFIX, live, &mut taken)
            .ok_or_else(|| format!("no free page uid for '{uid}' after {MAX_COLLISION_SUFFIX} attempts"))?;
        if new_uid != uid {
            remaps.push(AppliedRemap {
                artifact: "page",
                from: uid.to_string(),
                to: new_uid.clone(),
            });
            page_remap.insert(uid.to_string(), new_uid.clone());
        }
        page_defs.push((new_uid, page.clone()));
    }
    for (new_uid, page) in page_defs {
        let mut def = match &page {
            Value::Object(map) => map.clone(),
            _ => Map::new(),
        };
        def.insert("uid".to_string(), Value::String(new_uid.clone()));
        writes.push(PlannedWrite {
            artifact: "page",
            entity: format!("{PAGE_ENTITY_PREFIX}{new_uid}"),
            key: DEF_KEY,
            value: with_provenance(&Value::Object(def), provenance),
        });
    }

    // ── workspaces ───────────────────────────────────────────────────────
    for workspace in studio
        .get("workspaces")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
    {
        let Some(uid) = workspace
            .get("uid")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
        else {
            continue;
        };
        let new_uid = allocate_id(uid, WORKSPACE_ENTITY_PREFIX, live, &mut taken)
            .ok_or_else(|| format!("no free workspace uid for '{uid}' after {MAX_COLLISION_SUFFIX} attempts"))?;
        if new_uid != uid {
            remaps.push(AppliedRemap {
                artifact: "workspace",
                from: uid.to_string(),
                to: new_uid.clone(),
            });
        }
        let mut def = match workspace {
            Value::Object(map) => map.clone(),
            _ => Map::new(),
        };
        def.insert("uid".to_string(), Value::String(new_uid.clone()));
        if let Some(dests) = def.get_mut("dests").and_then(Value::as_array_mut) {
            for dest in dests.iter_mut() {
                let Some(pages) = dest.get_mut("pages").and_then(Value::as_array_mut) else {
                    continue;
                };
                for page_ref in pages.iter_mut() {
                    let Some(current) = page_ref.as_str() else { continue };
                    if let Some(remapped) = page_remap.get(current) {
                        *page_ref = Value::String(remapped.clone());
                    }
                }
            }
        }
        writes.push(PlannedWrite {
            artifact: "workspace",
            entity: format!("{WORKSPACE_ENTITY_PREFIX}{new_uid}"),
            key: DEF_KEY,
            value: with_provenance(&Value::Object(def), provenance),
        });
    }

    Ok(InstallPlan { writes, remaps })
}

// ── Cached index + pack fetch (mirrors extensions.rs) ────────────────────────

fn library_index_path(data_dir: &FsPath, override_path: Option<&FsPath>) -> PathBuf {
    match override_path {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => data_dir.join(path),
        None => data_dir.join(LIBRARY_INDEX_REL_PATH),
    }
}

fn load_and_verify_library_index(
    data_dir: &FsPath,
    index_path: &FsPath,
) -> Result<StudioLibraryIndex, (StatusCode, String)> {
    let bytes = std::fs::read(index_path).map_err(|err| {
        (
            StatusCode::NOT_FOUND,
            format!("Studio library index read failed: {err}"),
        )
    })?;
    let index: StudioLibraryIndex = serde_json::from_slice(&bytes).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("Studio library index JSON decode failed: {err}"),
        )
    })?;
    let policy = crate::extension_registry::build_policy(data_dir)
        .map_err(|err| (StatusCode::BAD_REQUEST, format!("trusted keyring read failed: {err}")))?;
    index.verify(&policy).map_err(|err| {
        (
            StatusCode::FORBIDDEN,
            format!("Studio library index signature verification failed: {err}"),
        )
    })?;
    Ok(index)
}

async fn fetch_pack(url: String) -> Result<Vec<u8>, (StatusCode, String)> {
    if !crux_integrations::studio_index::pack_url_allowed(&url) {
        return Err((
            StatusCode::BAD_REQUEST,
            "pack_url must be https://, or loopback http:// for local mirrors".to_string(),
        ));
    }
    tokio::task::spawn_blocking(move || fetch_pack_blocking(&url))
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, format!("pack fetch join error: {err}")))?
}

fn fetch_pack_blocking(url: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .into();
    let mut response = agent
        .get(url)
        .call()
        .map_err(|err| (StatusCode::BAD_GATEWAY, format!("pack fetch failed: {err}")))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err((StatusCode::BAD_GATEWAY, format!("pack URL returned status {status}")));
    }
    let mut reader = response.body_mut().as_reader();
    let mut out = Vec::with_capacity(64 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|err| (StatusCode::BAD_GATEWAY, format!("pack read failed: {err}")))?;
        if n == 0 {
            break;
        }
        if out.len() + n > PACK_DOWNLOAD_LIMIT_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("pack exceeds the {PACK_DOWNLOAD_LIMIT_BYTES}-byte cap"),
            ));
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crux_integrations::StudioEntryKind;

    fn test_entry(id: &str) -> StudioLibraryEntry {
        StudioLibraryEntry {
            id: id.to_string(),
            kind: StudioEntryKind::Pack,
            name: "Test".to_string(),
            version: "0.1.0".to_string(),
            summary: "Test.".to_string(),
            publisher_passport_fpr: "p_pub".to_string(),
            tags: Vec::new(),
            required_tier: None,
            pack_url: "https://example.com/p.json".to_string(),
            pack_sha256: "0".repeat(64),
            repo_url: None,
            preview: None,
        }
    }

    fn provenance_for(id: &str) -> Value {
        provenance_object(&test_entry(id), &"a".repeat(64), 1_700_000_000_000)
    }

    fn test_provenance() -> Value {
        provenance_for("studio.ops")
    }

    fn full_studio() -> Value {
        serde_json::json!({
            "schema": "crux.studio.v1",
            "version": 1,
            "board": { "id": "default", "doc": { "nodes": [{ "id": "a", "kind": "note" }], "links": [], "texts": [] } },
            "designs": [{ "slug": "latency-tile", "name": "Latency", "config": { "kind": "api" } }],
            "workspaces": [{
                "schema_version": 1, "uid": "ops", "name": "Ops", "icon": "meters", "order": 100, "source": "user",
                "dests": [{ "id": "main", "label": "Main", "icon": "work", "pages": ["ops-overview", "explorer"] }]
            }],
            "pages": [{ "schema_version": 1, "uid": "ops-overview", "type": "facts", "title": "Overview", "dest": "main" }]
        })
    }

    #[test]
    fn plans_every_artifact_kind_with_provenance() {
        let plan = plan_install(
            &test_entry("studio.ops"),
            &full_studio(),
            &BTreeSet::new(),
            &test_provenance(),
        )
        .expect("plan");
        let entities: Vec<&str> = plan.writes.iter().map(|w| w.entity.as_str()).collect();
        assert_eq!(
            entities,
            vec![
                "console:tileboard:studio.ops",
                "console:tiledesign:latency-tile",
                "console:page:ops-overview",
                "console:workspace:ops",
            ]
        );
        assert!(plan.remaps.is_empty(), "no collisions ⇒ no remaps");
        // Provenance rides on EVERY written artifact.
        for write in &plan.writes {
            let provenance = write.value.get(PROVENANCE_FIELD).expect("installed_from");
            assert_eq!(provenance["library_id"], "studio.ops");
            assert_eq!(provenance["version"], "0.1.0");
            assert_eq!(provenance["publisher_passport_fpr"], "p_pub");
            assert_eq!(provenance["installed_at_unix_ms"], 1_700_000_000_000_u64);
        }
    }

    #[test]
    fn board_id_comes_from_the_library_entry_not_the_pack() {
        let plan = plan_install(
            &test_entry("studio.renamed"),
            &full_studio(),
            &BTreeSet::new(),
            &test_provenance(),
        )
        .expect("plan");
        // The pack's board id was "default"; the install uses the entry id.
        assert_eq!(plan.writes[0].entity, "console:tileboard:studio.renamed");
        assert_eq!(plan.writes[0].key, "doc");
    }

    #[test]
    fn collisions_remap_and_never_overwrite() {
        let live: BTreeSet<String> = [
            "console:tileboard:studio.ops",
            "console:tiledesign:latency-tile",
            "console:page:ops-overview",
            "console:workspace:ops",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

        let plan = plan_install(&test_entry("studio.ops"), &full_studio(), &live, &test_provenance()).expect("plan");
        let entities: Vec<&str> = plan.writes.iter().map(|w| w.entity.as_str()).collect();
        assert_eq!(
            entities,
            vec![
                "console:tileboard:studio.ops-2",
                "console:tiledesign:latency-tile-2",
                "console:page:ops-overview-2",
                "console:workspace:ops-2",
            ]
        );
        // Nothing in `live` appears in the write set.
        for write in &plan.writes {
            assert!(!live.contains(&write.entity), "would overwrite {}", write.entity);
        }
        assert_eq!(plan.remaps.len(), 4);
    }

    #[test]
    fn page_remap_is_applied_to_workspace_dest_references() {
        let live: BTreeSet<String> = ["console:page:ops-overview".to_string()].into_iter().collect();
        let plan = plan_install(&test_entry("studio.ops"), &full_studio(), &live, &test_provenance()).expect("plan");

        let workspace = plan
            .writes
            .iter()
            .find(|w| w.artifact == "workspace")
            .expect("workspace write");
        let pages = workspace.value["dests"][0]["pages"].as_array().expect("pages");
        // The pack's own page was remapped and the reference followed it…
        assert_eq!(pages[0], "ops-overview-2");
        // …while a reference to a page the pack does NOT carry (the built-in
        // `explorer`) is left exactly as published.
        assert_eq!(pages[1], "explorer");
        // The written page itself carries the new uid.
        let page = plan.writes.iter().find(|w| w.artifact == "page").expect("page write");
        assert_eq!(page.value["uid"], "ops-overview-2");
        assert_eq!(page.entity, "console:page:ops-overview-2");
        // And the workspace uid is untouched (no workspace collision here).
        assert_eq!(workspace.value["uid"], "ops");
    }

    #[test]
    fn second_suffix_is_taken_when_the_first_is_also_live() {
        let live: BTreeSet<String> = [
            "console:tileboard:studio.ops".to_string(),
            "console:tileboard:studio.ops-2".to_string(),
        ]
        .into_iter()
        .collect();
        let plan = plan_install(&test_entry("studio.ops"), &full_studio(), &live, &test_provenance()).expect("plan");
        assert_eq!(plan.writes[0].entity, "console:tileboard:studio.ops-3");
    }

    #[test]
    fn empty_board_is_skipped_so_workspace_packs_do_not_write_a_blank_board() {
        let studio = serde_json::json!({
            "schema": "crux.studio.v1",
            "board": { "id": "workspace-ops", "doc": { "nodes": [], "links": [], "texts": [] } },
            "designs": [],
            "workspaces": [{ "uid": "ops", "name": "Ops", "dests": [] }],
            "pages": []
        });
        let plan =
            plan_install(&test_entry("studio.ops"), &studio, &BTreeSet::new(), &test_provenance()).expect("plan");
        assert_eq!(plan.writes.len(), 1);
        assert_eq!(plan.writes[0].artifact, "workspace");
    }

    #[test]
    fn pack_with_no_artifacts_plans_no_writes() {
        let studio = serde_json::json!({ "schema": "crux.studio.v1", "designs": [] });
        let plan = plan_install(&test_entry("studio.x"), &studio, &BTreeSet::new(), &test_provenance()).expect("plan");
        assert!(plan.writes.is_empty());
    }

    #[test]
    fn design_def_drops_slug_but_keeps_unknown_keys() {
        let studio = serde_json::json!({
            "schema": "crux.studio.v1",
            "designs": [{ "slug": "My Tile!", "name": "My Tile", "config": { "kind": "note" }, "future_field": 7 }]
        });
        let plan = plan_install(&test_entry("studio.x"), &studio, &BTreeSet::new(), &test_provenance()).expect("plan");
        let design = &plan.writes[0];
        // Slug is console-slugified into the entity suffix…
        assert_eq!(design.entity, "console:tiledesign:my-tile");
        // …and removed from the stored def (it is not part of tstudioSaveDesign's value).
        assert!(design.value.get("slug").is_none());
        assert_eq!(design.value["name"], "My Tile");
        // Unknown keys survive (tolerant reader contract).
        assert_eq!(design.value["future_field"], 7);
    }

    #[test]
    fn slugify_matches_the_console_rule() {
        assert_eq!(slugify("My Tile!"), "my-tile");
        assert_eq!(slugify("  --Leading and trailing-- "), "leading-and-trailing");
        assert_eq!(slugify("!!!"), "item");
        assert_eq!(slugify(&"x".repeat(80)).len(), 48);
    }

    #[test]
    fn canonical_value_is_key_sorted_for_console_byte_parity() {
        let value = serde_json::json!({ "z": 1, "a": { "d": 2, "b": 3 } });
        assert_eq!(
            super::super::studio_pack::canonical_json_string(&value),
            r#"{"a":{"b":3,"d":2},"z":1}"#
        );
    }

    #[test]
    fn console_prefix_key_maps_each_artifact_entity() {
        assert_eq!(console_prefix_key("console:tileboard:x"), Some("doc"));
        assert_eq!(console_prefix_key("console:tiledesign:x"), Some("def"));
        assert_eq!(console_prefix_key("console:workspace:x"), Some("def"));
        assert_eq!(console_prefix_key("console:page:x"), Some("def"));
        assert_eq!(console_prefix_key("__work__::x"), None);
    }
}
