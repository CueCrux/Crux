// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Local RCX Registry publish preview/emit flows.
//!
//! These routes build the passport/project publish records defined by
//! `RCX-Registry/schemas/2026-05-01`, sign them with the daemon-root passport
//! key, and optionally submit them to a registry endpoint. Emit always stores a
//! private local fact so audit replay can prove exactly what was published.

use std::collections::BTreeSet;

use chrono::{DateTime, SecondsFormat, Utc};
use corecrux_memory::fact_store::StoreFact;
use crux_session::canonical::CborValue;
use serde_json::{json, Value};

use super::{problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, State, StatusCode};

const PASSPORT_SCHEMA_URI: &str = "https://static.rcxprotocol.org/schemas/2026-05-01/passport-publish.schema.json";
const PROJECT_SCHEMA_URI: &str = "https://static.rcxprotocol.org/schemas/2026-05-01/project-publish.schema.json";
const PUBLISH_ENTITY_PREFIX: &str = "__rcx_publish__";
const PUBLISH_RECORD_KEY: &str = "record";

#[derive(Debug, serde::Deserialize)]
pub(super) struct PublishBody {
    #[serde(default)]
    pub registry_url: Option<String>,
    #[serde(default)]
    pub operator_metadata: Option<Value>,
}

pub(super) async fn preview_passport(
    State(state): State<AppState>,
    Path(passport_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PublishBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    match build_passport_publish_record(&state, &passport_id, body.operator_metadata).await {
        Ok(record) => preview_response("passport", record),
        Err((status, msg)) => problem_response(status, msg),
    }
}

pub(super) async fn emit_passport(
    State(state): State<AppState>,
    Path(passport_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PublishBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let record = match build_passport_publish_record(&state, &passport_id, body.operator_metadata).await {
        Ok(record) => record,
        Err((status, msg)) => return problem_response(status, msg),
    };
    emit_response(state, "passport", &passport_id, record, body.registry_url).await
}

pub(super) async fn preview_project(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PublishBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    match build_project_publish_record(&state, &project_id, body.operator_metadata).await {
        Ok(record) => preview_response("project", record),
        Err((status, msg)) => problem_response(status, msg),
    }
}

pub(super) async fn emit_project(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PublishBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let record = match build_project_publish_record(&state, &project_id, body.operator_metadata).await {
        Ok(record) => record,
        Err((status, msg)) => return problem_response(status, msg),
    };
    emit_response(state, "project", &project_id, record, body.registry_url).await
}

fn preview_response(kind: &str, record: Value) -> axum::response::Response {
    (
        StatusCode::OK,
        Json(json!({
            "schema": "crux.rcx_publish.preview.v1",
            "kind": kind,
            "dry_run": true,
            "schema_valid": true,
            "record_hash": publish_hash_for_kind(kind, &record),
            "record": record,
        })),
    )
        .into_response()
}

async fn emit_response(
    state: AppState,
    kind: &str,
    object_id: &str,
    record: Value,
    registry_url: Option<String>,
) -> axum::response::Response {
    let record_hash = publish_hash_for_kind(kind, &record);
    let receipt_id = format!(
        "rcx-publish:{kind}:{}",
        record_hash.chars().take(16).collect::<String>()
    );
    let (submitted, registry_status) = match registry_url {
        Some(url) => match submit_registry_record(url, record.clone()).await {
            Ok(status) => (true, json!({"status": status})),
            Err((status, msg)) => {
                return problem_response(status, msg);
            }
        },
        None => (false, Value::Null),
    };
    let receipt = json!({
        "schema": "crux.rcx_publish.receipt.v1",
        "receipt_id": receipt_id,
        "kind": kind,
        "object_id": object_id,
        "record_hash": record_hash,
        "submitted": submitted,
        "registry_status": registry_status,
        "record": record,
    });
    let value = match serde_json::to_string(&receipt) {
        Ok(value) => value,
        Err(err) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("publish receipt encode failed: {err}"),
            )
        }
    };
    let mut fact = StoreFact {
        entity: format!("{PUBLISH_ENTITY_PREFIX}::{kind}::{object_id}"),
        key: PUBLISH_RECORD_KEY.to_string(),
        value,
        source_receipt: Some(receipt_id.clone()),
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce(&state.privacy_policy, &mut fact);
    state.fact_store.write().await.store(fact);
    (
        StatusCode::CREATED,
        Json(json!({
            "schema": "crux.rcx_publish.emit.v1",
            "kind": kind,
            "record_hash": record_hash,
            "submitted": submitted,
            "registry_status": registry_status,
            "receipt": receipt,
        })),
    )
        .into_response()
}

async fn build_passport_publish_record(
    state: &AppState,
    passport_id: &str,
    operator_metadata: Option<Value>,
) -> Result<Value, (StatusCode, String)> {
    let store = state.fact_store.read().await;
    let passport = crate::passports::get_passport(&store, passport_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("passport '{passport_id}' not found")))?;
    let sponsor_passport_fpr = match passport.sponsor_id.as_deref() {
        Some(sponsor_id) => crate::passports::get_passport(&store, sponsor_id).map(|sponsor| sponsor.principal_id),
        None => None,
    };
    drop(store);
    let published_at = now_unix_ms();
    let mut unsigned = json!({
        "schema_uri": PASSPORT_SCHEMA_URI,
        "publisher_passport": state.passport_fpr,
        "passport_fpr": passport.principal_id,
        "passport_id": passport.id,
        "category": passport.category,
        "public_key_hex": passport.public_key_hex,
        "sponsor_passport_fpr": sponsor_passport_fpr,
        "reputation_tier": passport.reputation_tier,
        "receipt_count": passport.receipt_count,
        "agent_work_gate": passport.agent_work_gate,
        "is_default_for_category": passport.is_default_for_category,
        "issued_at": rfc3339_from_unix_ms(passport.issued_at_unix_ms),
        "published_at": rfc3339_from_unix_ms(published_at),
    });
    if let Some(metadata) = operator_metadata {
        unsigned["operator_metadata"] = metadata;
    }
    sign_publish_record(state, unsigned, "passport_hash")
}

async fn build_project_publish_record(
    state: &AppState,
    project_id: &str,
    operator_metadata: Option<Value>,
) -> Result<Value, (StatusCode, String)> {
    let store = state.fact_store.read().await;
    let detail = crate::projects::get_project_detail(&store, project_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("project '{project_id}' not found")))?;
    let default_passport =
        crate::passports::get_passport(&store, &detail.record.default_passport_id).ok_or_else(|| {
            (
                StatusCode::CONFLICT,
                format!("default passport '{}' not found", detail.record.default_passport_id),
            )
        })?;
    let mut allowed = BTreeSet::new();
    allowed.insert(default_passport.principal_id.clone());
    for member in &detail.members {
        let Some(passport) = crate::passports::get_passport(&store, &member.passport_id) else {
            return Err((
                StatusCode::CONFLICT,
                format!("project member passport '{}' not found", member.passport_id),
            ));
        };
        allowed.insert(passport.principal_id);
    }
    let mut tenant_categories = BTreeSet::new();
    if detail.tenants.is_empty() {
        tenant_categories.insert(default_passport.category.clone());
    } else {
        for tenant in &detail.tenants {
            let category = tenant
                .default_passport_id
                .as_deref()
                .and_then(|id| crate::passports::get_passport(&store, id).map(|p| p.category))
                .unwrap_or_else(|| default_passport.category.clone());
            tenant_categories.insert(category);
        }
    }
    let repos: Vec<String> = crate::project_repo_links::list_links(&store, project_id)
        .into_iter()
        .map(|repo| repo.slug())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    drop(store);

    let published_at = now_unix_ms();
    let mut unsigned = json!({
        "schema_uri": PROJECT_SCHEMA_URI,
        "publisher_passport": state.passport_fpr,
        "project_id": detail.record.id,
        "name": detail.record.name,
        "planning_target": detail.record.planning_target,
        "default_passport_fpr": default_passport.principal_id,
        "allowed_passport_fprs": allowed.into_iter().collect::<Vec<_>>(),
        "working_tenant_categories": tenant_categories.into_iter().collect::<Vec<_>>(),
        "linked_github_repos": repos,
        "created_at": rfc3339_from_unix_ms(detail.record.created_at_unix_ms),
        "published_at": rfc3339_from_unix_ms(published_at),
    });
    if let Some(metadata) = operator_metadata {
        unsigned["operator_metadata"] = metadata;
    }
    sign_publish_record(state, unsigned, "project_hash")
}

fn sign_publish_record(
    state: &AppState,
    mut unsigned: Value,
    hash_field: &'static str,
) -> Result<Value, (StatusCode, String)> {
    validate_operator_metadata(&unsigned)?;
    let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("passport key load failed: {err}"),
        )
    })?;
    if key.passport_fpr() != state.passport_fpr {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "passport signer mismatch: state={}, key={}",
                state.passport_fpr,
                key.passport_fpr()
            ),
        ));
    }
    let cbor = json_to_cbor(&unsigned)
        .map_err(|err| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("publish record contains unsupported JSON: {err}"),
            )
        })?
        .encode();
    let hash: [u8; 32] = *blake3::hash(&cbor).as_bytes();
    let signature = key.sign_hash(&hash);
    unsigned["signature"] = json!(hex::encode(signature));
    unsigned["signer_kid"] = json!(state.passport_fpr);
    unsigned[hash_field] = json!(hex::encode(hash));
    validate_publish_record(&unsigned, hash_field)?;
    Ok(unsigned)
}

fn validate_operator_metadata(record: &Value) -> Result<(), (StatusCode, String)> {
    if let Some(metadata) = record.get("operator_metadata") {
        if !metadata.is_object() {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "operator_metadata must be a JSON object".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_publish_record(record: &Value, hash_field: &str) -> Result<(), (StatusCode, String)> {
    for field in [
        "schema_uri",
        "publisher_passport",
        "signature",
        "signer_kid",
        hash_field,
    ] {
        if record.get(field).and_then(Value::as_str).is_none() {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("publish record missing '{field}'"),
            ));
        }
    }
    let hash = record[hash_field].as_str().unwrap_or_default();
    let sig = record["signature"].as_str().unwrap_or_default();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("publish record '{hash_field}' is not hex32"),
        ));
    }
    if sig.len() != 128 || !sig.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "publish record signature is not hex64".to_string(),
        ));
    }
    Ok(())
}

fn publish_hash_for_kind(kind: &str, record: &Value) -> String {
    let field = if kind == "passport" {
        "passport_hash"
    } else {
        "project_hash"
    };
    record[field].as_str().unwrap_or_default().to_string()
}

async fn submit_registry_record(url: String, record: Value) -> Result<u16, (StatusCode, String)> {
    if !registry_url_allowed(&url) {
        return Err((
            StatusCode::BAD_REQUEST,
            "registry_url must be https://, or loopback http:// for local tests".to_string(),
        ));
    }
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build()
            .into();
        let response = agent
            .post(&url)
            .header("Content-Type", "application/json")
            .send_json(record)
            .map_err(|err| (StatusCode::BAD_GATEWAY, format!("registry POST failed: {err}")))?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            Ok(status)
        } else {
            Err((
                StatusCode::BAD_GATEWAY,
                format!("registry POST returned status {status}"),
            ))
        }
    })
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, format!("registry POST join error: {err}")))?
}

fn registry_url_allowed(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost")
}

fn json_to_cbor(value: &Value) -> Result<CborValue, String> {
    match value {
        Value::Null => Ok(CborValue::Null),
        Value::Bool(value) => Ok(CborValue::Bool(*value)),
        Value::Number(number) => number
            .as_u64()
            .map(CborValue::Uint)
            .ok_or_else(|| format!("non-u64 number {number}")),
        Value::String(value) => Ok(CborValue::Text(value.clone())),
        Value::Array(values) => values
            .iter()
            .map(json_to_cbor)
            .collect::<Result<Vec<_>, _>>()
            .map(CborValue::Array),
        Value::Object(map) => map
            .iter()
            .map(|(key, value)| Ok((key.clone(), json_to_cbor(value)?)))
            .collect::<Result<Vec<_>, String>>()
            .map(CborValue::Map),
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn rfc3339_from_unix_ms(ms: u64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms as i64)
        .unwrap_or_else(Utc::now)
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}
