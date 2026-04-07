// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use super::*;

#[tracing::instrument(level = "info", skip(state, headers), fields(%receipt_id, tenant_id = %q.tenant_id))]
pub(super) async fn get_receipt_body_v1(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
    Query(q): Query<TenantQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["receipts:read"], &q.tenant_id) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let (_decision, store) = match pool
        .store_for_stream(&q.tenant_id, STREAM_TYPE_RECEIPT, &receipt_id, None)
        .await
    {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let store = store.read().await;
    let events = match store
        .read_stream(&q.tenant_id, STREAM_TYPE_RECEIPT, &receipt_id, 0, 16, None)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };

    let mut body = None;
    for e in events {
        if e.event_type == EVT_RECEIPT_BODY_V1
            && body.as_ref().map_or(0, |b: &corecrux_storage::StoredEvent| b.seq) <= e.seq
        {
            body = Some(e);
        }
    }
    let Some(body) = body else {
        return problem_response(StatusCode::NOT_FOUND, "receipt body not found");
    };

    if wants_cbor(&headers) {
        let mut resp = axum::response::Response::new(axum::body::Body::from(body.payload));
        *resp.status_mut() = StatusCode::OK;
        if let Ok(v) = body.content_type.parse() {
            resp.headers_mut().insert(header::CONTENT_TYPE, v);
        }
        return resp;
    }

    #[derive(serde::Serialize)]
    struct Resp {
        tenant_id: String,
        receipt_id: String,
        seq: u64,
        #[serde(rename = "occurredAt")]
        occurred_at: String,
        #[serde(rename = "ingestedAt")]
        ingested_at: String,
        #[serde(rename = "contentType")]
        content_type: String,
        #[serde(rename = "payloadBase64")]
        payload_base64: String,
        #[serde(rename = "payloadHash")]
        payload_hash: String,
    }

    let ph = corecrux_frame::compute_payload_hash(&body.payload);
    let payload_hash = hex32(&ph);
    (
        StatusCode::OK,
        Json(Resp {
            tenant_id: q.tenant_id,
            receipt_id,
            seq: body.seq,
            occurred_at: body.occurred_at,
            ingested_at: body.ingested_at,
            content_type: body.content_type,
            payload_base64: base64::engine::general_purpose::STANDARD.encode(&body.payload),
            payload_hash,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%receipt_id, tenant_id = %q.tenant_id))]
pub(super) async fn get_receipt_signature_v1(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
    Query(q): Query<TenantQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["receipts:read"], &q.tenant_id) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let (_decision, store) = match pool
        .store_for_stream(&q.tenant_id, STREAM_TYPE_RECEIPT, &receipt_id, None)
        .await
    {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let store = store.read().await;
    let events = match store
        .read_stream(&q.tenant_id, STREAM_TYPE_RECEIPT, &receipt_id, 0, 16, None)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };

    let mut sig = None;
    for e in events {
        if e.event_type == EVT_RECEIPT_SIG_V1
            && sig.as_ref().map_or(0, |s: &corecrux_storage::StoredEvent| s.seq) <= e.seq
        {
            sig = Some(e);
        }
    }
    let Some(sig) = sig else {
        return problem_response(StatusCode::NOT_FOUND, "receipt signature not found");
    };

    if wants_cbor(&headers) {
        let mut resp = axum::response::Response::new(axum::body::Body::from(sig.payload));
        *resp.status_mut() = StatusCode::OK;
        if let Ok(v) = sig.content_type.parse() {
            resp.headers_mut().insert(header::CONTENT_TYPE, v);
        }
        return resp;
    }

    #[derive(serde::Serialize)]
    struct Resp {
        tenant_id: String,
        receipt_id: String,
        seq: u64,
        #[serde(rename = "occurredAt")]
        occurred_at: String,
        #[serde(rename = "ingestedAt")]
        ingested_at: String,
        #[serde(rename = "contentType")]
        content_type: String,
        #[serde(rename = "payloadBase64")]
        payload_base64: String,
        #[serde(rename = "payloadHash")]
        payload_hash: String,
    }

    let ph = corecrux_frame::compute_payload_hash(&sig.payload);
    let payload_hash = hex32(&ph);
    (
        StatusCode::OK,
        Json(Resp {
            tenant_id: q.tenant_id,
            receipt_id,
            seq: sig.seq,
            occurred_at: sig.occurred_at,
            ingested_at: sig.ingested_at,
            content_type: sig.content_type,
            payload_base64: base64::engine::general_purpose::STANDARD.encode(&sig.payload),
            payload_hash,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%receipt_id, tenant_id = %q.tenant_id))]
pub(super) async fn get_receipt_verification_v1(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
    Query(q): Query<TenantQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["receipts:read"], &q.tenant_id) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let stream_hash = match stream_hash_xxhash64(&q.tenant_id, STREAM_TYPE_RECEIPT, &receipt_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let (decision, store) = match pool.store_for_stream_hash(stream_hash, None).await {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let shard_id_u32 = match parse_shard_id_u32(&decision.shard_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let store = store.read().await;
    match store.verify_receipt_stream_v1(shard_id_u32, &q.tenant_id, &receipt_id) {
        Ok(Some(report)) => (StatusCode::OK, Json(report)).into_response(),
        Ok(None) => problem_response(StatusCode::NOT_FOUND, "receipt body not found"),
        Err(err) => map_store_error_http(err).into_response(),
    }
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ExportQueryV1 {
    pub(super) tenant_id: String,
    pub(super) include: Option<String>,
    pub(super) redaction: Option<String>,
    pub(super) format: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct SubjectExportQueryV1 {
    pub(super) tenant_id: String,
    pub(super) mode: Option<String>, // latest|verified|audit
    pub(super) include: Option<String>,
    pub(super) redaction: Option<String>,
    pub(super) format: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct StreamExportQueryV1 {
    pub(super) tenant_id: String,
    #[serde(rename = "fromSeq")]
    pub(super) from_seq: Option<u64>,
    #[serde(rename = "toSeq")]
    pub(super) to_seq: Option<u64>,
    #[serde(rename = "maxEvents")]
    pub(super) max_events: Option<u32>,
    pub(super) include: Option<String>,
    pub(super) redaction: Option<String>,
    pub(super) format: Option<String>,
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%receipt_id, tenant_id = %q.tenant_id))]
pub(super) async fn get_receipt_export_v1(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
    Query(q): Query<ExportQueryV1>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) =
        require_http_scopes_for_tenant(&state.auth, &headers, &["exports:read", "receipts:read"], &q.tenant_id)
    {
        return problem.into_response();
    }

    let opts = match parse_receipt_export_options_v1(q.include.as_deref(), q.redaction.as_deref(), q.format.as_deref())
    {
        Ok(v) => v,
        Err(msg) => return problem_response(StatusCode::BAD_REQUEST, msg),
    };
    export_receipt_bundle_v1(&state, &q.tenant_id, &receipt_id, opts).await
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%answer_id, tenant_id = %q.tenant_id))]
pub(super) async fn get_answer_export_v1(
    State(state): State<AppState>,
    Path(answer_id): Path<String>,
    Query(q): Query<SubjectExportQueryV1>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) =
        require_http_scopes_for_tenant(&state.auth, &headers, &["exports:read", "receipts:read"], &q.tenant_id)
    {
        return problem.into_response();
    }

    let opts = match parse_receipt_export_options_v1(q.include.as_deref(), q.redaction.as_deref(), q.format.as_deref())
    {
        Ok(v) => v,
        Err(msg) => return problem_response(StatusCode::BAD_REQUEST, msg),
    };

    let mode = q.mode.as_deref().unwrap_or("latest");
    let resolve_mode = match SubjectResolveModeV1::parse(mode) {
        Some(v) => v,
        None => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                format!("invalid mode '{mode}' (expected latest|verified|audit)"),
            );
        }
    };

    let root = state.data_dir.join("meta").join("receipts").join("subjects");
    let receipt_id = match resolve_subject_receipt_id_v1(&root, &q.tenant_id, "answer", &answer_id, resolve_mode) {
        Ok(Some(v)) => v,
        Ok(None) => return problem_response(StatusCode::NOT_FOUND, "receipt not found for answer"),
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    export_receipt_bundle_v1(&state, &q.tenant_id, &receipt_id, opts).await
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%action_id, tenant_id = %q.tenant_id))]
pub(super) async fn get_action_export_v1(
    State(state): State<AppState>,
    Path(action_id): Path<String>,
    Query(q): Query<SubjectExportQueryV1>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) =
        require_http_scopes_for_tenant(&state.auth, &headers, &["exports:read", "receipts:read"], &q.tenant_id)
    {
        return problem.into_response();
    }

    let opts = match parse_receipt_export_options_v1(q.include.as_deref(), q.redaction.as_deref(), q.format.as_deref())
    {
        Ok(v) => v,
        Err(msg) => return problem_response(StatusCode::BAD_REQUEST, msg),
    };

    let mode = q.mode.as_deref().unwrap_or("latest");
    let resolve_mode = match SubjectResolveModeV1::parse(mode) {
        Some(v) => v,
        None => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                format!("invalid mode '{mode}' (expected latest|verified|audit)"),
            );
        }
    };

    let root = state.data_dir.join("meta").join("receipts").join("subjects");
    let receipt_id = match resolve_subject_receipt_id_v1(&root, &q.tenant_id, "action", &action_id, resolve_mode) {
        Ok(Some(v)) => v,
        Ok(None) => return problem_response(StatusCode::NOT_FOUND, "receipt not found for action"),
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    export_receipt_bundle_v1(&state, &q.tenant_id, &receipt_id, opts).await
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%stream_type, %stream_id, tenant_id = %q.tenant_id))]
pub(super) async fn get_stream_export_v1(
    State(state): State<AppState>,
    Path((stream_type, stream_id)): Path<(String, String)>,
    Query(q): Query<StreamExportQueryV1>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["exports:read"], &q.tenant_id) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let (_decision, store) = match pool
        .store_for_stream(&q.tenant_id, &stream_type, &stream_id, None)
        .await
    {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };

    let format = match q.format.as_deref() {
        None => ExportFormatV1::Zip,
        Some(s) => match ExportFormatV1::parse(s) {
            Some(v) => v,
            None => {
                return problem_response(
                    StatusCode::BAD_REQUEST,
                    format!("invalid format '{s}' (expected zip|tar.zst)"),
                );
            }
        },
    };
    let redaction = match q.redaction.as_deref() {
        None => ExportRedactionV1::TenantSafe,
        Some(s) => match ExportRedactionV1::parse(s) {
            Some(v) => v,
            None => {
                return problem_response(
                    StatusCode::BAD_REQUEST,
                    format!("invalid redaction '{s}' (expected none|metadata_only|tenant_safe)"),
                );
            }
        },
    };

    let include = match q.include.as_deref() {
        None => Vec::new(),
        Some(s) => {
            let mut out = Vec::new();
            for part in s.split(',').map(|v| v.trim()).filter(|v| !v.is_empty()) {
                match part {
                    "headers" | "payloads" => out.push(part.to_string()),
                    _ => {
                        return problem_response(
                            StatusCode::BAD_REQUEST,
                            format!("invalid include '{part}' (expected headers,payloads)"),
                        );
                    }
                }
            }
            out
        }
    };

    let from_seq = q.from_seq.unwrap_or(0);
    let to_seq = q.to_seq;
    if let Some(to) = to_seq {
        if to < from_seq {
            return problem_response(StatusCode::BAD_REQUEST, "toSeq must be >= fromSeq");
        }
    }

    let max_events_total = q.max_events.unwrap_or(10_000).min(50_000);

    let mut events: Vec<corecrux_storage::StoredEvent> = Vec::new();
    {
        let store = store.read().await;
        let mut cur = from_seq;
        while (events.len() as u32) < max_events_total {
            let remaining = max_events_total - (events.len() as u32);
            let batch = remaining.min(1024);
            let batch_events = match store
                .read_stream(&q.tenant_id, &stream_type, &stream_id, cur, batch, None)
                .await
            {
                Ok(v) => v,
                Err(err) => {
                    return map_store_error_http(err).into_response();
                }
            };
            if batch_events.is_empty() {
                break;
            }
            for ev in batch_events {
                if let Some(to) = to_seq {
                    if ev.seq > to {
                        break;
                    }
                }
                cur = ev.seq.saturating_add(1);
                events.push(ev);
                if (events.len() as u32) >= max_events_total {
                    break;
                }
            }
            if let Some(to) = to_seq {
                if cur > to {
                    break;
                }
            }
        }
    }

    // Build headers JSONL deterministically (serde struct field order).
    #[derive(serde::Serialize, Clone, Copy)]
    struct Loc {
        #[serde(rename = "shardId")]
        shard_id: u64,
        epoch: u64,
        #[serde(rename = "segmentSeq")]
        segment_seq: u64,
        offset: u64,
    }

    #[derive(serde::Serialize)]
    struct HeaderLine<'a> {
        #[serde(rename = "tenantId")]
        tenant_id: &'a str,
        #[serde(rename = "streamType")]
        stream_type: &'a str,
        #[serde(rename = "streamId")]
        stream_id: &'a str,
        seq: u64,
        #[serde(rename = "eventId")]
        event_id: &'a str,
        #[serde(rename = "occurredAt")]
        occurred_at: &'a str,
        #[serde(rename = "ingestedAt")]
        ingested_at: &'a str,
        #[serde(rename = "eventType")]
        event_type: &'a str,
        #[serde(rename = "contentType")]
        content_type: &'a str,
        #[serde(rename = "payloadLen")]
        payload_len: u32,
        #[serde(rename = "payloadHash")]
        payload_hash: String,
        #[serde(rename = "headerHash")]
        header_hash: String,
        location: Loc,
    }

    let mut headers_jsonl = Vec::<u8>::with_capacity(events.len() * 256);
    let mut payload_files: Vec<(String, Vec<u8>)> = Vec::new();

    let include_headers = include.is_empty() || include.iter().any(|v| v == "headers");
    let include_payloads = if include.is_empty() {
        redaction != ExportRedactionV1::MetadataOnly
    } else {
        include.iter().any(|v| v == "payloads")
    };

    if include_headers {
        for ev in &events {
            let payload_hash = corecrux_frame::compute_payload_hash(&ev.payload);
            let canonical = corecrux_frame::CanonicalHeaderV1 {
                tenant_id: q.tenant_id.clone(),
                stream_id: stream_id.clone(),
                stream_type: stream_type.clone(),
                seq: ev.seq,
                event_id: ev.event_id.clone(),
                occurred_at: ev.occurred_at.clone(),
                ingested_at: ev.ingested_at.clone(),
                event_type: ev.event_type.clone(),
                content_type: ev.content_type.clone(),
                payload_len: ev.payload.len() as u32,
                payload_hash,
            };
            let canon_bytes = corecrux_frame::canonical_header_bytes_v1(&canonical);
            let header_hash = compute_header_hash(&canon_bytes);

            let line = HeaderLine {
                tenant_id: &q.tenant_id,
                stream_type: &stream_type,
                stream_id: &stream_id,
                seq: ev.seq,
                event_id: &ev.event_id,
                occurred_at: &ev.occurred_at,
                ingested_at: &ev.ingested_at,
                event_type: &ev.event_type,
                content_type: &ev.content_type,
                payload_len: ev.payload.len() as u32,
                payload_hash: hex32(&payload_hash),
                header_hash: hex32(&header_hash),
                location: Loc {
                    shard_id: ev.location.shard_id,
                    epoch: ev.location.epoch,
                    segment_seq: ev.location.segment_seq,
                    offset: ev.location.offset,
                },
            };
            if serde_json::to_writer(&mut headers_jsonl, &line).is_err() {
                return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to serialize header jsonl");
            }
            headers_jsonl.push(b'\n');
        }
    }

    if include_payloads {
        for ev in &events {
            let name = format!("events/payloads/seq-{seq:020}.bin", seq = ev.seq);
            payload_files.push((name, ev.payload.clone()));
        }
    }

    // Manifest for stream slice export.
    #[derive(serde::Serialize)]
    struct BuildInfoV1 {
        version: String,
        commit: String,
    }

    #[derive(serde::Serialize)]
    struct StreamManifestV1 {
        #[serde(rename = "export_schema")]
        export_schema: String,
        #[serde(rename = "generated_at")]
        generated_at: String,
        #[serde(rename = "tenant_id")]
        tenant_id: String,
        #[serde(rename = "stream_type")]
        stream_type: String,
        #[serde(rename = "stream_id")]
        stream_id: String,
        #[serde(rename = "from_seq_inclusive")]
        from_seq_inclusive: u64,
        #[serde(rename = "to_seq_inclusive", skip_serializing_if = "Option::is_none")]
        to_seq_inclusive: Option<u64>,
        #[serde(rename = "corecrux_build")]
        corecrux_build: BuildInfoV1,
        #[serde(rename = "format")]
        format: String,
        #[serde(rename = "redaction")]
        redaction: String,
        #[serde(rename = "include")]
        include: Vec<String>,
        #[serde(rename = "included_files")]
        included_files: Vec<corecrux_receipts::ExportFileV1>,
        #[serde(rename = "total_events")]
        total_events: u64,
    }

    let generated_at = events.last().map_or_else(
        || chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        |e| e.ingested_at.clone(),
    );

    // Compute included file digests.
    let mut included_files: Vec<corecrux_receipts::ExportFileV1> = Vec::new();
    if include_headers {
        included_files.push(corecrux_receipts::ExportFileV1 {
            path: "events/headers.jsonl".to_string(),
            blake3: blake3::hash(&headers_jsonl).to_hex().to_string(),
            size: headers_jsonl.len() as u64,
        });
    }
    for (path, bytes) in &payload_files {
        included_files.push(corecrux_receipts::ExportFileV1 {
            path: path.clone(),
            blake3: blake3::hash(bytes).to_hex().to_string(),
            size: bytes.len() as u64,
        });
    }

    let manifest = StreamManifestV1 {
        export_schema: "cuecrux.replay.export.v1".to_string(),
        generated_at: generated_at.clone(),
        tenant_id: q.tenant_id.clone(),
        stream_type: stream_type.clone(),
        stream_id: stream_id.clone(),
        from_seq_inclusive: from_seq,
        to_seq_inclusive: to_seq,
        corecrux_build: BuildInfoV1 {
            version: state.build.version.clone(),
            commit: state.build.commit.clone(),
        },
        format: format.as_str().to_string(),
        redaction: redaction.as_str().to_string(),
        include,
        included_files: included_files.clone(),
        total_events: events.len() as u64,
    };
    let manifest_json = match serde_json::to_vec_pretty(&manifest) {
        Ok(v) => v,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    // Build archive.
    let mut archive_entries: Vec<(String, Vec<u8>)> = Vec::new();
    archive_entries.push(("manifest.json".to_string(), manifest_json.clone()));
    if include_headers {
        archive_entries.push(("events/headers.jsonl".to_string(), headers_jsonl));
    }
    archive_entries.extend(payload_files);
    archive_entries.sort_by(|a, b| a.0.cmp(&b.0));

    let archive_bytes = match format {
        ExportFormatV1::Zip => build_zip_deterministic_bytes(&archive_entries),
        ExportFormatV1::TarZst => build_tar_zst_deterministic_bytes(&archive_entries),
    };
    let archive_bytes = match archive_bytes {
        Ok(v) => v,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    let filename = format!(
        "stream-{stream_type}-{stream_id}-from{from_seq}.{ext}",
        ext = format.filename_ext()
    );

    let mut resp = axum::response::Response::new(axum::body::Body::from(archive_bytes));
    *resp.status_mut() = StatusCode::OK;
    // SAFETY: content_type() returns a static MIME string; filename is sanitised above.
    #[allow(clippy::unwrap_used)]
    {
        resp.headers_mut()
            .insert(header::CONTENT_TYPE, format.content_type().parse().unwrap());
        resp.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\"").parse().unwrap(),
        );
    }
    resp
}

pub(super) fn parse_receipt_export_options_v1(
    include: Option<&str>,
    redaction: Option<&str>,
    format: Option<&str>,
) -> Result<ReceiptExportOptionsV1, String> {
    let format = match format {
        None => ExportFormatV1::Zip,
        Some(s) => ExportFormatV1::parse(s).ok_or_else(|| format!("invalid format '{s}' (expected zip|tar.zst)"))?,
    };
    let redaction = match redaction {
        None => ExportRedactionV1::TenantSafe,
        Some(s) => ExportRedactionV1::parse(s)
            .ok_or_else(|| format!("invalid redaction '{s}' (expected none|metadata_only|tenant_safe)"))?,
    };
    let include = match include {
        None => Vec::new(),
        Some(s) => {
            let mut out = Vec::new();
            for part in s.split(',').map(|v| v.trim()).filter(|v| !v.is_empty()) {
                let v = ReceiptExportIncludeV1::parse(part).ok_or_else(|| {
                    format!(
                        "invalid include '{part}' (expected body,sig,verification,trace_summary,subject_links,linked_receipts)"
                    )
                })?;
                out.push(v);
            }
            out
        }
    };
    Ok(ReceiptExportOptionsV1 {
        format,
        redaction,
        include,
    })
}

pub(super) async fn export_receipt_bundle_v1(
    state: &AppState,
    tenant_id: &str,
    receipt_id: &str,
    opts: ReceiptExportOptionsV1,
) -> axum::response::Response {
    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let (_decision, store) = match pool
        .store_for_stream(tenant_id, STREAM_TYPE_RECEIPT, receipt_id, None)
        .await
    {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let store = store.read().await;
    let events = match store
        .read_tail(tenant_id, STREAM_TYPE_RECEIPT, receipt_id, 32, None)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            state.metrics.inc_receipt_export_total("error");
            return map_store_error_http(err).into_response();
        }
    };

    let mut body = None;
    let mut sig = None;
    for e in events {
        if e.event_type == EVT_RECEIPT_BODY_V1
            && body.as_ref().map_or(0, |b: &corecrux_storage::StoredEvent| b.seq) <= e.seq
        {
            body = Some(e);
        } else if e.event_type == EVT_RECEIPT_SIG_V1
            && sig.as_ref().map_or(0, |s: &corecrux_storage::StoredEvent| s.seq) <= e.seq
        {
            sig = Some(e);
        }
    }

    let Some(body) = body else {
        state.metrics.inc_receipt_export_total("not_found");
        return problem_response(StatusCode::NOT_FOUND, "receipt body not found");
    };
    let Some(sig) = sig else {
        state.metrics.inc_receipt_export_total("precondition");
        return problem_response(StatusCode::PRECONDITION_FAILED, "receipt signature missing");
    };

    let body_payload_hash = corecrux_frame::compute_payload_hash(&body.payload);
    let sig_payload_hash = corecrux_frame::compute_payload_hash(&sig.payload);

    let body_canon = corecrux_frame::CanonicalHeaderV1 {
        tenant_id: tenant_id.to_string(),
        stream_id: receipt_id.to_string(),
        stream_type: STREAM_TYPE_RECEIPT.to_string(),
        seq: body.seq,
        event_id: body.event_id.clone(),
        occurred_at: body.occurred_at.clone(),
        ingested_at: body.ingested_at.clone(),
        event_type: body.event_type.clone(),
        content_type: body.content_type.clone(),
        payload_len: body.payload.len() as u32,
        payload_hash: body_payload_hash,
    };
    let sig_canon = corecrux_frame::CanonicalHeaderV1 {
        tenant_id: tenant_id.to_string(),
        stream_id: receipt_id.to_string(),
        stream_type: STREAM_TYPE_RECEIPT.to_string(),
        seq: sig.seq,
        event_id: sig.event_id.clone(),
        occurred_at: sig.occurred_at.clone(),
        ingested_at: sig.ingested_at.clone(),
        event_type: sig.event_type.clone(),
        content_type: sig.content_type.clone(),
        payload_len: sig.payload.len() as u32,
        payload_hash: sig_payload_hash,
    };
    let body_canon_bytes = corecrux_frame::canonical_header_bytes_v1(&body_canon);
    let sig_canon_bytes = corecrux_frame::canonical_header_bytes_v1(&sig_canon);
    let body_header_hash = compute_header_hash(&body_canon_bytes);
    let sig_header_hash = compute_header_hash(&sig_canon_bytes);

    let generated_at = sig.ingested_at.clone();

    let shard_id_u32 = match u32::try_from(body.location.shard_id) {
        Ok(v) => v,
        Err(_) => {
            state.metrics.inc_receipt_export_total("error");
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "shard_id out of range");
        }
    };
    let report = match store.verify_receipt_stream_v1(shard_id_u32, tenant_id, receipt_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            state.metrics.inc_receipt_export_total("not_found");
            return problem_response(StatusCode::NOT_FOUND, "receipt body not found");
        }
        Err(err) => {
            state.metrics.inc_receipt_export_total("error");
            return problem_response(StatusCode::BAD_REQUEST, err.to_string());
        }
    };

    let sig_event_ref = format!(
        "shard={} segmentSeq={} offset={}",
        sig.location.shard_id, sig.location.segment_seq, sig.location.offset
    );

    let trace_summary_json = if opts.include.contains(&ReceiptExportIncludeV1::TraceSummary) {
        Some(build_trace_summary_json_v1(tenant_id, receipt_id, &body.payload))
    } else {
        None
    };
    let subject_links_json = if opts.include.contains(&ReceiptExportIncludeV1::SubjectLinks) {
        Some(build_subject_links_json_v1(tenant_id, receipt_id, &body.payload))
    } else {
        None
    };
    let lineage_json = if opts.include.contains(&ReceiptExportIncludeV1::LinkedReceipts) {
        Some(build_lineage_json_v1(tenant_id, receipt_id, &body.payload))
    } else {
        None
    };

    let export = match build_receipt_export_v1(
        corecrux_receipts::BuildReceiptExportInput {
            generated_at: &generated_at,
            tenant_id,
            receipt_id,
            build: &state.build,
            body_bytes: &body.payload,
            sig_bytes: &sig.payload,
            verification_report: &report,
            body_payload_hash_hex: &hex32(&body_payload_hash),
            sig_event_ref: &sig_event_ref,
            event_headers: vec![
                corecrux_receipts::ReceiptEventHeaderRefV1 {
                    header_hash: hex32(&body_header_hash),
                    payload_hash: hex32(&body_payload_hash),
                    seq: body.seq,
                    event_id: body.event_id.clone(),
                    occurred_at: body.occurred_at.clone(),
                },
                corecrux_receipts::ReceiptEventHeaderRefV1 {
                    header_hash: hex32(&sig_header_hash),
                    payload_hash: hex32(&sig_payload_hash),
                    seq: sig.seq,
                    event_id: sig.event_id.clone(),
                    occurred_at: sig.occurred_at.clone(),
                },
            ],
            trace_summary_json: trace_summary_json.as_deref(),
            subject_links_json: subject_links_json.as_deref(),
            lineage_json: lineage_json.as_deref(),
        },
        &opts,
    ) {
        Ok(b) => b,
        Err(err) => {
            state.metrics.inc_receipt_export_total("error");
            return match err {
                corecrux_receipts::ExportError::Precondition { msg } => {
                    problem_response(StatusCode::PRECONDITION_FAILED, msg)
                }
                _ => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            };
        }
    };

    state.metrics.inc_receipt_export_total("ok");

    let filename = format!("receipt-{receipt_id}.{}", export.filename_ext);

    let mut resp = axum::response::Response::new(axum::body::Body::from(export.archive_bytes));
    *resp.status_mut() = StatusCode::OK;
    // SAFETY: content_type is a known MIME string; filename is sanitised above.
    #[allow(clippy::unwrap_used)]
    {
        resp.headers_mut()
            .insert(header::CONTENT_TYPE, export.content_type.parse().unwrap());
        resp.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\"").parse().unwrap(),
        );
    }
    resp
}

pub(crate) fn build_trace_summary_json_v1(tenant_id: &str, receipt_id: &str, body_bytes: &[u8]) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct TraceSummary<'a> {
        schema: &'a str,
        #[serde(rename = "tenant_id")]
        tenant_id: &'a str,
        #[serde(rename = "receipt_id")]
        receipt_id: &'a str,
        #[serde(rename = "parse_ok")]
        parse_ok: bool,
        kind: Option<String>,
        mode: Option<String>,
        #[serde(rename = "subject_type")]
        subject_type: Option<String>,
        #[serde(rename = "subject_id")]
        subject_id: Option<String>,
    }

    let idx = corecrux_receipts::extract_body_index_v1(body_bytes);
    let (parse_ok, kind, mode, subject_type, subject_id) = match idx {
        Some(v) => (true, v.kind, v.mode, v.subject_type, v.subject_id),
        None => (false, None, None, None, None),
    };
    serde_json::to_vec_pretty(&TraceSummary {
        schema: "cuecrux.receipt.trace_summary.v1",
        tenant_id,
        receipt_id,
        parse_ok,
        kind,
        mode,
        subject_type,
        subject_id,
    })
    .unwrap_or_else(|_| b"{\"schema\":\"cuecrux.receipt.trace_summary.v1\",\"parse_ok\":false}\n".to_vec())
}

pub(crate) fn build_subject_links_json_v1(tenant_id: &str, receipt_id: &str, body_bytes: &[u8]) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct SubjectLinks<'a> {
        schema: &'a str,
        #[serde(rename = "tenant_id")]
        tenant_id: &'a str,
        #[serde(rename = "receipt_id")]
        receipt_id: &'a str,
        #[serde(rename = "parse_ok")]
        parse_ok: bool,
        kind: Option<String>,
        mode: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        subject: Option<Subject<'a>>,
    }
    #[derive(serde::Serialize)]
    struct Subject<'a> {
        #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
        subject_type: Option<&'a str>,
        id: &'a str,
    }

    let idx = corecrux_receipts::extract_body_index_v1(body_bytes);
    let (parse_ok, kind, mode, subject_type, subject_id) = match idx {
        Some(v) => (true, v.kind, v.mode, v.subject_type, v.subject_id),
        None => (false, None, None, None, None),
    };

    let subject_id = subject_id.unwrap_or_default();
    let subject_type = subject_type.as_deref();

    serde_json::to_vec_pretty(&SubjectLinks {
        schema: "cuecrux.receipt.subject_links.v1",
        tenant_id,
        receipt_id,
        parse_ok: parse_ok && !subject_id.is_empty(),
        kind,
        mode,
        subject: if subject_id.is_empty() {
            None
        } else {
            Some(Subject {
                subject_type,
                id: &subject_id,
            })
        },
    })
    .unwrap_or_else(|_| b"{\"schema\":\"cuecrux.receipt.subject_links.v1\",\"parse_ok\":false}\n".to_vec())
}

pub(crate) fn build_lineage_json_v1(tenant_id: &str, receipt_id: &str, body_bytes: &[u8]) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Lineage<'a> {
        schema: &'a str,
        #[serde(rename = "tenant_id")]
        tenant_id: &'a str,
        #[serde(rename = "receipt_id")]
        receipt_id: &'a str,
        #[serde(rename = "parse_ok")]
        parse_ok: bool,
        kind: Option<String>,
        mode: Option<String>,
        #[serde(rename = "subject_type")]
        subject_type: Option<String>,
        #[serde(rename = "subject_id")]
        subject_id: Option<String>,
        #[serde(rename = "linked_receipts")]
        linked_receipts: Vec<String>,
    }

    let idx = corecrux_receipts::extract_body_index_v1(body_bytes);
    let (kind, mode, subject_type, subject_id) = match idx {
        Some(v) => (v.kind, v.mode, v.subject_type, v.subject_id),
        None => (None, None, None, None),
    };
    let linked = corecrux_receipts::extract_linked_receipts_v1(body_bytes);
    let (parse_ok, linked_receipts) = match linked {
        Some(v) => (true, v),
        None => (false, Vec::new()),
    };

    serde_json::to_vec_pretty(&Lineage {
        schema: "cuecrux.receipt.lineage.v1",
        tenant_id,
        receipt_id,
        parse_ok,
        kind,
        mode,
        subject_type,
        subject_id,
        linked_receipts,
    })
    .unwrap_or_else(|_| b"{\"schema\":\"cuecrux.receipt.lineage.v1\",\"parse_ok\":false}\n".to_vec())
}

#[allow(clippy::expect_used)] // SAFETY: 1980-01-01 00:00:00 is a valid ZIP timestamp.
pub(super) fn build_zip_deterministic_bytes(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut cursor = std::io::Cursor::new(Vec::<u8>::with_capacity(4096));
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);
        let ts = zip::DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).expect("static zip timestamp");
        let opts = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(ts)
            .unix_permissions(0o644);
        for (path, bytes) in files {
            zw.start_file(path, opts).map_err(|e| e.to_string())?;
            zw.write_all(bytes).map_err(|e| e.to_string())?;
        }
        zw.finish().map_err(|e| e.to_string())?;
    }
    Ok(cursor.into_inner())
}

pub(super) fn build_tar_zst_deterministic_bytes(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut tar_bytes = Vec::<u8>::with_capacity(4096);
    {
        let mut tb = tar::Builder::new(&mut tar_bytes);
        tb.mode(tar::HeaderMode::Deterministic);

        for (path, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            tb.append_data(&mut header, path.as_str(), std::io::Cursor::new(bytes))
                .map_err(|e| e.to_string())?;
        }
        tb.finish().map_err(|e| e.to_string())?;
    }

    let mut enc = zstd::Encoder::new(Vec::new(), 3).map_err(|e| e.to_string())?;
    enc.write_all(&tar_bytes).map_err(|e| e.to_string())?;
    enc.finish().map_err(|e| e.to_string())
}
