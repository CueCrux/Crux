// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Session observation capture with Ed25519-signed receipts.
//!
//! Per ExecPlan `crux-daemon-session-observations-multi-provider-2026-05-13`:
//! the M1 surface is per-session append-only JSONL under
//! `<data_dir>/observations/<scoped_session_id>.jsonl`. Each line is a
//! canonical-JSON record carrying a CROWN-style receipt (Ed25519 sig over
//! the BLAKE3 hash of the canonical bytes, excluding the receipt itself).
//!
//! Storage upgrade to the hash-chained event stream is a downstream replay
//! with no API break (see ExecPlan §Migration).

use std::path::{Path, PathBuf};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::facts::{require_fact_read_ctx, require_session_write_ctx, scoped_session_id_for_http};
use super::{problem_response, AppState};

/// Default maximum JSON-payload size we accept per observation (bytes). Hooks &
/// proxy adapters should keep payloads small (and truncate oversize tool I/O);
/// the daemon enforces this as a hard limit to keep replay/verification cheap.
const DEFAULT_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Floor for the operator override — an absurdly small cap would silently drop
/// nearly every observation, so values below this are ignored.
const MIN_MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Effective per-observation payload cap. Overridable via
/// `CORECRUXD_MAX_OBSERVATION_PAYLOAD_BYTES` (bytes); values below
/// [`MIN_MAX_PAYLOAD_BYTES`] or unparseable values fall back to
/// [`DEFAULT_MAX_PAYLOAD_BYTES`]. Read once at first use.
static MAX_PAYLOAD_BYTES: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
    std::env::var("CORECRUXD_MAX_OBSERVATION_PAYLOAD_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n >= MIN_MAX_PAYLOAD_BYTES)
        .unwrap_or(DEFAULT_MAX_PAYLOAD_BYTES)
});

/// Default cap for GET responses.
const DEFAULT_GET_LIMIT: usize = 500;
const MAX_GET_LIMIT: usize = 5000;

/// Aggregate-route caps. Smaller defaults so a wide query against many
/// sessions doesn't dump everything; callers can override up to the max.
const DEFAULT_AGGREGATE_LIMIT: usize = 100;
const MAX_AGGREGATE_LIMIT: usize = 1000;

/// Subdirectory under `data_dir` for observation JSONL files.
const OBS_SUBDIR: &str = "observations";

// ── Request / response shapes ─────────────────────────────────────────────

/// Incoming body for `POST /v1/sessions/{id}/observations`.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct PostObservationBody {
    /// Lifecycle kind. Free-form on M1 (provider-specific schemas live on the
    /// adapter side). Conventional values: `session_start`, `user_prompt`,
    /// `tool_use`, `model_response`, `stop`, `session_end`.
    pub kind: String,
    /// Capture provider. Conventional values: `claude-code`, `openai`,
    /// `anthropic`, `openclaw`.
    pub provider: String,
    /// Optional client-side timestamp (RFC3339). Server still owns the
    /// canonical `ts`; this is recorded separately to surface clock skew.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ts: Option<DateTime<Utc>>,
    /// Opaque provider-specific payload. Capped at MAX_PAYLOAD_BYTES.
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// Batched-write variant body.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct PostObservationsBatchBody {
    pub items: Vec<PostObservationBody>,
}

/// Incoming body for `POST /v1/mediation/receipts` — an externally-mediated
/// (gateway) tool call to be recorded as a passport-attributed CROWN receipt.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct PostMediationReceiptBody {
    /// Passport the call is attributed to. The caller must be able to *resolve*
    /// it (capability-bound) or the ingest is rejected — this is what blocks
    /// forged attribution.
    pub passport_id: String,
    /// Upstream MCP server the tool belongs to (e.g. `playwright`, `openclaw`).
    pub tool_server: String,
    pub tool: String,
    /// Hash of the (redacted) tool arguments — never the raw args.
    #[serde(default)]
    pub args_sha: Option<String>,
    /// `allow` | `deny`.
    pub decision: String,
    /// `ok` | `denied` | `error` | `pending`.
    pub outcome: String,
    /// Gateway-side timestamp of the tool call (recorded as `client_ts`; the
    /// server still owns the canonical `ts`).
    #[serde(default)]
    pub ts: Option<DateTime<Utc>>,
    /// Originating agent session id — used only to group the mediation log.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Receipt envelope returned to the caller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct ReceiptEnvelopeV1 {
    pub alg: String,
    pub signed_by: String,
    pub body_hash: String,
    pub signature: String,
}

/// Persisted record (one JSONL line). Phase 2 M5e: carries `seq` + `prev_hash`
/// so the JSONL is sequence-level tamper-evident — removing or reordering any
/// line breaks the chain. `prev_hash` is `None` for the first record of a
/// chain (`seq == Some(0)`); subsequent records carry the previous record's
/// `body_hash` (the hex part after the `blake3:` prefix).
///
/// **Backwards compatibility**: both fields are `Option`-typed with
/// `skip_serializing_if = "Option::is_none"`. Pre-M5e records on disk had
/// neither field; re-reading them yields `seq == None, prev_hash == None`
/// and re-serialising omits both, so the original signature remains valid.
/// A session's chain may therefore have a "legacy prefix" of unchained
/// records followed by a "chained suffix" starting at `seq == Some(0)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ObservationRecordV1 {
    pub observation_id: String,
    pub session_id: String,
    pub ts: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ts: Option<DateTime<Utc>>,
    pub provider: String,
    pub principal: String,
    pub kind: String,
    pub payload: serde_json::Value,
    /// Monotonic 0-based index of this record within the chained suffix of
    /// the session's JSONL. `None` for pre-M5e legacy records. Verifiers
    /// reject gaps within a chained suffix (`seq` must be contiguous).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// `body_hash` of the previous record in this session (hex, no prefix).
    /// `None` iff this is the first record of a chained suffix, or the
    /// record is a pre-M5e legacy record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    pub receipt: ReceiptEnvelopeV1,
}

/// POST response (singleton).
#[derive(Debug, Clone, Serialize)]
pub(super) struct PostObservationResponse {
    pub observation_id: String,
    pub ts: DateTime<Utc>,
    pub receipt: ReceiptEnvelopeV1,
}

/// POST response (batch).
#[derive(Debug, Clone, Serialize)]
pub(super) struct PostObservationsBatchResponse {
    pub items: Vec<PostObservationResponse>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ListObservationsQuery {
    #[serde(default)]
    pub since: Option<DateTime<Utc>>,
    #[serde(default)]
    pub limit: Option<usize>,
    /// Optional capture-provider filter (e.g. `claude-code`, `openai`,
    /// `codex-cli`, `anthropic`). When set, only matching records are
    /// returned.
    #[serde(default)]
    pub provider: Option<String>,
}

/// Phase 2 M5f.1: query for `GET /v1/observations/aggregate`.
#[derive(Debug, Deserialize)]
pub(super) struct AggregateObservationsQuery {
    #[serde(default)]
    pub since: Option<DateTime<Utc>>,
    /// Filter by capture provider.
    #[serde(default)]
    pub provider: Option<String>,
    /// Filter by observation kind (`session_start`, `tool_use`, …).
    #[serde(default)]
    pub kind: Option<String>,
    /// Filter by exact session id (scoped via the caller's passport).
    /// Useful for replaying a specific session without knowing whether it
    /// has an active binding.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Maximum records to return. Defaults to `DEFAULT_AGGREGATE_LIMIT`,
    /// capped at `MAX_AGGREGATE_LIMIT`. Records are sorted by `ts`
    /// descending so the most recent observations always make the cut.
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub(super) struct AggregateObservationsResponse {
    pub observations: Vec<ObservationRecordV1>,
    /// Per-session chain status keyed by `session_id`. Lets a caller spot
    /// "the aggregate is fresh data, but session X's chain is broken on
    /// disk" without a follow-up call.
    pub chains: std::collections::BTreeMap<String, ChainStatusJson>,
    /// Total matched records *before* the `limit` truncation, so callers
    /// know whether they need to paginate via `since`.
    pub matched: usize,
    pub returned: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct ListObservationsResponse {
    pub observations: Vec<ObservationRecordV1>,
    /// Phase 2 M5e: structural integrity of the per-session chain across
    /// the returned records. `chain.status` is one of `"no_chain"`, `"ok"`,
    /// or `"broken"`. Clients that don't need this can ignore it.
    pub chain: ChainStatusJson,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ChainStatusJson {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_prefix_len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chained_len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<ChainStatus> for ChainStatusJson {
    fn from(status: ChainStatus) -> Self {
        match status {
            ChainStatus::NoChain => ChainStatusJson {
                status: "no_chain",
                legacy_prefix_len: None,
                chained_len: None,
                broken_at_index: None,
                reason: None,
            },
            ChainStatus::Ok {
                legacy_prefix_len,
                chained_len,
            } => ChainStatusJson {
                status: "ok",
                legacy_prefix_len: Some(legacy_prefix_len),
                chained_len: Some(chained_len),
                broken_at_index: None,
                reason: None,
            },
            ChainStatus::Broken { at_index, reason } => ChainStatusJson {
                status: "broken",
                legacy_prefix_len: None,
                chained_len: None,
                broken_at_index: Some(at_index),
                reason: Some(reason),
            },
        }
    }
}

// ── Path helpers ──────────────────────────────────────────────────────────

fn observations_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(OBS_SUBDIR)
}

/// Enumerate `<data_dir>/observations/*.jsonl`. Skips dotfiles, directories
/// (e.g. the future `.archived/`), and anything not ending in `.jsonl`.
fn list_observation_files(data_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let dir = observations_dir(data_dir);
    let read = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut out = Vec::new();
    for entry in read {
        let entry = entry?;
        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => continue,
        };
        if file_name.starts_with('.') {
            continue;
        }
        if !std::path::Path::new(file_name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
        {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        out.push(path);
    }
    out.sort();
    Ok(out)
}

/// Derive the session id from a `<session>.jsonl` filename. Inverse of
/// `sanitize_session_id_for_filename` for the common case where the
/// session id didn't need sanitisation (most UUIDs); for sanitised ids
/// we return the on-disk name as-is, which is the best we can do without
/// a sidecar mapping.
fn session_id_from_file(path: &Path) -> Option<String> {
    path.file_stem().and_then(|s| s.to_str()).map(String::from)
}

/// Filesystem-safe filename derived from the scoped session id. Slashes,
/// colons, and other separators get replaced with `_` so the scoped form
/// (which may include `agent/session-uuid`) maps cleanly to a single file.
fn sanitize_session_id_for_filename(session_id: &str) -> String {
    session_id
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .collect()
}

pub(super) fn observation_file_path(data_dir: &Path, scoped_session_id: &str) -> PathBuf {
    let filename = format!("{}.jsonl", sanitize_session_id_for_filename(scoped_session_id));
    observations_dir(data_dir).join(filename)
}

// ── Canonicalisation + signing ────────────────────────────────────────────

/// Build the canonical-bytes representation of the record body — every
/// field except `receipt`. Implemented as "serialise the record to a JSON
/// Value, drop the `receipt` key, re-serialise" so the daemon side and any
/// offline verifier converge by construction: both arrive at the same
/// `Value` after stripping `receipt`, and `serde_json::to_vec` on a
/// `Value::Object` writes keys in BTreeMap (alphabetical) order
/// deterministically. The verifier just needs to drop `receipt` from the
/// parsed JSONL line and re-serialise; it does not need to know the
/// daemon's struct field order or the DateTime format choice, because the
/// only thing that travels through the hash is the bytes produced by this
/// same operation.
fn canonical_body_bytes(record: &ObservationRecordV1) -> Result<Vec<u8>, String> {
    let mut value = serde_json::to_value(record).map_err(|err| format!("to_value: {err}"))?;
    if let serde_json::Value::Object(obj) = &mut value {
        obj.remove("receipt");
    }
    serde_json::to_vec(&value).map_err(|err| format!("canonicalise observation body: {err}"))
}

fn mint_receipt(state: &AppState, body_bytes: &[u8]) -> Result<ReceiptEnvelopeV1, (StatusCode, String)> {
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
    let hash = blake3::hash(body_bytes);
    let signature = key.sign_hash(hash.as_bytes());
    Ok(ReceiptEnvelopeV1 {
        alg: "ed25519".to_string(),
        signed_by: state.passport_fpr.clone(),
        body_hash: format!("blake3:{}", hex::encode(hash.as_bytes())),
        signature: hex::encode(signature),
    })
}

// ── Persistence ───────────────────────────────────────────────────────────

fn append_observation(file_path: &Path, line: &str) -> std::io::Result<()> {
    use std::fs::{create_dir_all, OpenOptions};
    use std::io::Write;
    if let Some(parent) = file_path.parent() {
        create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(file_path)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

/// Chain-tip info returned by `read_chain_tip`: the previous record's
/// `seq` (or `None` if it was a pre-M5e legacy record), and its
/// `body_hash` hex without the `blake3:` prefix. `None` from the function
/// itself means "no records at all" (new session).
type ChainTip = (Option<u64>, String);

/// Return the chain tip of the last record in the JSONL file, or `None`
/// if the file does not exist / is empty. Tail-reads up to 64KB from the
/// file's end for O(1)-ish chain lookup regardless of session length;
/// falls back to a full read if a single record exceeds 64KB or the
/// tail-window contains no parseable line.
fn read_chain_tip(file_path: &Path) -> std::io::Result<Option<ChainTip>> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    const TAIL_WINDOW: u64 = 64 * 1024;

    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(None);
    }
    let start = size.saturating_sub(TAIL_WINDOW);
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::with_capacity((size - start) as usize);
    file.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    // Walk lines in reverse — the LAST parseable record is the tip.
    for line in text.lines().rev() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<ObservationRecordV1>(line) {
            let hex = record
                .receipt
                .body_hash
                .strip_prefix("blake3:")
                .unwrap_or(record.receipt.body_hash.as_str())
                .to_string();
            return Ok(Some((record.seq, hex)));
        }
    }
    // 64KB window didn't yield a parseable record (single line > 64KB?).
    // Fall back to a full read so chain integrity isn't silently broken.
    let all = read_observations(file_path)?;
    Ok(all.last().map(|r| {
        let hex = r
            .receipt
            .body_hash
            .strip_prefix("blake3:")
            .unwrap_or(r.receipt.body_hash.as_str())
            .to_string();
        (r.seq, hex)
    }))
}

fn read_observations(file_path: &Path) -> std::io::Result<Vec<ObservationRecordV1>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ObservationRecordV1>(&line) {
            Ok(record) => out.push(record),
            Err(err) => {
                tracing::warn!(
                    target = "observations",
                    file = %file_path.display(),
                    error = %err,
                    "skipping malformed observation line"
                );
            }
        }
    }
    Ok(out)
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// Construct an observation record, sign it, and append it to the per-session
/// JSONL file. Shared by both the singleton and batch handlers.
///
/// `chain_tip` is the (seq, body_hash_hex) of the most recently appended
/// record. The batch handler passes the *previous in-flight* tip so the
/// chain is built without re-reading the file between records; singleton
/// callers pass `None`, which triggers a tail-read of the on-disk file.
/// Returns the response *plus* the new chain tip so the batch loop can
/// thread it forward.
pub(super) fn append_one(
    state: &AppState,
    scoped_session_id: &str,
    principal: &str,
    body: PostObservationBody,
    chain_tip: Option<ChainTip>,
) -> Result<(PostObservationResponse, ChainTip), (StatusCode, String)> {
    let payload_size = serde_json::to_vec(&body.payload)
        .map_err(|err| (StatusCode::BAD_REQUEST, format!("payload serialise: {err}")))?
        .len();
    let max_payload_bytes = *MAX_PAYLOAD_BYTES;
    if payload_size > max_payload_bytes {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("payload {payload_size} bytes exceeds {max_payload_bytes}-byte cap"),
        ));
    }

    let file_path = observation_file_path(&state.data_dir, scoped_session_id);
    // Determine chain position. Caller-supplied tip wins over file lookup so
    // batch handlers don't re-read the file between records in a single POST.
    let resolved_tip = match chain_tip {
        Some(tip) => Some(tip),
        None => read_chain_tip(&file_path)
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("read chain tip: {err}")))?,
    };
    // Build the new record's chain fields.
    //   - No prior records at all → start a fresh chain at seq=0.
    //   - Prior record is legacy (seq=None) → start a fresh chain at seq=0
    //     (the new record doesn't reference the legacy one's hash; the
    //     chain only covers M5e+ records).
    //   - Prior record is chained (seq=Some(n)) → extend with seq=n+1 and
    //     prev_hash referring to its body_hash.
    let (seq, prev_hash) = match resolved_tip {
        Some((Some(prev_seq), prev_hash)) => (Some(prev_seq + 1), Some(prev_hash)),
        Some((None, _)) | None => (Some(0), None),
    };

    let observation_id = uuid::Uuid::new_v4().to_string();
    let ts = Utc::now();
    let mut record = ObservationRecordV1 {
        observation_id: observation_id.clone(),
        session_id: scoped_session_id.to_string(),
        ts,
        client_ts: body.client_ts,
        provider: body.provider,
        principal: principal.to_string(),
        kind: body.kind,
        payload: body.payload,
        seq,
        prev_hash,
        receipt: ReceiptEnvelopeV1 {
            alg: String::new(),
            signed_by: String::new(),
            body_hash: String::new(),
            signature: String::new(),
        },
    };
    let body_bytes = canonical_body_bytes(&record).map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;
    let receipt = mint_receipt(state, &body_bytes)?;
    record.receipt = receipt.clone();

    // Extract hex without prefix for the next record's prev_hash.
    let body_hash_hex = receipt
        .body_hash
        .strip_prefix("blake3:")
        .unwrap_or(receipt.body_hash.as_str())
        .to_string();

    let line = serde_json::to_string(&record).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("serialise observation: {err}"),
        )
    })?;
    append_observation(&file_path, &line)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("append observation: {err}")))?;

    // M5f.3: also stream the (body, sig) pair via the dataplane pool if one
    // is wired. No-op in the Tier 1 local-only build. The JSONL append
    // above is the source of truth; streaming is best-effort.
    spawn_stream_observation_write(state, &observation_id, body_bytes, &receipt.signature, ts);

    Ok((
        PostObservationResponse {
            observation_id,
            ts,
            receipt,
        },
        (seq, body_hash_hex),
    ))
}

/// Validate the chain integrity of a parsed session JSONL. Returns a
/// `ChainStatus` so callers can surface "fully chained / partial / broken"
/// to UIs. Verifier callers should treat any non-`Ok` variant as a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ChainStatus {
    /// No records yet, or the file holds only pre-M5e legacy records — no
    /// chain to validate.
    NoChain,
    /// Every chained record links correctly. `legacy_prefix_len` is the
    /// count of pre-M5e records that precede the chained suffix.
    Ok {
        legacy_prefix_len: usize,
        chained_len: usize,
    },
    /// A chained record's `seq` or `prev_hash` does not link to the
    /// previous chained record. The chain has been tampered with.
    Broken { at_index: usize, reason: String },
}

pub(super) fn validate_chain(records: &[ObservationRecordV1]) -> ChainStatus {
    let mut legacy_prefix_len = 0usize;
    let mut chain_started = false;
    let mut last_chained_seq: Option<u64> = None;
    let mut last_chained_hash: Option<String> = None;
    let mut chained_len = 0usize;

    for (i, record) in records.iter().enumerate() {
        match record.seq {
            None => {
                if chain_started {
                    return ChainStatus::Broken {
                        at_index: i,
                        reason: "legacy record after chained suffix has started".to_string(),
                    };
                }
                legacy_prefix_len += 1;
            }
            Some(s) => {
                let expected_prev = last_chained_seq.map_or(0, |p| p + 1);
                if s != expected_prev {
                    return ChainStatus::Broken {
                        at_index: i,
                        reason: format!("seq gap: expected {expected_prev}, found {s}"),
                    };
                }
                let expected_prev_hash = last_chained_hash.clone();
                if record.prev_hash != expected_prev_hash {
                    return ChainStatus::Broken {
                        at_index: i,
                        reason: format!(
                            "prev_hash mismatch at seq={s}: expected {:?}, found {:?}",
                            expected_prev_hash, record.prev_hash,
                        ),
                    };
                }
                chain_started = true;
                last_chained_seq = Some(s);
                last_chained_hash = Some(
                    record
                        .receipt
                        .body_hash
                        .strip_prefix("blake3:")
                        .unwrap_or(record.receipt.body_hash.as_str())
                        .to_string(),
                );
                chained_len += 1;
            }
        }
    }

    if chained_len == 0 {
        ChainStatus::NoChain
    } else {
        ChainStatus::Ok {
            legacy_prefix_len,
            chained_len,
        }
    }
}

pub(super) async fn post_observation(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(session_id): AxumPath<String>,
    Json(body): Json<PostObservationBody>,
) -> Response {
    let ctx = match require_session_write_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let scoped = scoped_session_id_for_http(&ctx, &session_id);
    let principal = ctx.passport_id.clone().unwrap_or_else(|| state.passport_fpr.clone());
    match append_one(&state, &scoped, &principal, body, None) {
        Ok((resp, _tip)) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err((status, msg)) => problem_response(status, msg),
    }
}

pub(super) async fn post_observations_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(session_id): AxumPath<String>,
    Json(body): Json<PostObservationsBatchBody>,
) -> Response {
    let ctx = match require_session_write_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let scoped = scoped_session_id_for_http(&ctx, &session_id);
    let principal = ctx.passport_id.clone().unwrap_or_else(|| state.passport_fpr.clone());

    let mut items = Vec::with_capacity(body.items.len());
    // Thread the chain tip through the batch so we don't re-read the file
    // between records. First call uses `None` → reads the file once.
    let mut tip: Option<ChainTip> = None;
    for item in body.items {
        match append_one(&state, &scoped, &principal, item, tip.take()) {
            Ok((resp, new_tip)) => {
                tip = Some(new_tip);
                items.push(resp);
            }
            Err((status, msg)) => return problem_response(status, msg),
        }
    }
    (StatusCode::CREATED, Json(PostObservationsBatchResponse { items })).into_response()
}

/// Shape a mediation-receipt body into a scoped session id + an observation
/// body. Pure (no IO) so the mapping is unit-testable. The mediation log is
/// grouped per originating session (or per passport when none is supplied).
fn mediation_observation(body: &PostMediationReceiptBody) -> (String, PostObservationBody) {
    let group = body
        .session_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(&body.passport_id);
    let scoped = format!("mediation::{group}");
    let payload = serde_json::json!({
        "tool_server": body.tool_server,
        "tool": body.tool,
        "args_sha": body.args_sha,
        "decision": body.decision,
        "outcome": body.outcome,
        "mediator": "crux-gateway",
    });
    let obs = PostObservationBody {
        kind: "tool_mediation".to_string(),
        provider: "crux-gateway".to_string(),
        client_ts: body.ts,
        payload,
    };
    (scoped, obs)
}

/// `POST /v1/mediation/receipts` — record a CROWN receipt (and, in a
/// dataplane-enabled deployment, a `/v1/projections/entity/timeline` row via the
/// observation stream) for an externally-mediated tool call, attributed to a
/// passport the caller can resolve.
///
/// - **T.3 (authenticated):** rejects an unauthenticated caller.
/// - **T.1 + anti-forgery (capability-bound):** the caller may only ingest a
///   receipt for a passport it can `resolve_principal` for; the resolve is
///   tenant-scoped, so a mediator for tenant A cannot attribute to tenant B.
/// - **T.4 (audit):** always recorded through the signed-observation path
///   (`append_one` → CROWN receipt + JSONL + best-effort dataplane stream),
///   never a raw store write.
///
/// G19 (`Streaming-Receipts-Spec` §5): when `CORECRUXD_STREAM_RECEIPTS=1`,
/// the route also accepts stream/context/model-provenance receipt *drafts*
/// (`kind` one of `context_injected` / `stream_completed` /
/// `stream_aborted` / `model_invocation`) and lifts them into canonical
/// signed receipt bodies — see
/// [`super::stream_receipts`]. With the flag off (default) those drafts hit
/// the legacy tool-mediation parse and are rejected, exactly as before.
pub(super) async fn post_mediation_receipt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(raw): Json<serde_json::Value>,
) -> Response {
    // G19 dispatch — flag-gated, kind-discriminated, otherwise inert.
    if state.stream_receipts_enabled {
        if let Some(kind) = raw.get("kind").and_then(serde_json::Value::as_str) {
            if super::stream_receipts::is_stream_receipt_kind(kind) {
                return super::stream_receipts::handle_stream_receipt_draft(&state, &headers, &raw);
            }
        }
    }
    let body: PostMediationReceiptBody = match serde_json::from_value(raw) {
        Ok(body) => body,
        Err(err) => {
            // Mirror the axum `Json<T>` extractor's rejection status so the
            // legacy contract is unchanged by the Value-based dispatch.
            let pd = corecrux_types::ProblemDetails::new(
                StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                "https://errors.cuecrux.com/unprocessable-entity",
                "Unprocessable Entity",
            )
            .with_detail(format!("invalid body: {err}"));
            return crate::problem::ProblemResponse(pd).into_response();
        }
    };
    // T.3: caller must be authenticated (resolves the caller's scope context).
    if let Err(p) = crate::auth::http_scope_context(&state.auth, &headers) {
        return p.into_response();
    }
    if body.passport_id.trim().is_empty() || body.tool.trim().is_empty() || body.tool_server.trim().is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "passport_id, tool_server and tool are required",
        );
    }
    if !matches!(body.decision.as_str(), "allow" | "deny") {
        return problem_response(StatusCode::BAD_REQUEST, "decision must be 'allow' or 'deny'");
    }

    // Capability-bound (anti-forgery + T.1): resolve the target passport, then
    // tenant-scope on the *resolved* tenant. An unresolvable passport cannot be
    // attributed to (no forging a receipt for an identity you can't resolve).
    let resolved = {
        let store = state.fact_store.read().await;
        crate::principal::resolve_by_passport(&store, &body.passport_id, None)
    };
    let resolved = match resolved {
        Ok(r) => r,
        Err(_) => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "cannot attribute receipt: passport '{}' is not resolvable",
                    body.passport_id
                ),
            );
        }
    };
    if let Err(p) = crate::auth::require_http_any_scope_for_tenant(
        &state.auth,
        &headers,
        &["sessions:write", "admin:write"],
        &resolved.tenant_id,
    ) {
        return p.into_response();
    }

    // T.4: record through the signed-observation path. principal = the
    // attributed passport, so the CROWN receipt body carries the attribution.
    let (scoped, obs_body) = mediation_observation(&body);
    match append_one(&state, &scoped, &body.passport_id, obs_body, None) {
        Ok((resp, _tip)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "observation_id": resp.observation_id,
                "ts": resp.ts,
                "receipt": resp.receipt,
                "passport_id": body.passport_id,
                "principal": body.passport_id,
                "tenant_id": resolved.tenant_id,
                "session_id": scoped,
            })),
        )
            .into_response(),
        Err((status, msg)) => problem_response(status, msg),
    }
}

pub(super) async fn get_observations(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(session_id): AxumPath<String>,
    Query(params): Query<ListObservationsQuery>,
) -> Response {
    let ctx = match require_fact_read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let scoped = scoped_session_id_for_http(&ctx, &session_id);
    let file_path = observation_file_path(&state.data_dir, &scoped);
    let all_records = match read_observations(&file_path) {
        Ok(records) => records,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("read observations: {err}")),
    };
    // Chain integrity is a property of the *whole file*, not the filtered
    // result set. Validate before applying filters so the response reports
    // the truth about the on-disk JSONL.
    let chain = validate_chain(&all_records).into();

    let mut records = all_records;
    if let Some(since) = params.since {
        records.retain(|r| r.ts >= since);
    }
    if let Some(provider) = params.provider.as_deref() {
        records.retain(|r| r.provider == provider);
    }
    let limit = params.limit.unwrap_or(DEFAULT_GET_LIMIT).min(MAX_GET_LIMIT);
    if records.len() > limit {
        records.truncate(limit);
    }
    (
        StatusCode::OK,
        Json(ListObservationsResponse {
            observations: records,
            chain,
        }),
    )
        .into_response()
}

/// `GET /v1/observations/aggregate` — cross-session observation feed.
/// Scans every session JSONL under `<data_dir>/observations/`, applies
/// the optional `since`/`provider`/`kind`/`session_id` filters, then
/// returns the result merged + sorted by `ts` descending and capped by
/// `limit`. Each session's chain status is included so callers can spot
/// "the feed is fresh, but session X's chain is broken on disk" without
/// a follow-up call.
pub(super) async fn get_observations_aggregate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AggregateObservationsQuery>,
) -> Response {
    let ctx = match require_fact_read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let files = match list_observation_files(&state.data_dir) {
        Ok(files) => files,
        Err(err) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("list observation files: {err}"),
            )
        }
    };

    // Optional filter: only the named session id (scoped). Filters at the
    // file level so we don't read JSONL we won't use.
    let scoped_session_filter = params
        .session_id
        .as_deref()
        .map(|sid| scoped_session_id_for_http(&ctx, sid));

    let mut all: Vec<ObservationRecordV1> = Vec::new();
    let mut chains: std::collections::BTreeMap<String, ChainStatusJson> = Default::default();

    for path in files {
        let on_disk_session_id = match session_id_from_file(&path) {
            Some(s) => s,
            None => continue,
        };
        if let Some(target) = scoped_session_filter.as_deref() {
            // Compare against the sanitised on-disk filename — that's how
            // the appended sessions are stored.
            if on_disk_session_id != sanitize_session_id_for_filename(target) {
                continue;
            }
        }

        let records = match read_observations(&path) {
            Ok(records) => records,
            Err(err) => {
                tracing::warn!(
                    target = "observations",
                    file = %path.display(),
                    error = %err,
                    "skipping unreadable observation file"
                );
                continue;
            }
        };
        let chain = validate_chain(&records).into();
        chains.insert(on_disk_session_id, chain);

        for record in records {
            if let Some(since) = params.since {
                if record.ts < since {
                    continue;
                }
            }
            if let Some(provider) = params.provider.as_deref() {
                if record.provider != provider {
                    continue;
                }
            }
            if let Some(kind) = params.kind.as_deref() {
                if record.kind != kind {
                    continue;
                }
            }
            all.push(record);
        }
    }

    let matched = all.len();
    all.sort_by(|a, b| b.ts.cmp(&a.ts));
    let limit = params.limit.unwrap_or(DEFAULT_AGGREGATE_LIMIT).min(MAX_AGGREGATE_LIMIT);
    if all.len() > limit {
        all.truncate(limit);
    }
    let returned = all.len();

    (
        StatusCode::OK,
        Json(AggregateObservationsResponse {
            observations: all,
            chains,
            matched,
            returned,
        }),
    )
        .into_response()
}

// ── Dataplane stream writer (M5f.3) ───────────────────────────────────────

/// Tenant id used when streaming observations through a Tier 2+
/// `PoolBackedHttpDataplane`. The local single-binary daemon doesn't
/// scope observations per tenant; this constant is the routing key for
/// the shard map. Tier 2+ deployments that need per-tenant streams can
/// promote this to a runtime config or attach the caller's
/// `passport_id` as the tenant.
const OBS_DATAPLANE_TENANT: &str = "local";

/// Best-effort spawn that writes `(body, sig)` events for an observation
/// to the agent.observation event stream. No-op when the daemon has no
/// dataplane pool (Tier 1 single-binary distribution), which is the
/// common case. Failures are logged at WARN — the JSONL write that just
/// succeeded is the source of truth and the caller has already returned
/// 201 to the client.
/// Reason a stream-write build attempt was rejected before the spawn even
/// happened. Surfaced as an `Err` from `build_observation_stream_events`
/// so the caller can `tracing::warn!` once and bail without the noise of
/// nested `match` arms.
#[derive(Debug, PartialEq, Eq)]
enum BuildStreamEventsError {
    InvalidSignatureHex(String),
    /// Signature decoded to a byte length other than 64.
    WrongSignatureLength(usize),
}

impl std::fmt::Display for BuildStreamEventsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignatureHex(err) => write!(f, "signature hex invalid: {err}"),
            Self::WrongSignatureLength(len) => write!(f, "signature is not 64 bytes (got {len})"),
        }
    }
}

/// Pure construction of the `(body, sig)` `AppendEvent` pair that a Tier 2+
/// `PoolBackedHttpDataplane` will write to `STREAM_TYPE_AGENT_OBSERVATION`.
/// Extracted from `spawn_stream_observation_write` so the event shape (event
/// ids, content types, occurred_at, payload layout) is unit-testable without
/// needing a real `DataPlanePool` or a tokio runtime. The async wrapper just
/// routes the events through the pool.
fn build_observation_stream_events(
    observation_id: &str,
    body_bytes: Vec<u8>,
    signature_hex: &str,
    occurred_at: DateTime<Utc>,
) -> Result<
    (
        corecrux_proto::dataplane_v1::AppendEvent,
        corecrux_proto::dataplane_v1::AppendEvent,
    ),
    BuildStreamEventsError,
> {
    use corecrux_proto::dataplane_v1::AppendEvent;
    use corecrux_receipts::{
        CONTENT_TYPE_AGENT_OBSERVATION_BODY_V1, CONTENT_TYPE_AGENT_OBSERVATION_SIG_V1, EVT_AGENT_OBSERVATION_BODY_V1,
        EVT_AGENT_OBSERVATION_SIG_V1,
    };

    let signature_bytes =
        hex::decode(signature_hex).map_err(|err| BuildStreamEventsError::InvalidSignatureHex(err.to_string()))?;
    if signature_bytes.len() != 64 {
        return Err(BuildStreamEventsError::WrongSignatureLength(signature_bytes.len()));
    }
    let occurred_at_rfc3339 = occurred_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let body_event = AppendEvent {
        event_id: format!("{observation_id}.body"),
        occurred_at: occurred_at_rfc3339.clone(),
        event_type: EVT_AGENT_OBSERVATION_BODY_V1.to_string(),
        content_type: CONTENT_TYPE_AGENT_OBSERVATION_BODY_V1.to_string(),
        payload: body_bytes,
    };
    let sig_event = AppendEvent {
        event_id: format!("{observation_id}.sig"),
        occurred_at: occurred_at_rfc3339,
        event_type: EVT_AGENT_OBSERVATION_SIG_V1.to_string(),
        content_type: CONTENT_TYPE_AGENT_OBSERVATION_SIG_V1.to_string(),
        payload: signature_bytes,
    };
    Ok((body_event, sig_event))
}

fn spawn_stream_observation_write(
    state: &AppState,
    observation_id: &str,
    body_bytes: Vec<u8>,
    signature_hex: &str,
    occurred_at: DateTime<Utc>,
) {
    let Some(pool) = state.dataplane_pool.clone() else {
        return;
    };
    let observation_id = observation_id.to_string();
    let (body_event, sig_event) =
        match build_observation_stream_events(&observation_id, body_bytes, signature_hex, occurred_at) {
            Ok(events) => events,
            Err(err) => {
                tracing::warn!(observation_id, reason = %err, "skipping observation stream write");
                return;
            }
        };

    tokio::spawn(async move {
        use corecrux_receipts::STREAM_TYPE_AGENT_OBSERVATION;

        let route = match pool
            .store_for_stream(
                OBS_DATAPLANE_TENANT,
                STREAM_TYPE_AGENT_OBSERVATION,
                &observation_id,
                None,
            )
            .await
        {
            Ok((_decision, store)) => store,
            Err(err) => {
                tracing::warn!(observation_id, ?err, "observation stream route failed");
                return;
            }
        };
        let store = route.read().await;
        if let Err(err) = store
            .append_batch(
                OBS_DATAPLANE_TENANT,
                STREAM_TYPE_AGENT_OBSERVATION,
                &observation_id,
                0,
                None,
                &[body_event, sig_event],
            )
            .await
        {
            tracing::warn!(observation_id, ?err, "observation stream append failed");
        }
    });
}

// ── Retention (M5f.2) ─────────────────────────────────────────────────────

/// Subdirectory under `<data_dir>/observations/` where retained session
/// files are moved. Already starts with `.` so `list_observation_files`
/// skips it on the live query path.
const ARCHIVED_SUBDIR: &str = ".archived";

/// One pass of the retention policy: for every session JSONL whose most
/// recent record is older than `max_age`, move the file under
/// `<data_dir>/observations/.archived/<filename>`. The original signed
/// records are preserved unchanged — retention is an *archive*, not a
/// delete. Returns `(archived, scanned)` counts.
pub(crate) fn run_retention_pass(data_dir: &Path, max_age: chrono::Duration) -> std::io::Result<(usize, usize)> {
    let files = list_observation_files(data_dir)?;
    let scanned = files.len();
    if scanned == 0 {
        return Ok((0, 0));
    }
    let archive_dir = observations_dir(data_dir).join(ARCHIVED_SUBDIR);
    std::fs::create_dir_all(&archive_dir)?;
    let cutoff = Utc::now() - max_age;

    let mut archived = 0usize;
    for path in files {
        let records = match read_observations(&path) {
            Ok(records) => records,
            Err(err) => {
                tracing::warn!(
                    target = "observations.retention",
                    file = %path.display(),
                    error = %err,
                    "skipping unreadable session during retention pass"
                );
                continue;
            }
        };
        if records.is_empty() {
            continue;
        }
        // Records are appended in chronological order, so the last entry's
        // ts is the newest. If that's still inside the retention window,
        // keep the whole file live.
        let newest = records.iter().map(|r| r.ts).max().unwrap_or(Utc::now());
        if newest >= cutoff {
            continue;
        }
        let filename = match path.file_name() {
            Some(name) => name.to_owned(),
            None => continue,
        };
        let dest = archive_dir.join(&filename);
        match std::fs::rename(&path, &dest) {
            Ok(()) => {
                archived += 1;
                tracing::info!(
                    target = "observations.retention",
                    from = %path.display(),
                    to = %dest.display(),
                    newest_ts = %newest,
                    record_count = records.len(),
                    "archived session"
                );
            }
            Err(err) => {
                tracing::warn!(
                    target = "observations.retention",
                    file = %path.display(),
                    error = %err,
                    "rename to archive failed"
                );
            }
        }
    }
    Ok((archived, scanned))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn canonical_body_bytes_excludes_receipt() {
        let record = ObservationRecordV1 {
            observation_id: "obs-1".to_string(),
            session_id: "sess-a".to_string(),
            ts: DateTime::parse_from_rfc3339("2026-05-13T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            client_ts: None,
            provider: "claude-code".to_string(),
            principal: "fpr-x".to_string(),
            kind: "tool_use".to_string(),
            payload: serde_json::json!({"tool": "Read"}),
            seq: Some(0),
            prev_hash: None,
            receipt: ReceiptEnvelopeV1 {
                alg: "ed25519".to_string(),
                signed_by: "fpr-x".to_string(),
                body_hash: "blake3:deadbeef".to_string(),
                signature: "ffff".to_string(),
            },
        };
        let bytes = canonical_body_bytes(&record).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.get("receipt").is_none(), "receipt must not be in canonical body");
        assert_eq!(parsed["observation_id"], "obs-1");
        assert_eq!(parsed["payload"]["tool"], "Read");
    }

    #[test]
    fn sanitize_session_id_keeps_safe_chars() {
        assert_eq!(sanitize_session_id_for_filename("abc-123_xyz.test"), "abc-123_xyz.test");
        assert_eq!(sanitize_session_id_for_filename("agent/session"), "agent_session");
        assert_eq!(sanitize_session_id_for_filename("a:b\\c"), "a_b_c");
        // Slashes are replaced (no path-traversal possible); dots survive because
        // session IDs may legitimately contain them. The resulting filename lives
        // under `<data_dir>/observations/`, never escapes it.
        assert_eq!(sanitize_session_id_for_filename("../escape"), ".._escape");
        assert!(!sanitize_session_id_for_filename("../etc/passwd").contains('/'));
    }

    #[test]
    fn round_trip_signature_verifies_against_passport_public_key() {
        // Generate a passport key in a temp dir, sign a fixture, verify with the
        // public key. This exercises the same code path as `mint_receipt` minus
        // the AppState plumbing.
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let pubkey_hex = key.public_key_hex().to_string();

        let record = ObservationRecordV1 {
            observation_id: "obs-roundtrip".to_string(),
            session_id: "sess-roundtrip".to_string(),
            ts: DateTime::parse_from_rfc3339("2026-05-13T12:34:56.789Z")
                .unwrap()
                .with_timezone(&Utc),
            client_ts: None,
            provider: "test".to_string(),
            principal: key.passport_fpr().to_string(),
            kind: "user_prompt".to_string(),
            payload: serde_json::json!({"text": "hello"}),
            seq: Some(0),
            prev_hash: None,
            receipt: ReceiptEnvelopeV1 {
                alg: String::new(),
                signed_by: String::new(),
                body_hash: String::new(),
                signature: String::new(),
            },
        };

        let body_bytes = canonical_body_bytes(&record).unwrap();
        let hash = blake3::hash(&body_bytes);
        let sig_bytes = key.sign_hash(hash.as_bytes());

        // Verify with raw ed25519-dalek + the published public key.
        let pubkey_raw = hex::decode(&pubkey_hex).unwrap();
        let mut pubkey_arr = [0_u8; 32];
        pubkey_arr.copy_from_slice(&pubkey_raw);
        let verifying = VerifyingKey::from_bytes(&pubkey_arr).unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        verifying.verify(hash.as_bytes(), &signature).unwrap();

        // Tamper detection: flip a byte in the body, signature must fail.
        let mut tampered = body_bytes.clone();
        tampered[0] ^= 0xff;
        let tampered_hash = blake3::hash(&tampered);
        assert!(verifying.verify(tampered_hash.as_bytes(), &signature).is_err());
    }

    #[test]
    fn append_and_read_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let session_id = "test-session";
        let file_path = observation_file_path(tmp.path(), session_id);

        let record = ObservationRecordV1 {
            observation_id: "obs-a".to_string(),
            session_id: session_id.to_string(),
            ts: Utc::now(),
            client_ts: None,
            provider: "openai".to_string(),
            principal: "fpr-y".to_string(),
            kind: "model_response".to_string(),
            payload: serde_json::json!({"role": "assistant", "content": "ok"}),
            seq: Some(0),
            prev_hash: None,
            receipt: ReceiptEnvelopeV1 {
                alg: "ed25519".to_string(),
                signed_by: "fpr-y".to_string(),
                body_hash: "blake3:0".to_string(),
                signature: "00".to_string(),
            },
        };
        let line = serde_json::to_string(&record).unwrap();
        append_observation(&file_path, &line).unwrap();
        append_observation(&file_path, &line).unwrap();

        let read_back = read_observations(&file_path).unwrap();
        assert_eq!(read_back.len(), 2);
        assert_eq!(read_back[0].observation_id, "obs-a");
        assert_eq!(read_back[1].provider, "openai");
    }

    #[test]
    fn provider_filter_predicate_logic() {
        // Doesn't go through the handler; just confirms the predicate we use
        // inside the handler does what's expected. Full HTTP-level coverage is
        // out of scope for these unit tests (those tests live in http/tests.rs
        // and need the full AppState fixture).
        let claude = ObservationRecordV1 {
            observation_id: "a".into(),
            session_id: "s".into(),
            ts: Utc::now(),
            client_ts: None,
            provider: "claude-code".into(),
            principal: "p".into(),
            kind: "tool_use".into(),
            payload: serde_json::Value::Null,
            seq: Some(0),
            prev_hash: None,
            receipt: ReceiptEnvelopeV1 {
                alg: "ed25519".into(),
                signed_by: "p".into(),
                body_hash: "blake3:0".into(),
                signature: "00".into(),
            },
        };
        let openai = ObservationRecordV1 {
            provider: "openai".into(),
            observation_id: "b".into(),
            ..claude.clone()
        };
        let mut records = vec![claude, openai];
        let want = "claude-code".to_string();
        records.retain(|r| r.provider == want);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].observation_id, "a");
    }

    #[test]
    fn read_observations_missing_file_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nope.jsonl");
        let records = read_observations(&path).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn jsonl_line_verifies_against_strip_receipt_canonicalisation() {
        // This is the integration test the verifier example relies on: write a
        // record exactly the way the daemon would, then read the JSONL line,
        // strip `receipt`, re-serialise as Value, and confirm the BLAKE3 hash
        // matches the on-disk `receipt.body_hash`. If this passes, the offline
        // verifier in `examples/verify_observations.rs` will agree.
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();

        let mut record = ObservationRecordV1 {
            observation_id: "obs-verify".to_string(),
            session_id: "sess-verify".to_string(),
            ts: Utc::now(),
            client_ts: None,
            provider: "openai".to_string(),
            principal: key.passport_fpr().to_string(),
            kind: "model_response".to_string(),
            payload: serde_json::json!({"model": "gpt-4o-mini", "response": "hi"}),
            seq: Some(0),
            prev_hash: None,
            receipt: ReceiptEnvelopeV1 {
                alg: String::new(),
                signed_by: String::new(),
                body_hash: String::new(),
                signature: String::new(),
            },
        };
        let body_bytes = canonical_body_bytes(&record).unwrap();
        let hash = blake3::hash(&body_bytes);
        let sig_bytes = key.sign_hash(hash.as_bytes());
        record.receipt = ReceiptEnvelopeV1 {
            alg: "ed25519".to_string(),
            signed_by: key.passport_fpr().to_string(),
            body_hash: format!("blake3:{}", hex::encode(hash.as_bytes())),
            signature: hex::encode(sig_bytes),
        };

        // Write the JSONL line exactly as the handler would.
        let line = serde_json::to_string(&record).unwrap();
        let file_path = observation_file_path(tmp.path(), "sess-verify");
        append_observation(&file_path, &line).unwrap();

        // Now replay the verifier's algorithm: parse line → strip receipt →
        // re-serialise → re-hash → compare against `receipt.body_hash`.
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        let mut canonical_value = parsed.clone();
        if let serde_json::Value::Object(obj) = &mut canonical_value {
            obj.remove("receipt");
        }
        let recomputed = blake3::hash(&serde_json::to_vec(&canonical_value).unwrap());
        let expected_hex = parsed["receipt"]["body_hash"].as_str().unwrap();
        assert_eq!(format!("blake3:{}", hex::encode(recomputed.as_bytes())), expected_hex);

        // And the signature still verifies against the published public key.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let pubkey_hex = key.public_key_hex();
        let mut pubkey_arr = [0_u8; 32];
        pubkey_arr.copy_from_slice(&hex::decode(pubkey_hex).unwrap());
        let verifying = VerifyingKey::from_bytes(&pubkey_arr).unwrap();
        let sig_hex = parsed["receipt"]["signature"].as_str().unwrap();
        let mut sig_arr = [0_u8; 64];
        sig_arr.copy_from_slice(&hex::decode(sig_hex).unwrap());
        let signature = Signature::from_bytes(&sig_arr);
        verifying.verify(recomputed.as_bytes(), &signature).unwrap();
    }

    #[test]
    fn validate_chain_empty_is_no_chain() {
        assert_eq!(validate_chain(&[]), ChainStatus::NoChain);
    }

    #[test]
    fn validate_chain_only_legacy_is_no_chain() {
        let legacy = ObservationRecordV1 {
            observation_id: "leg-1".into(),
            session_id: "s".into(),
            ts: Utc::now(),
            client_ts: None,
            provider: "claude-code".into(),
            principal: "p".into(),
            kind: "tool_use".into(),
            payload: serde_json::Value::Null,
            seq: None,
            prev_hash: None,
            receipt: ReceiptEnvelopeV1 {
                alg: "ed25519".into(),
                signed_by: "p".into(),
                body_hash: "blake3:abc".into(),
                signature: "00".into(),
            },
        };
        assert_eq!(validate_chain(&[legacy]), ChainStatus::NoChain);
    }

    #[test]
    fn validate_chain_legacy_prefix_then_chain() {
        // Two legacy records followed by a fresh chain of three records.
        let mk = |seq: Option<u64>, prev: Option<&str>, hash: &str| ObservationRecordV1 {
            observation_id: format!("o-{hash}"),
            session_id: "s".into(),
            ts: Utc::now(),
            client_ts: None,
            provider: "claude-code".into(),
            principal: "p".into(),
            kind: "tool_use".into(),
            payload: serde_json::Value::Null,
            seq,
            prev_hash: prev.map(String::from),
            receipt: ReceiptEnvelopeV1 {
                alg: "ed25519".into(),
                signed_by: "p".into(),
                body_hash: format!("blake3:{hash}"),
                signature: "00".into(),
            },
        };
        let records = vec![
            mk(None, None, "legacy_a"),
            mk(None, None, "legacy_b"),
            mk(Some(0), None, "chain_0"),
            mk(Some(1), Some("chain_0"), "chain_1"),
            mk(Some(2), Some("chain_1"), "chain_2"),
        ];
        assert_eq!(
            validate_chain(&records),
            ChainStatus::Ok {
                legacy_prefix_len: 2,
                chained_len: 3,
            }
        );
    }

    #[test]
    fn validate_chain_detects_seq_gap() {
        let mk = |seq: Option<u64>, prev: Option<&str>, hash: &str| ObservationRecordV1 {
            observation_id: format!("o-{hash}"),
            session_id: "s".into(),
            ts: Utc::now(),
            client_ts: None,
            provider: "p".into(),
            principal: "p".into(),
            kind: "k".into(),
            payload: serde_json::Value::Null,
            seq,
            prev_hash: prev.map(String::from),
            receipt: ReceiptEnvelopeV1 {
                alg: "ed25519".into(),
                signed_by: "p".into(),
                body_hash: format!("blake3:{hash}"),
                signature: "00".into(),
            },
        };
        // seq jumps 0 → 2 (record at seq=1 removed).
        let records = vec![mk(Some(0), None, "a"), mk(Some(2), Some("a"), "c")];
        match validate_chain(&records) {
            ChainStatus::Broken { at_index, reason } => {
                assert_eq!(at_index, 1);
                assert!(reason.contains("seq gap"), "got: {reason}");
            }
            other => panic!("expected Broken, got {other:?}"),
        }
    }

    #[test]
    fn validate_chain_detects_prev_hash_mismatch() {
        let mk = |seq: Option<u64>, prev: Option<&str>, hash: &str| ObservationRecordV1 {
            observation_id: format!("o-{hash}"),
            session_id: "s".into(),
            ts: Utc::now(),
            client_ts: None,
            provider: "p".into(),
            principal: "p".into(),
            kind: "k".into(),
            payload: serde_json::Value::Null,
            seq,
            prev_hash: prev.map(String::from),
            receipt: ReceiptEnvelopeV1 {
                alg: "ed25519".into(),
                signed_by: "p".into(),
                body_hash: format!("blake3:{hash}"),
                signature: "00".into(),
            },
        };
        // seq=1's prev_hash claims "wrong_a" but the actual previous record's
        // body_hash hex is "a" — indicates the middle record was substituted.
        let records = vec![mk(Some(0), None, "a"), mk(Some(1), Some("wrong_a"), "b")];
        match validate_chain(&records) {
            ChainStatus::Broken { at_index, reason } => {
                assert_eq!(at_index, 1);
                assert!(reason.contains("prev_hash mismatch"), "got: {reason}");
            }
            other => panic!("expected Broken, got {other:?}"),
        }
    }

    #[test]
    fn validate_chain_detects_legacy_after_chain_started() {
        let mk = |seq: Option<u64>, prev: Option<&str>, hash: &str| ObservationRecordV1 {
            observation_id: format!("o-{hash}"),
            session_id: "s".into(),
            ts: Utc::now(),
            client_ts: None,
            provider: "p".into(),
            principal: "p".into(),
            kind: "k".into(),
            payload: serde_json::Value::Null,
            seq,
            prev_hash: prev.map(String::from),
            receipt: ReceiptEnvelopeV1 {
                alg: "ed25519".into(),
                signed_by: "p".into(),
                body_hash: format!("blake3:{hash}"),
                signature: "00".into(),
            },
        };
        // Once the chain has started, a legacy record (seq=None) is a tamper
        // signal — someone removed a chain record or injected an old one.
        let records = vec![mk(Some(0), None, "a"), mk(None, None, "legacy_after")];
        match validate_chain(&records) {
            ChainStatus::Broken { at_index, .. } => assert_eq!(at_index, 1),
            other => panic!("expected Broken, got {other:?}"),
        }
    }

    #[test]
    fn build_observation_stream_events_success_shape() {
        // 64-byte signature (128 hex chars). Use zeros — the test cares
        // about event shape, not signature contents.
        let sig_hex = "00".repeat(64);
        let occurred_at = chrono::DateTime::parse_from_rfc3339("2026-05-13T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let body_bytes = b"canonical-body-bytes".to_vec();

        let (body, sig) =
            build_observation_stream_events("obs-abc-123", body_bytes.clone(), &sig_hex, occurred_at).unwrap();

        use corecrux_receipts::{
            CONTENT_TYPE_AGENT_OBSERVATION_BODY_V1, CONTENT_TYPE_AGENT_OBSERVATION_SIG_V1,
            EVT_AGENT_OBSERVATION_BODY_V1, EVT_AGENT_OBSERVATION_SIG_V1,
        };

        // Body event
        assert_eq!(body.event_id, "obs-abc-123.body");
        assert_eq!(body.event_type, EVT_AGENT_OBSERVATION_BODY_V1);
        assert_eq!(body.content_type, CONTENT_TYPE_AGENT_OBSERVATION_BODY_V1);
        assert_eq!(body.payload, body_bytes);
        assert_eq!(body.occurred_at, "2026-05-13T10:00:00Z");

        // Sig event
        assert_eq!(sig.event_id, "obs-abc-123.sig");
        assert_eq!(sig.event_type, EVT_AGENT_OBSERVATION_SIG_V1);
        assert_eq!(sig.content_type, CONTENT_TYPE_AGENT_OBSERVATION_SIG_V1);
        assert_eq!(sig.payload.len(), 64);
        assert_eq!(sig.payload, vec![0u8; 64]);
        // Both events share the same occurred_at (clamped to Seconds RFC3339).
        assert_eq!(body.occurred_at, sig.occurred_at);
    }

    #[test]
    fn build_observation_stream_events_rejects_invalid_signature_hex() {
        let occurred_at = chrono::Utc::now();
        // "zz" is not valid hex.
        let err = build_observation_stream_events("obs-bad-hex", vec![], "zz", occurred_at).unwrap_err();
        assert!(
            matches!(err, BuildStreamEventsError::InvalidSignatureHex(_)),
            "expected InvalidSignatureHex, got {err:?}"
        );
        // Display impl should mention the cause.
        assert!(err.to_string().contains("signature hex"), "got: {err}");
    }

    #[test]
    fn build_observation_stream_events_rejects_wrong_signature_length() {
        let occurred_at = chrono::Utc::now();
        // 32 bytes (64 hex chars) — half the required length.
        let sig_hex = "ab".repeat(32);
        let err = build_observation_stream_events("obs-short-sig", vec![], &sig_hex, occurred_at).unwrap_err();
        assert_eq!(err, BuildStreamEventsError::WrongSignatureLength(32));
        // Display impl should mention the actual length.
        assert!(err.to_string().contains("32"), "got: {err}");
    }

    #[test]
    fn build_observation_stream_events_body_bytes_passed_through_verbatim() {
        // The pure builder MUST NOT touch the body payload — it's the
        // exact bytes the daemon already hashed and signed. Any rewrite
        // would break verification.
        let sig_hex = "11".repeat(64);
        let bytes_with_nulls = vec![0u8, 1, 2, 0, 3, 4, 0, 5];
        let (body, _) =
            build_observation_stream_events("obs-null-bytes", bytes_with_nulls.clone(), &sig_hex, chrono::Utc::now())
                .unwrap();
        assert_eq!(body.payload, bytes_with_nulls);
    }

    #[tokio::test]
    async fn retention_archives_only_old_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let state = stub_state_with_passport(tmp.path(), &key);

        // Session A: fresh (now)
        append_one(
            &state,
            "fresh-session",
            key.passport_fpr(),
            PostObservationBody {
                kind: "tool_use".into(),
                provider: "claude-code".into(),
                client_ts: None,
                payload: serde_json::Value::Null,
            },
            None,
        )
        .unwrap();

        // Session B: old. Write the file then forge the records' ts to the
        // past so the retention pass thinks the whole file is stale. We can
        // do this safely in the test because the retention check is purely
        // ts-based; signatures aren't re-verified during retention.
        append_one(
            &state,
            "stale-session",
            key.passport_fpr(),
            PostObservationBody {
                kind: "tool_use".into(),
                provider: "claude-code".into(),
                client_ts: None,
                payload: serde_json::Value::Null,
            },
            None,
        )
        .unwrap();
        let stale_path = observation_file_path(tmp.path(), "stale-session");
        let stale_records = read_observations(&stale_path).unwrap();
        let mut rewritten = String::new();
        for mut rec in stale_records {
            // 30 days old
            rec.ts = Utc::now() - chrono::Duration::days(30);
            rewritten.push_str(&serde_json::to_string(&rec).unwrap());
            rewritten.push('\n');
        }
        std::fs::write(&stale_path, rewritten).unwrap();

        // Retention threshold: 7 days. Stale session should be archived,
        // fresh session left alone.
        let (archived, scanned) = run_retention_pass(tmp.path(), chrono::Duration::days(7)).unwrap();
        assert_eq!(scanned, 2);
        assert_eq!(archived, 1);

        // Fresh session JSONL still in place.
        assert!(observation_file_path(tmp.path(), "fresh-session").exists());
        // Stale session moved to .archived/
        let archive_path = tmp
            .path()
            .join(OBS_SUBDIR)
            .join(ARCHIVED_SUBDIR)
            .join(observation_file_path(tmp.path(), "stale-session").file_name().unwrap());
        assert!(
            archive_path.exists(),
            "expected archived file at {}",
            archive_path.display()
        );
        assert!(!observation_file_path(tmp.path(), "stale-session").exists());

        // Second pass with no new old sessions: archives 0, scans only the
        // remaining (fresh) file.
        let (archived2, scanned2) = run_retention_pass(tmp.path(), chrono::Duration::days(7)).unwrap();
        assert_eq!(archived2, 0);
        assert_eq!(scanned2, 1);

        // list_observation_files must still skip the .archived/ dir entirely.
        let live = list_observation_files(tmp.path()).unwrap();
        assert_eq!(live.len(), 1);
        assert!(live[0].file_name().unwrap().to_str().unwrap().contains("fresh-session"));
    }

    #[test]
    fn list_observation_files_handles_missing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        // data_dir/observations doesn't exist yet.
        let files = list_observation_files(tmp.path()).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn list_observation_files_filters_dotfiles_and_non_jsonl() {
        let tmp = tempfile::tempdir().unwrap();
        let obs = tmp.path().join("observations");
        std::fs::create_dir_all(&obs).unwrap();
        std::fs::write(obs.join("session-a.jsonl"), "").unwrap();
        std::fs::write(obs.join("session-b.jsonl"), "").unwrap();
        std::fs::write(obs.join(".hidden.jsonl"), "").unwrap();
        std::fs::write(obs.join("README.md"), "ignore me").unwrap();
        std::fs::create_dir_all(obs.join(".archived")).unwrap();

        let files = list_observation_files(tmp.path()).unwrap();
        let names: Vec<String> = files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
            .collect();
        assert_eq!(
            names,
            vec!["session-a.jsonl".to_string(), "session-b.jsonl".to_string()]
        );
    }

    #[tokio::test]
    async fn aggregate_handler_merges_sessions_and_applies_filters() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let state = stub_state_with_passport(tmp.path(), &key);

        // Two sessions: each gets one claude-code + one openai record.
        for sid in ["sess-x", "sess-y"] {
            for provider in ["claude-code", "openai"] {
                append_one(
                    &state,
                    sid,
                    key.passport_fpr(),
                    PostObservationBody {
                        kind: "tool_use".into(),
                        provider: provider.into(),
                        client_ts: None,
                        payload: serde_json::json!({"sid": sid, "provider": provider}),
                    },
                    None,
                )
                .unwrap();
            }
        }

        // Read every record across sessions via list_observation_files.
        let files = list_observation_files(tmp.path()).unwrap();
        assert_eq!(files.len(), 2);
        let mut all_records: Vec<ObservationRecordV1> = Vec::new();
        for path in &files {
            let records = read_observations(path).unwrap();
            all_records.extend(records);
        }
        assert_eq!(all_records.len(), 4);
        let claude_count = all_records.iter().filter(|r| r.provider == "claude-code").count();
        let openai_count = all_records.iter().filter(|r| r.provider == "openai").count();
        assert_eq!(claude_count, 2);
        assert_eq!(openai_count, 2);

        // Per-session chain check: each session has its own 2-record chain.
        for path in &files {
            let records = read_observations(path).unwrap();
            assert_eq!(
                validate_chain(&records),
                ChainStatus::Ok {
                    legacy_prefix_len: 0,
                    chained_len: 2,
                }
            );
        }
    }

    /// Read a `Response`'s JSON body fully — mirror of `super::tests::json_body`.
    async fn response_to_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1_048_576).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn post_observation_handler_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let state = stub_state_with_passport(tmp.path(), &key);

        let resp = post_observation(
            State(state.clone()),
            HeaderMap::new(),
            AxumPath("handler-test".to_string()),
            Json(PostObservationBody {
                kind: "tool_use".to_string(),
                provider: "claude-code".to_string(),
                client_ts: None,
                payload: serde_json::json!({"tool": "Read"}),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_to_json(resp).await;
        assert!(body["observation_id"].is_string());
        assert_eq!(body["receipt"]["alg"], "ed25519");
        assert!(body["receipt"]["body_hash"].as_str().unwrap().starts_with("blake3:"));
        assert_eq!(body["receipt"]["signed_by"], key.passport_fpr());
    }

    #[tokio::test]
    async fn post_observation_handler_rejects_oversize_payload() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let state = stub_state_with_passport(tmp.path(), &key);
        // Build a payload > the effective cap by stuffing a long string.
        let oversize = "x".repeat(*MAX_PAYLOAD_BYTES + 100);
        let resp = post_observation(
            State(state),
            HeaderMap::new(),
            AxumPath("oversize-session".to_string()),
            Json(PostObservationBody {
                kind: "tool_use".to_string(),
                provider: "claude-code".to_string(),
                client_ts: None,
                payload: serde_json::json!({"big": oversize}),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn post_observations_batch_handler_threads_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let state = stub_state_with_passport(tmp.path(), &key);

        let resp = post_observations_batch(
            State(state.clone()),
            HeaderMap::new(),
            AxumPath("batch-session".to_string()),
            Json(PostObservationsBatchBody {
                items: (0..3)
                    .map(|i| PostObservationBody {
                        kind: format!("kind_{i}"),
                        provider: "openai".to_string(),
                        client_ts: None,
                        payload: serde_json::json!({"i": i}),
                    })
                    .collect(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_to_json(resp).await;
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 3);
        // Chain was threaded: seq=0,1,2 on the JSONL records.
        let path = observation_file_path(tmp.path(), "batch-session");
        let records = read_observations(&path).unwrap();
        assert_eq!(records.len(), 3);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.seq, Some(i as u64));
        }
        assert_eq!(records[0].prev_hash, None);
        assert!(records[1].prev_hash.is_some());
        assert!(records[2].prev_hash.is_some());
    }

    #[tokio::test]
    async fn get_observations_handler_returns_chain_block() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let state = stub_state_with_passport(tmp.path(), &key);

        for provider in ["claude-code", "openai"] {
            append_one(
                &state,
                "get-session",
                key.passport_fpr(),
                PostObservationBody {
                    kind: "tool_use".to_string(),
                    provider: provider.to_string(),
                    client_ts: None,
                    payload: serde_json::json!({"p": provider}),
                },
                None,
            )
            .unwrap();
        }

        // No filter → 2 records, chain ok.
        let resp = get_observations(
            State(state.clone()),
            HeaderMap::new(),
            AxumPath("get-session".to_string()),
            Query(ListObservationsQuery {
                since: None,
                limit: None,
                provider: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = response_to_json(resp).await;
        assert_eq!(body["observations"].as_array().unwrap().len(), 2);
        assert_eq!(body["chain"]["status"], "ok");
        assert_eq!(body["chain"]["chained_len"], 2);
        assert_eq!(body["chain"]["legacy_prefix_len"], 0);

        // provider=openai → 1 record.
        let resp = get_observations(
            State(state.clone()),
            HeaderMap::new(),
            AxumPath("get-session".to_string()),
            Query(ListObservationsQuery {
                since: None,
                limit: None,
                provider: Some("openai".to_string()),
            }),
        )
        .await;
        let body = response_to_json(resp).await;
        let obs = body["observations"].as_array().unwrap();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0]["provider"], "openai");

        // since=<far future> → 0 records but chain still reports the full file ok.
        let resp = get_observations(
            State(state),
            HeaderMap::new(),
            AxumPath("get-session".to_string()),
            Query(ListObservationsQuery {
                since: Some(chrono::Utc::now() + chrono::Duration::days(365)),
                limit: None,
                provider: None,
            }),
        )
        .await;
        let body = response_to_json(resp).await;
        assert_eq!(body["observations"].as_array().unwrap().len(), 0);
        assert_eq!(body["chain"]["status"], "ok");
        assert_eq!(body["chain"]["chained_len"], 2);
    }

    #[tokio::test]
    async fn get_observations_aggregate_handler_merges_and_filters() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let state = stub_state_with_passport(tmp.path(), &key);

        for sess in ["agg-a", "agg-b"] {
            for (provider, kind) in [("claude-code", "tool_use"), ("openai", "model_response")] {
                append_one(
                    &state,
                    sess,
                    key.passport_fpr(),
                    PostObservationBody {
                        kind: kind.to_string(),
                        provider: provider.to_string(),
                        client_ts: None,
                        payload: serde_json::Value::Null,
                    },
                    None,
                )
                .unwrap();
            }
        }

        // No filter → 4 records, 2 chains.
        let resp = get_observations_aggregate(
            State(state.clone()),
            HeaderMap::new(),
            Query(AggregateObservationsQuery {
                since: None,
                provider: None,
                kind: None,
                session_id: None,
                limit: None,
            }),
        )
        .await;
        let body = response_to_json(resp).await;
        assert_eq!(body["matched"], 4);
        assert_eq!(body["returned"], 4);
        assert_eq!(body["chains"].as_object().unwrap().len(), 2);

        // provider=openai filter
        let resp = get_observations_aggregate(
            State(state.clone()),
            HeaderMap::new(),
            Query(AggregateObservationsQuery {
                since: None,
                provider: Some("openai".to_string()),
                kind: None,
                session_id: None,
                limit: None,
            }),
        )
        .await;
        let body = response_to_json(resp).await;
        assert_eq!(body["matched"], 2);
        for o in body["observations"].as_array().unwrap() {
            assert_eq!(o["provider"], "openai");
        }

        // kind=model_response filter
        let resp = get_observations_aggregate(
            State(state.clone()),
            HeaderMap::new(),
            Query(AggregateObservationsQuery {
                since: None,
                provider: None,
                kind: Some("model_response".to_string()),
                session_id: None,
                limit: None,
            }),
        )
        .await;
        let body = response_to_json(resp).await;
        assert_eq!(body["matched"], 2);
        for o in body["observations"].as_array().unwrap() {
            assert_eq!(o["kind"], "model_response");
        }

        // session_id=agg-a filter
        let resp = get_observations_aggregate(
            State(state.clone()),
            HeaderMap::new(),
            Query(AggregateObservationsQuery {
                since: None,
                provider: None,
                kind: None,
                session_id: Some("agg-a".to_string()),
                limit: None,
            }),
        )
        .await;
        let body = response_to_json(resp).await;
        assert_eq!(body["matched"], 2);
        let sids: std::collections::HashSet<String> = body["observations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["session_id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(sids.len(), 1);
        assert!(sids.iter().next().unwrap().contains("agg-a"));

        // limit=1 with sorted-desc ordering.
        let resp = get_observations_aggregate(
            State(state),
            HeaderMap::new(),
            Query(AggregateObservationsQuery {
                since: None,
                provider: None,
                kind: None,
                session_id: None,
                limit: Some(1),
            }),
        )
        .await;
        let body = response_to_json(resp).await;
        assert_eq!(body["matched"], 4);
        assert_eq!(body["returned"], 1);
        assert_eq!(body["observations"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn end_to_end_chain_is_built_by_repeated_appends() {
        // Set up an AppState with a real passport key + scoped data_dir.
        // Then drive the daemon path: call append_one three times for one
        // session and confirm the resulting JSONL is a contiguous chain of
        // seq=0,1,2 where each record's prev_hash links to the previous
        // record's body_hash and validate_chain returns Ok.
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        // Stub AppState with just the fields append_one touches.
        let state = stub_state_with_passport(tmp.path(), &key);

        for i in 0..3 {
            let body = PostObservationBody {
                kind: format!("kind_{i}"),
                provider: "claude-code".into(),
                client_ts: None,
                payload: serde_json::json!({"i": i}),
            };
            append_one(&state, "chain-session", key.passport_fpr(), body, None).unwrap();
        }
        let path = observation_file_path(tmp.path(), "chain-session");
        let records = read_observations(&path).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].seq, Some(0));
        assert_eq!(records[0].prev_hash, None);
        for i in 1..3 {
            assert_eq!(records[i].seq, Some(i as u64));
            let prev_hash_expected = records[i - 1]
                .receipt
                .body_hash
                .strip_prefix("blake3:")
                .unwrap()
                .to_string();
            assert_eq!(records[i].prev_hash.as_deref(), Some(prev_hash_expected.as_str()));
        }
        assert_eq!(
            validate_chain(&records),
            ChainStatus::Ok {
                legacy_prefix_len: 0,
                chained_len: 3,
            }
        );
    }

    /// Build a minimal `AppState` whose only useful fields for `append_one`
    /// are the passport-key path + data_dir + the fingerprint/pubkey for
    /// verification.
    fn stub_state_with_passport(data_dir: &Path, key: &crux_session::LocalPassportKey) -> AppState {
        let mut state = super::super::tests::test_app_state(16);
        state.data_dir = data_dir.to_path_buf();
        state.passport_key_path = data_dir.join("passport.key");
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();
        state
    }

    // ── Mediation receipts (B2) ──────────────────────────────────────────

    #[test]
    fn mediation_observation_shapes_payload_and_groups_by_session() {
        let body = PostMediationReceiptBody {
            passport_id: "work-default".to_string(),
            tool_server: "playwright".to_string(),
            tool: "browser_navigate".to_string(),
            args_sha: Some("deadbeef".to_string()),
            decision: "allow".to_string(),
            outcome: "ok".to_string(),
            ts: None,
            session_id: Some("sess-1".to_string()),
        };
        let (scoped, obs) = mediation_observation(&body);
        assert_eq!(scoped, "mediation::sess-1");
        assert_eq!(obs.kind, "tool_mediation");
        assert_eq!(obs.provider, "crux-gateway");
        assert_eq!(obs.payload["tool"], "browser_navigate");
        assert_eq!(obs.payload["decision"], "allow");

        // No session_id → grouped by passport.
        let mut b2 = body.clone();
        b2.session_id = None;
        assert_eq!(mediation_observation(&b2).0, "mediation::work-default");
    }

    /// Seed the daemon passport store into a stub state's fact store so
    /// `resolve_by_passport` succeeds.
    async fn seed_passports_into(state: &AppState) {
        let mut store = state.fact_store.write().await;
        crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed");
    }

    #[tokio::test]
    async fn post_mediation_receipt_happy_path_records_attributed_receipt() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let state = stub_state_with_passport(tmp.path(), &key);
        seed_passports_into(&state).await;

        let resp = post_mediation_receipt(
            State(state.clone()),
            HeaderMap::new(),
            Json(serde_json::json!({
                "passport_id": "work-default",
                "tool_server": "openclaw",
                "tool": "openclaw_status",
                "args_sha": "abc123",
                "decision": "allow",
                "outcome": "ok",
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = response_to_json(resp).await;
        assert_eq!(body["receipt"]["alg"], "ed25519");
        assert_eq!(body["receipt"]["signed_by"], key.passport_fpr());
        assert_eq!(body["passport_id"], "work-default");
        assert_eq!(body["session_id"], "mediation::work-default");

        // The persisted JSONL line is attributed to the passport (principal).
        let file = observation_file_path(&state.data_dir, "mediation::work-default");
        let records = read_observations(&file).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].principal, "work-default");
        assert_eq!(records[0].kind, "tool_mediation");
    }

    #[tokio::test]
    async fn post_mediation_receipt_rejects_unresolvable_passport() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let state = stub_state_with_passport(tmp.path(), &key);
        seed_passports_into(&state).await;

        // No such passport → cannot attribute → 400 (forged-attribution guard).
        let resp = post_mediation_receipt(
            State(state.clone()),
            HeaderMap::new(),
            Json(serde_json::json!({
                "passport_id": "ghost-passport",
                "tool_server": "openclaw",
                "tool": "openclaw_status",
                "decision": "allow",
                "outcome": "ok",
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_mediation_receipt_rejects_bad_decision() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("passport.key");
        let key = crux_session::LocalPassportKey::from_path(&key_path).unwrap();
        let state = stub_state_with_passport(tmp.path(), &key);
        seed_passports_into(&state).await;

        let resp = post_mediation_receipt(
            State(state.clone()),
            HeaderMap::new(),
            Json(serde_json::json!({
                "passport_id": "work-default",
                "tool_server": "openclaw",
                "tool": "openclaw_status",
                "decision": "maybe", // invalid
                "outcome": "ok",
            })),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn read_observations_skips_malformed_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("mixed.jsonl");
        std::fs::create_dir_all(tmp.path()).unwrap();
        std::fs::write(
            &path,
            "{not json\n{\"observation_id\":\"ok\",\"session_id\":\"s\",\"ts\":\"2026-05-13T00:00:00Z\",\"provider\":\"p\",\"principal\":\"pr\",\"kind\":\"k\",\"payload\":null,\"receipt\":{\"alg\":\"ed25519\",\"signed_by\":\"x\",\"body_hash\":\"blake3:0\",\"signature\":\"00\"}}\n",
        )
        .unwrap();
        let records = read_observations(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].observation_id, "ok");
    }
}
