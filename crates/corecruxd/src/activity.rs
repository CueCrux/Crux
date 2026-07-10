// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Dual-surface activity log — capture layer (ExecPlan
//! `crux-dual-surface-activity-log-2026-06-18`, M1).
//!
//! ## What this is
//!
//! One source of truth for "what an agent did this session", captured once
//! per turn-event and projected two ways: a cheap token-budgeted agent pull
//! (`GET /v1/activity`, M2) and a rich human console tab (M3). Both lanes
//! join on `turn_id` and reference the same append id, so the human view is
//! the agent view with verbatim prose rehydrated — the two can never
//! disagree.
//!
//! This module owns the durable capture record ([`JournalEntry`], schema
//! `crux.activity.journal_entry.v1`) and a process-wide in-memory store
//! ([`JournalStore`]) keyed by `(tenant_id, session_id)` with a monotonic
//! per-session `seq`. It mirrors the per-passport trace ring in
//! `crux-mcp::traces` but scopes by session (D-C in the design doc): the
//! trace ring answers "what tools did *this passport* call", the journal
//! answers "what happened in *this session*". The two join on `turn_id`.
//!
//! ## Privacy & isolation (T.1 / T.3 / Art. 10)
//!
//! - Entries are `(tenant_id, session_id)`-scoped; a read for one tenant
//!   never returns another tenant's text.
//! - `text` is reserved-prefix-stripped (`__agent::`, `__ops::`,
//!   `__bootstrap__::`) before persist **and** the same const is reused on
//!   read, so both lanes share the envelope's privacy guarantee.
//! - `private: true` entries (PII) never sync to a remote and are only
//!   returned to the authoring passport.
//! - Unauthenticated writes land under the [`ANON_PASSPORT`] sentinel,
//!   never silently global (T.3).
//!
//! ## Feature flag
//!
//! Everything is gated by `CORECRUXD_FEATURE_ACTIVITY_LOG`, **default OFF**.
//! With the flag off, `record` is a no-op and the HTTP handlers return a
//! disabled problem, so the daemon behaves exactly as it does today.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use chrono::Utc;
use corecrux_frame::compute_header_hash;
use corecrux_receipts::is_reserved_entity_prefix;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Environment variable that gates the whole activity-log feature.
/// **Default OFF**; set to `1`/`true`/`on`/`yes` to enable.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_ACTIVITY_LOG";

/// Canonical schema id stamped on every persisted entry.
pub const JOURNAL_ENTRY_SCHEMA_V1: &str = "crux.activity.journal_entry.v1";

/// Default sliding-window retention horizon (365 days). The journal is now
/// disk-durable (see [`JournalStore::open`]), so the default keeps activity for
/// a year rather than the original 24h volatile window. Overridable via
/// `CORECRUXD_FEATURE_ACTIVITY_LOG_TTL_SECS`.
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// Per-session ring hard cap. Older entries are evicted FIFO.
pub const MAX_ENTRIES_PER_SESSION: usize = 5_000;

/// Sentinel passport id used when the caller is unauthenticated (T.3).
pub const ANON_PASSPORT: &str = "__anon__";

/// Redaction marker substituted for reserved-prefix tokens in `text`.
const REDACTED: &str = "[reserved]";

/// Return true if the activity log is enabled. **Default OFF** — an empty
/// value also counts as off, matching the trace-ring truthiness parser.
pub fn activity_log_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// Read the configured retention horizon, falling back to
/// [`DEFAULT_RETENTION`] when the env var is missing or unparseable.
pub fn retention() -> Duration {
    match std::env::var("CORECRUXD_FEATURE_ACTIVITY_LOG_TTL_SECS") {
        Ok(v) => v
            .trim()
            .parse::<u64>()
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_RETENTION),
        Err(_) => DEFAULT_RETENTION,
    }
}

/// The seven operator-requested activity categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JournalKind {
    /// Category 1 — a user prompt / question.
    Question,
    /// Category 2 — an agent answer.
    Answer,
    /// Category 3 — reasoning / thinking (best-effort, OD-15).
    Reasoning,
    /// Category 4 — a command / tool dispatch that completed.
    Command,
    /// Category 5 — a fact was stored (cross-reference only, not re-stored).
    Fact,
    /// Category 6a — an ExecPlan was started / advanced.
    Execplan,
    /// Category 6b — a cross-session handoff.
    Handoff,
    /// Category 7 — an error or recorded gotcha.
    Error,
}

impl JournalKind {
    /// Stable lowercase wire string (mirrors the serde rename).
    pub fn as_str(self) -> &'static str {
        match self {
            JournalKind::Question => "question",
            JournalKind::Answer => "answer",
            JournalKind::Reasoning => "reasoning",
            JournalKind::Command => "command",
            JournalKind::Fact => "fact",
            JournalKind::Execplan => "execplan",
            JournalKind::Handoff => "handoff",
            JournalKind::Error => "error",
        }
    }
}

/// Cross-references to other stores; the journal never re-stores facts or
/// receipts, it points at them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)] // The `_ids` suffix is part of the wire schema (fact_ids/receipt_ids/event_ids).
pub struct JournalRefs {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fact_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipt_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<String>,
}

/// Optional typed metadata used by the cheap agent-lane projection so it can
/// render intent/tool/confidence without rehydrating `text`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JournalMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execplan_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
}

/// Caller-supplied capture record. Server fills in `seq`, `created_at`,
/// `entry_id`, and the reserved-prefix strip.
#[derive(Debug, Clone, Deserialize)]
pub struct JournalInput {
    pub tenant_id: String,
    pub session_id: String,
    #[serde(default)]
    pub turn_id: Option<String>,
    pub kind: JournalKind,
    #[serde(default)]
    pub actor_passport: Option<String>,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub refs: JournalRefs,
    #[serde(default)]
    pub meta: JournalMeta,
    #[serde(default)]
    pub private: bool,
}

/// A persisted activity-log entry — schema `crux.activity.journal_entry.v1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub schema: String,
    /// Deterministic content-addressed id; doubles as the append-receipt
    /// reference (present in `refs.receipt_ids`, satisfying T.4).
    pub entry_id: String,
    pub tenant_id: String,
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    pub seq: u64,
    pub kind: JournalKind,
    pub actor_passport: String,
    /// Verbatim prose, reserved-prefix-stripped.
    pub text: String,
    #[serde(default)]
    pub refs: JournalRefs,
    #[serde(default)]
    pub meta: JournalMeta,
    pub private: bool,
    pub created_at: String,
    /// Optional embedded Ed25519 receipt over the canonical body (M2). Present
    /// only when `CORECRUXD_FEATURE_ACTIVITY_SIGN` is on at append time; the
    /// human-lane ✓verify badge verifies it against the daemon passport key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ActivityReceiptV1>,
    /// Microseconds since UNIX epoch — sort/eviction key (not serialised to
    /// agents; `created_at` is the human-facing timestamp).
    #[serde(skip)]
    pub ts_us: i64,
}

/// A self-contained Ed25519 receipt over an entry's canonical body
/// (`crux-activity-log-completion` M2). Same shape as the observe lane's
/// `ReceiptEnvelopeV1` (`mint_receipt`), so it is dataplane-independent and
/// verifiable offline against the daemon passport public key. Embedded in the
/// entry rather than written to the dataplane receipt stream (which is
/// pool-gated and unavailable in CE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityReceiptV1 {
    /// Signature algorithm — always `ed25519`.
    pub alg: String,
    /// Signer fingerprint (`state.passport_fpr`).
    pub signed_by: String,
    /// `blake3:<hex>` of the canonical signing bytes.
    pub body_hash: String,
    /// Hex Ed25519 signature over the blake3 hash.
    pub signature: String,
}

/// Mints an [`ActivityReceiptV1`] over an entry's canonical body. Implemented
/// in the HTTP layer (which owns the passport key); the store stays
/// crypto-agnostic.
pub trait ActivitySigner {
    fn sign_body(&self, body: &[u8]) -> ActivityReceiptV1;
}

/// Environment variable that gates per-append co-signing. **Default OFF** —
/// when off, entries carry no `receipt` and the badge shows "recorded"
/// (today's behaviour), so there is no regression.
pub const SIGN_FLAG_ENV: &str = "CORECRUXD_FEATURE_ACTIVITY_SIGN";

/// Return true if per-append co-signing is enabled.
pub fn activity_sign_enabled() -> bool {
    match std::env::var(SIGN_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// Redact whitespace-delimited tokens that begin with a reserved entity
/// prefix (`__agent::`, `__ops::`, `__bootstrap__::`) so neither lane leaks
/// reserved-namespace identifiers in verbatim text (T.1 parity with the
/// envelope's `memories_used`).
pub fn strip_reserved_text(text: &str) -> String {
    text.split_whitespace()
        .map(|tok| {
            // Trim common surrounding punctuation before the prefix check so
            // `(__ops::x)` is caught, not just a bare token.
            let core = tok.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != ':');
            if is_reserved_entity_prefix(core) {
                REDACTED
            } else {
                tok
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Deterministic, content-addressed entry id over the immutable fields. Used
/// as the append-receipt reference.
/// Canonical, delimited byte representation of an entry's immutable fields —
/// the single source the `entry_id` hashes **and** the M2 signature signs, so
/// a verifier reconstructs identical bytes from the public entry fields.
fn canonical_entry_string(
    tenant: &str,
    session: &str,
    seq: u64,
    kind: JournalKind,
    created_at: &str,
    text: &str,
) -> String {
    format!(
        "{tenant}\u{1f}{session}\u{1f}{seq}\u{1f}{}\u{1f}{created_at}\u{1f}{text}",
        kind.as_str()
    )
}

/// Reconstruct the canonical signing bytes from a finalised entry. The M2
/// verify path calls this, blake3-hashes it, and checks the embedded
/// signature against the daemon passport key.
pub fn canonical_signing_bytes(entry: &JournalEntry) -> Vec<u8> {
    canonical_entry_string(
        &entry.tenant_id,
        &entry.session_id,
        entry.seq,
        entry.kind,
        &entry.created_at,
        &entry.text,
    )
    .into_bytes()
}

fn compute_entry_id(tenant: &str, session: &str, seq: u64, kind: JournalKind, created_at: &str, text: &str) -> String {
    let canonical = canonical_entry_string(tenant, session, seq, kind, created_at, text);
    let digest = compute_header_hash(canonical.as_bytes());
    let mut s = String::with_capacity(4 + 32);
    s.push_str("act_");
    for b in &digest[..16] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// One session's append log plus its monotonic seq counter. The counter is
/// independent of `entries.len()` so FIFO eviction never reuses a `seq`.
#[derive(Debug, Default)]
struct SessionLog {
    entries: Vec<JournalEntry>,
    next_seq: u64,
}

/// Process-wide store of [`JournalEntry`] values keyed by
/// `(tenant_id, session_id)`.
#[derive(Debug, Default)]
pub struct JournalStore {
    by_session: HashMap<(String, String), SessionLog>,
    /// When set, every append is written through to this JSONL file and the
    /// store is hydrated from it at [`JournalStore::open`]. `None` → in-memory
    /// only (the default, used by tests).
    persist_path: Option<PathBuf>,
}

impl JournalStore {
    /// Open a store optionally backed by `path` (a JSONL append log). When
    /// `Some`, existing entries are loaded (retention-trimmed + compacted) and
    /// subsequent appends are written through. `None` keeps it purely in-memory.
    pub fn open(path: Option<PathBuf>) -> Self {
        let mut store = JournalStore {
            persist_path: path.clone(),
            ..Default::default()
        };
        if let Some(p) = path {
            store.load_from_disk(&p);
        }
        store
    }

    /// Hydrate `by_session` from the on-disk JSONL, skipping unparseable lines
    /// (forward-compatible), applying retention, then compacting the file to the
    /// retained set so it can't grow without bound across restarts.
    fn load_from_disk(&mut self, path: &Path) {
        let Ok(content) = std::fs::read_to_string(path) else {
            return; // first run / unreadable → start empty
        };
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(mut entry) = serde_json::from_str::<JournalEntry>(line) else {
                continue;
            };
            // `ts_us` is `#[serde(skip)]` (kept out of the public JSON), so it
            // deserialises to 0 — recompute the sort/eviction key from the
            // persisted RFC3339 `created_at`.
            entry.ts_us = chrono::DateTime::parse_from_rfc3339(&entry.created_at)
                .map(|d| d.timestamp_micros())
                .unwrap_or(0);
            let log = self
                .by_session
                .entry((entry.tenant_id.clone(), entry.session_id.clone()))
                .or_default();
            log.next_seq = log.next_seq.max(entry.seq + 1);
            log.entries.push(entry);
        }
        let ttl = retention();
        for log in self.by_session.values_mut() {
            log.entries.sort_by(|a, b| a.ts_us.cmp(&b.ts_us));
            Self::trim(&mut log.entries, ttl);
        }
        self.compact_to_disk(path);
    }

    /// Rewrite the persist file with the current (retained) entries, oldest
    /// first. Atomic via a temp file + rename so a crash mid-write can't corrupt
    /// the log. Best-effort: failures are logged by the caller's context, never
    /// fatal.
    fn compact_to_disk(&self, path: &Path) {
        let mut rows: Vec<&JournalEntry> = self.by_session.values().flat_map(|l| l.entries.iter()).collect();
        rows.sort_by(|a, b| a.ts_us.cmp(&b.ts_us));
        let mut buf = String::new();
        for e in rows {
            if let Ok(line) = serde_json::to_string(e) {
                buf.push_str(&line);
                buf.push('\n');
            }
        }
        let tmp = path.with_extension("jsonl.tmp");
        if std::fs::write(&tmp, &buf).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
    /// Append an entry (no co-signing). Convenience wrapper over
    /// [`JournalStore::append_with_signer`]; used by the test suite and any
    /// caller that does not co-sign (the HTTP handler always passes a signer).
    #[allow(dead_code)]
    pub fn append(&mut self, input: JournalInput) -> JournalEntry {
        self.append_with_signer(input, None)
    }

    /// Append an entry, assigning `seq`/`created_at`/`entry_id` and stripping
    /// reserved-prefix tokens from `text`. When `signer` is provided **and**
    /// `CORECRUXD_FEATURE_ACTIVITY_SIGN` is on, the finalised entry is co-signed
    /// (M2): an [`ActivityReceiptV1`] over the canonical body is embedded before
    /// persist, so the durable copy carries the receipt too. Returns the
    /// finalised entry (caller emits the event + receipt reference from it).
    pub fn append_with_signer(&mut self, input: JournalInput, signer: Option<&dyn ActivitySigner>) -> JournalEntry {
        let log = self
            .by_session
            .entry((input.tenant_id.clone(), input.session_id.clone()))
            .or_default();
        let seq = log.next_seq;
        log.next_seq += 1;

        let now = Utc::now();
        let created_at = now.to_rfc3339();
        let ts_us = now.timestamp_micros();
        let actor_passport = input
            .actor_passport
            .filter(|p| !p.trim().is_empty())
            .unwrap_or_else(|| ANON_PASSPORT.to_string());
        let text = strip_reserved_text(&input.text);
        let entry_id = compute_entry_id(&input.tenant_id, &input.session_id, seq, input.kind, &created_at, &text);

        let mut refs = input.refs;
        // T.4 — the append id is the receipt reference; record it on the
        // entry so the audit chain is always dereferenceable.
        if !refs.receipt_ids.iter().any(|r| r == &entry_id) {
            refs.receipt_ids.push(entry_id.clone());
        }

        let mut entry = JournalEntry {
            schema: JOURNAL_ENTRY_SCHEMA_V1.to_string(),
            entry_id,
            tenant_id: input.tenant_id,
            session_id: input.session_id,
            turn_id: input.turn_id,
            seq,
            kind: input.kind,
            actor_passport,
            text,
            refs,
            meta: input.meta,
            private: input.private,
            created_at,
            receipt: None,
            ts_us,
        };

        // M2 — co-sign the canonical body when enabled. Best-effort: the entry
        // is still appended unsigned if signing is off or no signer is wired.
        if activity_sign_enabled() {
            if let Some(signer) = signer {
                let body = canonical_signing_bytes(&entry);
                entry.receipt = Some(signer.sign_body(&body));
            }
        }

        log.entries.push(entry.clone());
        Self::trim(&mut log.entries, retention());
        // Write-through to the durable log (best-effort; an unwritable disk must
        // never break the in-memory append). Appends are idempotent enough for
        // the load path: duplicates are tolerated and compacted on next open.
        if let Some(path) = self.persist_path.clone() {
            append_line_to_disk(&path, &entry);
        }
        entry
    }

    /// Read up to `top_k` most-recent entries for `(tenant, session)`,
    /// newest first, honouring privacy scope. `caller_passport` only sees
    /// `private` entries it authored (T.1). `since_seq` (exclusive) skips
    /// entries already seen.
    pub fn recent(
        &mut self,
        tenant: &str,
        session: &str,
        caller_passport: &str,
        since_seq: Option<u64>,
        kinds: Option<&[JournalKind]>,
        top_k: usize,
    ) -> Vec<JournalEntry> {
        let Some(log) = self.by_session.get_mut(&(tenant.to_string(), session.to_string())) else {
            return Vec::new();
        };
        Self::trim(&mut log.entries, retention());
        log.entries
            .iter()
            .rev()
            .filter(|e| since_seq.is_none_or(|s| e.seq > s))
            .filter(|e| kinds.is_none_or(|ks| ks.contains(&e.kind)))
            .filter(|e| !e.private || e.actor_passport == caller_passport)
            .take(top_k)
            .cloned()
            .collect()
    }

    /// Like `recent` but across **all sessions** for `tenant`, newest-first
    /// globally (by absolute `ts_us`). Powers the human-lane "all activity"
    /// pane and the session dropdown. Same privacy scope + reserved-strip as
    /// `recent`. `before` is a pagination cursor (an entry `ts_us`): when
    /// `Some`, only entries strictly older are returned — the dash's infinite
    /// scroll passes the last row's `cursor` back as `before` to page down.
    pub fn recent_all(
        &mut self,
        tenant: &str,
        caller_passport: &str,
        before: Option<i64>,
        kinds: Option<&[JournalKind]>,
        execplan: Option<&str>,
        limit: usize,
    ) -> Vec<JournalEntry> {
        let mut out: Vec<JournalEntry> = Vec::new();
        for ((t, _s), log) in &mut self.by_session {
            if t != tenant {
                continue;
            }
            Self::trim(&mut log.entries, retention());
            for e in &log.entries {
                if before.is_some_and(|b| e.ts_us >= b) {
                    continue; // cursor: only entries strictly older than `before`
                }
                if kinds.is_some_and(|ks| !ks.contains(&e.kind)) {
                    continue;
                }
                if execplan.is_some_and(|want| e.meta.execplan_slug.as_deref() != Some(want)) {
                    continue; // plan filter: only entries tagged for this ExecPlan
                }
                if e.private && e.actor_passport != caller_passport {
                    continue;
                }
                out.push(e.clone());
            }
        }
        // Newest-first across sessions by absolute time, then cap to the page limit.
        out.sort_by(|a, b| b.ts_us.cmp(&a.ts_us));
        out.truncate(limit);
        out
    }

    /// Fetch a single entry by `(tenant, session, turn_id)` for the human
    /// lane's row-expand, honouring the same privacy scope as `recent`.
    pub fn by_turn(&self, tenant: &str, session: &str, turn_id: &str, caller_passport: &str) -> Vec<JournalEntry> {
        let Some(log) = self.by_session.get(&(tenant.to_string(), session.to_string())) else {
            return Vec::new();
        };
        log.entries
            .iter()
            .filter(|e| e.turn_id.as_deref() == Some(turn_id))
            .filter(|e| !e.private || e.actor_passport == caller_passport)
            .cloned()
            .collect()
    }

    fn trim(entries: &mut Vec<JournalEntry>, ttl: Duration) {
        let now_us = Utc::now().timestamp_micros();
        let cutoff = now_us.saturating_sub(ttl.as_micros() as i64);
        let split = entries.iter().position(|e| e.ts_us >= cutoff).unwrap_or(entries.len());
        if split > 0 {
            entries.drain(0..split);
        }
        if entries.len() > MAX_ENTRIES_PER_SESSION {
            let overflow = entries.len() - MAX_ENTRIES_PER_SESSION;
            entries.drain(0..overflow);
        }
    }
}

/// Resolve the on-disk journal log path: `<CORECRUXD_DATA_DIR>/activity/journal.jsonl`.
/// `None` when the data dir is unset (e.g. tests) → the store stays in-memory.
/// Creates the `activity/` directory as a side effect.
pub fn activity_persist_path() -> Option<PathBuf> {
    let dir = std::env::var("CORECRUXD_DATA_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    let activity_dir = PathBuf::from(dir).join("activity");
    if std::fs::create_dir_all(&activity_dir).is_err() {
        return None;
    }
    Some(activity_dir.join("journal.jsonl"))
}

/// Append one entry as a JSON line to the durable log. Best-effort: any IO error
/// is swallowed so a full/unwritable disk never propagates into the append path.
fn append_line_to_disk(path: &Path, entry: &JournalEntry) {
    use std::io::Write as _;
    let Ok(line) = serde_json::to_string(entry) else { return };
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

/// Process-wide journal store (lazy-init, single mutex), mirroring the trace
/// ring's [`crux_mcp::traces::global`] singleton pattern. Hydrates from
/// `<CORECRUXD_DATA_DIR>/activity/journal.jsonl` on first access so activity
/// survives daemon restarts.
pub fn global() -> &'static Mutex<JournalStore> {
    static STORE: OnceLock<Mutex<JournalStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(JournalStore::open(activity_persist_path())))
}

/// Compact agent-lane row (schema 2 in the design doc): the cheap projection
/// of a [`JournalEntry`] — `preview` is truncated, never the verbatim text.
#[derive(Debug, Clone, Serialize)]
pub struct ActivityRow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    /// Owning session — always present so the all-sessions pane can group/label
    /// rows and the session dropdown can enumerate distinct values.
    pub session_id: String,
    pub seq: u64,
    pub ts: String,
    /// Opaque pagination cursor (the entry's `ts_us`); pass back as `?before=`
    /// to fetch the next older page (infinite scroll).
    pub cursor: i64,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    pub fact_refs: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub preview: String,
}

/// Truncate `text` to at most `max_chars`, appending an ellipsis when cut.
fn preview_of(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut s: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    s.push('…');
    s
}

impl ActivityRow {
    /// Project a journal entry into a compact row with a budget-scaled
    /// `preview`.
    pub fn from_entry(entry: &JournalEntry, preview_chars: usize) -> Self {
        ActivityRow {
            turn_id: entry.turn_id.clone(),
            session_id: entry.session_id.clone(),
            seq: entry.seq,
            ts: entry.created_at.clone(),
            cursor: entry.ts_us,
            kind: entry.kind.as_str(),
            intent: entry.meta.intent.clone(),
            tool: entry.meta.tool.clone(),
            confidence: entry.meta.confidence,
            fact_refs: entry.refs.fact_ids.clone(),
            receipt_ids: entry.refs.receipt_ids.clone(),
            preview: preview_of(&entry.text, preview_chars),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn input(tenant: &str, session: &str, kind: JournalKind, text: &str) -> JournalInput {
        JournalInput {
            tenant_id: tenant.to_string(),
            session_id: session.to_string(),
            turn_id: Some("turn-1".to_string()),
            kind,
            actor_passport: Some("alice".to_string()),
            text: text.to_string(),
            refs: JournalRefs::default(),
            meta: JournalMeta::default(),
            private: false,
        }
    }

    #[test]
    fn flag_default_off() {
        std::env::remove_var(FEATURE_FLAG_ENV);
        assert!(!activity_log_enabled(), "activity log must default OFF");
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        assert!(activity_log_enabled());
        for off in ["0", "false", "off", "no", ""] {
            std::env::set_var(FEATURE_FLAG_ENV, off);
            assert!(!activity_log_enabled(), "{off:?} should disable");
        }
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[test]
    fn disk_persistence_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("crux-activity-persist-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("journal.jsonl");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = JournalStore::open(Some(path.clone()));
            store.append(input("t", "s1", JournalKind::Question, "q1"));
            store.append(input("t", "s1", JournalKind::Answer, "a1"));
            store.append(input("t", "s2", JournalKind::Command, "c1"));
        } // dropped — only the on-disk log remains

        let mut store2 = JournalStore::open(Some(path.clone()));
        assert_eq!(
            store2.recent("t", "s1", "alice", None, None, 100).len(),
            2,
            "s1 persisted"
        );
        assert_eq!(
            store2.recent_all("t", "alice", None, None, None, 100).len(),
            3,
            "all sessions persisted"
        );
        // next_seq continues past the reloaded entries — no seq collision.
        assert_eq!(store2.append(input("t", "s1", JournalKind::Answer, "a2")).seq, 2);

        // In-memory mode (no path) writes nothing.
        let mut mem = JournalStore::open(None);
        mem.append(input("t", "s", JournalKind::Question, "x"));
        assert_eq!(mem.recent("t", "s", "alice", None, None, 10).len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_assigns_monotonic_seq_and_receipt_ref() {
        let mut store = JournalStore::default();
        let e0 = store.append(input("t", "s", JournalKind::Question, "hello"));
        let e1 = store.append(input("t", "s", JournalKind::Answer, "world"));
        assert_eq!(e0.seq, 0);
        assert_eq!(e1.seq, 1);
        // T.4: the append id is referenced as a receipt id.
        assert!(e0.refs.receipt_ids.contains(&e0.entry_id));
        assert_eq!(e0.schema, JOURNAL_ENTRY_SCHEMA_V1);
    }

    #[test]
    fn reserved_prefix_text_is_stripped() {
        let mut store = JournalStore::default();
        let e = store.append(input(
            "t",
            "s",
            JournalKind::Reasoning,
            "checked __ops::config-audit and __bootstrap__::pattern but kept project-x",
        ));
        assert!(!e.text.contains("__ops::"), "ops prefix must be redacted: {}", e.text);
        assert!(!e.text.contains("__bootstrap__::"), "bootstrap prefix must be redacted");
        assert!(e.text.contains("project-x"), "non-reserved tokens survive");
        assert!(e.text.contains(REDACTED));
    }

    #[test]
    fn recent_is_newest_first_and_tenant_scoped() {
        let mut store = JournalStore::default();
        store.append(input("t", "s", JournalKind::Question, "q"));
        store.append(input("t", "s", JournalKind::Answer, "a"));
        store.append(input("other", "s", JournalKind::Question, "leak?"));
        let rows = store.recent("t", "s", "alice", None, None, 10);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].kind, JournalKind::Answer);
        // Cross-tenant probe returns nothing (T.1).
        let cross = store.recent("t", "other-session", "alice", None, None, 10);
        assert!(cross.is_empty());
    }

    #[test]
    fn private_entries_only_visible_to_author() {
        let mut store = JournalStore::default();
        let mut priv_in = input("t", "s", JournalKind::Answer, "secret");
        priv_in.private = true;
        priv_in.actor_passport = Some("alice".to_string());
        store.append(priv_in);
        assert_eq!(store.recent("t", "s", "alice", None, None, 10).len(), 1);
        assert_eq!(store.recent("t", "s", "bob", None, None, 10).len(), 0);
    }

    #[test]
    fn since_seq_and_kind_filters() {
        let mut store = JournalStore::default();
        store.append(input("t", "s", JournalKind::Question, "q0"));
        store.append(input("t", "s", JournalKind::Command, "c1"));
        store.append(input("t", "s", JournalKind::Error, "e2"));
        let after0 = store.recent("t", "s", "alice", Some(0), None, 10);
        assert_eq!(after0.len(), 2);
        let only_err = store.recent("t", "s", "alice", None, Some(&[JournalKind::Error]), 10);
        assert_eq!(only_err.len(), 1);
        assert_eq!(only_err[0].kind, JournalKind::Error);
    }

    #[test]
    fn anon_passport_when_unauth() {
        let mut store = JournalStore::default();
        let mut anon = input("t", "s", JournalKind::Question, "q");
        anon.actor_passport = None;
        let e = store.append(anon);
        assert_eq!(e.actor_passport, ANON_PASSPORT);
    }

    #[test]
    fn by_turn_fetches_and_scopes() {
        let mut store = JournalStore::default();
        store.append(input("t", "s", JournalKind::Question, "q"));
        store.append(input("t", "s", JournalKind::Answer, "a"));
        let rows = store.by_turn("t", "s", "turn-1", "alice");
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn row_preview_truncates() {
        let mut store = JournalStore::default();
        let e = store.append(input("t", "s", JournalKind::Answer, &"x".repeat(200)));
        let row = ActivityRow::from_entry(&e, 20);
        assert!(row.preview.chars().count() <= 20);
        assert!(row.preview.ends_with('…'));
        assert!(row.receipt_ids.contains(&e.entry_id));
    }
}
