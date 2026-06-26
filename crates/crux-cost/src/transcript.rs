// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Claude Code transcript (`<session>.jsonl`) parsing.
//!
//! The schema is **undocumented and drifts** — so this module is the one place
//! that touches it, and it **fails soft**: a malformed line is skipped, an
//! unknown block shape is ignored, and the parser never panics on bad input.
//! Only what's needed for the cost lens is extracted:
//!
//! * measured `message.usage` (the ground-truth four numbers), and
//! * a per-content-block source tag + token-length + short preview.
//!
//! To stay bounded on large sessions we keep **the character length and an
//! 80-char preview per block, never the full block text** ("truncated for large
//! I/O"). Thinking-block previews are deliberately redacted — raw reasoning is
//! never surfaced, even in a cost summary.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use serde_json::Value;

use crate::report::Measured;

/// Max characters retained for a block preview.
const PREVIEW_CHARS: usize = 80;

/// What kind of transcript record this is, for the carried-cost segment model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// A model turn (`type: "assistant"`).
    Assistant,
    /// A user turn or tool-result delivery (`type: "user"`).
    User,
    /// A compaction boundary — resets the carried-context segment.
    Compaction,
    /// Anything else (summary/system/meta) — ignored by attribution.
    Meta,
}

/// One content block, reduced to what attribution needs.
#[derive(Debug, Clone)]
pub struct ContentBlock {
    /// Fine-grained source key, e.g. `tool_result:Bash`, `assistant_prose`.
    pub source: String,
    /// Tool name when this is tool I/O.
    pub tool: Option<String>,
    /// Character count of the block text (input to the chars/4 estimator).
    pub text_chars: usize,
    /// Single-lined preview (≤80 chars; thinking is redacted).
    pub preview: String,
    /// Full block text — populated **only** when parsed via
    /// [`parse_str_capturing`] / [`parse_file_capturing`] (the M3 ingester
    /// path); `None` in the default redact-by-default mode. For thinking blocks
    /// this is the raw reasoning, surfaced solely so the ingester can summarise
    /// it — never persisted as-is (R1).
    pub text: Option<String>,
}

/// How strong a transcript signal is that the session **worked** an ExecPlan
/// (OD-29). Ordered weakest→strongest by declaration, so `>`/`Ord` compares
/// reliability directly. Weak signals are **tie-breakers only** — never sole
/// evidence (see [`crate::attribution`]'s ranking).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignalStrength {
    /// A prose `[[<slug>]]` wiki-link mention — the plan was merely *referenced*.
    Weak,
    /// An `Edit`/`Write`/`Read`/`MultiEdit`/`NotebookEdit` `tool_use` whose path
    /// is `*/.agent/execplans/<slug>.md` — the session opened/changed the plan
    /// file.
    Strong,
    /// An MCP `store_fact`/`save_session`/`coord_announce` `tool_use` that wrote
    /// to `entity="execplan:<slug>"` / `session_id="execplan:<slug>"` / an
    /// `execplan_slug` field — the agent literally recorded work against the plan.
    Strongest,
}

impl SignalStrength {
    /// Additive weight used to rank slugs by accumulated evidence.
    #[must_use]
    pub fn weight(self) -> u32 {
        match self {
            SignalStrength::Weak => 1,
            SignalStrength::Strong => 2,
            SignalStrength::Strongest => 3,
        }
    }
}

/// One piece of evidence, extracted at parse time, that the session worked a
/// given ExecPlan. Collected per record into [`Event::execplan_signals`] and
/// ranked into `CostReport.execplan_slugs` by [`crate::attribution::analyze`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPlanSignal {
    /// The plan slug (the `<slug>` in `execplan:<slug>` / `<slug>.md`).
    pub slug: String,
    /// How reliable this signal is.
    pub strength: SignalStrength,
}

/// A parsed transcript record.
#[derive(Debug, Clone)]
pub struct Event {
    /// Record kind.
    pub kind: EventKind,
    /// Measured usage, when the record carried a `usage` object.
    pub usage: Option<Measured>,
    /// Content blocks (may be empty).
    pub blocks: Vec<ContentBlock>,
    /// `sessionId`, when present.
    pub session_id: Option<String>,
    /// The record's RFC3339 `timestamp` (e.g. `2026-06-25T11:38:40.060Z`), kept
    /// verbatim when it has the expected fixed-width UTC `Z` shape. Used by the
    /// analyzer to derive the session's active time window; `None` when absent or
    /// malformed. Every Claude Code record (including `queue-operation`/meta)
    /// carries one, so the window spans the whole transcript, not just turns.
    pub timestamp: Option<String>,
    /// ExecPlan-link signals found in this record's `tool_use` inputs and prose
    /// (OD-29). Empty for records that touched no plan. Detected at parse time
    /// because the full `tool_use` input + block text is only available here
    /// (block previews are truncated to 80 chars downstream).
    pub execplan_signals: Vec<ExecPlanSignal>,
    /// The record's `gitBranch`, when present and non-empty. A weak tie-breaker
    /// only (often `HEAD`/detached or a `feat/...` name that doesn't map cleanly
    /// to a dated slug) — never introduces a slug on its own.
    pub git_branch: Option<String>,
}

/// Cheap shape check for the Claude Code transcript timestamp: a fixed-width
/// RFC3339 UTC instant like `2026-06-25T11:38:40.060Z`. Strings of this form
/// compare lexically in chronological order, so the analyzer can take a min/max
/// without a date-time dependency. Anything that doesn't match is ignored.
fn looks_like_rfc3339_utc(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 20 && b[0].is_ascii_digit() && s.contains('T') && s.ends_with('Z')
}

/// Parse a transcript file path, failing soft on bad lines. Errors only on the
/// file being unreadable.
///
/// # Errors
/// Returns the underlying [`std::io::Error`] if the file cannot be opened.
pub fn parse_file(path: &Path) -> std::io::Result<Vec<Event>> {
    parse_file_opts(path, false)
}

/// Like [`parse_file`] but captures full block text into [`ContentBlock::text`]
/// (the M3 ingester path; raw thinking is surfaced only to summarise it).
///
/// # Errors
/// Returns the underlying [`std::io::Error`] if the file cannot be opened.
pub fn parse_file_capturing(path: &Path) -> std::io::Result<Vec<Event>> {
    parse_file_opts(path, true)
}

fn parse_file_opts(path: &Path, capture: bool) -> std::io::Result<Vec<Event>> {
    let file = std::fs::File::open(path)?;
    Ok(parse_reader(BufReader::new(file), capture))
}

/// Parse from any reader, line by line, skipping malformed lines. `capture`
/// fills [`ContentBlock::text`] with the full block text.
pub fn parse_reader<R: Read>(reader: BufReader<R>, capture: bool) -> Vec<Event> {
    let mut tool_names: HashMap<String, String> = HashMap::new();
    let mut events = Vec::new();
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            events.push(parse_record(&value, &mut tool_names, capture));
        }
    }
    events
}

/// Parse from an in-memory string (one JSON object per line). Convenience for
/// tests and small inputs.
#[must_use]
pub fn parse_str(text: &str) -> Vec<Event> {
    parse_str_opts(text, false)
}

/// Like [`parse_str`] but captures full block text into [`ContentBlock::text`].
#[must_use]
pub fn parse_str_capturing(text: &str) -> Vec<Event> {
    parse_str_opts(text, true)
}

fn parse_str_opts(text: &str, capture: bool) -> Vec<Event> {
    let mut tool_names: HashMap<String, String> = HashMap::new();
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .map(|v| parse_record(&v, &mut tool_names, capture))
        .collect()
}

fn parse_record(value: &Value, tool_names: &mut HashMap<String, String>, capture: bool) -> Event {
    let session_id = value.get("sessionId").and_then(Value::as_str).map(str::to_owned);
    let timestamp = value
        .get("timestamp")
        .and_then(Value::as_str)
        .filter(|s| looks_like_rfc3339_utc(s))
        .map(str::to_owned);
    let rtype = value.get("type").and_then(Value::as_str);

    let kind = if is_compaction(value) {
        EventKind::Compaction
    } else {
        match rtype {
            Some("assistant") => EventKind::Assistant,
            // Attachment records carry user-injected file content that is
            // re-read every turn — TokenBurn attributes them as a user block.
            Some("user" | "attachment") => EventKind::User,
            _ => EventKind::Meta,
        }
    };

    let message = value.get("message");
    let usage = message
        .and_then(|m| m.get("usage"))
        .or_else(|| value.get("usage"))
        .and_then(parse_usage);

    let mut execplan_signals: Vec<ExecPlanSignal> = Vec::new();
    let blocks = if rtype == Some("attachment") {
        attachment_blocks(value, capture)
    } else {
        match (kind, message) {
            (EventKind::Assistant | EventKind::User, Some(msg)) => {
                extract_blocks(msg, kind, tool_names, capture, &mut execplan_signals)
            }
            _ => Vec::new(),
        }
    };

    let git_branch = value
        .get("gitBranch")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "HEAD")
        .map(str::to_owned);

    Event {
        kind,
        usage,
        blocks,
        session_id,
        timestamp,
        execplan_signals,
        git_branch,
    }
}

/// A top-level `type:"attachment"` record stores its payload in the
/// `attachment` field (not `message.content`).
fn attachment_blocks(value: &Value, capture: bool) -> Vec<ContentBlock> {
    match value.get("attachment") {
        Some(a) if !a.is_null() => {
            let text = value_to_text(a);
            vec![text_block("attachment", None, &text, capture)]
        }
        _ => Vec::new(),
    }
}

/// Detect a compaction boundary. Claude Code has marked these several ways
/// across versions, so we accept any of them.
fn is_compaction(value: &Value) -> bool {
    if value.get("isCompactSummary").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if value.get("type").and_then(Value::as_str) == Some("system") {
        if value.get("compactMetadata").is_some() {
            return true;
        }
        if matches!(
            value.get("subtype").and_then(Value::as_str),
            Some("compact_boundary" | "compact")
        ) {
            return true;
        }
    }
    false
}

fn parse_usage(raw: &Value) -> Option<Measured> {
    let obj = raw.as_object()?;
    let u64_at = |k: &str| obj.get(k).and_then(Value::as_u64).unwrap_or(0);
    // Newer API nests cache_creation as {ephemeral_5m_input_tokens, …}.
    let cache_creation = match u64_at("cache_creation_input_tokens") {
        0 => raw
            .get("cache_creation")
            .and_then(Value::as_object)
            .map_or(0, |m| m.values().filter_map(Value::as_u64).sum()),
        direct => direct,
    };
    Some(Measured {
        input: u64_at("input_tokens"),
        output: u64_at("output_tokens"),
        cache_read: u64_at("cache_read_input_tokens"),
        cache_creation,
    })
}

fn extract_blocks(
    message: &Value,
    kind: EventKind,
    tool_names: &mut HashMap<String, String>,
    capture: bool,
    signals: &mut Vec<ExecPlanSignal>,
) -> Vec<ContentBlock> {
    let content = match message.get("content") {
        Some(c) => c,
        None => return Vec::new(),
    };

    // User prompts often arrive as a bare string.
    if let Some(text) = content.as_str() {
        if text.is_empty() {
            return Vec::new();
        }
        collect_wikilink_signals(text, signals);
        let source = if kind == EventKind::User {
            "user_prompt"
        } else {
            "assistant_prose"
        };
        return vec![text_block(source, None, text, capture)];
    }

    let Some(items) = content.as_array() else {
        return Vec::new();
    };

    let mut blocks = Vec::new();
    for item in items {
        if let Some(block) = parse_block(item, kind, tool_names, capture, signals) {
            blocks.push(block);
        }
    }
    blocks
}

fn parse_block(
    item: &Value,
    kind: EventKind,
    tool_names: &mut HashMap<String, String>,
    capture: bool,
    signals: &mut Vec<ExecPlanSignal>,
) -> Option<ContentBlock> {
    match item.get("type").and_then(Value::as_str)? {
        "text" => {
            let text = item.get("text").and_then(Value::as_str).unwrap_or_default();
            collect_wikilink_signals(text, signals);
            let source = if kind == EventKind::User {
                "user_prompt"
            } else {
                "assistant_prose"
            };
            Some(text_block(source, None, text, capture))
        }
        "thinking" => {
            // Always redact the preview (R1 posture); carry the raw text only
            // when explicitly capturing (the ingester summarises it, never
            // persists it).
            let raw = item.get("thinking").and_then(Value::as_str).unwrap_or_default();
            let chars = raw.chars().count();
            Some(ContentBlock {
                source: "assistant_thinking".to_owned(),
                tool: None,
                text_chars: chars,
                preview: format!("(thinking · {chars} chars · redacted)"),
                text: capture.then(|| raw.to_owned()),
            })
        }
        "tool_use" => {
            let name = item.get("name").and_then(Value::as_str).unwrap_or("unknown").to_owned();
            if let Some(id) = item.get("id").and_then(Value::as_str) {
                tool_names.insert(id.to_owned(), name.clone());
            }
            if let Some(input) = item.get("input") {
                collect_tool_use_signals(&name, input, signals);
            }
            let input_text = item.get("input").map(value_to_text).unwrap_or_default();
            Some(text_block(
                &format!("tool_use_args:{name}"),
                Some(name),
                &input_text,
                capture,
            ))
        }
        "tool_result" => {
            let name = item
                .get("tool_use_id")
                .and_then(Value::as_str)
                .and_then(|id| tool_names.get(id))
                .cloned()
                .unwrap_or_else(|| "unknown".to_owned());
            let result_text = item.get("content").map(value_to_text).unwrap_or_default();
            Some(text_block(
                &format!("tool_result:{name}"),
                Some(name),
                &result_text,
                capture,
            ))
        }
        // Images count as a tiny fixed marker, never the base64 payload
        // (matches TokenBurn; avoids a base64 spike dominating attribution).
        "image" => {
            let source = if kind == EventKind::User {
                "user_image"
            } else {
                "assistant_image"
            };
            Some(text_block(source, None, "[image]", capture))
        }
        _ => None,
    }
}

fn text_block(source: &str, tool: Option<String>, text: &str, capture: bool) -> ContentBlock {
    ContentBlock {
        source: source.to_owned(),
        tool,
        text_chars: text.chars().count(),
        preview: preview_of(text),
        text: capture.then(|| text.to_owned()),
    }
}

/// Detect ExecPlan-link signals in a `tool_use` block's `input` (OD-29). MCP
/// fact-writes to an `execplan:<slug>` entity are the strongest evidence; file
/// tools opening a plan file are strong. Fails soft — an unknown tool or shape
/// adds nothing.
fn collect_tool_use_signals(name: &str, input: &Value, signals: &mut Vec<ExecPlanSignal>) {
    match tool_leaf(name) {
        "store_fact" | "save_session" | "coord_announce" => {
            // `entity` (store_fact) / `session_id` (save_session) = "execplan:<slug>".
            for key in ["entity", "session_id"] {
                if let Some(slug) = input
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(slug_from_execplan_entity)
                {
                    signals.push(ExecPlanSignal {
                        slug,
                        strength: SignalStrength::Strongest,
                    });
                }
            }
            // `execplan_slug` (coord_announce) carries the bare slug.
            if let Some(slug) = input
                .get("execplan_slug")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                signals.push(ExecPlanSignal {
                    slug: slug.to_owned(),
                    strength: SignalStrength::Strongest,
                });
            }
        }
        "Edit" | "Write" | "Read" | "MultiEdit" | "NotebookEdit" => {
            for key in ["file_path", "path", "notebook_path"] {
                if let Some(slug) = input.get(key).and_then(Value::as_str).and_then(slug_from_execplan_path) {
                    signals.push(ExecPlanSignal {
                        slug,
                        strength: SignalStrength::Strong,
                    });
                }
            }
        }
        _ => {}
    }
}

/// Scan prose for `[[<slug>]]` wiki-link mentions — a weak signal. Only
/// slug-shaped inner text counts, so `[[1]]` / arbitrary brackets are ignored.
fn collect_wikilink_signals(text: &str, signals: &mut Vec<ExecPlanSignal>) {
    if !text.contains("[[") {
        return;
    }
    let mut rest = text;
    while let Some(open) = rest.find("[[") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("]]") else { break };
        let inner = after[..close].trim();
        if is_plausible_slug(inner) {
            signals.push(ExecPlanSignal {
                slug: inner.to_owned(),
                strength: SignalStrength::Weak,
            });
        }
        rest = &after[close + 2..];
    }
}

/// The leaf of a (possibly MCP-namespaced) tool name: `mcp__crux__store_fact` →
/// `store_fact`; `Edit` → `Edit`.
fn tool_leaf(name: &str) -> &str {
    name.rsplit("__").next().unwrap_or(name)
}

/// `execplan:<slug>` → `Some(<slug>)`; anything without the prefix → `None`.
fn slug_from_execplan_entity(value: &str) -> Option<String> {
    let slug = value.strip_prefix("execplan:")?.trim();
    (!slug.is_empty()).then(|| slug.to_owned())
}

/// `…/.agent/execplans/<slug>.md` → `Some(<slug>)`. Tolerates `\` separators so
/// a Windows-style path still matches.
fn slug_from_execplan_path(path: &str) -> Option<String> {
    let norm = path.replace('\\', "/");
    let after = norm.split(".agent/execplans/").nth(1)?;
    let file = after.split('/').next()?;
    let slug = file.strip_suffix(".md")?.trim();
    (!slug.is_empty()).then(|| slug.to_owned())
}

/// A conservative check that a string looks like an ExecPlan slug (`kebab-case`,
/// usually date-suffixed). Guards the weak wiki-link signal against arbitrary
/// `[[…]]` text. ASCII-only by construction (slugs are).
fn is_plausible_slug(s: &str) -> bool {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if !(3..=120).contains(&len) || !s.contains('-') {
        return false;
    }
    let edge_ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    edge_ok(bytes[0])
        && edge_ok(bytes[len - 1])
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Best-effort flattening of a `content` value to text for token estimation.
/// Mirrors TokenBurn's `_as_text` (image items collapse to `[image]`, dicts with
/// a `text` field use it, else compact JSON).
fn value_to_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                if let Some(text) = item.get("text").and_then(Value::as_str) {
                    parts.push(text.to_owned());
                } else if item.get("type").and_then(Value::as_str) == Some("image") {
                    parts.push("[image]".to_owned());
                } else if let Some(s) = item.as_str() {
                    parts.push(s.to_owned());
                } else {
                    parts.push(item.to_string());
                }
            }
            parts.join("\n")
        }
        Value::Object(map) => map
            .get("text")
            .and_then(Value::as_str)
            .map_or_else(|| value.to_string(), str::to_owned),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Collapse whitespace and truncate to [`PREVIEW_CHARS`] characters.
fn preview_of(text: &str) -> String {
    let mut collapsed = String::with_capacity(PREVIEW_CHARS + 1);
    let mut last_was_space = false;
    for ch in text.chars() {
        let is_space = ch.is_whitespace();
        if is_space {
            if !last_was_space && !collapsed.is_empty() {
                collapsed.push(' ');
            }
        } else {
            collapsed.push(ch);
        }
        last_was_space = is_space;
        if collapsed.chars().count() >= PREVIEW_CHARS {
            collapsed.push('…');
            break;
        }
    }
    collapsed.trim_end().to_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    /// One assistant record carrying a single `tool_use` block.
    fn tool_use_record(name: &str, input: Value) -> String {
        json!({"type":"assistant","sessionId":"s","message":{"role":"assistant",
            "content":[{"type":"tool_use","id":"t1","name":name,"input":input}]}})
        .to_string()
    }

    fn first_signals(record: &str) -> Vec<ExecPlanSignal> {
        parse_str(record)
            .into_iter()
            .next()
            .map(|e| e.execplan_signals)
            .unwrap_or_default()
    }

    #[test]
    fn slug_from_entity_strips_prefix_only() {
        assert_eq!(
            slug_from_execplan_entity("execplan:foo-2026-01-01").as_deref(),
            Some("foo-2026-01-01")
        );
        assert_eq!(
            slug_from_execplan_entity("execplan: spaced ").as_deref(),
            Some("spaced")
        );
        assert!(slug_from_execplan_entity("bench:lme-s").is_none());
        assert!(slug_from_execplan_entity("execplan:").is_none());
    }

    #[test]
    fn slug_from_path_matches_plan_files_only() {
        assert_eq!(
            slug_from_execplan_path("/home/me/CueCrux/PlanCrux/.agent/execplans/bar-2026-06-26.md").as_deref(),
            Some("bar-2026-06-26")
        );
        // Windows-style separators are tolerated.
        assert_eq!(
            slug_from_execplan_path(r"C:\repo\.agent\execplans\baz.md").as_deref(),
            Some("baz")
        );
        // A non-plan path, or the directory itself, yields nothing.
        assert!(slug_from_execplan_path("/home/me/src/main.rs").is_none());
        assert!(slug_from_execplan_path("x/.agent/execplans/").is_none());
    }

    #[test]
    fn plausible_slug_guards_weak_signal() {
        assert!(is_plausible_slug("token-burn-precise-attribution-2026-06-26"));
        assert!(is_plausible_slug("a-b"));
        // Rejected: no dash, too short, non-slug chars, edge punctuation.
        assert!(!is_plausible_slug("1"));
        assert!(!is_plausible_slug("nodash"));
        assert!(!is_plausible_slug("-leading"));
        assert!(!is_plausible_slug("Has_Caps-x"));
        assert!(!is_plausible_slug("a b-c"));
    }

    #[test]
    fn store_fact_to_execplan_entity_is_strongest() {
        let rec = tool_use_record(
            "mcp__crux__store_fact",
            json!({"entity":"execplan:foo-2026-01-01","key":"gate:M1","value":"x"}),
        );
        let sigs = first_signals(&rec);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].slug, "foo-2026-01-01");
        assert_eq!(sigs[0].strength, SignalStrength::Strongest);
    }

    #[test]
    fn save_session_execplan_id_is_strongest() {
        let rec = tool_use_record(
            "mcp__crux__save_session",
            json!({"session_id":"execplan:bar","state":{}}),
        );
        let sigs = first_signals(&rec);
        assert_eq!(
            sigs,
            vec![ExecPlanSignal {
                slug: "bar".to_owned(),
                strength: SignalStrength::Strongest
            }]
        );
    }

    #[test]
    fn coord_announce_execplan_slug_field_is_strongest() {
        let rec = tool_use_record(
            "coord_announce",
            json!({"session_id":"uuid-123","execplan_slug":"qux-plan"}),
        );
        let sigs = first_signals(&rec);
        assert_eq!(
            sigs,
            vec![ExecPlanSignal {
                slug: "qux-plan".to_owned(),
                strength: SignalStrength::Strongest
            }]
        );
    }

    #[test]
    fn plan_file_edit_is_strong() {
        let rec = tool_use_record(
            "Edit",
            json!({"file_path":"/x/.agent/execplans/bar-2026-06-26.md","old_string":"a","new_string":"b"}),
        );
        let sigs = first_signals(&rec);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].slug, "bar-2026-06-26");
        assert_eq!(sigs[0].strength, SignalStrength::Strong);
    }

    #[test]
    fn non_plan_tool_use_yields_no_signal() {
        // A fact write to a non-execplan entity, and a Bash command, are inert.
        assert!(first_signals(&tool_use_record(
            "mcp__crux__store_fact",
            json!({"entity":"bench:lme-s","key":"k","value":"v"})
        ))
        .is_empty());
        assert!(first_signals(&tool_use_record("Bash", json!({"command":"ls /x/.agent/execplans/"}))).is_empty());
        // A Read of a source file (not a plan) is inert.
        assert!(first_signals(&tool_use_record("Read", json!({"file_path":"/x/src/main.rs"}))).is_empty());
    }

    #[test]
    fn prose_wikilink_is_weak_and_validated() {
        let rec = json!({"type":"assistant","sessionId":"s","message":{"role":"assistant",
            "content":[{"type":"text","text":"see [[real-plan-2026-01-01]] but ignore [[1]] and [[Bad_Caps]]"}]}})
        .to_string();
        let sigs = first_signals(&rec);
        assert_eq!(
            sigs,
            vec![ExecPlanSignal {
                slug: "real-plan-2026-01-01".to_owned(),
                strength: SignalStrength::Weak
            }]
        );
    }

    #[test]
    fn user_prompt_string_content_is_scanned_for_wikilinks() {
        // The bare-string content path (not an array of blocks) is also scanned.
        let rec = json!({"type":"user","sessionId":"s","message":{"role":"user","content":"work on [[my-plan-2026-02-02]] please"}})
            .to_string();
        let sigs = first_signals(&rec);
        assert_eq!(
            sigs,
            vec![ExecPlanSignal {
                slug: "my-plan-2026-02-02".to_owned(),
                strength: SignalStrength::Weak
            }]
        );
    }

    #[test]
    fn git_branch_captured_except_head() {
        let with = json!({"type":"assistant","sessionId":"s","gitBranch":"feat/token-burn","message":{"role":"assistant","content":[]}}).to_string();
        let detached =
            json!({"type":"assistant","sessionId":"s","gitBranch":"HEAD","message":{"role":"assistant","content":[]}})
                .to_string();
        assert_eq!(parse_str(&with)[0].git_branch.as_deref(), Some("feat/token-burn"));
        assert!(parse_str(&detached)[0].git_branch.is_none());
    }

    #[test]
    fn malformed_tool_input_fails_soft() {
        // `input` is a string, not an object — must not panic, yields no signal.
        let rec = json!({"type":"assistant","sessionId":"s","message":{"role":"assistant",
            "content":[{"type":"tool_use","id":"t1","name":"mcp__crux__store_fact","input":"oops"}]}})
        .to_string();
        assert!(first_signals(&rec).is_empty());
    }
}
