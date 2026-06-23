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

    let blocks = if rtype == Some("attachment") {
        attachment_blocks(value, capture)
    } else {
        match (kind, message) {
            (EventKind::Assistant | EventKind::User, Some(msg)) => extract_blocks(msg, kind, tool_names, capture),
            _ => Vec::new(),
        }
    };

    Event {
        kind,
        usage,
        blocks,
        session_id,
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
        if let Some(block) = parse_block(item, kind, tool_names, capture) {
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
) -> Option<ContentBlock> {
    match item.get("type").and_then(Value::as_str)? {
        "text" => {
            let text = item.get("text").and_then(Value::as_str).unwrap_or_default();
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
