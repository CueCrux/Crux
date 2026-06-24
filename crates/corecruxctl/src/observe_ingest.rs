// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl observe ingest` — the **honest transcript ingester** (M3).
//!
//! Reads a Claude Code transcript (the same adapter the cost lens uses) and, per
//! assistant turn, builds a signed observe trace node that captures what the
//! turn actually produced:
//!
//! * the assistant's **text answer** → an `OutputKind::Answer` output (the
//!   live observe hook captures tool calls but not the prose);
//! * a deterministic **thinking-summary** → written to a local
//!   `reasoning/<node_id>.txt` blob, with `reasoning_ref = blob:…` materialising
//!   the pointer the schema expects but nothing wrote.
//!
//! **R1 (never raw chain-of-thought):** the raw thinking is read only to
//! summarise it; the summary is emitted only when it is a proper compression
//! (strictly shorter than and not byte-equal to the raw), and the raw text is
//! never written or posted. Nodes/blobs are `private:true`.
//!
//! Default is a dry run (parse + build + write blobs + print). `--post` ships
//! the nodes to the daemon's observe surface (`CORECRUXD_OBSERVE=1` required).

use std::path::{Path, PathBuf};

use crux_cost::summary::extractive_summary;
use crux_cost::transcript::{self, Event, EventKind};

use crate::login;
use crate::machine::{agent, resolve_daemon};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Only summarise a turn's thinking when it's at least this many chars — tiny
/// thoughts aren't worth a blob and rarely compress.
const MIN_THINKING_CHARS: usize = 200;
/// Target length of an extractive reasoning summary.
const MAX_SUMMARY_CHARS: usize = 600;
/// Truncation cap for the captured answer excerpt (a ref + excerpt, never an
/// inline blob — Art. 10 / bounded node I/O).
const MAX_ANSWER_CHARS: usize = 2000;

/// A trace node the ingester will produce for one assistant turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IngestNode {
    /// Deterministic id: `ingest_<sid8>_<seq>`.
    pub node_id: String,
    /// The transcript session id.
    pub session_id: String,
    /// Captured assistant answer excerpt (the `Answer` output), if any.
    pub answer: Option<String>,
    /// Extractive thinking summary (written to the blob), if any.
    pub reasoning_summary: Option<String>,
    /// `blob:reasoning/<node_id>.txt` when a summary was produced.
    pub reasoning_ref: Option<String>,
}

/// Build the per-turn ingest nodes from parsed (capturing) transcript events.
/// Only turns that produced an answer and/or a reasoning summary yield a node.
pub(crate) fn build_nodes(events: &[Event], session_id: &str) -> Vec<IngestNode> {
    let sid8: String = session_id.chars().take(8).collect();
    let mut nodes = Vec::new();
    let mut seq = 0u64;
    for ev in events {
        if ev.kind != EventKind::Assistant {
            continue;
        }
        seq += 1;
        let node_id = format!("ingest_{sid8}_{seq}");

        let mut answer = String::new();
        let mut thinking = String::new();
        for b in &ev.blocks {
            let Some(text) = b.text.as_deref() else { continue };
            match b.source.as_str() {
                "assistant_prose" => push_joined(&mut answer, text),
                "assistant_thinking" => push_joined(&mut thinking, text),
                _ => {}
            }
        }

        // Reasoning: summarise only substantial thinking, and only keep it when
        // it is a strict compression of the raw (the mechanical R1 guard).
        let (reasoning_summary, reasoning_ref) = if thinking.chars().count() >= MIN_THINKING_CHARS {
            let s = extractive_summary(&thinking, MAX_SUMMARY_CHARS);
            if !s.is_empty() && s.len() < thinking.len() && s != thinking {
                (Some(s), Some(format!("blob:reasoning/{node_id}.txt")))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let answer = (!answer.trim().is_empty()).then(|| truncate_chars(answer.trim(), MAX_ANSWER_CHARS));

        // Skip turns that produced neither prose nor a summary (e.g. tool-only).
        if answer.is_none() && reasoning_ref.is_none() {
            continue;
        }
        nodes.push(IngestNode {
            node_id,
            session_id: session_id.to_owned(),
            answer,
            reasoning_summary,
            reasoning_ref,
        });
    }
    nodes
}

/// Write each node's reasoning summary to `<blob_dir>/reasoning/<node_id>.txt`.
/// Returns the number of blobs written.
///
/// # Errors
/// Propagates any filesystem error creating the directory or writing a blob.
pub(crate) fn write_blobs(nodes: &[IngestNode], blob_dir: &Path) -> std::io::Result<usize> {
    let dir = blob_dir.join("reasoning");
    let mut written = 0;
    for node in nodes {
        if let Some(summary) = &node.reasoning_summary {
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join(format!("{}.txt", node.node_id)), summary)?;
            written += 1;
        }
    }
    Ok(written)
}

/// `corecruxctl observe ingest` entry point.
pub fn run_ingest(
    file: Option<String>,
    session: Option<String>,
    blob_dir: Option<String>,
    actor: Option<String>,
    post: bool,
    tenant: Option<String>,
    url: Option<String>,
) -> Result<(), DynErr> {
    let path = crate::cost::resolve_transcript(file, session)?;
    let events = transcript::parse_file_capturing(&path)?;
    let session_id = session_id_of(&events, &path);
    let nodes = build_nodes(&events, &session_id);

    let blob_dir = resolve_blob_dir(blob_dir)?;
    let blobs = write_blobs(&nodes, &blob_dir)?;

    let with_answer = nodes.iter().filter(|n| n.answer.is_some()).count();
    println!(
        "observe ingest · {}\n  session   {session_id}\n  turns     {} nodes ({with_answer} with answer, {blobs} with reasoning summary)\n  blobs     {}/reasoning/",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
        nodes.len(),
        blob_dir.display(),
    );

    if post {
        let actor = actor.unwrap_or_else(|| "agent:claude-code-ingest".to_owned());
        let (posted, reasoning_acts) = post_nodes(&nodes, &actor, tenant, url)?;
        println!("  posted    {posted} nodes → daemon observe surface");
        if reasoning_acts > 0 {
            println!("  activity  {reasoning_acts} reasoning entries → activity lane (kind=reasoning)");
        }
    } else {
        println!("  (dry run — pass --post to ship nodes to the daemon)");
    }
    Ok(())
}

fn push_joined(buf: &mut String, text: &str) {
    if text.is_empty() {
        return;
    }
    if !buf.is_empty() {
        buf.push('\n');
    }
    buf.push_str(text);
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push_str(" …[truncated]");
    out
}

fn session_id_of(events: &[Event], path: &Path) -> String {
    events
        .iter()
        .find_map(|e| e.session_id.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("session")
                .to_owned()
        })
}

fn resolve_blob_dir(blob_dir: Option<String>) -> Result<PathBuf, DynErr> {
    if let Some(d) = blob_dir {
        return Ok(PathBuf::from(d));
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not set; pass --blob-dir")?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("cuecrux")
        .join("observe"))
}

/// Post each node to the daemon: `open_step` then `close_step` with the captured
/// answer output + reasoning_ref. Additionally surfaces each reasoning summary
/// as a `kind=reasoning` activity entry (M3, so the console renders category 3
/// — best-effort: a disabled activity log never fails the observe ingest).
/// Returns `(observe_nodes_posted, reasoning_activity_entries_posted)`.
fn post_nodes(
    nodes: &[IngestNode],
    actor: &str,
    tenant: Option<String>,
    url: Option<String>,
) -> Result<(usize, usize), DynErr> {
    let http_url = resolve_daemon(url)?;
    // Observe routes are scope-gated (not tenant-scoped); the activity lane IS
    // tenant-scoped, so the reasoning entries use the passed tenant (or default).
    let activity_tenant = tenant.unwrap_or_else(|| "default".to_string());
    let bearer = login::resolve_fresh_bearer(&http_url)?;
    let ts = now_rfc3339();
    let mut posted = 0;
    let mut reasoning_acts = 0;
    for node in nodes {
        let open = serde_json::json!({
            "node_id": node.node_id,
            "label": format!("ingested turn {}", node.node_id),
            "actor": actor,
            "ts_start": ts,
            "private": true,
            "inputs": [],
        });
        send(
            &http_url,
            bearer.as_deref(),
            "POST",
            &format!("/v1/observe/sessions/{}/steps", node.session_id),
            &open,
        )?;

        let mut outputs = Vec::new();
        if let Some(answer) = &node.answer {
            outputs.push(serde_json::json!({ "type": "answer", "ref": answer }));
        }
        let mut close = serde_json::json!({
            "outputs": outputs,
            "status": "ok",
            "ts_end": ts,
        });
        if let Some(rref) = &node.reasoning_ref {
            close["reasoning_ref"] = serde_json::Value::String(rref.clone());
        }
        send(
            &http_url,
            bearer.as_deref(),
            "PATCH",
            &format!("/v1/observe/sessions/{}/steps/{}", node.session_id, node.node_id),
            &close,
        )?;
        posted += 1;

        // M3 — surface the honest extractive reasoning summary as a
        // `kind=reasoning` activity entry (private, cross-walked to its blob via
        // event_ids). Best-effort so a daemon without the activity log enabled
        // (404) doesn't fail the observe ingest.
        if let Some(act) = reasoning_activity_body(node, &activity_tenant) {
            if post_activity_best_effort(&http_url, bearer.as_deref(), &act) {
                reasoning_acts += 1;
            }
        }
    }
    Ok((posted, reasoning_acts))
}

/// Build the `kind=reasoning` activity body for a node, or `None` when the node
/// carried no reasoning summary. Private, cross-walked to the reasoning blob via
/// `refs.event_ids`, joined to the observe step by `turn_id = node_id`.
fn reasoning_activity_body(node: &IngestNode, tenant: &str) -> Option<serde_json::Value> {
    let summary = node.reasoning_summary.as_ref()?;
    Some(serde_json::json!({
        "tenant_id": tenant,
        "session_id": node.session_id,
        "turn_id": node.node_id,
        "kind": "reasoning",
        "text": summary,
        "meta": { "intent": "reasoning" },
        "refs": { "event_ids": node.reasoning_ref.clone().into_iter().collect::<Vec<_>>() },
        "private": true,
    }))
}

/// POST a `kind=reasoning` entry to `/v1/activity`. Returns `true` on a 2xx;
/// any non-2xx (incl. 404 when the activity log is disabled) is swallowed so
/// reasoning-surfacing never breaks the observe ingest.
fn post_activity_best_effort(http_url: &str, bearer: Option<&str>, body: &serde_json::Value) -> bool {
    let url = format!("{http_url}/v1/activity");
    let mut req = agent().post(&url).header("content-type", "application/json");
    match bearer {
        Some(t) => req = req.header("authorization", format!("Bearer {t}")),
        None => req = req.header("x-corecrux-scopes", "facts:write"),
    }
    matches!(req.send_json(body.clone()), Ok(resp) if resp.status().as_u16() < 300)
}

fn send(
    http_url: &str,
    bearer: Option<&str>,
    method: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<(), DynErr> {
    let url = format!("{http_url}{path}");
    let mut req = match method {
        "PATCH" => agent().patch(&url),
        _ => agent().post(&url),
    }
    .header("content-type", "application/json");
    match bearer {
        Some(t) => req = req.header("authorization", format!("Bearer {t}")),
        None => req = req.header("x-corecrux-scopes", "facts:write"),
    }
    match req.send_json(body.clone()) {
        Ok(resp) if resp.status().as_u16() < 300 => Ok(()),
        Ok(resp) => {
            let s = resp.status().as_u16();
            if s == 501 {
                return Err(
                    format!("observe surface disabled (HTTP 501) — set CORECRUXD_OBSERVE=1 on {http_url}").into(),
                );
            }
            Err(format!(
                "observe {method} {path} failed (HTTP {s}): {}",
                resp.into_body().read_to_string().unwrap_or_default()
            )
            .into())
        }
        Err(ureq::Error::StatusCode(code)) => Err(format!("observe {method} {path} failed (HTTP {code})").into()),
        Err(other) => Err(Box::new(other)),
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A 2-turn transcript: turn 1 has substantial thinking + a text answer;
    /// turn 2 has only a tiny thought + a tool call (no prose).
    fn fixture() -> Vec<Event> {
        let big_thinking = "Let me weigh the options for the parser. \
            The problem is the offset is off by one because we skipped the header row. \
            A lot of narration here that is pure middle filler and adds nothing. \
            Even more narration that pads the reasoning out without substance. \
            Therefore I will add one to the index and re-run."
            .to_string();
        let lines = [
            format!(
                r#"{{"type":"assistant","sessionId":"abcdef123456","message":{{"role":"assistant","content":[{{"type":"thinking","thinking":{}}},{{"type":"text","text":"I'll fix the off-by-one in the parser."}}]}}}}"#,
                serde_json::to_string(&big_thinking).unwrap()
            ),
            r#"{"type":"assistant","sessionId":"abcdef123456","message":{"role":"assistant","content":[{"type":"thinking","thinking":"quick"},{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}]}}"#.to_string(),
        ];
        transcript::parse_str_capturing(&lines.join("\n"))
    }

    #[test]
    fn reasoning_activity_body_shape_and_skip() {
        let nodes = build_nodes(&fixture(), "abcdef123456");
        let n = &nodes[0];
        // M3: a node with a reasoning summary yields a private kind=reasoning
        // activity body cross-walked to its blob.
        let body = reasoning_activity_body(n, "acme").expect("reasoning body");
        assert_eq!(body["kind"], "reasoning");
        assert_eq!(body["tenant_id"], "acme");
        assert_eq!(body["session_id"], "abcdef123456");
        assert_eq!(body["turn_id"], "ingest_abcdef12_1");
        assert_eq!(body["private"], true);
        assert_eq!(body["meta"]["intent"], "reasoning");
        assert_eq!(body["refs"]["event_ids"][0], "blob:reasoning/ingest_abcdef12_1.txt");
        assert!(body["text"].as_str().is_some_and(|t| !t.is_empty()));

        // A node with no reasoning summary produces no activity body.
        let bare = IngestNode {
            node_id: "n0".into(),
            session_id: "s".into(),
            answer: Some("a".into()),
            reasoning_summary: None,
            reasoning_ref: None,
        };
        assert!(reasoning_activity_body(&bare, "acme").is_none());
    }

    #[test]
    fn captures_answer_and_reasoning_with_r1_guard() {
        let nodes = build_nodes(&fixture(), "abcdef123456");
        // Turn 1 yields a node (answer + reasoning); turn 2 is tool-only with a
        // sub-threshold thought → no node.
        assert_eq!(nodes.len(), 1, "only the substantive turn should produce a node");
        let n = &nodes[0];
        assert_eq!(n.node_id, "ingest_abcdef12_1");
        // Answer captured.
        assert_eq!(n.answer.as_deref(), Some("I'll fix the off-by-one in the parser."));
        // Reasoning summary present + ref points at the blob.
        let summary = n.reasoning_summary.as_ref().expect("summary");
        assert_eq!(n.reasoning_ref.as_deref(), Some("blob:reasoning/ingest_abcdef12_1.txt"));
        // R1: the summary is a strict compression; it must NOT be the raw thinking.
        assert!(!summary.contains("pure middle filler"), "filler must be dropped");
        assert!(summary.contains("off by one") || summary.contains("offset is off"));
        assert!(summary.contains("add one to the index"));
    }

    #[test]
    fn thinking_off_yields_no_reasoning_ref() {
        // An assistant turn with only a text answer, no thinking.
        let events = transcript::parse_str_capturing(
            r#"{"type":"assistant","sessionId":"s1","message":{"role":"assistant","content":[{"type":"text","text":"Done."}]}}"#,
        );
        let nodes = build_nodes(&events, "s1");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].answer.as_deref(), Some("Done."));
        // No dangling pointer when there's no reasoning.
        assert!(nodes[0].reasoning_ref.is_none());
        assert!(nodes[0].reasoning_summary.is_none());
    }

    #[test]
    fn write_blobs_resolves_summary_shorter_than_raw() {
        let events = fixture();
        let nodes = build_nodes(&events, "abcdef123456");
        let dir = std::env::temp_dir().join(format!("crux-ingest-{}", uuid::Uuid::new_v4()));
        let n = write_blobs(&nodes, &dir).unwrap();
        assert_eq!(n, 1);
        let blob = dir.join("reasoning").join("ingest_abcdef12_1.txt");
        let content = std::fs::read_to_string(&blob).expect("blob written");
        // Resolves to the summary; never byte-equal to the raw thinking.
        assert_eq!(content, nodes[0].reasoning_summary.clone().unwrap());
        assert!(!content.contains("pure middle filler"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nodes_are_private_and_answer_truncates() {
        let long = "x".repeat(5000);
        let events = transcript::parse_str_capturing(&format!(
            r#"{{"type":"assistant","sessionId":"s","message":{{"role":"assistant","content":[{{"type":"text","text":"{long}"}}]}}}}"#
        ));
        let nodes = build_nodes(&events, "s");
        assert_eq!(nodes.len(), 1);
        let ans = nodes[0].answer.as_ref().unwrap();
        assert!(ans.chars().count() <= MAX_ANSWER_CHARS + 16, "answer must be truncated");
        assert!(ans.ends_with("…[truncated]"));
    }
}
