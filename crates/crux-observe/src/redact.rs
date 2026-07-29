// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Log & ops-fact redaction core (ExecPlan `crux-log-redaction-2026-06-11`).
//!
//! One [`Redactor`] implementation applied at every sink boundary: stderr/stdout
//! fmt + JSON log output (via the `redact_writer` MakeWriter wrapper), the
//! `OpsObserveLayer` fact path, and the MCP parse-error echo.
//!
//! Three matching planes:
//! 1. **Field-name matching** (case-insensitive): an explicit allowlist
//!    (`token_budget`-class telemetry) is checked first, then an exact
//!    denylist hash-set hit, then a keyword substring scan.
//! 2. **Value-pattern matching** for high-confidence secret shapes (JWT,
//!    `sk-…`, `ghp_…`, AWS `AKIA…`, PEM private-key blocks).
//! 3. **Line scanning** (`key=value` / `"key": "value"`) for formatted log
//!    lines where field structure is no longer available.
//!
//! Replacement is `[REDACTED:<rule>#<blake3-8>]` — the 8-char BLAKE3 prefix
//! keeps two occurrences of the same secret correlatable without disclosure.
//! The `#` separator (never `=`/`:`) makes markers inert under re-scanning,
//! so redaction is idempotent.
//!
//! Modes (`CORECRUXD_REDACT=on|off|audit`, default `audit`):
//! - `off`   — no scanning at all (zero overhead).
//! - `audit` — scan + count per-rule hits, but never alter output (for
//!   sidecar soak / false-positive tuning before the M4 enforce-flip).
//! - `on`    — scan, count, and redact.
//!
//! ## Limits (audit-v2 L3 — best-effort, not a guarantee)
//!
//! Redaction is **pattern- and keyword-based best-effort**, not a cryptographic
//! guarantee. It catches known secret *shapes* (JWT, `sk-…`, `ghp_…`, AWS
//! `AKIA…`, PEM blocks) and known *field/key names*. A **high-entropy custom
//! secret with no recognizable prefix, keyword, or field name is NOT redacted**
//! and passes through into the (append-only, non-rewritable) log/receipt chain.
//! Do not rely on this layer as the sole control for novel secret formats.
//!
//! **Operator mitigation:** add site-specific value patterns via
//! `CORECRUXD_REDACT_EXTRA_PATTERNS` — `;;`-separated `id=regex` entries, e.g.
//! `CORECRUXD_REDACT_EXTRA_PATTERNS='myco=MYCO-[0-9]{6};;legacy=LK_[a-f0-9]{32}'`.
//! Each becomes an `xtra.<id>` rule applied alongside the built-ins, no code
//! change or redeploy of the binary required. Invalid regexes are logged and
//! skipped (they never disable the built-in rules).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use regex::Regex;

/// Redaction mode, parsed from `CORECRUXD_REDACT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactMode {
    /// No scanning at all.
    Off,
    /// Scan and count rule hits, but do not alter output (default).
    Audit,
    /// Scan, count, and redact.
    On,
}

impl RedactMode {
    /// Parse from the `CORECRUXD_REDACT` env var. Default: `Audit`.
    pub fn from_env() -> Self {
        match std::env::var("CORECRUXD_REDACT") {
            Ok(v) => Self::parse(&v),
            Err(_) => Self::Audit,
        }
    }

    /// Parse a mode string (case-insensitive). Unknown values fall back to
    /// `Audit` — fail-safe towards observation, never towards silent `Off`.
    pub fn parse(v: &str) -> Self {
        match v.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "false" | "disabled" => Self::Off,
            "on" | "1" | "true" | "enforce" => Self::On,
            _ => Self::Audit,
        }
    }
}

/// A compiled value-pattern rule.
struct ValueRule {
    id: String,
    regex: Regex,
}

/// Field-name keywords (case-insensitive substring match) that mark a field
/// as secret-bearing unless the exact name is allowlisted.
const FIELD_KEYWORDS: [&str; 12] = [
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "auth",
    "jwt",
    "bearer",
    "credential",
    "private_key",
    "cookie",
];

/// Exact field names that must never be redacted even though they contain a
/// denylist keyword. The workspace's `token_budget` telemetry depends on this.
const FIELD_ALLOWLIST: [&str; 18] = [
    "token_budget",
    "tokens",
    "token_count",
    "token_estimate",
    "tokens_used",
    "max_tokens",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "est_tokens",
    "prompt_tokens",
    "completion_tokens",
    "cache_read_tokens",
    "cache_creation_tokens",
    "auth_mode",
    "jwt_auth_mode",
    "author",
    "authors",
];

/// Minimum string length before value-pattern regexes run (perf gate).
const VALUE_SCAN_MIN_LEN: usize = 9;

/// Maximum echoed-fragment length for error scrubbing (MCP parse errors).
pub const ERROR_ECHO_MAX_CHARS: usize = 256;

fn builtin_value_rules() -> Vec<ValueRule> {
    // SAFETY: all patterns are static literals validated by unit tests; a
    // failure here is a programmer error caught at first test run.
    #[allow(clippy::expect_used)]
    let rule = |id: &str, pat: &str| ValueRule {
        id: id.to_string(),
        regex: Regex::new(pat).expect("builtin redaction regex must compile"),
    };
    vec![
        // PEM first so its base64 body is consumed before other rules see it.
        rule(
            "pem",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[A-Za-z0-9+/=\r\n]+-----END [A-Z ]*PRIVATE KEY-----)?",
        ),
        rule("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"),
        rule("sk", r"\bsk-[A-Za-z0-9_-]{16,}"),
        rule("ghp", r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
        rule("aws", r"\bAKIA[0-9A-Z]{16}\b"),
    ]
}

/// Parse `CORECRUXD_REDACT_EXTRA_PATTERNS`: `;;`-separated `id=regex` entries.
fn parse_extra_patterns(raw: &str) -> Vec<ValueRule> {
    let mut rules = Vec::new();
    for entry in raw.split(";;") {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((id, pat)) = entry.split_once('=') else {
            continue;
        };
        let id = id.trim();
        if id.is_empty() {
            continue;
        }
        match Regex::new(pat) {
            Ok(regex) => {
                rules.push(ValueRule {
                    id: format!("xtra.{id}"),
                    regex,
                });
            }
            Err(err) => {
                tracing::warn!(rule = %id, error = %err, "ignoring invalid CORECRUXD_REDACT_EXTRA_PATTERNS entry");
            }
        }
    }
    rules
}

/// Hook invoked once per rule hit (e.g. to increment a Prometheus counter).
pub type RedactionHook = Arc<dyn Fn(&str) + Send + Sync>;

/// The redactor: field denylist/allowlist + compiled value rules + counters.
pub struct Redactor {
    mode: RedactMode,
    allow: HashSet<&'static str>,
    deny_exact: HashSet<&'static str>,
    value_rules: Vec<ValueRule>,
    /// `key[=:]value` scanner for formatted lines.
    line_kv: Regex,
    counters: Mutex<HashMap<String, u64>>,
    hook: Option<RedactionHook>,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("mode", &self.mode)
            .field("value_rules", &self.value_rules.len())
            .finish_non_exhaustive()
    }
}

impl Redactor {
    /// Build with an explicit mode and no extra patterns.
    pub fn with_mode(mode: RedactMode) -> Self {
        Self::build(mode, Vec::new(), None)
    }

    /// Build from `CORECRUXD_REDACT` + `CORECRUXD_REDACT_EXTRA_PATTERNS`.
    pub fn from_env() -> Self {
        let extras = std::env::var("CORECRUXD_REDACT_EXTRA_PATTERNS").unwrap_or_default();
        Self::build(RedactMode::from_env(), parse_extra_patterns(&extras), None)
    }

    /// Build from env with a counter hook installed.
    pub fn from_env_with_hook(hook: RedactionHook) -> Self {
        let extras = std::env::var("CORECRUXD_REDACT_EXTRA_PATTERNS").unwrap_or_default();
        Self::build(RedactMode::from_env(), parse_extra_patterns(&extras), Some(hook))
    }

    fn build(mode: RedactMode, extras: Vec<ValueRule>, hook: Option<RedactionHook>) -> Self {
        let mut value_rules = builtin_value_rules();
        value_rules.extend(extras);
        // key (optionally quoted) [=:] value (quoted | bearer <tok> | bare).
        // SAFETY: static pattern, validated by unit tests.
        #[allow(clippy::expect_used)]
        let line_kv = Regex::new(
            r#"(?i)([A-Za-z0-9_.]*(?:secret|token|password|passwd|api_?key|auth|jwt|bearer|credential|private_key|cookie)[A-Za-z0-9_.]*)["']?\s*[=:]\s*("(?:[^"\\]|\\.)*"|'[^']*'|bearer\s+[^\s,;)}\]"']+|[^\s,;)}\]"']+)"#,
        )
        .expect("line kv redaction regex must compile");
        Self {
            mode,
            allow: FIELD_ALLOWLIST.iter().copied().collect(),
            deny_exact: FIELD_KEYWORDS.iter().copied().collect(),
            value_rules,
            line_kv,
            counters: Mutex::new(HashMap::new()),
            hook,
        }
    }

    /// Build with explicit extra `(id, regex)` patterns (test/bench helper).
    pub fn with_mode_and_extras(mode: RedactMode, extras: &[(String, String)]) -> Self {
        let joined = extras
            .iter()
            .map(|(id, pat)| format!("{id}={pat}"))
            .collect::<Vec<_>>()
            .join(";;");
        Self::build(mode, parse_extra_patterns(&joined), None)
    }

    /// Install a per-hit hook (call before sharing the redactor).
    pub fn set_hook(&mut self, hook: RedactionHook) {
        self.hook = Some(hook);
    }

    /// Current mode.
    pub fn mode(&self) -> RedactMode {
        self.mode
    }

    /// Snapshot of per-rule hit counts (rule id → count).
    pub fn counts(&self) -> Vec<(String, u64)> {
        // SAFETY: mutex poisoning implies a prior panic; propagating is correct.
        #[allow(clippy::unwrap_used)]
        let map = self.counters.lock().unwrap();
        let mut v: Vec<(String, u64)> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort();
        v
    }

    fn record_hit(&self, rule: &str) {
        // SAFETY: mutex poisoning implies a prior panic; propagating is correct.
        #[allow(clippy::unwrap_used)]
        {
            *self.counters.lock().unwrap().entry(rule.to_string()).or_insert(0) += 1;
        }
        if let Some(hook) = &self.hook {
            hook(rule);
        }
    }

    /// Which field keyword (if any) marks this field name as secret-bearing.
    /// Allowlist wins. Returns the matched keyword.
    fn field_rule(&self, name_lc: &str) -> Option<&'static str> {
        if self.allow.contains(name_lc) {
            return None;
        }
        if let Some(kw) = self.deny_exact.get(name_lc) {
            return Some(*kw);
        }
        FIELD_KEYWORDS.iter().copied().find(|kw| name_lc.contains(kw))
    }

    /// Redact a structured field (name + string value).
    ///
    /// Denylisted field names get their whole value replaced; otherwise the
    /// value is scanned with the value-pattern rules.
    pub fn redact_field<'a>(&self, name: &str, value: &'a str) -> Cow<'a, str> {
        if self.mode == RedactMode::Off {
            return Cow::Borrowed(value);
        }
        let name_lc = name.to_ascii_lowercase();
        if let Some(kw) = self.field_rule(&name_lc) {
            if is_marker(value) {
                return Cow::Borrowed(value); // idempotence
            }
            let rule = format!("fld.{kw}");
            self.record_hit(&rule);
            if self.mode == RedactMode::Audit {
                return Cow::Borrowed(value);
            }
            return Cow::Owned(marker(&rule, value));
        }
        self.redact_value(value)
    }

    /// Scan a bare value (or message) with the value-pattern rules only.
    pub fn redact_value<'a>(&self, value: &'a str) -> Cow<'a, str> {
        if self.mode == RedactMode::Off || value.len() < VALUE_SCAN_MIN_LEN {
            return Cow::Borrowed(value);
        }
        let mut out = Cow::Borrowed(value);
        for rule in &self.value_rules {
            if !rule.regex.is_match(&out) {
                continue;
            }
            if self.mode == RedactMode::Audit {
                for _ in rule.regex.find_iter(&out) {
                    self.record_hit(&rule.id);
                }
                continue;
            }
            let replaced = rule
                .regex
                .replace_all(&out, |caps: &regex::Captures<'_>| {
                    self.record_hit(&rule.id);
                    marker(&rule.id, &caps[0])
                })
                .into_owned();
            out = Cow::Owned(replaced);
        }
        out
    }

    /// Redact a formatted log line: `key=value` / `"key": "value"` pairs with
    /// denylisted keys, then value-pattern rules over the remainder.
    pub fn redact_line<'a>(&self, line: &'a str) -> Cow<'a, str> {
        if self.mode == RedactMode::Off {
            return Cow::Borrowed(line);
        }
        let kv_pass = self.redact_line_kv(line);
        match kv_pass {
            Cow::Borrowed(s) => self.redact_value(s),
            Cow::Owned(s) => match self.redact_value(&s) {
                Cow::Borrowed(_) => Cow::Owned(s),
                Cow::Owned(o) => Cow::Owned(o),
            },
        }
    }

    fn redact_line_kv<'a>(&self, line: &'a str) -> Cow<'a, str> {
        if !self.line_kv.is_match(line) {
            return Cow::Borrowed(line);
        }
        let mut out = String::with_capacity(line.len());
        let mut last = 0usize;
        for caps in self.line_kv.captures_iter(line) {
            // SAFETY: groups 1 and 2 are non-optional in the pattern.
            #[allow(clippy::unwrap_used)]
            let (key, value) = (caps.get(1).unwrap(), caps.get(2).unwrap());
            let key_lc = key.as_str().to_ascii_lowercase();
            let Some(kw) = self.field_rule(&key_lc) else {
                continue; // allowlisted (e.g. token_budget=500) — untouched
            };
            let raw = value.as_str();
            let (quote, inner) = strip_quotes(raw);
            if is_marker(inner) {
                continue; // idempotence
            }
            let rule = format!("fld.{kw}");
            self.record_hit(&rule);
            if self.mode == RedactMode::Audit {
                continue;
            }
            out.push_str(&line[last..value.start()]);
            let m = marker(&rule, inner);
            match quote {
                Some(q) => {
                    out.push(q);
                    out.push_str(&m);
                    out.push(q);
                }
                None => out.push_str(&m),
            }
            last = value.end();
        }
        if last == 0 {
            return Cow::Borrowed(line); // audit mode or all matches skipped
        }
        out.push_str(&line[last..]);
        Cow::Owned(out)
    }

    /// Scrub an error string that may echo request-body fragments: truncate
    /// to [`ERROR_ECHO_MAX_CHARS`] then apply line redaction.
    pub fn scrub_error_echo(&self, err: &str) -> String {
        let truncated: String = if err.chars().count() > ERROR_ECHO_MAX_CHARS {
            let mut s: String = err.chars().take(ERROR_ECHO_MAX_CHARS).collect();
            s.push_str("…[truncated]");
            s
        } else {
            err.to_string()
        };
        self.redact_line(&truncated).into_owned()
    }
}

/// Replacement marker. `#` (never `=`/`:`) separates rule from hash so the
/// marker itself can never re-trigger the kv scanner — idempotence by shape.
fn marker(rule: &str, secret: &str) -> String {
    let hash = blake3::hash(secret.as_bytes()).to_hex();
    format!("[REDACTED:{rule}#{}]", &hash.as_str()[..8])
}

fn is_marker(value: &str) -> bool {
    // The "[REDACTED:" prefix can only have been produced by this module —
    // bare-value captures may stop before the closing `]`, so prefix is enough.
    value.starts_with("[REDACTED:")
}

fn strip_quotes(raw: &str) -> (Option<char>, &str) {
    let b = raw.as_bytes();
    if b.len() >= 2 {
        let (first, last) = (b[0], b[b.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return (Some(first as char), &raw[1..raw.len() - 1]);
        }
    }
    (None, raw)
}

/// Process-global shared redactor. `set_global` (daemon: installs the hooked
/// instance) must run before the first `global()` call to take effect; later
/// callers (e.g. crux-mcp) get whatever is installed, else a from-env default.
static GLOBAL_REDACTOR: OnceLock<Arc<Redactor>> = OnceLock::new();

/// Install the process-global redactor. Returns `false` if one was already set.
pub fn set_global(redactor: Arc<Redactor>) -> bool {
    GLOBAL_REDACTOR.set(redactor).is_ok()
}

/// Get the process-global redactor, initialising from env on first use.
pub fn global() -> &'static Arc<Redactor> {
    GLOBAL_REDACTOR.get_or_init(|| Arc::new(Redactor::from_env()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── fixtures: SYNTHETIC secrets only (clearly marked, never real) ──
    const FIX_JWT: &str = "eyJfixtureSYNTHETICheader00.eyJfixturePayload00.fixtureSigSYNTHETIC";
    const FIX_SK: &str = "sk-fixtureSYNTHETIC0000000000";
    const FIX_GHP: &str = "ghp_fixtureSYNTHETIC0123456789";
    const FIX_AWS: &str = "AKIAFIXTURESYNTH0000";
    const FIX_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nZml4dHVyZQ==\n-----END RSA PRIVATE KEY-----";

    fn on() -> Redactor {
        Redactor::with_mode(RedactMode::On)
    }

    #[test]
    fn mode_parse() {
        assert_eq!(RedactMode::parse("on"), RedactMode::On);
        assert_eq!(RedactMode::parse("OFF"), RedactMode::Off);
        assert_eq!(RedactMode::parse("audit"), RedactMode::Audit);
        assert_eq!(
            RedactMode::parse("bogus"),
            RedactMode::Audit,
            "unknown → audit, fail-safe"
        );
    }

    #[test]
    fn value_rule_jwt() {
        let r = on();
        let out = r.redact_value(FIX_JWT);
        assert!(out.contains("[REDACTED:jwt#"), "got: {out}");
        assert!(!out.contains("eyJfixture"));
    }

    #[test]
    fn value_rule_sk_key() {
        let r = on();
        let input = format!("calling with {FIX_SK} now");
        let out = r.redact_value(&input);
        assert!(out.contains("[REDACTED:sk#"), "got: {out}");
        assert!(!out.contains(FIX_SK));
    }

    #[test]
    fn value_rule_github_token() {
        let r = on();
        let out = r.redact_value(FIX_GHP);
        assert!(out.contains("[REDACTED:ghp#"), "got: {out}");
        assert!(!out.contains(FIX_GHP));
    }

    #[test]
    fn value_rule_aws_key() {
        let r = on();
        let input = format!("key id {FIX_AWS}.");
        let out = r.redact_value(&input);
        assert!(out.contains("[REDACTED:aws#"), "got: {out}");
        assert!(!out.contains(FIX_AWS));
    }

    #[test]
    fn value_rule_pem_block_and_header_only() {
        let r = on();
        let out = r.redact_value(FIX_PEM);
        assert!(out.contains("[REDACTED:pem#"), "got: {out}");
        assert!(!out.contains("Zml4dHVyZQ"));
        // Truncated PEM (header only) still hits.
        let out2 = r.redact_value("-----BEGIN PRIVATE KEY-----");
        assert!(out2.contains("[REDACTED:pem#"), "got: {out2}");
    }

    #[test]
    fn field_denylist_exact_and_compound() {
        let r = on();
        for name in [
            "password",
            "PASSWORD",
            "db_password",
            "x_api_key",
            "client.secret",
            "session_token",
        ] {
            let out = r.redact_field(name, "fixture-hunter2-SYNTHETIC");
            assert!(out.starts_with("[REDACTED:fld."), "{name} → {out}");
            assert!(!out.contains("hunter2"), "{name} leaked: {out}");
        }
    }

    #[test]
    fn field_allowlist_never_redacted() {
        let r = on();
        for (name, val) in [
            ("token_budget", "500"),
            ("tokens", "12345"),
            ("auth_mode", "jwt_hs256"),
            ("author", "myles"),
            ("max_tokens", "4096"),
            ("output_tokens", "222"),
        ] {
            assert_eq!(r.redact_field(name, val), val, "allowlisted {name} must pass through");
        }
    }

    #[test]
    fn non_matching_field_untouched() {
        let r = on();
        assert_eq!(r.redact_field("request_id", "abc-123"), "abc-123");
        assert_eq!(r.redact_field("message", "all good here"), "all good here");
    }

    #[test]
    fn unicode_values_safe() {
        let r = on();
        let v = "пароль-фикстура-✓-SYNTHETIC";
        let out = r.redact_field("password", v);
        assert!(out.starts_with("[REDACTED:fld.password#"));
        // Non-secret unicode passes through value scan unharmed.
        assert_eq!(r.redact_value("héllo wörld — naïve café"), "héllo wörld — naïve café");
    }

    #[test]
    fn idempotence_double_redaction_safe() {
        let r = on();
        let once = r.redact_field("api_key", FIX_SK).into_owned();
        let twice = r.redact_field("api_key", &once).into_owned();
        assert_eq!(once, twice, "field redaction must be idempotent");

        let line = format!("WARN auth failed password=fixture-pw-SYNTHETIC jwt={FIX_JWT}");
        let l1 = r.redact_line(&line).into_owned();
        let l2 = r.redact_line(&l1).into_owned();
        assert_eq!(l1, l2, "line redaction must be idempotent: {l1} vs {l2}");

        let v1 = r.redact_value(FIX_JWT).into_owned();
        let v2 = r.redact_value(&v1).into_owned();
        assert_eq!(v1, v2, "value redaction must be idempotent");
    }

    #[test]
    fn marker_correlation() {
        let r = on();
        let a1 = r.redact_field("secret", "fixture-same-SYNTHETIC").into_owned();
        let a2 = r.redact_field("secret", "fixture-same-SYNTHETIC").into_owned();
        let b = r.redact_field("secret", "fixture-other-SYNTHETIC").into_owned();
        assert_eq!(a1, a2, "same secret → same marker");
        assert_ne!(a1, b, "different secrets → different markers");
    }

    #[test]
    fn line_redaction_text_format() {
        let r = on();
        let line = format!("2026-06-11T00:00:00Z WARN corecruxd: upstream call failed api_key={FIX_SK} attempt=3");
        let out = r.redact_line(&line);
        assert!(!out.contains(FIX_SK), "got: {out}");
        assert!(out.contains("[REDACTED:fld.api_key#"), "got: {out}");
        assert!(out.contains("attempt=3"), "non-secret fields preserved: {out}");
    }

    #[test]
    fn line_redaction_json_format() {
        let r = on();
        let line = format!(
            r#"{{"level":"WARN","fields":{{"password":"fixture-pw-SYNTHETIC","attempt":3}},"jwt":"{FIX_JWT}"}}"#
        );
        let out = r.redact_line(&line);
        assert!(!out.contains("fixture-pw-SYNTHETIC"), "got: {out}");
        assert!(!out.contains(FIX_JWT), "got: {out}");
        assert!(out.contains(r#""attempt":3"#), "got: {out}");
        // Quoted values keep their quotes (JSON stays parseable).
        assert!(out.contains(r#""password":"[REDACTED:fld.password#"#), "got: {out}");
    }

    #[test]
    fn line_redaction_bearer_header() {
        let r = on();
        let out = r.redact_line("request denied authorization=Bearer fixture-SYNTHETIC-tok-123456");
        assert!(!out.contains("fixture-SYNTHETIC-tok"), "got: {out}");
        assert!(out.contains("[REDACTED:fld.auth"), "got: {out}");
    }

    #[test]
    fn line_token_budget_telemetry_untouched() {
        let r = on();
        let line = "INFO query done token_budget=500 tokens=1234 auth_mode=jwt_hs256";
        assert_eq!(
            r.redact_line(line),
            line,
            "allowlisted telemetry must survive line scan"
        );
    }

    #[test]
    fn snapshot_non_matching_line_unchanged() {
        let r = on();
        let line = "2026-06-11T00:00:00Z INFO corecruxd: segment seal complete frames=4096 duration_ms=18 tenant=lme-s shard=2";
        let out = r.redact_line(line);
        assert!(
            matches!(out, Cow::Borrowed(_)),
            "non-matching line must be borrowed (zero-copy)"
        );
        assert_eq!(out, line);
    }

    #[test]
    fn off_mode_zero_touch() {
        let r = Redactor::with_mode(RedactMode::Off);
        assert_eq!(r.redact_field("password", "fixture-pw"), "fixture-pw");
        assert_eq!(r.redact_value(FIX_JWT), FIX_JWT);
        assert_eq!(r.redact_line("password=fixture-pw"), "password=fixture-pw");
        assert!(r.counts().is_empty());
    }

    #[test]
    fn audit_mode_counts_without_redacting() {
        let r = Redactor::with_mode(RedactMode::Audit);
        assert_eq!(
            r.redact_field("password", "fixture-pw-SYNTHETIC"),
            "fixture-pw-SYNTHETIC"
        );
        assert_eq!(r.redact_value(FIX_JWT), FIX_JWT);
        let line = format!("api_key={FIX_SK}");
        assert_eq!(r.redact_line(&line), line);
        let counts = r.counts();
        let total: u64 = counts.iter().map(|(_, c)| *c).sum();
        assert!(total >= 3, "audit mode must count hits: {counts:?}");
        assert!(counts.iter().any(|(k, _)| k == "fld.password"));
        assert!(counts.iter().any(|(k, _)| k == "jwt"));
    }

    #[test]
    fn hook_fires_per_hit() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let hits = Arc::new(AtomicU64::new(0));
        let h2 = Arc::clone(&hits);
        let mut r = Redactor::with_mode(RedactMode::On);
        r.set_hook(Arc::new(move |_rule| {
            h2.fetch_add(1, Ordering::Relaxed);
        }));
        let _ = r.redact_field("password", "fixture-pw-SYNTHETIC");
        let _ = r.redact_value(FIX_JWT);
        assert_eq!(hits.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn extra_patterns_parse_and_match() {
        let extras = vec![("crx".to_string(), r"crx_fix_[a-z0-9]{8,}".to_string())];
        let r = Redactor::with_mode_and_extras(RedactMode::On, &extras);
        let out = r.redact_value("found crx_fix_synthetic01 in flight");
        assert!(out.contains("[REDACTED:xtra.crx#"), "got: {out}");
        assert!(!out.contains("crx_fix_synthetic01"));
    }

    #[test]
    fn extra_patterns_invalid_regex_skipped() {
        let rules = parse_extra_patterns("bad=[unclosed;;good=fixture_[0-9]{4}");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "xtra.good");
    }

    #[test]
    fn documented_limit_high_entropy_secret_without_shape_passes_through() {
        // L3 limit made executable: a high-entropy secret with no known prefix,
        // keyword, or field-name shape is NOT redacted by the built-in rules.
        // This is the documented best-effort boundary (see module docs).
        let r = on();
        let opaque = "Zx9Q2m7Kd4Rf8Wp1Nb6Vy3Ht0Lc5Ju"; // 31 random-looking chars, no shape
        assert_eq!(
            r.redact_value(opaque),
            opaque,
            "unshaped secret is not caught by built-ins"
        );

        // ...and the operator mitigation closes exactly that gap without a redeploy:
        let extras = vec![("opaque".to_string(), r"Zx9Q2m7Kd4Rf8Wp1Nb6Vy3Ht0Lc5Ju".to_string())];
        let r2 = Redactor::with_mode_and_extras(RedactMode::On, &extras);
        assert!(
            r2.redact_value(opaque).contains("[REDACTED:xtra.opaque#"),
            "a custom pattern redacts the previously-unshaped secret"
        );
    }

    #[test]
    fn scrub_error_echo_truncates_and_redacts() {
        let r = on();
        let long_tail = "x".repeat(400);
        let err = format!("invalid type: string \"{FIX_SK}\" {long_tail}");
        let out = r.scrub_error_echo(&err);
        assert!(!out.contains(FIX_SK), "got: {out}");
        assert!(
            out.chars().count() < 300,
            "must truncate: {} chars",
            out.chars().count()
        );
        assert!(out.contains("[truncated]"));
    }

    // ── bench (M1 gate): p99 per-event overhead < 20µs ──
    // Run: cargo test -p crux-observe --release -- --ignored bench_redact_p99 --nocapture
    #[test]
    #[ignore = "perf bench — run explicitly in release mode"]
    fn bench_redact_p99() {
        let r = on();
        let clean = "2026-06-11T00:00:00Z INFO corecruxd: append complete stream=projections frames=128 duration_ms=4 tenant=lme-s";
        let hot = format!(
            "2026-06-11T00:00:00Z WARN corecruxd: upstream auth failed api_key={FIX_SK} jwt={FIX_JWT} attempt=3"
        );

        let p99_of = |f: &dyn Fn()| -> (f64, f64) {
            const N: usize = 100_000;
            let mut samples = Vec::with_capacity(N);
            for _ in 0..N {
                let t0 = std::time::Instant::now();
                f();
                samples.push(t0.elapsed().as_nanos() as u64);
            }
            samples.sort_unstable();
            let p50 = samples[N / 2] as f64 / 1000.0;
            let p99 = samples[N * 99 / 100] as f64 / 1000.0;
            (p50, p99)
        };

        let (c50, c99) = p99_of(&|| {
            std::hint::black_box(r.redact_line(std::hint::black_box(clean)));
        });
        let (h50, h99) = p99_of(&|| {
            std::hint::black_box(r.redact_line(std::hint::black_box(&hot)));
        });
        let (f50, f99) = p99_of(&|| {
            std::hint::black_box(r.redact_field(std::hint::black_box("token_budget"), std::hint::black_box("500")));
        });

        println!("bench_redact_p99 (µs): clean_line p50={c50:.2} p99={c99:.2}; secret_line p50={h50:.2} p99={h99:.2}; field_allow p50={f50:.2} p99={f99:.2}");
        assert!(c99 < 20.0, "clean-line p99 {c99:.2}µs >= 20µs budget");
        assert!(h99 < 20.0, "secret-line p99 {h99:.2}µs >= 20µs budget");
        assert!(f99 < 20.0, "field-check p99 {f99:.2}µs >= 20µs budget");
    }
}
