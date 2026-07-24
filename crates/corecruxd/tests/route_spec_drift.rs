// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Contract-drift gate for the daemon HTTP surface (unified-shell-console M2).
//!
//! Three checks, all driven off the source tree at `CARGO_MANIFEST_DIR` — this
//! is an external integration-test crate, so it cannot see `corecruxd`'s
//! internals and instead reads the `.rs` files as text:
//!
//!   1. `route_manifest_matches_router` — the `ROUTES` manifest in
//!      `src/http/openapi.rs` must be set-equal (by `(METHOD, path)`) to the
//!      `.route(...)` calls the router actually mounts. Adding a route without
//!      registering it in the manifest (or leaving a stale manifest row) fails
//!      here. This is the CI drift gate.
//!   2. `generated_api_js_is_in_sync` — `console/v2/api.js` must be byte-equal
//!      to what the generator emits from the manifest (so the checked-in fetch
//!      layer never drifts from the contract).
//!   3. `regen_api_js` (`#[ignore]`) — the writer that (re)generates
//!      `console/v2/api.js`. Run with `-- --ignored regen_api_js`.
//!
//! Route scanning mirrors `src/http/route_auth.rs::parse_routes_in_source`
//! byte-for-byte so this test sees exactly the route set that module already
//! validates for auth coverage.

// `generate_api_js` is a string-builder codegen; `s.push_str(&format!(..))` is
// the established idiom throughout it, so silence the (stylistic) push-string
// lint file-wide rather than scatter `write!` calls through a generator.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::format_push_string)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

// ── Curated gated-mutation allowlist (unified-shell-console M3) ───────────────
//
// The ENTIRE set of write routes the v2 console may call, as
// `(METHOD, path, jsName)`. `generate_api_js()` emits a second, frozen
// `CruxApiGated` object from exactly this list (each method does a
// JSON-body `fetch` with the given verb). Every entry is BOTH operator-posture
// UI-gated (render.js `operatorGatedCall` refuses unless `isOperator()`) AND
// server-side auth-gated (the daemon enforces admin/facts scopes).
//
// Keep this tiny. Adding a row is the *only* way to widen what the console can
// mutate, and it lands as a reviewable diff here + a regenerated `api.js`.
//
// Every row is BOTH operator-posture UI-gated (render.js `operatorGatedCall` +
// the `WIRED_WRITES` harness: bound-passport Art.14 refusal, a confirm dialog on
// the destructive subset, and a real-receipt render) AND server-side auth-gated.
// Grounded against the handlers (unified-shell-console M3 + M13b live wiring):
//   * work.rs::post_gate_approve  — POST /v1/work/gate/{actionId}/approve  (body {approver_passport})
//   * work.rs::post_gate_reject   — POST /v1/work/gate/{actionId}/reject   (body {approver_passport}; also drives "Withhold all" as a pending-gate loop)
//   * work.rs::post_comment       — POST /v1/work/{id}/comments            (body {author_passport, body})
//   * actions.rs::post_action_enrich — POST /v1/actions/enrich             (body ActionEnrichmentInput)
//   * projects.rs::post_project              — POST /v1/projects                              (body {id,name,planning_target,…})  [mod.rs:757]
//   * passports.rs::post_passport            — POST /v1/passports                             (body {id,category,name,owner,…})   [mod.rs:1022]
//   * console.rs::post_console_review_consolidation — POST /v1/console/review/consolidations  (ConsolidationRequestV1 {entity,key,canonical_value,target_fact_ids,actor,…}) [mod.rs:1151]
//   * identity_links.rs::post_identity_candidate_confirm — POST /v1/identity/candidates/{candidateId}/confirm (CreateLinkRequest {local_passport_id,remote_fpr,remote_public_key_hex,created_at,sig_local,sig_remote}) [mod.rs:545]
//   * console.rs::put_console_corecrux_lane_weights    — PUT  /v1/console/corecrux/lane-weights (body {tenant_id?,weights,fusion_rrf_enabled,reason?,actor?}) [mod.rs:1142]
//   * console.rs::delete_console_corecrux_lane_weights — DELETE /v1/console/corecrux/lane-weights (no body; global-scope reset) [mod.rs:1143]
//   * admin.rs::post_restart_daemon          — POST /v1/admin/restart                         (no body; std::process::exit + restart policy) [mod.rs:435]
//   * console.rs::post_console_onboarding_restart — POST /v1/console/onboarding/restart       (no body) [mod.rs:1161]
//   * console.rs::post_console_embedding_probe    — POST /v1/console/embedding/probe          (body {url}; SSRF-guarded outbound probe) [mod.rs:1137]
//   * integrations_github.rs::post_connect   — POST /v1/integrations/github/connect           (body {pat,skip_verify,username_override}) [mod.rs:1068]
//   * integrations_openai.rs::post_chat      — POST /v1/integrations/openai/chat              (body {messages,model,max_tokens,temperature}; token spend → confirm) [mod.rs:1117]
//   * extensions.rs::add_trusted_key         — POST /v1/extensions/keys                       (body {passport_fpr,public_key_hex,trust_tier,added_by}) [mod.rs:886]
//   * workspace.rs::post_scan                — POST /v1/workspace/scan                        (no body; persists a scan fact) [mod.rs:835]
//   * workbench.rs::post_context_pack        — POST /v1/workbench/context-pack                (body {tenant_id,query,token_budget,…}; returns receipt.receipt_id) [mod.rs:675]
//   * workbench.rs::post_impact_preflight    — POST /v1/workbench/impact-preflight            (body {tenant_id,changed_paths,…}; returns receipt.receipt_id) [mod.rs:679]
//   * workbench.rs::post_policy_simulation   — POST /v1/workbench/policy-simulation           (flattened ActionEnrichmentInput {tool_name,action_description,tool_parameters}; returns receipt.receipt_id) [mod.rs:702]
//   * workbench.rs::post_route_probe         — POST /v1/workbench/route-probe                 (body {route,include_storyline,include_tests}; returns receipt.receipt_id) [mod.rs:697]
//   * features.rs::post_audit                — POST /v1/features/capabilities/{id}/audit      (body {status,auditor,notes}) [mod.rs:591]
const GATED_MUTATIONS: &[(&str, &str, &str)] = &[
    ("POST", "/v1/work/gate/{actionId}/approve", "gateApprove"),
    ("POST", "/v1/work/gate/{actionId}/reject", "gateReject"),
    ("POST", "/v1/work/{id}/comments", "workComment"),
    ("POST", "/v1/actions/enrich", "actionsEnrich"),
    (
        "POST",
        "/v1/passport/mint-requests/{request_id}/approve",
        "passportMintRequestApprove",
    ),
    (
        "POST",
        "/v1/passport/mint-requests/{request_id}/reject",
        "passportMintRequestReject",
    ),
    // ── M13b: live-wired write controls (each behind the WIRED_WRITES harness) ──
    ("POST", "/v1/projects", "createProject"),
    ("POST", "/v1/passports", "createPassport"),
    ("POST", "/v1/console/review/consolidations", "reviewConsolidation"),
    (
        "POST",
        "/v1/identity/candidates/{candidateId}/confirm",
        "identityCandidateConfirm",
    ),
    // console-surfaces-remediation M6: operator-gated "Seed candidates" — runs the
    // candidate proposers so a fresh workspace can populate /v1/identity/candidates.
    ("POST", "/v1/identity/candidates/propose", "identityCandidatePropose"),
    ("PUT", "/v1/console/corecrux/lane-weights", "laneWeightsApply"),
    ("DELETE", "/v1/console/corecrux/lane-weights", "laneWeightsReset"),
    ("POST", "/v1/admin/restart", "adminRestart"),
    ("POST", "/v1/console/onboarding/restart", "onboardingRestart"),
    ("POST", "/v1/console/embedding/probe", "embeddingProbe"),
    ("POST", "/v1/integrations/github/connect", "githubConnect"),
    ("POST", "/v1/integrations/openai/chat", "openaiChat"),
    ("POST", "/v1/extensions/keys", "extensionAddKey"),
    ("POST", "/v1/workspace/scan", "workspaceScanRun"),
    ("POST", "/v1/workbench/context-pack", "workbenchContextPack"),
    ("POST", "/v1/workbench/impact-preflight", "workbenchImpactPreflight"),
    ("POST", "/v1/workbench/policy-simulation", "workbenchPolicySimulation"),
    ("POST", "/v1/workbench/route-probe", "workbenchRouteProbe"),
    ("POST", "/v1/features/capabilities/{id}/audit", "featureCapabilityAudit"),
    // console-surfaces-remediation M14: Canvas Studio persists tile boards + saved
    // tile designs daemon-side. The write is the existing facts-add console route
    // (facts:write scope, category-enforced); the console reaches it ONLY through
    // operatorGatedCall, and the entity is fixed to the `console:tileboard:` /
    // `console:tiledesign:` prefixes by the caller (render.js tileStudio*).
    ("POST", "/v1/console/facts/add", "consoleFactsAdd"),
];

// ── Curated read-POST allowlist (unified-shell-console M11) ───────────────────
//
// Retrieval is a READ, but the daemon models searches as POST (a JSON body
// carries the query + budget). The generated `CruxApi` is GET-only and the
// generic `get()` allowlist refuses POST, so searches need their own frozen
// client. `generate_api_js()` emits a THIRD object, `CruxApiRead`, from exactly
// this list — each method POSTs a JSON body, same-origin credentialed.
//
// These are CURATED READ POSTs (retrieval, not mutation): customer-safe,
// allowlist-guarded, and carry NO write semantics — there is NO arbitrary POST
// on this client. That is the whole point of keeping them separate from the
// GET-only `CruxApi` (reads) and the tiny operator-gated `CruxApiGated`
// (writes). Widening it is a reviewable diff here + a regenerated `api.js`.
//
// Grounded against the handlers:
//   * query.rs::post_query_text_search        — POST /v1/query/text-search
//   * query.rs::post_query_text_search_expand — POST /v1/query/text-search/expand
//   * query.rs::post_query_graph_expand       — POST /v1/query/graph-expand
//   * query.rs::post_query_time_range         — POST /v1/query/time-range
//   * engine_console.rs::post_engine_search   — POST /v1/console/engine/search
//     (the ONE mediated read POST; proxies CruxEngine POST /v1/retrieve)
//   * studio_pack.rs::post_build_pack   — POST /v1/studio/pack/build
//   * studio_pack.rs::post_verify_pack  — POST /v1/studio/pack/verify
//     (console-surfaces-remediation M15: Studio board pack export/import. Both
//     are pure transforms/validators over a client-supplied payload — no store
//     mutation, no operator posture — so they are read POSTs, not gated
//     mutations. The apply step reuses the gated /v1/console/facts/add.)
const READ_POST_ROUTES: &[(&str, &str, &str)] = &[
    ("POST", "/v1/query/text-search", "queryTextSearch"),
    ("POST", "/v1/query/text-search/expand", "queryTextSearchExpand"),
    ("POST", "/v1/query/graph-expand", "queryGraphExpand"),
    ("POST", "/v1/query/time-range", "queryTimeRange"),
    ("POST", "/v1/console/engine/search", "engineSearch"),
    ("POST", "/v1/studio/pack/build", "studioPackBuild"),
    ("POST", "/v1/studio/pack/verify", "studioPackVerify"),
];

// ── Router source scanning (mirrors route_auth::parse_routes_in_source) ──────

/// Brace/quote-aware scan of `.route("<path>", <method>(...))` calls. Returns
/// `(METHOD, path)` pairs. Identical algorithm to
/// `route_auth::parse_routes_in_source` so the two stay in lock-step.
fn parse_routes_in_source(src: &str) -> Vec<(String, String)> {
    let bytes = src.as_bytes();
    let needle = b".route(";
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] != needle {
            i += 1;
            continue;
        }
        let chunk_start = i + needle.len();
        let mut depth = 1i32;
        let mut j = chunk_start;
        let mut in_str = false;
        let mut prev = 0u8;
        while j < bytes.len() && depth > 0 {
            let c = bytes[j];
            if in_str {
                if c == b'"' && prev != b'\\' {
                    in_str = false;
                }
            } else {
                match c {
                    b'"' => in_str = true,
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
            }
            prev = c;
            if depth == 0 {
                break;
            }
            j += 1;
        }
        if depth == 0 {
            let chunk = std::str::from_utf8(&bytes[chunk_start..j]).unwrap_or("");
            out.extend(parse_route_chunk(chunk));
            i = j + 1;
        } else {
            i += needle.len();
        }
    }
    out
}

fn parse_route_chunk(chunk: &str) -> Vec<(String, String)> {
    let Some(after) = chunk.trim_start().strip_prefix('"') else {
        return Vec::new();
    };
    let Some((path, rest)) = after.split_once('"') else {
        return Vec::new();
    };
    let mut routes = Vec::new();
    for method in ["get", "post", "put", "patch", "delete"] {
        if rest.contains(&format!("{method}(")) || rest.contains(&format!(".{method}(")) {
            routes.push((method.to_ascii_uppercase(), path.to_string()));
        }
    }
    routes
}

/// Drop test code so test-only routers don't pollute the mounted set.
///
/// Heuristic (line-based, documented): truncate the file at the first
/// `#[cfg(test)]` attribute whose next non-attribute line opens an inline module
/// **body** (`mod <ident> {`). A `#[cfg(test)] mod <ident>;` *declaration*
/// (semicolon, e.g. `mod route_auth;` / `#[path = "tests.rs"] mod tests;` in
/// `mod.rs`) is NOT a boundary — the real router lives after it, so a naive
/// "cut at the first `#[cfg(test)]`" would wrongly discard the whole router.
fn strip_test_code(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    for (k, line) in lines.iter().enumerate() {
        if !line.trim_start().starts_with("#[cfg(test)]") {
            continue;
        }
        // Skip any further attribute lines (e.g. `#[allow(...)]`, `#[path=...]`).
        let mut j = k + 1;
        while j < lines.len() && lines[j].trim_start().starts_with("#[") {
            j += 1;
        }
        if j < lines.len() && opens_mod_body(lines[j]) {
            return lines[..k].join("\n");
        }
    }
    src.to_string()
}

/// True for a line of the form `mod <ident> {` / `pub mod <ident> {` (inline
/// module body). False for `mod <ident>;` (external module declaration).
fn opens_mod_body(line: &str) -> bool {
    let s = line.trim_start();
    let s = s.strip_prefix("pub ").unwrap_or(s);
    let Some(rest) = s.strip_prefix("mod ") else {
        return false;
    };
    let rest = rest.trim_start();
    let ident_end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    !rest[..ident_end].is_empty() && rest[ident_end..].trim_start().starts_with('{')
}

/// A path is in the versioned-API drift scope: `/v1/*` plus the three health
/// probes. This deliberately excludes the HTML console asset routes
/// (`/console*`, `/activate`, `/`) and the legacy non-`/v1` invocation rails
/// (`/session`, `/invocation/verify`); see the `ROUTES` doc in `openapi.rs`.
fn in_scope(path: &str) -> bool {
    path.starts_with("/v1/") || matches!(path, "/healthz" | "/readyz" | "/metrics")
}

/// Every `(METHOD, path)` the router mounts, scanned from the source tree and
/// filtered to the drift scope.
fn router_pairs() -> BTreeSet<(String, String)> {
    // Whole-file `#[cfg(test)]` modules (declared elsewhere) and the manifest
    // source itself carry no *mounted* routes but do contain `.route(`
    // substrings (test routers, doc examples) — exclude them by name.
    const EXCLUDE: [&str; 3] = ["tests.rs", "route_auth.rs", "openapi.rs"];

    let mut sources: Vec<PathBuf> = Vec::new();
    let http_dir = manifest_dir().join("src/http");
    for entry in fs::read_dir(&http_dir).expect("read src/http") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if EXCLUDE.contains(&name) {
            continue;
        }
        sources.push(path);
    }
    sources.push(manifest_dir().join("src/main.rs"));

    let mut out = BTreeSet::new();
    for src_path in sources {
        let Ok(src) = fs::read_to_string(&src_path) else {
            continue;
        };
        let stripped = strip_test_code(&src);
        for (method, path) in parse_routes_in_source(&stripped) {
            if in_scope(&path) {
                out.insert((method, path));
            }
        }
    }
    out
}

// ── Manifest parsing (reads the ROUTES table out of openapi.rs source) ───────

struct ManifestEntry {
    path: String,
    methods: Vec<String>,
}

/// Parse the `#[rustfmt::skip] const ROUTES` table from `openapi.rs` source.
/// Each row is one line: `RouteEntry { path: "..", methods: &["..", ..], .. }`.
fn parse_manifest() -> Vec<ManifestEntry> {
    let src = fs::read_to_string(manifest_dir().join("src/http/openapi.rs")).expect("read openapi.rs");
    let start = src.find("const ROUTES:").expect("ROUTES const declaration");
    let block = &src[start..];
    let end = block.find("\n];").expect("end of ROUTES table");
    let block = &block[..end];

    let mut out = Vec::new();
    for line in block.lines() {
        let line = line.trim();
        if !line.starts_with("RouteEntry {") {
            continue;
        }
        let path = str_field(line, "path:").expect("path field");
        let methods = methods_field(line).expect("methods field");
        out.push(ManifestEntry { path, methods });
    }
    out
}

/// Extract the first `<key> "<value>"` string literal on a line.
fn str_field(line: &str, key: &str) -> Option<String> {
    let idx = line.find(key)?;
    let rest = &line[idx + key.len()..];
    let q1 = rest.find('"')?;
    let after = &rest[q1 + 1..];
    let q2 = after.find('"')?;
    Some(after[..q2].to_string())
}

/// Extract the quoted method tokens from `methods: &["GET", "POST"]`.
fn methods_field(line: &str) -> Option<Vec<String>> {
    let idx = line.find("methods:")?;
    let rest = &line[idx..];
    let lb = rest.find('[')?;
    let rb = rest.find(']')?;
    let mut inner = &rest[lb + 1..rb];
    let mut methods = Vec::new();
    while let Some(q1) = inner.find('"') {
        let after = &inner[q1 + 1..];
        let q2 = after.find('"')?;
        methods.push(after[..q2].to_string());
        inner = &after[q2 + 1..];
    }
    Some(methods)
}

/// Every `(METHOD, path)` the manifest declares, filtered to the drift scope.
fn manifest_pairs() -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for entry in parse_manifest() {
        if !in_scope(&entry.path) {
            continue;
        }
        for method in &entry.methods {
            out.insert((method.to_ascii_uppercase(), entry.path.clone()));
        }
    }
    out
}

// ── Generated fetch layer (console/v2/api.js) ────────────────────────────────

fn api_js_path() -> PathBuf {
    manifest_dir().join("console/v2/api.js")
}

/// GET-only paths from the manifest, sorted, deduplicated — the read surface
/// the v2 console is allowed to call.
fn get_paths() -> Vec<String> {
    let mut paths: Vec<String> = parse_manifest()
        .into_iter()
        .filter(|e| e.methods.iter().any(|m| m.eq_ignore_ascii_case("GET")))
        .map(|e| e.path)
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// PascalCase a path segment, splitting on non-alphanumeric boundaries.
fn pascal(token: &str) -> String {
    let mut out = String::new();
    for word in token.split(|c: char| !c.is_alphanumeric()) {
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
}

/// camelCase method name for a GET path: segments joined PascalCase (dropping
/// the `v1` prefix), `{param}` rendered as `By<Param>`, first char lowered.
fn method_name(path: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        if seg == "v1" {
            continue;
        }
        if let Some(param) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            parts.push(format!("By{}", pascal(param)));
        } else {
            parts.push(pascal(seg));
        }
    }
    let joined = parts.join("");
    let mut chars = joined.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
        None => joined,
    }
}

/// Ordered path-parameter names (`{factId}` -> `factId`).
fn path_params(path: &str) -> Vec<String> {
    let mut params = Vec::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            break;
        };
        params.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    params
}

/// The inside of a JS template literal: `{param}` -> `${encodeURIComponent(param)}`.
fn url_template(path: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push('{');
            rest = after;
            continue;
        };
        let name = &after[..close];
        out.push_str(&format!("${{encodeURIComponent({name})}}"));
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// Emit `console/v2/api.js` deterministically from the manifest's GET routes.
fn generate_api_js() -> String {
    let paths = get_paths();
    let mut s = String::new();
    s.push_str("// Copyright (c) 2026 CueCrux Ltd. All rights reserved.\n");
    s.push_str("// Licensed under the CueCrux Community Licence (CCL v1.0).\n");
    s.push_str("// See LICENCE.md in the repository root.\n");
    s.push_str("//\n");
    s.push_str("// @generated — DO NOT EDIT BY HAND.\n");
    s.push_str("// Source of truth: the ROUTES manifest in crates/corecruxd/src/http/openapi.rs.\n");
    s.push_str("// Regenerate:\n");
    s.push_str("//   cargo test -p corecruxd --test route_spec_drift -- --ignored regen_api_js\n");
    s.push_str("//\n");
    s.push_str("// Customer-safe posture: CruxApi (below) exposes only GET (read) routes; its\n");
    s.push_str("// generic get(path) is allowlist-guarded to literal manifest GET paths. The ONLY\n");
    s.push_str("// writes this console can perform live in the separate CruxApiGated object at the\n");
    s.push_str(&format!(
        "// bottom — exactly {} curated, operator-posture-gated mutation(s), no more.\n",
        GATED_MUTATIONS.len()
    ));
    s.push_str("//\n");
    s.push_str("// Every call is same-origin credentialed; the browser never holds a bearer\n");
    s.push_str("// token (the daemon authenticates the session at its own origin).\n");
    s.push_str("//\n");
    s.push_str(&format!(
        "// {} read endpoints, generated from the route manifest.\n\n",
        paths.len()
    ));

    s.push_str("/**\n");
    s.push_str(" * Append a plain query object to a path as a URL search string.\n");
    s.push_str(" * @param {string} path\n");
    s.push_str(" * @param {Object<string, (string|number|boolean)>} [query]\n");
    s.push_str(" * @returns {string}\n");
    s.push_str(" */\n");
    s.push_str("function withQuery(path, query) {\n");
    s.push_str("  if (!query) return path;\n");
    s.push_str("  const usp = new URLSearchParams();\n");
    s.push_str("  for (const [k, v] of Object.entries(query)) {\n");
    s.push_str("    if (v !== undefined && v !== null) usp.append(k, String(v));\n");
    s.push_str("  }\n");
    s.push_str("  const qs = usp.toString();\n");
    s.push_str("  return qs ? `${path}?${qs}` : path;\n");
    s.push_str("}\n\n");

    s.push_str("/**\n");
    s.push_str(" * Literal (parameter-free) GET paths from the manifest — the allowlist for\n");
    s.push_str(" * CruxApi.get(). Parameterised routes are reachable only via named methods.\n");
    s.push_str(" */\n");
    s.push_str("const LITERAL_GET_PATHS = Object.freeze({\n");
    for path in paths.iter().filter(|p| !p.contains('{')) {
        s.push_str(&format!("  '{path}': true,\n"));
    }
    s.push_str("});\n\n");

    s.push_str("/**\n");
    s.push_str(" * Generated read-only client for the Crux daemon HTTP API.\n");
    s.push_str(" * One method per GET route; each returns the raw `fetch` Promise.\n");
    s.push_str(" */\n");
    s.push_str("const CruxApi = Object.freeze({\n");
    s.push_str("  /**\n");
    s.push_str("   * Allowlist-guarded generic read: only literal (parameter-free) GET paths\n");
    s.push_str("   * from the manifest are callable. Unknown paths reject without touching\n");
    s.push_str("   * the network. Parameterised routes: use their named methods below.\n");
    s.push_str("   * @param {string} path\n");
    s.push_str("   * @param {Object<string, (string|number|boolean)>} [query]\n");
    s.push_str("   * @returns {Promise<Response>}\n");
    s.push_str("   */\n");
    s.push_str("  get(path, query) {\n");
    s.push_str("    if (!LITERAL_GET_PATHS[path]) {\n");
    s.push_str(
        "      return Promise.reject(new Error('CruxApi.get: path not in the generated GET allowlist: ' + path));\n",
    );
    s.push_str("    }\n");
    s.push_str("    return fetch(withQuery(path, query), { credentials: 'same-origin' });\n");
    s.push_str("  },\n");
    for path in &paths {
        let name = method_name(path);
        let mut args = path_params(path);
        args.push("query".to_string());
        let args = args.join(", ");
        let url = url_template(path);
        s.push_str(&format!(
            "  {name}({args}) {{\n    return fetch(withQuery(`{url}`, query), {{ credentials: 'same-origin' }});\n  }},\n"
        ));
    }
    s.push_str("});\n\n");

    // ── Gated mutation surface (M3) ──────────────────────────────────────────
    s.push_str("// ─────────────────────────────────────────────────────────────────────────────\n");
    s.push_str("// CruxApiGated — the ONLY mutations the v2 console can perform.\n");
    s.push_str("//\n");
    s.push_str("// Every method below is BOTH:\n");
    s.push_str("//   * operator-posture UI-gated — pages/render/shell reach these only through\n");
    s.push_str("//     render.js operatorGatedCall(), which refuses unless CRUX_POSTURE==='operator';\n");
    s.push_str("//   * server-side auth-gated — the daemon enforces admin/facts scopes on each.\n");
    s.push_str("//\n");
    s.push_str("// Adding a mutation requires editing GATED_MUTATIONS in the generator\n");
    s.push_str("// (crates/corecruxd/tests/route_spec_drift.rs) — a reviewable diff + a regenerated\n");
    s.push_str("// api.js. Do NOT widen this list casually: the customer-safe posture depends on\n");
    s.push_str("// it staying tiny. The GATED_MUTATIONS array is the machine-readable twin the\n");
    s.push_str("// smoke audits against the methods below.\n");
    s.push_str("// ─────────────────────────────────────────────────────────────────────────────\n");
    s.push_str("const GATED_MUTATIONS = Object.freeze([\n");
    for (method, path, _name) in GATED_MUTATIONS {
        s.push_str(&format!("  Object.freeze(['{method}', '{path}']),\n"));
    }
    s.push_str("]);\n\n");

    s.push_str("const CruxApiGated = Object.freeze({\n");
    for (method, path, name) in GATED_MUTATIONS {
        let mut args = path_params(path);
        args.push("body".to_string());
        let args = args.join(", ");
        let url = url_template(path);
        s.push_str(&format!(
            "  {name}({args}) {{\n    \
             return fetch(`{url}`, {{ method: '{method}', credentials: 'same-origin', \
             headers: {{ 'content-type': 'application/json' }}, body: JSON.stringify(body || {{}}) }});\n  \
             }},\n"
        ));
    }
    s.push_str("});\n\n");

    // ── Curated read-POST surface (M11) ──────────────────────────────────────
    s.push_str("// ─────────────────────────────────────────────────────────────────────────────\n");
    s.push_str("// CruxApiRead — curated READ POSTs (retrieval, not mutation).\n");
    s.push_str("//\n");
    s.push_str("// Searches are reads, but the daemon carries the query + budget in a JSON body,\n");
    s.push_str("// so they are POSTs — which the GET-only CruxApi (and its allowlisted get())\n");
    s.push_str("// cannot express. Each method below POSTs a JSON body, same-origin credentialed.\n");
    s.push_str("// Every route is customer-safe and allowlist-guarded: there is NO arbitrary POST\n");
    s.push_str("// here — only these curated retrieval routes. This is NOT a mutation surface\n");
    s.push_str("// (that is CruxApiGated); nothing here writes.\n");
    s.push_str("//\n");
    s.push_str("// Adding a route requires editing READ_POST_ROUTES in the generator\n");
    s.push_str("// (crates/corecruxd/tests/route_spec_drift.rs) — a reviewable diff + a regenerated\n");
    s.push_str("// api.js. The READ_POST_ROUTES array is the machine-readable twin the smoke\n");
    s.push_str("// audits against the methods below.\n");
    s.push_str("// ─────────────────────────────────────────────────────────────────────────────\n");
    s.push_str("const READ_POST_ROUTES = Object.freeze([\n");
    for (method, path, _name) in READ_POST_ROUTES {
        s.push_str(&format!("  Object.freeze(['{method}', '{path}']),\n"));
    }
    s.push_str("]);\n\n");

    s.push_str("const CruxApiRead = Object.freeze({\n");
    for (method, path, name) in READ_POST_ROUTES {
        let mut args = path_params(path);
        args.push("body".to_string());
        let args = args.join(", ");
        let url = url_template(path);
        s.push_str(&format!(
            "  {name}({args}) {{\n    \
             return fetch(`{url}`, {{ method: '{method}', credentials: 'same-origin', \
             headers: {{ 'content-type': 'application/json' }}, body: JSON.stringify(body || {{}}) }});\n  \
             }},\n"
        ));
    }
    s.push_str("});\n\n");

    s.push_str("// --- Hosted platform session (BFF /api/auth/*) ---------------------------\n");
    s.push_str("// NOT daemon routes and NOT part of the daemon GET/mutation allowlists: on a\n");
    s.push_str("// hosted deployment a BFF fronts the daemon and owns the account session\n");
    s.push_str("// (cookies on the parent domain, CSRF double-submit). On a local daemon these\n");
    s.push_str("// paths 404 — callers treat that as \"no session surface, hide the control\".\n");
    s.push_str("// Lives here so the through-client rule holds: api.js is the sole network layer.\n");
    s.push_str("const CruxSession = {\n");
    s.push_str("  /** Resolves true when a hosted session surface exists (route present at all). */\n");
    s.push_str("  probe() {\n");
    s.push_str("    return fetch('/api/auth/session', { credentials: 'same-origin' })\n");
    s.push_str("      .then((res) => res.status !== 404)\n");
    s.push_str("      .catch(() => false);\n");
    s.push_str("  },\n");
    s.push_str("  /** POST logout with the CSRF double-submit header; resolves response.ok. */\n");
    s.push_str("  logout() {\n");
    s.push_str("    const m = document.cookie.match(/(?:^|; )cc_csrf=([^;]*)/);\n");
    s.push_str("    const csrf = m ? decodeURIComponent(m[1]) : '';\n");
    s.push_str("    return fetch('/api/auth/logout', {\n");
    s.push_str("      method: 'POST',\n");
    s.push_str("      credentials: 'same-origin',\n");
    s.push_str("      headers: csrf ? { 'x-csrf-token': csrf } : {},\n");
    s.push_str("    }).then((res) => res.ok);\n");
    s.push_str("  },\n");
    s.push_str("};\n\n");

    s.push_str("// Classic-script globals for the no-build v2 console. No `export` — the\n");
    s.push_str("// console loads this with a plain <script src=\"/console-v2/api.js\">.\n");
    s.push_str("if (typeof window !== 'undefined') {\n");
    s.push_str("  window.CruxApi = CruxApi;\n");
    s.push_str("  window.CruxApiGated = CruxApiGated;\n");
    s.push_str("  window.CruxApiRead = CruxApiRead;\n");
    s.push_str("  window.CruxSession = CruxSession;\n");
    s.push_str("  window.CRUX_GATED_MUTATIONS = GATED_MUTATIONS;\n");
    s.push_str("  window.CRUX_READ_POST_ROUTES = READ_POST_ROUTES;\n");
    s.push_str("  // Known literal (query-less) GET routes — the validated source for the\n");
    s.push_str("  // Canvas Studio API-tile route picker (M14). An API tile may bind ONLY to a\n");
    s.push_str("  // route in this list; arbitrary strings are rejected before any fetch.\n");
    s.push_str("  window.CRUX_GET_ROUTES = Object.freeze(Object.keys(LITERAL_GET_PATHS));\n");
    s.push_str("}\n");
    s
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn route_manifest_matches_router() {
    let router = router_pairs();
    let manifest = manifest_pairs();

    let missing: Vec<String> = router.difference(&manifest).map(|(m, p)| format!("{m} {p}")).collect();
    let stale: Vec<String> = manifest.difference(&router).map(|(m, p)| format!("{m} {p}")).collect();

    assert!(
        missing.is_empty() && stale.is_empty(),
        "OpenAPI route↔spec drift detected.\n\
         MISSING ({} mounted route(s) with no ROUTES row — add them to src/http/openapi.rs):\n  {}\n\
         STALE ({} ROUTES row(s) not mounted anywhere — remove them from src/http/openapi.rs):\n  {}",
        missing.len(),
        missing.join("\n  "),
        stale.len(),
        stale.join("\n  "),
    );

    // Guard against a parser that silently matches nothing.
    assert!(
        manifest.len() >= 250,
        "manifest suspiciously small ({} pairs) — parser or table regression",
        manifest.len(),
    );
}

#[test]
fn generated_api_js_is_in_sync() {
    let expected = generate_api_js();
    let actual = fs::read_to_string(api_js_path()).unwrap_or_else(|e| {
        panic!(
            "console/v2/api.js is missing or unreadable ({e}); regenerate with:\n  \
             cargo test -p corecruxd --test route_spec_drift -- --ignored regen_api_js"
        )
    });
    assert_eq!(
        actual, expected,
        "console/v2/api.js is out of sync with the ROUTES manifest; regenerate with:\n  \
         cargo test -p corecruxd --test route_spec_drift -- --ignored regen_api_js"
    );

    // Method names must be unique or the JS object would silently drop routes.
    let names: Vec<String> = get_paths().iter().map(|p| method_name(p)).collect();
    let unique: BTreeSet<&String> = names.iter().collect();
    assert_eq!(
        names.len(),
        unique.len(),
        "generated api.js has colliding method names — disambiguate method_name()",
    );
    assert!(
        !names.iter().any(|n| n == "get"),
        "a generated method collides with the hand-emitted generic get()",
    );
}

/// Writer for `console/v2/api.js`. Ignored by default (it mutates a checked-in
/// file); run explicitly to regenerate after the manifest changes.
#[test]
#[ignore = "writer: run with -- --ignored regen_api_js to regenerate console/v2/api.js"]
fn regen_api_js() {
    let out = generate_api_js();
    fs::write(api_js_path(), out).expect("write console/v2/api.js");
}
