// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
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

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

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
    s.push_str("// Customer-safe posture: only GET (read) routes are exposed here. The v2 console\n");
    s.push_str("// performs NO mutations through this client — POST/PUT/PATCH/DELETE routes are\n");
    s.push_str("// deliberately omitted until M3 wires specific gated mutations explicitly.\n");
    s.push_str("// The generic CruxApi.get(path) is allowlist-guarded to literal manifest GET paths.\n");
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
    s.push_str("// Classic-script global for the no-build v2 console. No `export` — the\n");
    s.push_str("// console loads this with a plain <script src=\"/console-v2/api.js\">.\n");
    s.push_str("if (typeof window !== 'undefined') { window.CruxApi = CruxApi; }\n");
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
