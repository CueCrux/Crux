// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Test-only route authorization contract for the daemon HTTP surface.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteAuthClass {
    Public,
    Read,
    Write,
    AdminRead,
    AdminWrite,
    InternalReplication,
    FeatureGated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RouteAuthContract {
    class: RouteAuthClass,
    scopes: &'static [&'static str],
    feature_gate: Option<&'static str>,
}

impl RouteAuthContract {
    const fn new(class: RouteAuthClass, scopes: &'static [&'static str]) -> Self {
        Self {
            class,
            scopes,
            feature_gate: None,
        }
    }

    const fn gated(class: RouteAuthClass, scopes: &'static [&'static str], feature_gate: &'static str) -> Self {
        Self {
            class,
            scopes,
            feature_gate: Some(feature_gate),
        }
    }
}

fn classify_route(method: &str, path: &str) -> Option<RouteAuthContract> {
    let method = method.to_ascii_uppercase();
    let method = method.as_str();

    if matches!(
        path,
        "/healthz"
            | "/readyz"
            | "/metrics"
            | "/session"
            | "/invocation/verify"
            | "/v1/openapi.json"
            | "/v1/version"
            | "/v1/witness/smoke"
    ) {
        return Some(RouteAuthContract::new(RouteAuthClass::Public, &[]));
    }

    if path.starts_with("/v1/auth/") {
        // Unified-login auth rails (whoami, tailscale token, device grant) perform
        // their own identity gating (verified tailnet identity, device-grant
        // codes) and are reachable without a prior bearer by design — that is the
        // bootstrap they exist to provide. The device *approve* step is gated to
        // an authenticated console admin inside the handler, not by route scope.
        return Some(RouteAuthContract::new(RouteAuthClass::Public, &[]));
    }

    if path.starts_with("/v1/internal/replication/") {
        return Some(RouteAuthContract::new(
            RouteAuthClass::InternalReplication,
            &["replication:write"],
        ));
    }

    if path.starts_with("/v1/admin/") || matches!(path, "/v1/shard-map" | "/v1/gpus" | "/v1/shards" | "/v1/route") {
        let write = method != "GET" && !matches!(path, "/v1/admin/sharing/backfill" | "/v1/admin/restart");
        let class = if write {
            RouteAuthClass::AdminWrite
        } else if method == "POST" && matches!(path, "/v1/admin/sharing/backfill" | "/v1/admin/restart") {
            RouteAuthClass::AdminWrite
        } else {
            RouteAuthClass::AdminRead
        };
        let scopes = match class {
            RouteAuthClass::AdminWrite => &["admin:write"][..],
            _ => &["admin:read"][..],
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/routing/") {
        return Some(RouteAuthContract::new(RouteAuthClass::AdminRead, &["admin:read"]));
    }

    if path.starts_with("/v1/projections/entity/") || path.starts_with("/v1/query/") {
        return Some(RouteAuthContract::new(
            RouteAuthClass::Read,
            &["query:read", "admin:read"],
        ));
    }

    if path.starts_with("/v1/projections/") {
        let class = if method == "GET" {
            RouteAuthClass::AdminRead
        } else {
            RouteAuthClass::AdminWrite
        };
        let scopes = if method == "GET" {
            &["admin:read"][..]
        } else {
            // Write-class: only a write scope authorizes (handler requires
            // admin:write). Read scopes must never be sufficient for a mutation.
            &["admin:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/receipts/")
        || path.starts_with("/v1/replay/")
        || path.starts_with("/v1/events/")
        || path.starts_with("/v1/observations/")
        || path.starts_with("/v1/ops/")
        || path.starts_with("/v1/bootstrap/")
    {
        return Some(RouteAuthContract::new(
            RouteAuthClass::Read,
            &["query:read", "receipts:read", "exports:read", "admin:read"],
        ));
    }

    if path.starts_with("/v1/facts")
        || path.starts_with("/v1/sessions/")
        || path.starts_with("/v1/entities")
        || path.starts_with("/v1/edges")
        || path.starts_with("/v1/kinds")
    {
        let class = if method == "GET" {
            RouteAuthClass::Read
        } else {
            RouteAuthClass::Write
        };
        let scopes = if method == "GET" {
            &["query:read", "admin:read"][..]
        } else {
            &["facts:write", "sessions:write", "admin:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/features/capabilities") {
        let class = if method == "GET" {
            RouteAuthClass::Read
        } else {
            RouteAuthClass::Write
        };
        let scopes = if method == "GET" {
            &["facts:read", "admin:read"][..]
        } else {
            &["facts:write", "admin:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/sync/tenants/") {
        let class = if method == "GET" {
            RouteAuthClass::Read
        } else {
            RouteAuthClass::Write
        };
        let scopes = if method == "GET" {
            &["facts:read"][..]
        } else {
            &["facts:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path == "/v1/identity/candidates" || path.starts_with("/v1/identity/candidates/") {
        let class = if method == "GET" {
            RouteAuthClass::AdminRead
        } else {
            RouteAuthClass::AdminWrite
        };
        let scopes = if method == "GET" {
            &["admin:read", "admin:write"][..]
        } else {
            &["admin:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/memory/import")
        || path.starts_with("/v1/result-envelope/import")
        || path.starts_with("/v1/identity/links")
        || path.starts_with("/v1/append")
    {
        let class = if method == "GET" {
            RouteAuthClass::Read
        } else {
            RouteAuthClass::Write
        };
        // Write-class (POST/…) must not accept a read-only scope; the GET
        // read-class branch may keep the broader union.
        let scopes = if method == "GET" {
            &["facts:write", "admin:write", "admin:read"][..]
        } else {
            &["facts:write", "admin:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/console/") {
        let mutating = !matches!(method, "GET")
            || path.ends_with("/install")
            || path.ends_with("/grant")
            || path.ends_with("/disable")
            || path.ends_with("/add");
        let class = if mutating {
            RouteAuthClass::AdminWrite
        } else {
            RouteAuthClass::AdminRead
        };
        let scopes = if mutating {
            &[
                "admin:write",
                "facts:write",
                "integrations:install",
                "integrations:grant",
                "integrations:disable",
            ][..]
        } else {
            &["admin:read", "tenant:chunks:read", "tenant:content:preview"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/integrations/") {
        let class = if method == "GET" {
            RouteAuthClass::AdminRead
        } else {
            RouteAuthClass::Write
        };
        let scopes = if method == "GET" {
            &["admin:read"][..]
        } else {
            &["integrations:install", "integrations:disable"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/work")
        || path.starts_with("/v1/projects")
        || path.starts_with("/v1/rcx/publish/")
        || path.starts_with("/v1/workspace/")
        || path.starts_with("/v1/mcp/tools")
        || path.starts_with("/v1/engrams")
        || path.starts_with("/v1/extensions")
        || path.starts_with("/v1/passports")
        || path.starts_with("/v1/principal/")
        || path.starts_with("/v1/policy/")
        || path.starts_with("/v1/relations")
        || path.starts_with("/v1/agents/")
        || path.starts_with("/v1/cost/")
        || path.starts_with("/v1/cloud/")
        || path.starts_with("/v1/actions/")
        || path.starts_with("/v1/workbench/")
        || path.starts_with("/v1/mediation/")
        || path.starts_with("/v1/memory/")
    {
        let class = if method == "GET" {
            RouteAuthClass::Read
        } else {
            RouteAuthClass::Write
        };
        let scopes = if method == "GET" {
            &["admin:read", "facts:read", "query:read", "sessions:read"][..]
        } else {
            // Write-class: drop the read-only query:read — a read token must not
            // authorize a mutation here.
            &["admin:write", "facts:write", "integrations:install"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/gpu1/") {
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &["query:read", "admin:read"],
            "gpu1_compute",
        ));
    }

    if path.starts_with("/v1/context") {
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &["query:read", "admin:read"],
            "CORECRUXD_CONTEXT_SURFACE",
        ));
    }

    if path.starts_with("/v1/openai/") {
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &["query:read", "admin:read", "admin:write"],
            "CORECRUXD_OPENAI_SHIM",
        ));
    }

    if path.starts_with("/v1/quota") {
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &["query:read", "admin:read"],
            "CORECRUXD_QUOTA",
        ));
    }

    if path.starts_with("/v1/coord/") {
        let scopes = if method == "GET" {
            &["admin:read", "sessions:read"][..]
        } else {
            &["admin:write", "sessions:write"][..]
        };
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            scopes,
            "CORECRUXD_COORD",
        ));
    }

    if path.starts_with("/v1/observe/sessions/") {
        let scopes = if method == "GET" {
            &["query:read", "admin:read"][..]
        } else {
            &["facts:write", "admin:write"][..]
        };
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            scopes,
            "CORECRUXD_OBSERVE",
        ));
    }

    if path.starts_with("/v1/orchestrators") || path.starts_with("/v1/punchcards") {
        let scopes = if method == "GET" {
            &["facts:read", "admin:read"][..]
        } else {
            &["facts:write", "admin:write"][..]
        };
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            scopes,
            "CORECRUXD_AGENTGRAPH",
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scope that only grants read access. Such a scope must never appear in a
    /// write-class route's accepted (sufficient) set.
    fn is_read_only_scope(scope: &str) -> bool {
        scope.ends_with(":read") || scope == "tenant:content:preview"
    }

    /// A scope that grants a mutation. Every write-class route must accept at
    /// least one of these.
    fn is_write_scope(scope: &str) -> bool {
        scope.ends_with(":write")
            || matches!(
                scope,
                "integrations:install" | "integrations:grant" | "integrations:disable"
            )
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct ParsedRoute {
        method: String,
        path: String,
    }

    fn parse_routes_in_source(src: &str) -> Vec<ParsedRoute> {
        let mut out = Vec::new();
        let bytes = src.as_bytes();
        let needle = b".route(";
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

    fn parse_route_chunk(chunk: &str) -> Vec<ParsedRoute> {
        let Some(after_quote) = chunk.trim_start().strip_prefix('"') else {
            return Vec::new();
        };
        let Some((path, rest)) = after_quote.split_once('"') else {
            return Vec::new();
        };

        let mut routes = Vec::new();
        let mut rest = rest;
        for method in ["get", "post", "put", "patch", "delete"] {
            let first = format!("{method}(");
            let chained = format!(".{method}(");
            if rest.contains(&first) || rest.contains(&chained) {
                routes.push(ParsedRoute {
                    method: method.to_ascii_uppercase(),
                    path: path.to_string(),
                });
                rest = rest.trim_start_matches(',');
            }
        }
        routes
    }

    fn router_routes() -> Vec<ParsedRoute> {
        let mut routes = Vec::new();
        for source in [
            include_str!("mod.rs"),
            include_str!("observe_audit.rs"),
            include_str!("orchestrators.rs"),
            include_str!("punchcards.rs"),
        ] {
            routes.extend(parse_routes_in_source(source));
        }
        routes.sort();
        routes.dedup();
        routes
    }

    #[test]
    fn route_auth_matrix_is_complete() {
        let missing: Vec<String> = router_routes()
            .into_iter()
            .filter(|route| classify_route(&route.method, &route.path).is_none())
            .map(|route| format!("{} {}", route.method, route.path))
            .collect();
        assert!(missing.is_empty(), "routes missing auth classification: {missing:?}");
    }

    #[test]
    fn route_auth_scope_contracts() {
        let cases = [
            (
                "GET",
                "/v1/admin/version",
                RouteAuthClass::AdminRead,
                &["admin:read"][..],
            ),
            (
                "POST",
                "/v1/admin/restart",
                RouteAuthClass::AdminWrite,
                &["admin:write"][..],
            ),
            (
                "POST",
                "/v1/internal/replication/segments",
                RouteAuthClass::InternalReplication,
                &["replication:write"][..],
            ),
            (
                "POST",
                "/v1/console/embedding/probe",
                RouteAuthClass::AdminWrite,
                &["admin:write"][..],
            ),
            (
                "GET",
                "/v1/projections/entity/count",
                RouteAuthClass::Read,
                &["query:read", "admin:read"][..],
            ),
            (
                "POST",
                "/v1/gpu1/answer",
                RouteAuthClass::FeatureGated,
                &["query:read", "admin:read"][..],
            ),
            (
                "GET",
                "/v1/identity/candidates",
                RouteAuthClass::AdminRead,
                &["admin:read"][..],
            ),
            (
                "POST",
                "/v1/identity/candidates/{candidateId}/confirm",
                RouteAuthClass::AdminWrite,
                &["admin:write"][..],
            ),
            (
                "POST",
                "/v1/identity/candidates/{candidateId}/reject",
                RouteAuthClass::AdminWrite,
                &["admin:write"][..],
            ),
        ];

        for (method, path, class, scopes) in cases {
            let contract = classify_route(method, path).expect("route contract");
            assert_eq!(contract.class, class, "{method} {path}");
            for scope in scopes {
                assert!(
                    contract.scopes.contains(scope),
                    "{method} {path} missing expected scope {scope}; got {:?}",
                    contract.scopes
                );
            }
        }
    }

    #[test]
    fn write_class_routes_do_not_accept_read_only_scopes() {
        // Sweep every live route: any classified Write/AdminWrite contract must
        // require a write scope and must not list a read-only scope as
        // sufficient (else a read token could authorize a mutation).
        for route in router_routes() {
            let Some(contract) = classify_route(&route.method, &route.path) else {
                continue;
            };
            if !matches!(contract.class, RouteAuthClass::Write | RouteAuthClass::AdminWrite) {
                continue;
            }
            for scope in contract.scopes {
                assert!(
                    !is_read_only_scope(scope),
                    "{} {} is write-class but accepts read-only scope {scope}; got {:?}",
                    route.method,
                    route.path,
                    contract.scopes
                );
            }
            assert!(
                contract.scopes.iter().any(|s| is_write_scope(s)),
                "{} {} is write-class but accepts no write scope; got {:?}",
                route.method,
                route.path,
                contract.scopes
            );
        }
    }

    #[test]
    fn write_class_contracts_for_known_mutations_are_write_only() {
        // Direct check on representative mutations (independent of the router
        // parser) so a regression is caught even if a path drops out of the
        // parsed sources.
        let mutations = [
            ("POST", "/v1/projections/rebuild"),
            ("POST", "/v1/append"),
            ("POST", "/v1/work/items"),
            ("POST", "/v1/facts"),
            ("PUT", "/v1/sync/tenants/abc"),
            ("POST", "/v1/features/capabilities/x/audit"),
            ("POST", "/v1/identity/candidates/x/confirm"),
            ("POST", "/v1/admin/restart"),
        ];
        for (method, path) in mutations {
            let contract = classify_route(method, path).expect("contract");
            assert!(
                matches!(contract.class, RouteAuthClass::Write | RouteAuthClass::AdminWrite),
                "{method} {path} should classify write-class, got {:?}",
                contract.class
            );
            for scope in contract.scopes {
                assert!(
                    !is_read_only_scope(scope),
                    "{method} {path} accepts read-only scope {scope}; got {:?}",
                    contract.scopes
                );
            }
            assert!(
                contract.scopes.iter().any(|s| is_write_scope(s)),
                "{method} {path} has no write scope; got {:?}",
                contract.scopes
            );
        }
    }

    #[test]
    fn admin_write_routes_do_not_accept_admin_read_only() {
        for route in router_routes() {
            let Some(contract) = classify_route(&route.method, &route.path) else {
                continue;
            };
            if contract.class == RouteAuthClass::AdminWrite {
                assert!(
                    !contract.scopes.contains(&"admin:read"),
                    "{} {} is AdminWrite but accepts admin:read; got {:?}",
                    route.method,
                    route.path,
                    contract.scopes
                );
            }
        }
    }

    #[test]
    fn feature_gated_write_routes_have_write_scope() {
        // Feature-gated routes invoked with a mutating method must require a
        // write scope and reject read-only scopes on the write branch.
        let gated_mutations = [
            ("POST", "/v1/coord/lease"),
            ("POST", "/v1/observe/sessions/abc/event"),
            ("POST", "/v1/orchestrators/run"),
            ("POST", "/v1/punchcards/x"),
        ];
        for (method, path) in gated_mutations {
            let contract = classify_route(method, path).expect("contract");
            assert_eq!(contract.class, RouteAuthClass::FeatureGated, "{method} {path}");
            assert!(
                contract.scopes.iter().any(|s| is_write_scope(s)),
                "{method} {path} gated write must include a write scope; got {:?}",
                contract.scopes
            );
            for scope in contract.scopes {
                assert!(
                    !is_read_only_scope(scope),
                    "{method} {path} gated write accepts read-only scope {scope}; got {:?}",
                    contract.scopes
                );
            }
        }
    }

    #[test]
    fn http_boundary_contracts() {
        let routes = router_routes();
        assert!(
            routes
                .iter()
                .any(|r| r.method == "POST" && r.path == "/v1/admin/restart"),
            "admin restart route must stay covered by the auth matrix"
        );
        assert!(
            routes
                .iter()
                .any(|r| r.method == "GET" && r.path == "/v1/projections/entity/count"),
            "entity projection routes must stay covered by the auth matrix"
        );
        assert!(
            routes
                .iter()
                .any(|r| r.method == "POST" && r.path == "/v1/console/embedding/probe"),
            "embedding probe route must stay covered by the auth matrix"
        );
    }
}
