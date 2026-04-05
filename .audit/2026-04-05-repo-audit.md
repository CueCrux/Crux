# Crux Repository Audit — 2026-04-05

Two-perspective audit: senior Rust developer + AI agent consumer.

---

## Senior Developer Perspective

### CRITICAL

| # | Finding | Files | Fix |
|---|---|---|---|
| 1 | **Binary naming**: `corecruxd`/`corecruxctl` should be `crux serve`/`crux` per v1.1 plan | Cargo.toml, README, CI, Dockerfile | Rename crates + binaries |
| 2 | **2100+ unwrap/expect in production code** — any malformed input panics the daemon | Pervasive, especially crux-mcp tools | Promote `unwrap_used` to deny, refactor to `?` |
| 3 | **corecruxd is a 35K LOC monolith** — http.rs (10K), grpc.rs (6K), dataplane_store.rs (5K) | crates/corecruxd/src/ | Split into sub-modules |
| 4 | **4 core crates lack module docs** — types, proto, frame, corecruxctl | lib.rs in each | Add 100+ lines of `//!` docs |
| 5 | **No MSRV pinned** — `rust-toolchain.toml` says `stable`, no version guarantee | rust-toolchain.toml, ci.yml | Pin to e.g. `1.82.0`, add MSRV CI job |

### HIGH

| # | Finding | Fix |
|---|---|---|
| 6 | Suppressed CVE (RUSTSEC-2024-0437 protobuf) without upgrade plan | Evaluate tonic 0.14+ upgrade |
| 7 | No criterion benchmarks for BM25, index loading, graph fusion | Add `benches/` with criterion |
| 8 | Docker lacks `HEALTHCHECK`, no resource limits in compose | Add healthcheck + limits |
| 9 | Integration tests minimal (14 tests, no data flow scenarios) | Expand: append→query, multi-tenant isolation, receipts |
| 10 | 10 of 17 crates have <40 lines of documentation | Target 100+ lines per crate |

### MEDIUM

| # | Finding | Fix |
|---|---|---|
| 11 | CI missing MSRV check | Add MSRV job |
| 12 | CI missing cross-compilation test (ARM64 Linux) | Add cross-rs job |
| 13 | Release workflow not gated on CI success | Add `needs: [lint, test]` |
| 14 | No runnable Rust examples (only MCP configs) | Add examples/*.rs |
| 15 | 28 pedantic clippy lints allowed, some worth enforcing | Tighten incrementally |
| 16 | docs.yml points to nonexistent `crux_core` crate | Fix redirect target |

### LOW

| # | Finding | Fix |
|---|---|---|
| 17 | CHANGELOG has no guidance for contributors | Add note in CONTRIBUTING |
| 18 | README API examples lack request/response bodies | Add curl examples |
| 19 | Release profile could use `lto = "fat"` | Benchmark and decide |
| 20 | No OpenAPI/Swagger spec | Consider aide crate |

---

## Agent Perspective

### CRITICAL

| # | Finding | Impact | Fix |
|---|---|---|---|
| 1 | **Handoff tools defined but not wired** — dispatch returns "not yet implemented" | Multi-agent workflows completely blocked | Wire `create_handoff`/`accept_handoff` in dispatch (3-line fix) |

### HIGH

| # | Finding | Impact | Fix |
|---|---|---|---|
| 2 | **No agent-facing documentation** — no guide on when to use which tool, no workflows | Agent must guess or read source code | Write `docs/agent-guide.md` |
| 3 | **Bootstrap not discoverable via MCP** — patterns/resolutions only in compile-time JSON | Agent can't learn best practices at runtime | Add `get_bootstrap` tool |
| 4 | **No automatic error fact logging** — tool failures don't create ops facts | Agent can't query "what went wrong recently" | Auto-store errors as `__ops__::error` facts |
| 5 | **Handoff protocol undocumented** — no bootstrap entry explaining the flow | Agent won't know how to coordinate handoffs | Add handoff guide to bootstrap data |

### MEDIUM

| # | Finding | Impact | Fix |
|---|---|---|---|
| 6 | `query_expand` returns metadata, not content | Scan→expand pattern incomplete | Return content or document the gap |
| 7 | Missing `delete_fact`, `delete_session`, `list_entities`, `list_sessions` tools | Agent can't clean up or discover state | Add CRUD operations |
| 8 | `query` tool description doesn't mention token_budget benefit | Agent misses key cost optimization | Expand description |
| 9 | Error messages lack structured `data` field | Agent can't programmatically handle errors | Add `data` to JsonRpcError responses |
| 10 | Agent identity not queryable | Agent doesn't know its own name | Add `get_agent_identity` tool |

### LOW

| # | Finding | Fix |
|---|---|---|
| 11 | Private fact behavior undocumented when agent is None | Document fallback |
| 12 | No MCP-specific bootstrap entries | Add mcp-agent-guide.json |
| 13 | Session overwrite semantics (no merge) | Document clearly |
| 14 | No agent self-registration API | Document as deployment-time concern |
| 15 | Coverage guidance doesn't tell agent what to DO when low | Add decision tree |

---

## Top 10 Actions (Priority Order)

1. **Wire handoff dispatch** — 3-line fix, unblocks multi-agent
2. **Rename binaries to `crux`** — brand alignment, first impression
3. **Deny `unwrap_used` + fix production panics** — safety
4. **Write agent guide** — `docs/agent-guide.md` with tool decision tree
5. **Add `get_bootstrap` MCP tool** — runtime discoverability
6. **Docker healthcheck + resource limits** — ops readiness
7. **Pin MSRV + add CI job** — build reproducibility
8. **Add missing MCP tools** — `delete_fact`, `list_entities`, `list_sessions`
9. **Add criterion benchmarks** — performance claims need evidence
10. **Expand integration tests** — append→query flow, multi-tenant, receipts

---

*Audit conducted against commit state of 2026-04-05.*
