# Crux Repo Audit Fixing Checklist

**Doc-ID:** cuecrux/plancrux/audits/crux-repo-fixing-checklist/2026-06-15  
**Date:** 2026-06-15  
**Owner:** Platform Data + Trust / CoreCrux maintainers  
**Status:** Draft — implementation checklist from source audit  
**Source repo audited:** `CueCrux/Crux`  
**Target planning repo:** `CueCrux/PlanCrux`  
**Branch:** `audit/crux-fixing-checklist-2026-06-15`

---

## 0. Audit scope and limits

This checklist records the follow-up work from a targeted audit of the `CueCrux/Crux` repository carried out on 2026-06-15.

The audit covered:

- repo shape, workspace layout, docs, threat model, CI, release, Docker, and fuzz workflows
- HTTP/MCP ingress hardening
- auth posture and JWT handling
- admin, facts, query, receipt/export, relations, console, and MCP server handlers
- release boundary scripts and supply-chain posture

The audit did **not** run the full local verification suite, fuzzers, dependency advisory tools, or a complete line-by-line review of all workspace crates. Each finding below must therefore be confirmed against current `main` before implementation.

Recommended baseline before fixing:

```bash
git checkout main
git pull --ff-only
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
scripts/assert-daemon-release-boundary.sh
```

Also run, or add if currently missing from CI:

```bash
cargo deny check
cargo audit
```

---

## 1. Priority map

| Priority | Meaning | Deployment gate |
|---|---|---|
| **P0** | Fix before any public or team-exposed deployment. | Blocks non-loopback / reverse-proxied use. |
| **P1** | Fix before broader beta or repeated operator usage. | Blocks “trust-first” posture claims. |
| **P2** | Hardening, correctness, and proof-quality improvements. | Should land before external audit / launch. |
| **P3** | Documentation, polish, and confidence-building. | Should land as part of normal roadmap. |

---

## 2. P0 — network and auth boundary fixes

### 2.1 Rate-limit bypass via spoofed passport header

**Status:** open  
**Area:** `crates/corecruxd/src/http/ingress.rs`  
**Severity:** high when exposed beyond trusted localhost  

The rate limiter keys by `X-Corecrux-Passport-Id` when the header is present, before route-level authentication has proved that the passport belongs to the bearer token. Tests also confirm that different passport IDs from the same IP get independent buckets.

**Risk:** An unauthenticated caller can rotate fake passport IDs to avoid per-IP throttling.

**Checklist:**

- [ ] Change pre-auth rate limiting to key by client IP unless the request already has an authenticated principal.
- [ ] Alternative acceptable fix: key by a combined `{client_ip, passport_header}` before auth, then by authenticated passport after auth.
- [ ] Add a maximum length and safe character policy for `X-Corecrux-Passport-Id` at ingress.
- [ ] Add a regression test: same IP + rotating unauthenticated passport headers must still reach `429`.
- [ ] Add a regression test: authenticated distinct passports may still receive independent buckets only after auth.
- [ ] Update ingress comments so they do not imply unauthenticated passport IDs are trustworthy.

**Suggested validation:**

```bash
cargo test -p corecruxd passport_key_enforced_with_429_retry_after_and_metric
cargo test -p corecruxd unauthenticated_rotating_passports_rate_limit_by_ip
```

---

### 2.2 Loopback reverse-proxy rate-limit bypass

**Status:** open  
**Area:** `crates/corecruxd/src/http/ingress.rs`, deployment docs, threat model  
**Severity:** high behind same-host reverse proxy  

The server uses `ConnectInfo<SocketAddr>` correctly, but loopback clients are exempt by default. If Caddy/nginx/Envoy connects to the daemon over `127.0.0.1`, all internet clients may appear loopback and bypass daemon-level rate limits.

**Checklist:**

- [ ] Decide supported posture: reverse proxy owns rate limiting, or daemon supports trusted proxy headers.
- [ ] If proxy headers are supported, add `CORECRUXD_TRUSTED_PROXY_CIDRS` and only trust `Forwarded` / `X-Forwarded-For` from those peers.
- [ ] Add a default-safe mode: untrusted `X-Forwarded-For` must be ignored.
- [ ] Add docs for Caddy/nginx deployment: either enforce proxy-side rate limits or configure trusted proxy CIDRs.
- [ ] Add tests for loopback proxy + external XFF mapping.
- [ ] Add tests showing spoofed XFF from untrusted non-proxy clients is ignored.

**Suggested validation:**

```bash
cargo test -p corecruxd trusted_proxy_rate_limit_keying
cargo test -p corecruxd untrusted_forwarded_for_is_ignored
```

---

### 2.3 MCP SSE GET lacks bearer auth and can leak session registrations

**Status:** open  
**Area:** `crates/crux-mcp/src/server.rs`, `crates/crux-mcp/src/sse.rs`  
**Severity:** high when MCP is reachable outside single-user localhost  

`POST /mcp` enforces bearer-token auth when an agent registry is configured. `GET /mcp` handles server info and SSE without the same agent-registry check. The SSE registry uses a process-global map. `unregister()` exists, but the GET handler does not call it when streams close.

**Risks:**

- unauthenticated SSE stream creation when agent tokens are configured
- session-ID squatting / notification interception in shared deployments
- registry growth from many unique session IDs

**Checklist:**

- [ ] Require bearer auth for SSE `GET /mcp` when `CRUX_AGENT_TOKEN(S)` are configured.
- [ ] Keep public server-info discovery separate if needed, but do not let unauthenticated callers open SSE streams.
- [ ] Limit `Mcp-Session-Id` length and accepted character set.
- [ ] Add a global cap on open SSE sessions.
- [ ] Add per-agent / per-IP caps on open SSE sessions.
- [ ] Wrap SSE streams so `unregister(session_id)` runs when the stream ends.
- [ ] Add tests for auth-required SSE when registry is non-empty.
- [ ] Add tests for cleanup after client disconnect / dropped receiver.

**Suggested validation:**

```bash
cargo test -p crux-mcp sse_requires_bearer_when_registry_configured
cargo test -p crux-mcp sse_unregisters_on_stream_end
cargo test -p crux-mcp sse_session_id_limits
```

---

### 2.4 Console settings/onboarding write endpoints need stronger auth

**Status:** open  
**Area:** `crates/corecruxd/src/http/console.rs`  
**Severity:** high if console is reachable by any untrusted browser/client  

Several console write-like endpoints are guarded by `admin:read`, and `post_console_onboarding_complete` appears to write onboarding state without an auth guard. It prevents `auth_mode=off` on non-loopback unless the explicit insecure override is set, but that is not sufficient for a write endpoint.

**Checklist:**

- [ ] Require `admin:write` for `put_console_settings`.
- [ ] Require `admin:write` for `post_console_onboarding_restart`.
- [ ] Gate `post_console_onboarding_complete`:
  - [ ] unauthenticated only during first-run onboarding
  - [ ] only when HTTP bind is loopback
  - [ ] only before `completed_at_unix_ms` is set, or behind a setup nonce
  - [ ] after initial setup, require `admin:write`
- [ ] Consider a local-only CSRF/setup nonce for browser-origin console setup.
- [ ] Add tests for first-run loopback onboarding.
- [ ] Add tests proving completed onboarding cannot be changed without `admin:write`.

**Suggested validation:**

```bash
cargo test -p corecruxd console_settings_requires_admin_write
cargo test -p corecruxd onboarding_complete_is_first_run_only
cargo test -p corecruxd onboarding_restart_requires_admin_write
```

---

## 3. P1 — SSRF, secrets, and resource-exhaustion hardening

### 3.1 Console embedding probe is an SSRF-style network probe

**Status:** open  
**Area:** `crates/corecruxd/src/http/console.rs`  
**Severity:** high for non-local or multi-user console deployments  

The console embedding probe accepts any `http://` or `https://` URL and the daemon probes `/api/tags` and `/v1/models`. It also rewrites localhost targets to Docker-aware hostnames. This is convenient for local Ollama/TEI setup but is also an internal-network probe.

**Checklist:**

- [ ] Require `admin:write` or a dedicated `console:probe` scope for embedding probe.
- [ ] Parse with a URL library; do not rely only on string prefix checks.
- [ ] Block metadata service ranges by default, including `169.254.169.254` and IPv6 equivalents.
- [ ] Block private/link-local CIDRs by default unless `CORECRUXD_ALLOW_PRIVATE_PROBE_CIDRS=1` or a configured allowlist is set.
- [ ] Add DNS rebinding protection: resolve and validate all returned addresses before connect.
- [ ] Redact detailed internal upstream errors for lower-privilege callers.
- [ ] Add tests for blocked link-local, RFC1918, localhost rewrite, and allowlisted local endpoints.

**Suggested validation:**

```bash
cargo test -p corecruxd embedding_probe_blocks_metadata_ip
cargo test -p corecruxd embedding_probe_blocks_private_cidr_by_default
cargo test -p corecruxd embedding_probe_allows_configured_local_endpoint
```

---

### 3.2 HS256 JWT secrets need strength enforcement

**Status:** open  
**Area:** `crates/corecruxd/src/auth.rs`, docs, examples  
**Severity:** medium/high depending on production use of `jwt_hs256`  

HS256 mode requires `CORECRUXD_JWT_HS256_SECRET`, but currently only empty secrets appear to be rejected. Weak secrets such as `secret` are accepted in tests.

**Checklist:**

- [ ] Require at least 32 bytes of random secret material for HS256.
- [ ] Prefer base64 or hex secret format with explicit decode errors.
- [ ] Add an explicit dev/test override for weak secrets, if tests need it.
- [ ] Update examples and docs to show strong generated secrets.
- [ ] Add tests for empty, short, and strong secrets.

**Suggested validation:**

```bash
cargo test -p corecruxd hs256_rejects_short_secret
cargo test -p corecruxd hs256_accepts_32_byte_secret
```

---

### 3.3 Global body and inflight defaults create a large memory envelope

**Status:** open  
**Area:** `crates/corecruxd/src/config.rs`, `crates/corecruxd/src/http/ingress.rs`  
**Severity:** medium/high under hostile traffic  

The default request body cap is 256 MB and default admitted in-flight cap is 4096. That is appropriate for some bulk/import routes but too permissive as a global default.

**Checklist:**

- [ ] Lower the global default body cap.
- [ ] Add route-specific larger body limits for bulk import / memory import / append paths that need them.
- [ ] Consider endpoint-specific in-flight classes: small query/admin routes should not compete with bulk upload routes.
- [ ] Add tests proving normal query/admin routes reject large bodies early.
- [ ] Add tests proving import/bulk routes still accept documented maximums.
- [ ] Document recommended limits for local dev vs reverse-proxied deployment.

**Suggested validation:**

```bash
cargo test -p corecruxd route_specific_body_limits
cargo test -p corecruxd admin_routes_reject_large_bodies
```

---

### 3.4 `/v1/version` should redact deployment-sensitive details for unauthenticated callers

**Status:** open  
**Area:** `crates/corecruxd/src/http/health.rs`  
**Severity:** medium  

`/v1/version` returns useful support data, but it also includes product posture, GPU posture, semantic profile, sync configuration state, remote URL, and update status. Public deployments should not leak this whole shape.

**Checklist:**

- [ ] Split public `/v1/version` from privileged `/v1/admin/version`, or dynamically redact unless `admin:read` is present.
- [ ] Keep public fields minimal: version, commit, MSRV, compat, public passport verification key if intentionally public.
- [ ] Move sync remote URL, update status, semantic profile, and posture internals behind `admin:read`.
- [ ] Add tests for public redaction and admin full view.

**Suggested validation:**

```bash
cargo test -p corecruxd version_public_view_is_redacted
cargo test -p corecruxd version_admin_view_includes_operational_details
```

---

## 4. P1 — route and coverage auditability

### 4.1 Add a route-auth matrix CI gate

**Status:** open  
**Area:** router, tests, CI  
**Severity:** high for long-term maintenance  

Auth is currently enforced inside handlers. The inspected handlers often do the right thing, but this style makes accidental unauthenticated routes easy to introduce.

**Checklist:**

- [ ] Generate or maintain a route manifest with these classes:
  - [ ] `public`
  - [ ] `read`
  - [ ] `write`
  - [ ] `admin`
  - [ ] `internal-replication`
  - [ ] `feature-gated`
- [ ] Add a test that fails when a route is not represented in the manifest.
- [ ] Add a test helper that asserts expected status for missing auth, weak scope, and correct scope.
- [ ] Add route coverage for console routes, MCP routes, admin actions, receipts/export, facts, sessions, relations, query routes, sync routes, and workbench routes.
- [ ] Include the matrix in docs or generated CI artifacts.

**Suggested validation:**

```bash
cargo test -p corecruxd route_auth_matrix_is_complete
cargo test -p corecruxd route_auth_scope_contracts
```

---

### 4.2 Coverage gate excludes high-risk HTTP boundary files

**Status:** open  
**Area:** `.github/workflows/ci.yml`, coverage policy  
**Severity:** medium/high  

The coverage ignore regex excludes several sensitive daemon HTTP files, including admin, append, query, projections, and receipts handlers. These are precisely the boundaries where auth, tenant isolation, export, and mutation bugs occur.

**Checklist:**

- [ ] Remove or reduce coverage exclusions for high-risk HTTP boundary files.
- [ ] If file-level coverage remains impractical, add explicit integration-test gates that cover:
  - [ ] route auth and scope checks
  - [ ] tenant isolation
  - [ ] export redaction
  - [ ] append bounds
  - [ ] admin action lifecycle
  - [ ] console write scopes
- [ ] Publish coverage exceptions in a short doc with rationale and compensating tests.
- [ ] Fix the README/CI coverage mismatch if still present.

**Suggested validation:**

```bash
cargo llvm-cov --workspace --all-features --summary-only
cargo test -p corecruxd http_boundary_contracts
```

---

### 4.3 Threat model drift must be fixed

**Status:** open  
**Area:** `docs/THREAT_MODEL.md`, CI  
**Severity:** medium/high for a proof-first product  

The threat model says the daemon does not implement application-level rate limiting, but code now implements body limits, concurrency caps, and keyed rate limiting. The threat model also claims `cargo deny check` and `cargo audit` run in CI; this was not visible in the inspected CI workflow.

**Checklist:**

- [ ] Update the threat model to describe current ingress hardening.
- [ ] Clarify reverse-proxy posture and loopback exemption interactions.
- [ ] Either add `cargo deny check` and `cargo audit` to CI or remove the claim.
- [ ] Add a CI/doc drift check for security claims where possible.
- [ ] Add a release checklist item: threat model reviewed when ingress/auth changes.

**Suggested validation:**

```bash
cargo deny check
cargo audit
```

---

## 5. P2 — correctness and integrity hardening

### 5.1 Admin action IDs need stricter validation

**Status:** open  
**Area:** `crates/corecruxd/src/http/admin.rs`  
**Severity:** medium  

Caller-supplied `actionId` is length-limited but not strongly charset-limited, then appears in event IDs and logs.

**Checklist:**

- [ ] Restrict action IDs to a safe charset such as `[A-Za-z0-9._:-]`.
- [ ] Reject control characters, whitespace, slashes, and very long path-like strings.
- [ ] Consider server-generated action IDs only, with caller metadata in a separate field.
- [ ] Add tests for accepted and rejected IDs.

**Suggested validation:**

```bash
cargo test -p corecruxd admin_action_id_rejects_unsafe_chars
```

---

### 5.2 MCP bearer token comparison and token policy

**Status:** open  
**Area:** `crates/crux-mcp/src/agent.rs`  
**Severity:** medium  

Agent token hashes are compared as arrays. That is acceptable for local development but not ideal for a trust boundary.

**Checklist:**

- [ ] Use constant-time comparison for token hashes.
- [ ] Enforce a minimum token length and prefix format.
- [ ] Reject empty or trivially short token values from env parsing.
- [ ] Warn on malformed `CRUX_AGENT_TOKENS` entries instead of silently skipping all malformed entries.
- [ ] Add tests for short tokens and malformed multi-agent env strings.

**Suggested validation:**

```bash
cargo test -p crux-mcp agent_token_policy
```

---

### 5.3 Console index writes should be made concurrency-safe

**Status:** investigate  
**Area:** `crates/corecruxd/src/console_index.rs`, append path  
**Severity:** medium  

The console chunk index reads a JSON file, mutates in memory, then writes and renames a temp file. If multiple append calls run concurrently, last-writer-wins behavior could drop chunk metadata.

**Checklist:**

- [ ] Confirm whether append path serialisation already prevents concurrent `record_appended_events` calls.
- [ ] If not guaranteed, add a process-level mutex around console index writes.
- [ ] Consider append-only JSONL for console chunk metadata plus periodic compaction.
- [ ] Add a concurrent write test that appends two batches and expects both to be present.

**Suggested validation:**

```bash
cargo test -p corecruxd console_index_concurrent_appends_preserve_all_chunks
```

---

### 5.4 Query self-observation facts need privacy and volume review

**Status:** investigate  
**Area:** `crates/corecruxd/src/http/query.rs`, `crates/corecruxd/src/fact_privacy.rs`  
**Severity:** medium  

Low-coverage queries can be recorded as ops facts when self-observe is enabled. The entity prefix appears to fall under the default private prefixes, which is good, but the path should be reviewed for volume and raw-query leakage.

**Checklist:**

- [ ] Confirm `__ops__::` facts are always born private on this path.
- [ ] Consider hashing or redacting raw query text before storing ops coverage events.
- [ ] Add rate limits / sampling for low-coverage self-observation facts.
- [ ] Add tests proving self-observe query facts are private and not synced.

**Suggested validation:**

```bash
cargo test -p corecruxd self_observe_query_coverage_facts_private
```

---

## 6. P2 — supply chain, fuzzing, and release gates

### 6.1 Add CI dependency advisory gates or fix docs

**Status:** open  
**Area:** `.github/workflows/ci.yml`, `deny.toml`, `docs/THREAT_MODEL.md`  
**Severity:** medium  

The repo has `deny.toml`, but inspected CI did not visibly run `cargo deny` or `cargo audit`.

**Checklist:**

- [ ] Add `cargo deny check` to CI.
- [ ] Add `cargo audit` or a maintained equivalent advisory scan to CI.
- [ ] Decide whether advisory failures block PRs, release only, or both.
- [ ] Document any ignores with owner and expiry.

---

### 6.2 Make Docker vulnerability scan exceptions receipted

**Status:** open  
**Area:** `.github/workflows/docker.yml`, release policy docs  
**Severity:** medium  

Docker workflow supports a manual Trivy gate skip. That is pragmatic, but a trust product should require a structured waiver.

**Checklist:**

- [ ] Require waiver ID for `skip_trivy_gate`.
- [ ] Require expiry date and approver in workflow inputs.
- [ ] Emit the waiver into the release manifest or audit artifact.
- [ ] Add a follow-up issue automatically when a skip is used.
- [ ] Fail if the waiver is expired.

---

### 6.3 Promote fuzzing from weekly hygiene to release-confidence infrastructure

**Status:** open  
**Area:** `.github/workflows/fuzz.yml`, fuzz targets  
**Severity:** medium  

Fuzz targets exist for important parsers/verifiers, but the current posture should be strengthened for release confidence.

**Checklist:**

- [ ] Keep the weekly long fuzz run.
- [ ] Add short PR fuzz runs when parser/verifier crates are touched.
- [ ] Retain and publish minimized crash artifacts.
- [ ] Persist corpora between runs.
- [ ] Add explicit release checklist: last fuzz run green.

---

## 7. P3 — docs, positioning, and trust hygiene

### 7.1 Make at-rest confidentiality boundaries more visible

**Status:** open  
**Area:** README, threat model  
**Severity:** documentation/trust  

The threat model is honest that BLAKE3 provides integrity, not confidentiality, and that data at rest is not encrypted unless the operator uses filesystem encryption. That boundary should be visible in the README near Quickstart.

**Checklist:**

- [ ] Add a README note: local data is integrity-protected but not encrypted at rest by default.
- [ ] Recommend filesystem encryption for sensitive deployments.
- [ ] Clarify which integration secrets are envelope-encrypted and which data remains plaintext on disk.

---

### 7.2 Publish signed benchmark packs for headline claims

**Status:** open  
**Area:** README, `docs/benchmarks.md`, release artifacts  
**Severity:** product trust  

Performance and LongMemEval-style claims are high-value claims. They should link to corpus/config/commit/output artifacts.

**Checklist:**

- [ ] Create signed benchmark packs containing inputs, configs, commit SHA, command line, and outputs.
- [ ] Link README numbers to those packs.
- [ ] Mark unpublished or preliminary claims as preliminary.
- [ ] Add a benchmark reproduction command.

---

### 7.3 Keep release-boundary checks, but make scope clear

**Status:** keep / document  
**Area:** `scripts/assert-daemon-release-boundary.sh`, README  
**Severity:** documentation  

The release-boundary script is a strong signal: it checks for required distribution files and blocks hosted GPU/CUDA surface leakage. Keep it, but make clear that it covers daemon distribution scope, not hosted platform completeness.

**Checklist:**

- [ ] Document exactly what the boundary script proves.
- [ ] Add a note that hosted backend/GPU surfaces are out of this repo.
- [ ] Keep the boundary script in CI and release.

---

## 8. Regression test pack to add

Add a dedicated integration-test module, or multiple focused modules, that cover the findings above.

**Checklist:**

- [ ] `unauthenticated_rotating_passports_rate_limit_by_ip`
- [ ] `trusted_proxy_rate_limit_keying`
- [ ] `untrusted_forwarded_for_is_ignored`
- [ ] `sse_requires_bearer_when_registry_configured`
- [ ] `sse_unregisters_on_stream_end`
- [ ] `console_settings_requires_admin_write`
- [ ] `onboarding_complete_is_first_run_only`
- [ ] `embedding_probe_blocks_metadata_ip`
- [ ] `embedding_probe_blocks_private_cidr_by_default`
- [ ] `hs256_rejects_short_secret`
- [ ] `version_public_view_is_redacted`
- [ ] `route_auth_matrix_is_complete`
- [ ] `admin_action_id_rejects_unsafe_chars`
- [ ] `self_observe_query_coverage_facts_private`
- [ ] `console_index_concurrent_appends_preserve_all_chunks` if concurrency risk is confirmed

---

## 9. Suggested implementation order

1. **Patch route/auth hazards first**
   - rate-limit passport spoofing
   - MCP SSE auth and cleanup
   - console write scopes / onboarding guard
   - embedding probe SSRF guard

2. **Patch production hardening next**
   - reverse-proxy rate-limit posture
   - HS256 secret strength
   - version endpoint redaction
   - body-limit route classes

3. **Add proof against regression**
   - route-auth matrix
   - regression test pack
   - CI dependency advisory gates

4. **Clean docs and trust posture**
   - threat model update
   - README confidentiality note
   - benchmark artifact links
   - release waiver policy

---

## 10. Definition of done

This checklist is complete when:

- [ ] All P0 and P1 items have PRs merged or have an explicit accepted-risk waiver.
- [ ] The route-auth matrix exists and fails closed on new unclassified routes.
- [ ] Threat model matches the code for ingress, rate limiting, dependency scanning, auth modes, and at-rest data posture.
- [ ] CI includes dependency advisory scanning, or docs no longer claim it does.
- [ ] Security-sensitive HTTP route files are either covered or explicitly protected by integration-test gates.
- [ ] Release artifacts include any required waivers and benchmark receipts.
- [ ] A final audit run records exact commit SHAs, command output, and any remaining accepted risks.

---

## 11. Notes for implementers

- Treat this as a planning checklist, not proof that each bug is exploitable in every deployment mode.
- Most issues are severe only when the daemon is reachable outside a trusted single-user loopback setup.
- The repo already has strong foundations: explicit auth modes, non-loopback guardrails for dev/off auth, release signing, SBOM/provenance workflows, fuzz targets, and clear boundary scripts. This checklist is about closing edge-surface gaps so the proof-first posture stays true as the surface grows.
