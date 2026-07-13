# M3 Governance Tier — Crux Daemon Report

Date: 2026-07-13

## Outcome

The Crux half of the M3 governance milestone is implemented. Incident reconstruction is
the primary workflow, certified evidence exports now use a stable issuer by default,
and minimal legal holds are enforced across soft forget, retention eligibility, and
hard erasure. The local coordination plane remains free, default-on, and ungated.

## Built

### Incident reconstruction

- Added `POST /v1/incidents`, `GET /v1/incidents`,
  `GET /v1/incidents/{id}`, and `POST /v1/incidents/{id}/export`.
- Incident cases merge selected reasoning timelines, entity timelines, observations,
  mediation records, coordination announces and lease history, and cost totals into a
  deterministic time-ordered event stream.
- Events retain their source lane, timestamp, actor identity, record or receipt ID where
  available, payload, and one of `verifiable_record`, `mediated_evidence`, or
  `self_reported` as their assurance class.
- Cost is reported as case/session totals. The existing cost lane does not expose a
  sufficiently cheap, stable per-event join key, so the case says explicitly that no
  per-event cost join was performed.
- Added `corecruxctl incident create`, `incident show`, and `incident export`.
- Export uses the existing signed audit-bundle builder. It includes the case JSON,
  referenced receipt envelopes, and signed-covered `VerificationReportV1` records, and
  verifies with the existing offline audit verifier.

### Certified evidence packs

- Added one resolver shared by MCP, daemon incident export, and CLI audit export.
- Resolution order is an operator-supplied environment key, a data-directory key, then
  an ephemeral key only when no data directory exists.
- The data-directory key is generated once as
  `audit-export-signing.key`, written with mode `0600`, and reused on subsequent opens.
- Audit bundle format v3 signs both the issuer public key and a `key_class` of `env`,
  `persistent`, or `ephemeral`. Offline verification remains compatible with existing
  v1 and v2 bundles.
- Added independent v3 archive vectors and updated the standalone generator and verifier.

### Legal holds

- Added `POST /v1/legal-holds` and `DELETE /v1/legal-holds/{id}` with signed observation
  receipts for placement and release.
- A hold covers a tenant and, optionally, entity prefixes. Active matching holds:
  - reject `memory_forget` with the structured `LEGAL_HOLD_ACTIVE` error and hold details;
  - cause `FactStore::mark_retention_eligible` to skip the covered facts; and
  - reject ordinary hard-delete compaction for covered facts.
- Full-tenant GDPR erasure wins only when the caller explicitly requests the existing
  full-tenant erasure mode. That path persists complete override material, emits a signed
  `legal_hold_overridden` receipt, and then enters the guarded compaction path.

### Coordination packaging

The architecture documentation now states the packaging boundary: the local coordination
plane remains free, default-on daemon functionality; Governance packaging applies to
hosted fleet aggregation, attribution, and policy in CruxEngine. No coordination-plane
code or availability changed.

## Feature flags

All governance features introduced or used here are default-off:

| Flag | Scope | Default |
| --- | --- | --- |
| `CORECRUXD_FEATURE_INCIDENTS` | Incident routes and export | off |
| `CORECRUXD_FEATURE_LEGAL_HOLD` | Legal-hold placement and release routes | off |
| `CORECRUXD_FEATURE_AUDIT_EXPORT` | Existing MCP audit-export tool | off |

Existing legal holds continue to enforce protection even if placement/release is later
disabled; turning a feature flag off cannot silently remove an active hold.

## Decisions

### Case persistence

Cases use the existing `FactStore` rather than a new side store. Each current case is a
private fact at entity `__incident__::<id>`, key `case`, with no retention horizon. The
prefix is registered in both the privacy policy and cruxpack filtering, so cases are
born private and stay aligned with existing versioning, tenant isolation, and backup
behavior.

Legal-hold state follows the same established reserved-fact pattern under
`__legal_hold__::<id>`; override receipt material uses
`__legal_hold_receipt__::<id>`.

### GDPR versus legal hold

Explicit full-tenant GDPR erasure wins. It cannot be inferred from a free-form reason:
the caller must provide the full-tenant erasure selector, the server records which holds
were overridden, and a signed `legal_hold_overridden` receipt is required before guarded
compaction. Ordinary hard deletion remains blocked.

### Issuer lifetime

Persistent issuer creation is lazy on the first enabled audit or incident export rather
than unconditional daemon startup. This keeps default-off governance functionality
dormant while still giving every exporting daemon data directory a stable, pinnable
issuer across restarts. An environment key always wins.

## Principal files

- Incident HTTP and assembly: `crates/corecruxd/src/http/incidents.rs`
- Legal-hold HTTP and receipts: `crates/corecruxd/src/http/legal_holds.rs`
- HTTP/auth/OpenAPI wiring: `crates/corecruxd/src/http/mod.rs`,
  `crates/corecruxd/src/http/route_auth.rs`, `crates/corecruxd/src/http/openapi.rs`
- Supporting timeline/observation reads: `crates/corecruxd/src/http/workbench.rs`,
  `crates/corecruxd/src/http/observations.rs`
- GDPR override enforcement: `crates/corecruxd/src/http/admin.rs`
- Incident CLI: `crates/corecruxctl/src/incident.rs`,
  `crates/corecruxctl/src/main.rs`, `crates/corecruxctl/src/lib.rs`
- Shared key resolution and bundle format:
  `crates/corecrux-receipts/src/audit_signing_key.rs`,
  `crates/corecrux-receipts/src/audit_bundle_v1.rs`,
  `crates/corecrux-receipts/src/lib.rs`
- Audit-export callers: `crates/crux-mcp/src/tools/audit_export.rs`,
  `crates/corecruxctl/src/audit_export.rs`
- Legal-hold model/enforcement: `crates/corecrux-memory/src/legal_hold.rs`,
  `crates/corecrux-memory/src/fact_store.rs`, `crates/corecrux-memory/src/lib.rs`
- Forget enforcement: `crates/crux-mcp/src/tools/forget.rs`
- Privacy/export reserved prefixes: `crates/corecrux-memory/src/fact_privacy.rs`,
  `crates/corecrux-memory/src/cruxpack.rs`
- Bundle vectors/tools/spec: `crates/corecrux-receipts/vectors/audit-bundle-v1/`,
  `crates/corecrux-receipts/examples/gen_audit_bundle_archive_vectors.rs`,
  `tools/gen_audit_bundle_vectors.py`, `tools/verify_audit_bundle_v1.py`,
  `docs/spec/audit-bundle-v1.md`
- Packaging/config docs: `docs/architecture.md`, `config.example.env`, `llms-full.txt`
- Generated route client: `crates/corecruxd/console/v2/api.js`

## Verification

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --workspace -- -D warnings`: passed.
- `cargo doc --no-deps -p corecruxd -p corecruxctl -p crux-mcp -p corecrux-receipts -p corecrux-memory`:
  passed.
- `scripts/build-llms-full.sh --check`: passed.
- Route/OpenAPI generated-client drift test: passed (2 passed, 1 intentionally ignored).
- Seeded incident assembly/export test: passed. It covers two sessions, reasoning facts,
  observations, mediation evidence, merged ordering, every assurance class, private case
  persistence, `VerificationReportV1` content, and export-to-offline-verify roundtrip.
- Persistent-key tests: passed for first creation with `0600`, reuse, environment override,
  malformed configured key rejection, and ephemeral fallback without a data directory.
- Legal-hold tests: passed for forget refusal, retention skipping, ordinary hard-erasure
  refusal, signed place/release receipts, and signed GDPR override.
- Independent audit-bundle verifier: passed for unpacked and archived v1, v2, and v3 vectors.
- New Rust source files contain the required CCL licence header.

The requested combined test command was run. Every non-network test completed without a
failure. The only failures were the expected sandbox restriction when tests attempted a
loopback `TcpListener` bind (`PermissionDenied`):

| Test binary/package | Passed | Bind-only failures | Ignored |
| --- | ---: | ---: | ---: |
| `corecrux-memory` unit tests | 201 | 0 | 0 |
| `corecrux-memory` sync integration | 2 | 5 | 0 |
| `corecrux-receipts` | 221 | 0 | 0 |
| `corecruxctl` | 755 | 44 | 0 |
| `crux-mcp` | 719 | 12 | 0 |
| `corecruxd` | 1813 | 20 | 2 |

The orchestrator should rerun the combined test command outside the restricted sandbox,
where loopback binds are permitted.

## Deferred and out of scope

No requested daemon feature was deferred. Per the brief, SAR/RTBF automation, organization
trust graphs, cross-tenant aggregation, hosted fleet governance, and all CruxEngine work
remain out of scope. The local coordination plane was deliberately not tier-gated.
