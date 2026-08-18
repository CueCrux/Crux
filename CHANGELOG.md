# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Cadence:** weekly rolling builds are cut from `main`; versioned releases
> ship every 4–8 weeks. Every versioned release gets human-readable notes
> here — if you tag a release, you write its entry.

## [Unreleased]

### Fixed

- **The console Gates page rendered "queue is clear" while approvals were
  waiting in another tenant.** `GET /v1/work/gate/pending` resolved the caller
  to exactly one tenant via `resolve_authorized_tenant`, which collapses a
  wildcard/admin credential to `default`. Pending gates held in any other
  tenant — the reported case had two under `work` — were filtered out, and
  `/console#/trust/cx-gates`, which asked with no tenant context at all,
  showed the rich empty state. That hides the passport-attributed Art.14
  human-oversight path exactly when it is owed.

  The read now answers for **every tenant the credential is authorized for**
  and declares that scope on the wire as `tenant_scope` (`["*"]` = all).
  A verified wildcard token spans every tenant; a multi-tenant token lists the
  tenants it owns (where the single-tenant write resolver refuses to guess); a
  single-tenant token is unchanged; a token with no tenant claim is still
  refused. Auth-off/DevScopes stay confined to `default` — those wildcards are
  a local-development convenience, not a proven principal, so an
  unauthenticated reader still has to name a tenant rather than enumerate the
  queue. Naming `?tenant_id=` keeps the previous, narrower behaviour and every
  existing denial.

  The Gates page carries the scope verbatim, offers an authorized-tenant
  selector, names each row's tenant, refuses to reuse the "queue is clear"
  state when the view is narrowed, and renders a failed or unauthorized read as
  an explicit failure instead of an empty queue. The same fix reaches the
  Overwatch "needs you" lane and "Withhold all", which read the same endpoint.
  Approve/reject are untouched: still operator-gated, canonical-passport bound,
  and still mint a CROWN `ad_ga_*` receipt. (#703)

## [0.5.59] - 2026-08-08

### Fixed

- **Erasing a tenant's corpus could take every subsequent write down with it.**
  `POST /v1/admin/forget-tenants` with `"reclaim": true` deleted each
  whole-tenant segment's file group but never updated the shard MANIFEST.
  `ShardStorage::open` opens every segment the manifest references, and local
  ingest opens the shard once per request, so from the first reclaim onward
  *every* `POST /v1/local/ingest` returned 500 — while reads, which scan the
  `segments/` directory rather than the manifest, carried on normally. On the
  affected host that combination went unnoticed for 38 hours: 17 dangling
  entries, all ingest dead, `/readyz` green throughout.
  - Reclaim now appends a `RemoveSegment` tombstone to the manifest and fsyncs
    it **before** unlinking anything. A crash in that window leaves files on
    disk under a manifest that has already forgotten them — inert, and
    reclaimable again — instead of files deleted with the manifest still
    pointing at them.
  - If the manifest cannot be updated, nothing is unlinked and the response says
    so (`reclaimed: false`, plus a `manifest_error`) rather than reporting a
    reclaim that did not happen.
  - `RemoveSegment` is a new manifest record type. Removal is expressed as an
    **append**, so no existing record or checksum is rewritten. Older daemons
    skip the unknown record and simply see the pre-repair state, which makes a
    downgrade safe but means an affected shard is only repaired once running
    0.5.59 or later.
- **`corecruxctl storage repair-manifest`** reports MANIFEST entries whose
  segment file is missing, and with `--apply` retires them. It works on the
  manifest alone rather than through `ShardStorage`, because opening the shard
  is precisely what a shard in this state can no longer do.
- **Live `.ccxp` embedding-profile sidecars were being quarantined on every
  shard open.** The companion allowlist named `.ccxi` and `.ccxv` but not
  `.ccxp`, so each open swept every profile sidecar out of `segments/`. This
  failed silently in the worst direction: a segment with no `.ccxp` reads as
  legacy and is scored *without* the embedding-fingerprint check the sidecar
  exists to enforce. Recovering the files is a matter of moving them back out of
  `quarantine/`.

### Added

- **The write path now has a health signal.** Local-ingest seal failures
  increment `corecrux_local_ingest_seal_failed_total`, and after 3 consecutive
  failures `/readyz` reports `local_ingest_seal` unhealthy with the underlying
  error. Consecutive rather than cumulative, so a single malformed document
  cannot unready a node. Tune or disable with
  `CORECRUXD_SEAL_FAILED_READYZ_THRESHOLD` (`0` disables); it defaults to on,
  because a write path that fails silently is what made the outage above last as
  long as it did.

## [0.5.58] - 2026-08-07

### Fixed

- **Ingest can no longer seal a corpus with no vectors and call it healthy.**
  `POST /v1/local/ingest` returned an ordinary `202` with `sealed: true`, a full
  `frame_count` and `dense_vectors: 0` whenever the embed step failed. BM25 still
  indexes, so the tenant looked fine while semantic retrieval was simply gone —
  a corpus that reads as healthy and answers worse, with nothing in the response
  to check. The cause was **ureq's default 10 MiB response-body cap**, hit while
  *reading* the embedder's reply: a 1024-dim vector is ~12.6 KB of JSON, so a
  batch past roughly 830 chunks overflowed it. The ceiling therefore moved with
  the embedding dimension, not the chunk count, which is why 749 chunks passed
  and 776 failed.
  - `EmbeddingClient::embed_batch` now issues sub-batches of at most 128 texts
    and concatenates in order, so how many chunks a caller sends no longer
    decides whether embedding succeeds. A failing sub-batch fails the whole call
    — never a short or partially embedded result.
  - The `202` carries `dense_status` (`ok` | `partial` | `skipped` |
    `not_configured` | `not_applicable`) and `dense_expected` beside the existing
    `dense_vectors`, and the daemon logs `local-ingest-dense-gap-sealed` at WARN
    with the segment sequence. **Assert `dense_status == "ok"`** after any ingest
    that expects semantic recall. `crux-ingest` asserts it for you and warns when
    a batch seals lexical-only.
  - Both fields are additive: a client that ignores them sees the response shape
    it saw before.
  - This matters beyond the response cap — *any* embedder error took the same
    silent path. An audit of one host found 41 of 641 segments sealed
    lexical-only, most of them from ordinary `502`s.
- **`/v1/local/ingest` honours the request-body limit its own error advertises.**
  The route inherited axum's 2 MiB `DefaultBodyLimit` while its `413` named the
  16 MiB daemon limit, so every client that sized batches from that number sized
  them eight times too large.

### Added

- **`segment_seq` on query results.** Each `/v1/query/text-search` result and
  `/expand` chunk now carries the sealed segment's own sequence — the value the
  ingest receipt returned — so a consumer can join a result back to the ingest
  that produced it. `segment_index`, which sits beside it, is a position in the
  daemon-wide loaded-reader list: it is **not** convertible to `segment_seq`, and
  the difference between them was measured at 1, then 18, then 17 on one host
  within hours as unrelated segments came and went. Deriving one from the other
  unmaps every hit at once and scores a plausible, uniform 0% instead of
  erroring. `segment_index` is unchanged for existing consumers.

## [0.5.57] - 2026-08-07

### Fixed

- **A CPU-only daemon can verify the governance receipts it mints.** Erasure,
  `compact_facts` erasure, `memory_forget` and held hard-erasure overrides all
  persist their receipt as the observation envelope itself — Ed25519, passport
  signed, on disk. Until now none of the three documented surfaces could attest
  to one: `GET /v1/receipts/{id}` is 501 without a dataplane (by design), the
  verification endpoint's local fallback only understood *stream* receipts, and
  `corecruxctl inspect-receipt` searches sealed segments, where a governance
  receipt never appears. The daemon produced an audit artefact nothing could
  check.
  - `GET /v1/receipts/{id}/verification` gains a second local fallback for the
    observation-envelope shape, reporting
    `crux.governance_receipt_verification.v1`. A caller lacking scope for the
    receipt's *own* tenant gets **404**, byte for byte identical to a missing
    receipt, so the endpoint cannot be used as a cross-tenant existence oracle.
  - `corecruxctl inspect-receipt` resolves and verifies them too, printing kind,
    signer, body hash and signature status.
  - Both scans are bounded to `__governance__*` logs. This is a correctness
    constraint, not a tuning choice: a production node carries tens of thousands
    of per-session observation logs, and walking them all on an audit lookup
    would make verification a denial-of-service surface.
- **`serde_json/preserve_order` is now declared where the wire format is
  defined.** `canonical_body_bytes` signs `serde_json::to_value(record)`, so map
  ordering *is* the signed format. `corecruxd` only had the feature because
  `crux-session` happens to enable it and Cargo unifies features across the
  graph — an accidental dependency that left the audit trail one dependency
  change away from every existing receipt failing to verify. The feature is now
  declared by `corecrux-receipts` and pinned by a golden-vector test.

### Changed

- Observation record types, `canonical_body_bytes` and
  `verify_observation_envelope` move from `corecruxd` into `corecrux-receipts`.
  `corecruxd` is a bin-only crate, so `corecruxctl` could not otherwise reach
  the verifier; sharing beats a second copy of a signature check that can drift.

### Added

- `corecruxctl start --agent <claude|codex|cursor>`.
- LlamaIndex and CrewAI adapters under the unchanged conformance suite.
- Console Patchbay no longer freezes the tab when a system has more than 28
  plans; drift reporting distinguishes a rejected credential from an
  unreachable daemon.

## [0.5.56] - 2026-08-07

### Added

- **A tenant's retrieval corpus can finally be erased.** Until now a corpus
  could be created but never retired, so a mis-ingested or superseded tenant was
  permanent — and there was no GDPR Art.17 story for the daemon. Two layers,
  deliberately separated by reversibility:
  - *Layer 1, logical erasure.* A persisted set of forgotten
    `(tenant_hash, watermark_segment_seq)` pairs, enforced in the BM25 scorers
    as a **required** parameter rather than an optional wrapper — so the
    compiler forces every present and future serving path to state its intent
    instead of one being silently missed. Reversible via
    `DELETE /v1/admin/forget-tenants/{tenantId}`.
  - *Layer 2, physical reclaim.* Opt-in per request (`"reclaim": true`), never
    automatic. Whole-tenant segments are evicted from the `IndexManager` and
    only then unlinked; mixed-tenant segments are retained, still masked, and
    reported as `mixed_segments_retained`. Irreversible — recovery is
    restore-from-backup only.
  - `POST /v1/admin/forget-tenants` (+ singular alias) requires `admin:write`
    **per named tenant**, with the whole batch rejected if any tenant fails and
    nothing masked. Reserved `__`-prefixed namespaces are refused by convention,
    so a future reserved namespace is protected the day it is introduced.
  - `GET /v1/admin/tenants/{tenantId}/footprint` reports segments, docs and
    bytes, so the blast radius is inspectable *before* anything is erased.
  - The whole surface is gated on `CORECRUXD_TENANT_ERASURE=1` and the routes
    404 without it. Fact-store erasure remains out of scope: the response key is
    `corpus_erased`, never `tenant_forgotten`.
- Key escrow M0–M3b, device-identity and CRL transport auth for the relay, and a
  span outcome dimension.
- Console Patchbay — a spatial projection of the open work board
  (`GET /v1/work/graph`).

### Changed

- Tenant scoping tightened across the stack: derived from the token, applied by
  type, exact-matched, and pushed down into gRPC and the lower layers.
- Login verification is strict, and M1 auth fails closed.

## [0.5.55] - 2026-08-02

### Added

- **Account entitlement is now a verified property of a signed token, not an
  environment variable.** Three milestones of
  `crux-pro-capabilities-rcx-entitled-2026-07-27` land together, all **dark** —
  nothing enforces on them yet, `OperatingMode` still comes from
  `CORECRUXD_OPERATING_MODE`, and the cutover is a later milestone.
  - `corecruxd::entitlement` — an on-disk entitlement store on the reserved
    `__entitlement__::rcx` entity (born private, no freshness horizon), plus
    `resolve_entitlement`: revocation → presence → parse → tenant scope →
    signature → expiry → tier. Forgery and revocation always resolve
    `FreeLocal`; an expired token follows its own `FallbackPolicy`, so a paying
    user who is merely offline keeps working.
  - `corecruxd::pairing` — the daemon half of account pairing, reusing the
    RFC 8628 device grant already shipped at `/v1/auth/device/*`. No licence key
    and no typed secret: the `user_code` is a short-lived, single-use public
    correlator, useless without an authenticated browser session, and never
    written to configuration.
  - `OperatingMode::GovernanceHosted`. `MaxPrivate` remains a composite —
    Governance entitlement plus a private deployment shape — so no issuer can
    hand it out.

### Changed

- **`RcxTier` cut over to the published ladder: `Free | Pro | Governance`.**
  The previous `Free | Pro | Team | Enterprise` matched no product CueCrux
  sells. `Team` is retired outright and `Enterprise` becomes `Governance`;
  `crux-enterprise-shim` re-gates accordingly (`not_enterprise_tier` →
  `not_governance_tier`). Retired values now fail *deserialisation*, which is
  what makes a stale token fail closed to `FreeLocal` rather than resolve to
  some default. `team_scope` and `enterprise_scope` stay on the token: removing
  either would change the signed bytes for every tier, not just the retired one.
- **New spec version `rcx-ct/1.2`, accepted alongside `rcx-ct/1.1` rather than
  replacing it.** The spec-version check is not a version ladder but a match
  with a rejecting catch-all, so repointing the 1.1 constant would have failed
  every delegation token already minted. `1.2` is a *tier-vocabulary* version and
  is orthogonal to delegation: 1.0 forbids a delegation policy, 1.1 requires
  one, 1.2 makes it optional — a plain entitlement token carries none. A
  cross-language byte-parity vector pins the Rust and TypeScript encoders
  together on a `1.2` token with `tier: governance`.
- **`corecruxd` split into sibling crates** — `corecrux-workspace-scan`,
  `corecrux-billing`, `corecrux-providers` and `corecrux-secrets` — with the
  unwrap ratchet re-baselined across the new boundary and `AGENTS.md` added for
  the extracted crates.
- Desktop shell gains isolated Registry and WikiCrux tabs.
- Workspace test coverage raised from 88.49% to 90.11% across the nine
  highest-debt files.

### Fixed

- **Seat identity is taken from the credential, not the request body**, closing
  a bypass of the M8 per-seat rate ceiling on enriched verdicts.
- **`dossier` and `storybook` now authorise against the tenant they answer for**
  (code-intel M3b).
- `ledger:history` is no longer advertised as a Pro claim. The route is fully
  implemented but nothing produces a record, and selling a capability with no
  producer is a truth-in-selling problem; the route and its handlers stay.
- `run_git` gained a real wall-clock deadline. `GIT_TIMEOUT_SECS` fed only
  `GIT_HTTP_LOW_SPEED_TIME`, an HTTP-transport setting that neither a local
  `git blame` nor an SSH remote ever consults, so the call could block
  unbounded on a stale `index.lock`.
- `corecruxctl --version` now exists. It had no version surface at all, unlike
  `crux-hook` and `corecruxd`.
- The console `.mcpb` is rebuilt so it ships Apache-2.0 rather than the retired
  CCL-1.0.
- The config wizard parses profile frontmatter on a CRLF checkout.
- The release path and a hang guard that was failing tests are unbroken.

### Security

- **wasmtime 47.0.2 → 47.0.3**, clearing [RUSTSEC-2026-0222] (stores can mix up
  type indices between engines) and [RUSTSEC-2026-0223] (preemption and traps
  during bulk operations break internal VM state). Lockfile only; `wasmtime` is
  optional behind the default-off `wasm-extensions` feature, so default builds
  never compiled it.

[RUSTSEC-2026-0222]: https://rustsec.org/advisories/RUSTSEC-2026-0222
[RUSTSEC-2026-0223]: https://rustsec.org/advisories/RUSTSEC-2026-0223

## [0.5.54] - 2026-07-30

### Changed

- **Relicensed to Apache-2.0 — Crux Daemon is now open source.** The CueCrux
  Community Licence (CCL v1.0), a source-available BSL-style licence, is
  replaced by the **Apache License, Version 2.0** across the repository. The CCL
  already named Apache 2.0 as its Change Licence, so this brings that conversion
  forward for every version instead of waiting out the per-release three-year
  clock. Redistribution in competing products and offering Crux as a hosted
  service to third parties — the two rights the CCL withheld — are now granted,
  along with Apache-2.0's express patent grant (section 3).
  - `LICENCE.md` → `LICENSE`, containing the unmodified upstream Apache-2.0
    text, so GitHub and SBOM scanners detect `Apache-2.0` instead of reporting
    an unrecognised custom licence.
  - New `NOTICE` file carrying the attribution required by section 4(d), plus
    the trademark and `content/` scope notes that must not be edited into the
    verbatim licence text.
  - Per-file headers on all 539 crate `.rs` files (and every script, workflow,
    proto, SDK source, and console asset) now read
    `SPDX-License-Identifier: Apache-2.0`. The contradictory
    "All rights reserved." line is dropped.
  - `license = "Apache-2.0"` in `[workspace.package]` and in the desktop shell,
    Python/TypeScript SDK, deb, Homebrew, and MCPB manifests;
    `LicenseRef-CCL-1.0` removed from the `cargo-deny` allowlist.
  - `scripts/check-licence-headers.sh` now enforces the Apache-2.0 header and
    SPDX line. Contribution terms in `CONTRIBUTING.md` are inbound=outbound
    under section 5 — no CLA. `docs/LICENCE-FAQ.md` rewritten;
    `docs/design/licence-recommendation.md` (the BUSL 1.1 proposal) marked
    superseded.
  - Curated content under `content/` keeps its separate licence
    (`content/LICENCE-CONTENT.md`) and is unaffected; that directory currently
    ships a placeholder manifest with no covered assets.
- **Licence file layout deduplicated to a single GitHub licence tab.**
  `LICENCE-CODE.md` (a three-line stub pointing at `LICENCE.md`) is removed, and
  the content licence moved from the root to `content/LICENCE-CONTENT.md` — the
  directory it governs. GitHub's licence detector scans only the repository
  root, so it now surfaces one top-level licence (`LICENCE.md`, the code
  licence) instead of two tabs. `LICENCE.md` links to the content licence, and
  release bundles ship it under `content/` alongside the assets it covers.

### Added

- **The token-burn cost lens gains a model/effort axis.** `crux-cost` already
  opened every transcript line by line and discarded what it found: `gitBranch`
  was parsed but used only as an internal ranking tie-breaker, and `model`,
  `effort` and `cwd` were not parsed at all. All four are now parsed onto the
  event, promoted onto `CostReport`, and rolled up into a per-model burn
  breakdown with per-effort burn *within* each model, rendered by both
  `corecruxctl session cost` and the console `cx-cost` page.
  - **It reconciles.** Per-model context, plus the `<synthetic>` pseudo-model,
    plus records carrying usage but no model id, sum exactly to
    `headline.measured_context_total`.
  - **Coverage travels with every effort number.** `effort` is absent from 61%
    of the measured corpus and its absence correlates with model — 100% / 100% /
    22.5% / 9.4% across 46,239 assistant records — so a cross-model effort
    comparison is confounded at source and no sample size fixes it.
    `effort_coverage_pct` lives on the type, so no surface can render an effort
    figure without the denominator that qualifies it.
  - `<synthetic>` is reported separately, never ranked as a model and never
    dropped. Model-id normalisation folds only stable presentation variants
    (`[1m]` context suffix, `us.anthropic.`/`bedrock/`/`vertex/` route prefixes,
    `-v1:0`); floating aliases such as `opus` and `sonnet` are deliberately left
    unresolved, since resolving them would silently merge two models the day the
    alias moves.
  - The five new `CostReport` fields are additive, serde-default and omitted
    when absent, so an older daemon ignores a newer report and a legacy report
    is unchanged on the wire. A daemon must be upgraded before the console can
    render the axis.
  - Adds the cost lane's first integration coverage: a post-then-get test
    through both `/v1/cost/report` handlers.

- **`CITATION.cff`.** Machine-readable citation metadata (GitHub "Cite this
  repository" button). Under Apache-2.0 citation is appreciated but not a
  licence condition.

- **A Windows GUI smoke lane for the desktop shell.** `desktop-shell.yml` gains
  `desktop GUI smoke (windows, interactive session)`, running on a self-hosted
  runner that executes inside a real logged-on desktop
  (`[self-hosted, windows-gui]`). It bundles the MSI, installs it per-machine,
  launches the installed app, and asserts what only a desktop can show: a window
  appears, an `msedgewebview2` host actually starts, the bundled `corecruxd`
  sidecar is spawned from the `externalBin` slot, and a graceful close reaps that
  sidecar. A desktop screenshot uploads on every run, including failures.
  Non-blocking — it depends on a single operator-owned box, so an offline runner
  must not gate the merge queue.

  This closes the gap the native-Windows build fix left open: that change noted
  there was "no Windows job to catch the next one" of ~49 `#[cfg(unix)]` sites.
  Compiling was never the hard part — a Tauri/WebView2 window cannot be created
  in a headless or Session 0 context at all, so app launch was unobservable on
  every existing runner. `scripts/provision-windows-gui-runner.ps1` provisions
  such a box and refuses to run where a GUI cannot exist; `docs/self-hosted-runner.md`
  records why Server Core and Session 0 are each disqualifying, and what the lane
  deliberately does not cover (reboot re-attach, the Defender first-bind prompt,
  WSL2 parity with a developer box).

### Fixed

- **The SessionEnd cost hook now records whether it worked.** The generated
  `cost)` launcher branch failed silently on three paths — `corecruxctl` absent,
  no configured endpoint, post rejected — each swallowed by `|| true`. Quiet is
  the correct posture for a SessionEnd hook, which must never block session end;
  undiagnosable is not. There was no way to distinguish "no sessions ran" from
  "every session silently failed to post", and the branch had no test coverage
  of any kind, which is why it survived.
  - Every attempt writes a one-line outcome record (result, reason, endpoint,
    endpoint source, launcher version) to `~/.claude/hooks/crux-cost.state.json`;
    failures additionally append to `crux-cost.errors.log`. `exit 0` remains
    unconditional on every path.
  - `CRUX_HTTP_URL` can never actually be empty — `${CRUX_HTTP_URL:-…}`
    substitutes for empty as well as unset — so the real misconfiguration is the
    *unconfigured loopback default*, which fails with a connection refused the
    operator cannot place. The launcher now records whether the endpoint came
    from config or from the built-in default, and names the remedy.
  - `corecruxctl hooks status` reports the last outcome and flags a stale
    launcher by version marker. The boot self-check warns when the installed
    launcher predates the running build, or when capture last failed or was
    never attempted — nothing warns when no outcome has been recorded yet, since
    a fresh install has simply not ended a session.
  - Six shell-level tests run the *embedded* launcher template under `bash`, so
    they cannot drift from what `hooks install` writes.

  **This takes effect only after `corecruxctl hooks install` is re-run.** An
  un-re-run wizard keeps the old silent script, and that is the most likely way
  this fix appears not to work.

- **Three tests that asserted things the machine does not guarantee.** Each
  failed CI on an unrelated PR and passed on a re-run of the identical commit;
  two of them gate required checks, so they cost merges rather than just noise.
  - `envelope_build_latency_under_2ms_for_10_facts` (`crux-mcp`) asserted a
    wall-clock bound — the only one in the workspace. On a shared runner that
    measures how busy the machine is, not how fast the code is. The figure is
    still measured and printed; the assertion is gone, and the test is renamed
    `envelope_build_covers_all_ten_facts` after the check that carries content
    (`memories_used.len() == 10`). Raising the constant was rejected: it trades a
    frequent flake for a rarer one and keeps a load-dependent test.
  - `allowed_origins_reads_the_env_var` (`corecruxd`) round-tripped through
    `set_var`/`getenv` and read back the built-in defaults instead of the value
    it had just set — *while holding the module's `env_lock()`*. The mutex was
    never the problem: `setenv` can reallocate the environment block, and a
    concurrent `getenv` anywhere in this 2000-plus-test binary may then read a
    stale pointer, which no Rust-level lock can fence (hence `set_var` being
    `unsafe` from the 2024 edition). It now parses via `resolve_allowed_origins`
    directly, matching its five neighbours, and removes the last `set_var` in
    the file.
  - `pick_free_port_is_bindable` (`crux-shell-lifecycle`) asserted that a port
    picked by binding `:0` and dropping the listener is immediately re-bindable.
    Nothing promises that — sibling tests binding `:0` in parallel can take it
    in the gap. It now retries a bounded number of times, so only a genuinely
    broken helper fails.

- **The desktop shell no longer opens stray console windows on Windows.** Two
  spawn sites, both console-subsystem binaries launched from a GUI-subsystem app
  (`windows_subsystem = "windows"`) that has no console to inherit — so Windows
  allocated a fresh console *window* for each:
  - `spawn_sidecar` (`crux-shell-lifecycle`) launched the bundled `corecruxd`
    with a visible console that sat beside the app for its entire lifetime.
    Redirecting stdout/stderr into the sidecar log did not suppress it: the
    streams and the window are independent.
  - the Windows credential lookup (`crux-shell-connection`) shells out to
    `powershell.exe` for the `PasswordVault` read, flashing a console on *every*
    attach-profile activation and retry. `-NonInteractive` governs the prompt,
    not the window.

  Both now set `CREATE_NO_WINDOW` (`0x08000000`) via `CommandExt::creation_flags`.
  `rundll32.exe`, used to open external links, is GUI-subsystem (verified from
  its PE header) and needed no change.

  Found by the new Windows GUI smoke lane on its first green run — the
  assertions passed while the uploaded screenshot showed the console box. That
  lane now fails if either window returns.

- **A cold `cargo build` now completes on native Windows.** Three unrelated
  stops, none of which CI can see (every runner is Linux, and the release matrix
  is Linux + macOS — both unix):
  - `aws-lc-sys` assembles its x86_64 Windows routines with NASM, absent from a
    default Windows toolchain, so the build script aborted. The crate ships
    pre-assembled objects for this case; `AWS_LC_SYS_PREBUILT_NASM = "1"` now
    lives in `.cargo/config.toml`. Inert on Linux and macOS, where the prebuilt
    path is gated off by target.
  - `fsync_dir` (`corecrux-projections`) and `write_control_atomic`
    (`corecruxd`) bound a variable consumed only inside `#[cfg(unix)]`. Against
    the workspace-wide `unused_variables = "deny"`, that is a hard error off
    unix. Both bind the value under `#[cfg(not(unix))]` rather than renaming to
    `_path`/`_parent`, which would have suppressed the lint on unix where the
    variable is load-bearing.

- **`cargo clippy --workspace -- -D warnings` now passes on native Windows.**
  Seven `clippy::unnecessary_wraps` errors across `corecrux-receipts`,
  `corecrux-storage`, and `crux-claude-hooks`: each is a directory-fsync or
  file-permission routine whose body is unix-only, so off-unix it collapses to
  `Ok(())` and the `Result` looks redundant. The signature is shared with a
  genuinely fallible unix implementation, so these are suppressed at the site
  with a note, not "fixed" by dropping the return type.

  Native Windows remains post-v1 per `docs/getting-started.md`; WSL2 is still
  the supported path. This only stops the gap widening — there are ~49
  `#[cfg(unix)]` sites and no Windows job to catch the next one.

- **`config.example.env` no longer claims a `.env` file is read.** The daemon
  has no dotenv support, so copying the file and starting `corecruxd` failed
  with "CORECRUXD_AUTH_MODE must be set explicitly" — indistinguishable from a
  genuine config error. The header now shows how to export the values.

### Security

- **`.mcp.json` is gitignored.** MCP clients write the daemon's agent bearer
  token into that file at the repository root, where it was previously
  committable.

## [0.5.38] - 2026-07-10

### Added

- **AST-derived code-structure scanner.** Behind `CORECRUXD_AST_SCAN`, the
  workspace scanner produces the `WorkspaceScan` shape from a `syn` AST pass
  instead of the regex scanner (flag-off byte-identical). ~17× faster on the
  Crux tree (p95 ~0.9 s vs ~15 s) and more accurate: call-edges resolved
  module-qualified, dead-code by AST identifier-reachability rather than the
  O(n²) substring pass. Context-graph edges fold in as `Extracted` confidence.
- **Watched repositories.** `POST/GET/DELETE /v1/repos` register a repo the
  daemon should know about (tenant-scoped; `corecruxctl repo add|list|remove`;
  MCP `register_repo` / `list_repos`). Registering a local path runs a one-shot
  scan. An active file-watch loop (`CORECRUXD_REPO_WATCH`, default off) keeps a
  repo's graph current via incremental re-index — a single-file edit re-parses
  only that file — using `notify` with a WSL `/mnt` polling fallback.
- **Polyglot extraction.** TypeScript/TSX, Vue (`<script>` blocks) and Python
  via `tree-sitter`, alongside Rust via `syn`; a language-agnostic repo walk
  scans repositories that are not Cargo workspaces.
- **Typed code edges in the relation graph.** `RelationTypeV1` gains
  `Calls` / `Imports` / `Defines` / `DependsOn` (append-only); behind
  `CORECRUXD_CODEGRAPH_EDGES` a repo's code graph is emitted as tenant-scoped,
  temporal relation edges and traversable via `POST /v1/relations/expand`.
- **Code-graph retrieval boost (spike).** A code-graph adjacency closure for
  `fused_retrieve`'s graph lane, behind `CORECRUXD_CODEGRAPH_FUSION`
  (default off; no recall study yet — see the ExecPlan).
- **Console code-graph view.** `/console/codegraph` renders the typed code+claim
  graph with node/edge/confidence visual language, focus + inspector, and
  `file:line` deep-links.

  _ExecPlan: `ast-polyglot-code-graph-and-repo-watch-2026-07-08` (M0–M8);
  supersedes `workspace-scan-storyline-improvements-2026-05-03` and
  `crux-code-intelligence-2026-06-12`._

- **Code map serving.** `GET /v1/repos/{repoId}/codemap` (`format=summary|full`)
  serves the AST scan persisted at registration/re-index — the read side of
  `POST /v1/repos`. Tenant-scoped `admin:read`; distinct 404s for unregistered
  vs never-scanned repos. Downstream: the WikiCrux code-maps surface
  (wiki.cuecrux.com/code, `wiki_codemap` MCP tool) consumes this endpoint.
  _ExecPlan: `codemap-endpoint-and-agent-docs-hardening-2026-07-10`._
- **Credit Meter spend rail (default-off).** `CORECRUXD_CREDIT_METER=1` enables
  the comped-wallet `POST /v1/credits/spend` path: pinned quotes → signed
  `crux.credit_spend_receipt.v1`, idempotent on retry (no double-debit).
- **Vendor observations.** Handoff/vendor observation capture with provider
  breakdowns (`list_observations` / `get_observation` / `verify_observation`);
  MCP handoffs are observed.
- **Usage receipts (opt-in).** Signed, metadata-only `usage_ping` receipts with
  a consent-gated submitter; `/v1/version` gains update/version-notify state.
- **Agent-docs hardening.** Nested `AGENTS.md` in all 28 crates
  (symbol-anchored, ≤50 lines); `check-agent-docs.sh` v2 gates llms.txt link
  parity, nested-file presence, `llms-full.txt` freshness and (in CI) executes
  the cheap documented commands; deterministic `llms-full.txt` generator;
  CLAIMS 10–15 and INVARIANTS I5 (witness anchoring) / I6 (custody-proof
  export); README redesigned around the 60-second agent-first quickstart.

### Fixed

- **Merged scan routing.** A cargo workspace containing any non-Rust supported
  files no longer flattens to a single polyglot package with zero routes:
  `run_repo_scan_at` merges the native Rust workspace scan with a
  rust-excluded tree-sitter pass (self-scan: 29 packages / 319 routes /
  14,290 symbols), and the watch loop re-indexes through the same path.
- Stale agent docs: MCP tool `token_usage` → `session_token_usage`; CODEMAP's
  nonexistent `ShardStorage::append` → `append_batch`/`append_batch_with_stats`.
- **Passport key create race.** `write_new_passport_seed` losers of the
  `create_new` race could read the winner's key file before its bytes landed
  ("key file is empty"); the key is now written in one buffer and the
  AlreadyExists path retries briefly. Test temp dirs additionally salt
  nanos with pid + a counter (coarse VM clocks collided parallel tests into
  one dir — the CI flake behind this).

## [0.5.36] - 2026-07-03

### Added

- **Usage receipts self-populate.** The daemon now auto-emits one `usage_ping`
  (`event_class=daemon_start`, keyed to the root passport) on startup — but only
  when the operator has opted into submission (the three-way consent gate).
  Default installs still dial nothing (`assert-no-phone-home` stays green); once
  opted in, the adoption signal registers on every boot with no manual mint (#322).
- **Version-notify.** The usage-receipt collector's response advertises the
  latest Crux release; the daemon compares it to its own version and, when
  behind, logs a warning and surfaces `update.latest_release` / `update.behind`
  on `/v1/version` (#322).

## [0.5.35] - 2026-07-03

### Added

- **Opt-in signed usage receipts (Phase T).** A local, signed, metadata-only
  `usage_ping` CROWN receipt (default-OFF), plus a consent-gated, verifiable
  opt-in submitter — the daemon's only sanctioned outbound signal, gated behind
  `CORECRUXD_USAGE_RECEIPTS_{SUBMIT,ENDPOINT,CONSENT_AT}`; inert under default
  config so `assert-no-phone-home` stays green (#315, #317, #318). See
  `docs/usage-receipts.md`.
- **Side-by-side demo** — `/console/receipts-vs-console`: the CROWN
  receipts-as-debugging timeline next to a vendor free-console mock (#316).
- OpenAPI: receipts routes covered in `/v1/openapi.json` plus a route-level
  contract test (#168).
- Upgrade-aware `501` responses on platform-only endpoints (HTTP + MCP) that
  signpost the hosted platform instead of a bare not-implemented (#169).
- Workspace wizard: live-session coordination protocol (`workspace-cuecrux` v2 → v3).

### Changed

- **Launch defaults ON** — coordination plane (`CORECRUXD_COORD`),
  passport-revocation enforcement (`CRUX_PASSPORT_REVOCATION`), agent-card
  discovery (`CRUX_AGENT_CARD`), and scoped-forget default to ON for fresh
  installs; typed action traces + activity signing remain documented opt-in (#314).
- Trust surface: `assert-no-phone-home.sh` + the CROWN receipt-tamper demo are
  now release-blocking gates in `release.yml` (#313).
- CI: `paths-ignore` replaced with a skip-but-report change-scope gate.

## [0.4.6] - 2026-06-11

### Added

- Console: Live board panel (`#/coord`) — coordination plane viewer (#166).

## [0.4.5] - 2026-06-11

### Fixed

- Coord board per-session recency gate (#165).

## [0.4.4] - 2026-06-11

### Fixed

- Coordination follow-up: announce overlap warnings, plus presence touch at
  bind/announce — board liveness fix (#164).

## [0.4.3] - 2026-06-11

### Added

- Coordination plane: live-session board for concurrent agent sessions —
  `/v1/coord`, `coord_status` / `coord_announce` MCP tools, boot digest (#163).
- Console: receipts view + CROWN verify panel with `#/receipts` deep link
  (#162).

## [0.4.2] - 2026-06-11

### Added

- Agent→passport resolution + mediation receipts for external mediators
  (B0–B4) (#161).

## [0.4.1] - 2026-06-10

### Added

- MCP tool-surface floor additions: `get_passport`, `receipt_verify`,
  `sync_status` (#160).

### Changed

- CRC-v1 default-on, with a legacy opt-out (#159).

## [0.4.0] - 2026-06-10

### Added

- Graph-driven dynamic MCP tool surface + capability-graph edges (#158).
- CRC-v1 pointer-first response contract: spec + daemon search tools (M0+M2)
  (#156).
- `corecrux.lane.*` registry with free→paid minting and usage-report ingest
  (#154).

### Changed

- Hardened daemon auth and agent helpers (#153).
- Dependency bumps (opentelemetry_sdk, wasmtime, rcgen, sha2, chrono, uuid,
  and others).

### Fixed

- Flaky gRPC replication-auth env-test race serialized (#157).

## [0.3.1] - 2026-06-05

### Fixed

- `corecruxd --version` and the boot banner now report the real short git sha in
  container builds instead of `(unknown)`. The Docker builder has no `.git`, so
  `build.rs` now honours a `CORECRUX_GIT_SHA` env (set from a `GIT_SHA` build-arg
  the Docker workflow passes as `github.sha`), falling back to `git` then
  `unknown`. Makes deploy audits able to confirm the running commit.

## [0.3.0] - 2026-06-05

### Fixed

- **New-tool probe fixes** (memory / freshness / coordination surface). A probe
  of the freshness/memory + orchestrator/punchcard/work tools surfaced 12 issues;
  all are fixed (ExecPlan `crux-new-tool-probe-fixes-2026-06-05`):
  - **Latest-version-wins recall.** `FactStore::store`/`try_store` now retire the
    prior `(entity, key)` version (`superseded_by`) so `query_facts` returns the
    current value instead of every historical version. Re-stores and `memory_edit`
    were leaking stale values into recall; `include_superseded` / `memory_view` /
    `memory_history` still expose the full chain.
  - **`memory_edit`** now stamps the editor's passport `actor` (was `null`),
    preserves the prior `horizon_class` (was reset to the entity default), and
    carries the user pin to the new version (was silently dropped — losing decay
    and scoped-forget protection).
  - **Scoped-forget honours pins.** Pinned facts survive `memory_forget` by
    default (documented #9 contract); `include_pinned: true` overrides for a
    GDPR Art.17 erasure. `__memory_pin::` added to the forget reserved prefixes.
  - **`update_work_state` 401.** The MCP `loopback_patch` helper was the only
    loopback verb not attaching the bearer token; it now does.
  - **Anonymous coordination writes.** MCP loopback writes forward
    `X-Corecrux-Passport-Id` from the session, and the punchcard
    acquire/release bodies accept `holder_passport` (preferred over the header
    actor), so orchestrator/punchcard/work writes are attributed to a real
    passport instead of `anonymous`.
  - **Orchestrator passport members.** `attach_to_orchestrator` accepts a
    `passport` member (validated against the passport store by id or
    principal_id) instead of returning an opaque 400; the error now names all
    accepted types.
  - **`memory_forget_dry_run`** returns `facts_that_would_be_affected` under
    `structuredContent` so MCP clients actually receive it.
  - **`create_work`** documents that `project_id` must be an existing project
    (no implicit `default`).
  - **Loopback error surfacing.** The MCP→daemon loopback helpers now disable
    `ureq`'s `http_status_as_error`, read the response body on 4xx/5xx, and
    surface the daemon's problem+json `detail` (e.g. `daemon returned 404:
    project not found` / `passport 'x' not found`) instead of a bare
    `status 404`. All four verbs (get/post/patch/delete) share one agent +
    status-error path; transport failures are reported distinctly.

### Changed

- **New `update_orchestrator` MCP tool** wraps `PATCH /v1/orchestrators/{id}`
  (name / assignee / state incl. `archived`) so an orchestrator can be closed
  out via MCP.
- **`store_fact`** advertises `horizon_class` + `freshness_horizon` in its
  schema (the handler already read them) so a freshness horizon is settable in
  one call.
- **Envelope `memories_used`** carries `age_hours` alongside `age_days` for
  unit consistency with the freshness/query rows.

### Added

- **GitHub shared memory** — selected GitHub repos become a searchable corpus
  any agent attached to the daemon can read:
  - PAT-based connection; the token is encrypted at rest with XChaCha20-
    Poly1305 using a key derived from the daemon-root passport via BLAKE3
    KDF (`LocalPassportKey::derive_subkey`). Endpoints:
    `GET /v1/integrations/github/status`,
    `POST /v1/integrations/github/connect` (verifies via api.github.com),
    `POST /v1/integrations/github/disconnect`.
  - Repo selection: `GET /v1/integrations/github/repos[/accessible]`,
    `POST/DELETE /v1/integrations/github/repos/{owner}/{repo}/select`.
  - Background sync worker pulls commits + PRs + issues + comments into
    facts under `github::owner/repo::{commit,pr,issue,comment}/{id}`.
    Polling cadence configurable via
    `CORECRUXD_GITHUB_SYNC_INTERVAL_SECS` (default 900s);
    `POST /v1/integrations/github/sync` triggers immediately.
  - Mention parser: `[work:<id>]` markers in PR/issue bodies link back to
    Plan A work items.
  - Five new MCP tools surface the indexed corpus to coding agents:
    `github_search`, `github_recent_commits`, `github_open_prs`,
    `github_open_issues`, `github_comments_since`.
  - Console UI: GitHub section in Settings with PAT connect form, repo
    picker, sync button, and per-repo selection. Project drawer surfaces
    open issues inline when `planning_target = github://owner/repo`.
- **Coordination** — multi-passport, projects, and a 6-state work kanban for
  cross-agent coordination on the same daemon:
  - `GET/POST/PATCH/DELETE /v1/passports` + `GET /v1/passports/{id}` — multi-
    passport store; auto-seeds `personal-default` / `work-default` /
    `public-default` on first boot. Per-passport `agent_work_gate` toggle
    queues agent state changes for human approval when set.
  - `POST /session` accepts new optional `project_id` / `tenant_id` /
    `passport_id` and returns the resolved binding via `X-CueCrux-*` response
    headers. `GET /v1/sessions/active` lists recent bindings.
  - `GET/POST/DELETE /v1/projects` + `GET /v1/projects/{id}` + member/tenant
    sub-routes. Auto-seeds a `default` project on first boot. `planning_target`
    supports `tenant://` or `github://` URLs (the latter activates once Plan B
    GitHub indexing ships).
  - `GET/POST /v1/work` + `GET/PATCH /v1/work/{id}` + comments + transitions +
    `POST /v1/work/gate/{id}/approve|reject`. Six work states: Planned ·
    In Progress · Blocked · Archive · Complete · Deployed. PATCH returns 200
    (applied) or 202 (queued behind a gate).
  - Six new MCP tools: `list_projects`, `get_project_context`, `list_work`,
    `create_work`, `update_work_state`, `comment_on_work`. Both Claude Code
    sessions and other agents can read/write the same kanban from inside
    their own session.
  - Console UI: new `Projects` and `Work` panels, rebuilt `Passport` panel
    with the six layers of agent self-knowledge (Identity + Rules filled;
    Operator/Directive/Playbook/Continuity as "Available in CueCrux Cloud"
    placeholders). Active-project picker in the rail.
- In-process relation graph wired into the open Crux Daemon: new
  `POST /v1/relations` (write edge — `facts:write` scope),
  `GET /v1/relations?tenant_id=&from_id=` (list outgoing — `admin:read`),
  `POST /v1/relations/expand` (multi-hop graph traversal — `admin:read`).
  Edges persist as JSONL at `data_dir/relations.jsonl` and are replayed into
  in-memory `ProjectionState` on startup. The `corecrux-projections::query::graph_expand`
  algorithm is now usable from the open daemon without a dataplane stub.
- Console settings page (cog icon, top-right of rail): persists chosen auth
  mode, embedding endpoint URL, and model; surfaces `restart_required` when
  changes need a daemon bounce. New endpoints: `GET/PUT /v1/console/settings`.
- Storage-breakdown chart relabelled to Text Search / Projections / Embedding /
  Graph, each with a hover tooltip explaining what populates it. Graph bar now
  reads real edge counts from the new relation surface.
- Overview hero condensed: daemon-posture and boundary-check facts are now
  inline chips with custom CSS tooltips inside the hero band, replacing the
  two stacked cards beneath.
- Embedded Crux Console redesigned for non-technical users: first-run
  onboarding flow with live healthz/readyz/version tiles and a 3-card auth
  picker (off / dev_scopes / jwt_hs256), nav reordered (Passport before
  Integrations), Add Fact form, fact search box, tenant Personal/Work/Public
  tabs, and a hand-rolled SVG storage-breakdown bar chart with Chunks/Bytes
  toggle. Aligned to the cuecrux palette. Single-file `playground/index.html`
  stays under 100 KB with no external dependencies.
- New console endpoints: `GET /v1/console/onboarding`,
  `POST /v1/console/onboarding/complete`, `POST /v1/console/onboarding/restart`,
  `GET /v1/console/storage-breakdown`, `POST /v1/console/facts/add`. Existing
  `GET /v1/console/facts` accepts `q=` and `top_k=`; `GET /v1/console/tenants`
  accepts `category=personal|work|public|all` and emits a `category` field per
  tenant (prefix-based; `personal` is the default).
- `CORECRUXD_CONSOLE_DEV_PATH` env: when set, the daemon serves the console
  HTML from disk instead of the embedded `include_str!` copy. Bind-mount via
  the new `docker-compose.dev.yml` overlay for instant browser-refresh
  iteration without rebuilding the image.
- Persistent console settings file at `data_dir/console/settings.json`
  (atomic tmp+rename writes, schema-versioned).
- JSONL persistence for fact store and session store — facts survive daemon restarts
- Paginated fact export endpoint (`GET /v1/facts/export`) with cursor pagination
- Bidirectional sync client — pull enriched facts from remote CoreCrux, push local facts back
- Background sync task with configurable interval (`CORECRUXD_SYNC_INTERVAL_SECS`)
- Privacy controls for sync: `private` flag on facts, 14 default entity-prefix blocklist, preview-before-push
- 3 new MCP tools: `sync_pull`, `sync_push`, `sync_status` (21 tools total)
- Architecture Decision Records (`docs/adr/`): append-only segments, CROWN receipts, CPU-only edition
- Benchmark documentation (`docs/benchmarks.md`)
- gRPC integration tests covering all data-plane RPCs
- Runnable Rust example (`examples/rust/append_and_query.rs`)

### Changed

- Split `corecrux-storage/src/lib.rs` (13k LOC) into 9 domain modules
- Split `corecruxd/src/http.rs` (10k LOC) into 10 handler sub-modules
- Migrated CI to self-hosted Hetzner runners
- Stripped all GPU/CUDA data-plane code (~10k LOC removed) — Crux Daemon is CPU-only
- Built-in MCP support is now part of the supported `corecruxd` runtime path, quickstarts/examples/docs, and CI smoke checks
- Standalone integration-test runs now have a dedicated helper script that builds `corecruxd`, exports `CORECRUXD_BINARY`, and runs the integration crate consistently

### Fixed

- Flaky `crux-observe` config test (env-var race condition)
- `SessionStore::put` TTL parameter across all callers
- `arduino/setup-protoc` GitHub API rate limit (added `repo-token`)
- Handoff import/export privacy and authenticity handling for MCP agent transfers
- MCP agent/session scoping across fact queries, entity listing, and session operations
- HTTP `private=true` fact writes are now rejected instead of implying unsupported caller scoping
- Runtime/docs/example drift around append compatibility, text-search request shapes, and local-daemon feature surfaces
- Integration harness startup and readiness behavior across HTTP, gRPC, and MCP listeners

### Security

- Fact sync privacy: sensitive entity prefixes (`finance:`, `health:`, `personal:`, etc.) are never pushed upstream
- Sync push requires explicit `confirm: true` via MCP tool — preview mode by default
- MCP bearer-token enforcement now returns `401` instead of silently accepting anonymous POSTs when agent tokens are configured

## [0.1.0] - 2026-04-03

### Added

- Append-only event store with sealed segments, BLAKE3 integrity, and crash recovery
- CPU BM25 retrieval via `.ccxi` companion indexes with PForDelta compression
- Graph signal fusion for relation-aware retrieval
- CROWN receipt generation with Ed25519 signatures and BLAKE3 chain
- Token-budgeted retrieval (fill results until token budget exhausted)
- Relevance floor (minimum BM25 score threshold with `below_floor` count)
- Progressive retrieval (scan/expand two-pass pattern)
- Coverage and gap reporting on every query response
- Fact store (receipted key-value entity memory with BM25 search)
- Session store (scoped state per session with token counting)
- CLI tools: `corecruxctl verify-store`, `replay`, `inspect-receipt`, `explain`, `gaps`
- Contribution manifest (`crux-contrib`) with BLAKE3 content-addressed envelopes
- Sync client (`crux-sync`) with outbox-based offline-first VaultCrux sync
- HTTP API on port 14800 (`/healthz`, `/readyz`, `/metrics`, `/v1/append`, `/v1/query/*`, `/v1/facts/*`, `/v1/sessions/*`)
- gRPC data plane (append, read, replay, export)
- Prometheus metrics endpoint (100+ operational metrics)
- Docker image (Debian bookworm-slim) with docker-compose.yml
- GitHub Actions CI (lint, test, 82%+ coverage, release binaries, Docker push)
- Strict linting (`unsafe_code` forbidden, pedantic clippy, 81% coverage floor)

### Security

- CueCrux Community Licence (CCL v1.0) with 3-year Apache 2.0 conversion
- No telemetry, no phone-home, no tracking in standalone mode
- `cargo-deny` supply chain and licence audit in CI
- `cargo-audit` CVE scanning in CI

[unreleased]: https://github.com/CueCrux/Crux/compare/v0.5.59...HEAD
[0.5.59]: https://github.com/CueCrux/Crux/compare/v0.5.58...v0.5.59
[0.5.58]: https://github.com/CueCrux/Crux/compare/v0.5.57...v0.5.58
[0.5.57]: https://github.com/CueCrux/Crux/compare/v0.5.56...v0.5.57
[0.5.56]: https://github.com/CueCrux/Crux/compare/v0.5.55...v0.5.56
[0.5.55]: https://github.com/CueCrux/Crux/compare/v0.5.54...v0.5.55
[0.5.54]: https://github.com/CueCrux/Crux/compare/v0.5.53...v0.5.54
[0.4.6]: https://github.com/CueCrux/Crux/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/CueCrux/Crux/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/CueCrux/Crux/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/CueCrux/Crux/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/CueCrux/Crux/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/CueCrux/Crux/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/CueCrux/Crux/compare/v0.3.1...v0.4.0
[0.1.0]: https://github.com/CueCrux/Crux/releases/tag/v0.1.0
