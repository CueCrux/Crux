# Mutation testing audit — 2026-07-19

Trigger: operator report that "mutation testing in Crux Daemon could be better." Confirmed. Two distinct problems: the nightly job silently never completes, and the partial data we do have shows a ~33% survivor rate in the trust-core crates.

## Current state

- Workflow: `.github/workflows/mutants.yml` — nightly 04:00 UTC, `cargo-mutants` over
  `corecrux-receipts`, `corecrux-segment`, `corecrux-storage` (3 of 28 crates),
  report-only (`continue-on-error: true`, `|| true`), self-hosted runner,
  `CARGO_BUILD_JOBS=4`, per-mutant timeout 120s. Added under ExecPlan
  `crux-testing-system-hardening-2026-06-17` (M5).

## Finding 1 — the job has effectively never delivered a report (P0)

Sampled runs across 2026-06-18 → 2026-07-18 (~31 nightly runs):

- Every sampled "success" run (29633470202, 29559766203, 29310787450, 28698243392)
  shows the `Run cargo-mutants` step **cancelled** mid-run at ~2.5–4.2h, with
  `Upload mutants report` **skipped** despite `if: always()` — consistent with the
  runner process being killed outright (no grace period), not a GitHub-side cancel.
- Cancellations cluster around **09:20–10:30 UTC**, suggesting a daily event on the
  shared self-hosted runner fleet (restart/update/cleanup cron). Root cause not yet
  pinned down.
- Only **2 artifacts ever uploaded** (runs 29142589381, 29232035466) — and those are
  the two runs that hit the 6h job timeout, where GitHub's cancel path did allow the
  `always()` upload.
- Net effect: ~3–6 h of runner time burned nightly for a month, green checkmark shown,
  **no report produced, no triage possible**. This is exactly the green-on-cancel
  silent-failure anti-pattern.

## Finding 2 — the partial data shows a real assertion gap

From the 2026-07-13 artifact (run truncated at 6h: 2,532 of 3,244 mutants tested):

| outcome | count |
|---|---|
| caught | 1,090 |
| **missed (survivors)** | **544** |
| timeout | 19 |
| unviable | 877 |
| never tested (6h cut) | ~712 |

Mutation score ≈ **67%** caught (1,090 / 1,634 viable tested) — weak for crates whose
whole point is tamper-evidence. Survivors by file (top):

| survivors | file |
|---|---|
| 141 | `crates/corecrux-storage/src/lib.rs` |
| 104 | `crates/corecrux-segment/src/sealer.rs` |
| 52 | `crates/corecrux-segment/src/builder.rs` |
| 47 | `crates/corecrux-storage/src/append.rs` |
| 44 | `crates/corecrux-receipts/src/witness_v1.rs` |
| 41 | `crates/corecrux-segment/src/trailer.rs` |
| 17 | `crates/corecrux-segment/src/footer.rs` |
| 13 | `crates/corecrux-receipts/src/candidate_digest_v1.rs` |
| 10 | `crates/corecrux-receipts/src/audit_gap_v1.rs` (incl. `||`→`&&` in `verify_coverage_window_body_v1`) |

Survivors in `sealer.rs`, `witness_v1.rs`, and `audit_gap_v1.rs` verification logic are
the alarming ones — those are the claims `docs/agent/CLAIMS.md` says tests prove.

Also: 877/3,244 (27%) unviable mutants = pure wasted compile time.

## Proposed first-class approach

Phase 0 — make it deliver (small, do first):
1. **Shard the run** so each job finishes inside the runner-disruption window:
   `cargo mutants --shard k/8` as a matrix job (~25–45 min each), artifact per shard.
   This alone fixes both the 6h overrun and the 09:20–10:30 kill window.
2. **Upload mid-run state regardless**: keep `mutants.out/` under the workspace, add a
   final step with `if: ${{ always() }}` per shard; short jobs make this moot anyway.
3. **Surface the score**: merge shard outcomes, write caught/missed/unviable + per-crate
   score to `$GITHUB_STEP_SUMMARY`; fail the workflow (it is non-gating anyway) when
   the step is cancelled, so silent death is visible.
4. Separately: find what kills long jobs on the runner fleet at ~09:20 UTC — this
   likely affects other long workflows (fuzz, coverage-attestation).

Phase 1 — make it incremental (the actual first-class pattern):
5. **PR-time `--in-diff`**: run `cargo mutants --in-diff <(git diff origin/main...)` on
   PRs touching trust-core crates. Minutes, not hours; gate *new* code at 100%
   caught-or-annotated. Keeps the nightly sweep as the safety net.
6. **Baseline ratchet**: check in `missed.txt` (or a digest of it) as a baseline;
   nightly job diffs against it — new survivors fail, fixed survivors ratchet down.
7. **Speed**: `--test-tool=nextest`; consider `--baseline=skip` once the workspace
   baseline is known-green from ci.yml; keep `CARGO_BUILD_JOBS=4` for fleet safety.

Phase 2 — burn down and expand:
8. **Triage the 544-survivor backlog** starting with receipts verification + sealer.
   Buckets: (a) write the missing assertion, (b) genuinely inert (log/metric lines) →
   `#[mutants::skip]` or `exclude_globs` in `.cargo/mutants.toml` with a justification
   comment — this also cuts the 27% unviable waste.
9. **Expand scope** crate-by-crate (candidate next: `corecrux-memory`, retrieval
   fusion) only after the trust-core score is ≥90% and gated.

## Root cause of the kill window (resolved 2026-07-19, session 2)

Diagnosed on runner-hel1 (62G RAM, 8G swap, 6 runner slots + caddy-hooks):

- `journalctl`: `cargo-mutants invoked oom-killer` at 09:42:51Z on 2026-07-18;
  the runner reported `Job cargo-mutants … completed with result: Canceled` 18s
  later. One OOM event **every day** in the 09:20–10:30 UTC window since at
  least 07-10 (victims vary: cargo-mutants, `.NET` runner workers, test
  binaries) — the morning eval-job burst pushes the shared host into memory
  pressure, and the long-running mutants job (highest OOM score) was the usual
  casualty. Not a cron/timer: `gha-cargo-reaper` (hourly) only removes
  `.cargo-*` dirs older than 180 min and never matched mutants dirs.
- Because the job died without running its cleanup step, ~21 `.cargo-mutants-*`
  CARGO_HOME dirs (~188M each) had leaked into /home/gha-runner.

Host changes applied (reversible):
- Deleted the 21 leaked `.cargo-mutants-*` dirs (age-guarded `-mmin +360`).
- Extended `/usr/local/bin/gha-cargo-reaper.sh` to also reap
  `.cargo-mutants-*` / `.cargo-mutants-diff-*` (backup:
  `gha-cargo-reaper.sh.bak-2026-07-19`; revert = restore the backup).

Still open for the operator: the *fleet-wide* morning memory crunch also
OOM-kills other jobs (`.NET` workers on 07-12/07-17, test binaries on
07-15/07-16) and mass-cancels eval jobs (~09:50Z). Options: stagger the eval
crons, add per-slot systemd `MemoryHigh=` limits, or add swap. Left as an
operator decision — it touches other teams' workflows.

## Testing-architecture review (M5, 2026-07-19)

Two independent reviews (Fable inline + codex/GPT read-only sweep, 20 findings)
over `.github/workflows/*`, `scripts/ci-*`, and the trust-core test surfaces.
Every finding below was verified against the code before acting.

### Fixed on this branch

| finding | fix |
|---|---|
| "Semver Compatibility" (a REQUIRED check) could never fail: `\|\| echo` AND `continue-on-error` | now surfaces violations in job summary + warning; kept advisory deliberately (hard-fail would wedge the merge queue if the baseline is broken) — promote after a clean history |
| `buf.yml`: job-level `continue-on-error` (justified only for the lint layout rule) also hid `buf breaking` wire-format regressions | split into advisory `lint` + visible blocking-red `breaking` job |
| `changes` classifier: `echo "$files" \| grep -q` under pipefail can SIGPIPE on big change lists; the `!` then flags a code PR docs-only and skips every heavy gate (same bug in desktop-shell.yml) | herestrings, no pipe |
| Smoke test used fixed ports 14800/14801 — concurrent Test jobs on the shared runner can silently probe each other's daemon (false green) and never assert the spawned PID is alive | per-job `CORECRUXD_HTTP_PORT`/`MCP_PORT` (stride-2 from run_id) + `kill -0 $PID` after readiness |
| hosted-surfaces feature tests never ran anywhere in CI (only `cargo check`) | new non-required `Test (hosted-surfaces)` job runs them with the feature ON |
| mutants ratchet ignored timeouts (missed→timeout looked like progress) | survivors = missed + timeout; baseline regenerated (565 entries) |
| `coverage-attestation.yml` missing the `if: always()` CARGO_HOME cleanup every other job has (disk-leak incident 2026-06-15 class) | cleanup step added |
| fuzz.yml PR trigger omitted `crates/corecrux-frame/**` despite THREAT_MODEL promising fuzz on frame changes | path added |
| **Fork-PR workflows ran with only first-time-contributor approval on a PUBLIC repo whose self-hosted runners have passwordless sudo** — any once-merged contributor could execute arbitrary code on the CI host | repo setting flipped to `all_external_contributors` (every fork PR now needs an operator "Approve and run"; revert: `gh api -X PUT repos/CueCrux/Crux/actions/permissions/fork-pr-contributor-approval -f approval_policy=first_time_contributors`) |

### Documented, needs operator/product decision (in priority order)

1. **Fork PRs still execute on the privileged runner pool after approval.** The
   approval gate is a mitigation, not a fix. Options: ephemeral runners for
   `pull_request` from forks, or a sudo-less runner class for untrusted code.
2. **`verify-store --strict` doesn't verify seal receipts / predecessor links**
   (`corecrux-storage/src/integrity.rs`); only chain *creation* is tested. Needs
   a negative chain-verification suite (deletion / reorder / link tamper / bad
   sig). Sizeable test work — good next burn-down slice.
3. **Corruption matrix permits the unhashed CRC-table/trailer region** while
   THREAT_MODEL.md claims "any modification" detection — either sweep that
   region through the lazy reader path and reject, or narrow the documented claim.
4. **`single_byte_mutation_fails_verification` (segment decoder proptest) is
   tautological in its `Ok` branch** (asserts mutated bytes ≠ original bytes,
   trivially true). A naive `Err`-required fix would be flaky for unhashed
   bytes; the fix must constrain offsets to covered regions. Deliberate defer —
   a wrong fix makes a required check flaky.
5. **No non-canonical/malleable Ed25519 vectors** in the signature suites — a
   swap of `verify_strict` for permissive verify would survive current tests
   and most mutation operators.
6. **Fuzzing gaps**: `receipt_verify_cbor` always passes `keyring: None`
   (never reaches key parsing / verify_strict); no target for
   `decode_canonical_header_bytes_v1`; nightly toolchain + unlocked fuzz
   workspace = weak reproducibility (pin a dated nightly).
7. **ci-fallback.yml can't actually satisfy the required checks** (check names
   differ, no Coverage job) — its advertised purpose fails; fold fallback into
   the primary jobs or rename to match.
8. **Coverage floors have ≤1.4pt headroom** (integer floors vs decimal actuals)
   — fine today; ratchet to decimals after the M4 tests raise
   receipts/segment coverage.
9. **Ratchet identity is a per-bucket count** (`path: description`, line-less):
   a same-bucket swap (one old survivor fixed, one new identical-description
   survivor) stays green. Documented in the script; accept or move to
   function-scoped identity later.

## Verification pointers

- Run list: `gh run list --workflow=mutants.yml`
- Step conclusions: `gh api repos/CueCrux/Crux/actions/runs/<id>/jobs --jq '.jobs[0].steps[]'`
- Artifacts (only 2 exist): `gh api "repos/CueCrux/Crux/actions/artifacts?name=mutants-report"`
- Analyzed artifact extracted at scratchpad `mutants-0713/` (session-ephemeral).
