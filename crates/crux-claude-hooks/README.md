# crux-claude-hooks

Claude Code lifecycle hook binaries for the Crux Daemon.

The compaction/context subcommands below ship under a single `crux-hook`
binary, each fired by the Claude Code harness at a specific lifecycle event.
Best-effort and non-blocking: a missing or unreachable daemon never blocks
tool execution. Run `crux-hook --help` for the additional observation and
code-context subcommands.

## Subcommands

| Subcommand | Hook event | Purpose |
|---|---|---|
| `context-monitor` | `PostToolUse` | Read-only loop / file-scope warnings. Surfaces inline via `additionalContext`. **Never writes facts** (CueCrux/CLAUDE.md §11.2). |
| `pre-compact` | `PreCompact` | Snapshots session state to the Crux daemon via MCP `save_session` before harness compaction. On a hosted (Pro) node it *also* stores a client-side-encrypted `session_snapshot` fact (see [Hosted encrypted snapshot sync](#hosted-encrypted-snapshot-sync-pro)). |
| `session-start` | `SessionStart` | Automates the §11.1 session-boot ritual: `sync_status` + `get_bootstrap("patterns")` with `token_budget=500`. Injects result as `additionalContext`. On a `compact`/`resume` boot it also restores the hosted encrypted snapshot from another device. |

## Install or build

The signed release installer, Debian package, and Homebrew formula install
`crux-hook` alongside the daemon and CLI. Verify a release per
[`docs/verify-release.md`](../../docs/verify-release.md), then use `crux-hook`
from `PATH` in the configuration below. To build from source instead:

```bash
cd /home/myles/CueCrux/Crux
cargo build --release -p crux-claude-hooks
# Binary at: target/release/crux-hook
```

## Install (project-local)

Add to `.claude/settings.local.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "crux-hook context-monitor",
            "timeout": 5
          }
        ]
      }
    ],
    "PreCompact": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "crux-hook pre-compact",
            "timeout": 5
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "crux-hook session-start",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `CRUX_MCP_URL` | `http://127.0.0.1:14801/mcp` | Crux MCP endpoint. |
| `CRUX_HOOK_CONTEXT_MONITOR` | (unset) | Set to `off` to disable PostToolUse warnings. |
| `CRUX_HOOK_PRE_COMPACT` | (unset) | Set to `off` to disable PreCompact snapshots. |
| `CRUX_HOOK_SESSION_START` | (unset) | Set to `off` to disable SessionStart bootstrap. |
| `CRUX_COMPACTION_SYNC` | (unset) | Hosted encrypted snapshot sync — **explicit default-OFF opt-in**: `1`/`on` enable; `0`/`off`/unset are all off. Checked before any key derivation or network op (no `sync_status` auto-enable). |
| `CRUX_PASSPORT_KEY_PATH` | (unset) | Explicit path to the passport seed used to derive the snapshot key. Falls back to `CORECRUXD_PASSPORT_KEY_PATH`, then `CORECRUXD_DATA_DIR/passport.key`. Read-only; never created by the hook. |

## Hosted encrypted snapshot sync (Pro)

Free tier keeps its local baseline: `pre-compact` writes `save_session` to the
local daemon and the [free shell preset](../../integrations/claude-code/compaction-survival/)
writes `~/.claude/compaction-snapshots/<session_id>.md`. Nothing leaves the
machine. **The `save_session` state is itself sealed** whenever a passport seed
is available, so even the session store holds only ciphertext regardless of the
endpoint; with no seed to encrypt with, plaintext `save_session` is sent **only
to a verified-loopback daemon** and skipped for any remote endpoint.

When hosted sync is **explicitly enabled** (`CRUX_COMPACTION_SYNC=1|on`; the Pro
mirror is the product-posture gate on the daemon side) the same `pre-compact`
hook *additionally* stores the snapshot as a **client-side-encrypted,
non-private `session_snapshot` fact**. Because `facts` is a synced collection
and the fact is non-private, it rides the existing per-tenant mirror to the
user's other devices — and because the value is ciphertext, that is safe. On the
other device, a `compact`/`resume` `session-start` boot decrypts the snapshot
locally and re-injects the working state as `additionalContext`. Restore supports
**both** cross-device flows:

- **Same-session resume** — device B ran `claude --resume <same id>`: the snapshot
  bound to that session id opens and restores directly.
- **Fresh-session pickup** — device B starts a *new* session: it restores this
  passport's **newest** snapshot (highest counter) that authenticates and is
  strictly newer than a locally-persisted high-water mark.

### "Unreadable to us" guarantee

Only a sealed envelope ever occupies a synced or server-readable field — not the
value, not the key name, not any metadata. The scheme:

- **AEAD:** XChaCha20-Poly1305 (24-byte extended nonce, fresh random nonce per
  seal). Authenticated: a wrong key or a tampered byte fails to open.
- **Key:** derived on demand via `blake3::derive_key("crux/compaction-snapshot/v1", passport_seed)`
  (`crux_session::LocalPassportKey::derive_subkey`). The input is the ed25519
  **passport seed**, which never leaves the device — the hosted mirror
  authenticates with a *separate* bearer token (`CRUX_AGENT_TOKEN`) and never
  receives the seed, so it cannot derive the key. The derived key is computed on
  demand, never persisted or logged.
- **Envelope:** versioned `{v, alg, passport_scope, session_id, counter, nonce,
  ct}` (currently **v3**), base64-wrapped into the fact value. Unknown `v`/`alg`
  are rejected, so the scheme can evolve without breaking stored blobs.
  `passport_scope`/`session_id`/`counter` are metadata (not secrets) carried in
  the clear so the reader can select candidates and reconstruct the AAD.
- **AAD binding (v3):** each seal binds canonical additional-authenticated-data
  `{v, alg, entity, passport_scope, session_id, counter}` (fixed field order,
  byte-identical reconstruction on `open` or auth fails). Tampering with any of
  those fields — including bumping the counter to defeat the rollback check, or
  relabelling the scope/session to slip past the reader's filters — fails
  authentication. `passport_scope` is the passport public-key fingerprint (1:1
  with the seed), which the reader computes locally to bind and to select "this
  passport's" snapshots.
- **Rollback / replay defence:** each snapshot carries a per-passport
  monotonic-ish `counter` (a wall-clock nanosecond timestamp — see below), and the
  reader persists the highest **accepted** counter as a durable per-passport
  **high-water mark** (next to `passport.key`, not `TMPDIR`). Fresh-session pickup
  accepts only a snapshot whose counter is strictly greater than the mark, so an
  attacker who re-serves an old ciphertext (which they cannot re-sign or
  re-counter) is rejected. Same-session resume is exempt from the high-water gate
  (trusted by exact session match + auth) so a legitimate re-resume is never
  self-blocked. A missing mark is first-run (restore allowed); a corrupt mark
  fails toward *no restore* for that boot and self-heals.
- **No key handoff:** if `CRUX_AGENT_TOKEN` is set to the passport seed itself
  (any hex/base64 form), hosted sync is refused — the server must never receive
  the material the key is derived from.

> **Counter source + multi-writer.** The counter is a wall-clock nanosecond
> timestamp — the simplest correct monotonic-ish source, needing no persisted
> write-side state, and ordering snapshots by real write time (exactly the notion
> of "latest" restore wants). If two devices ever collide on a counter, restore
> breaks the tie deterministically by `session_id`. Residual (documented
> follow-up, not a threat-model hole — the AAD binding means a counter still
> can't be forged): a backward wall-clock step or cross-device clock skew could
> misorder snapshots; a hard per-device logical counter is the upgrade path.

### Same-passport prerequisite

Cross-device restore works **iff both devices carry the same passport seed**
(`passport.key`) — that is the whole "same passport provisioned on both machines"
Pro continuity story; there is no key-exchange UX. If device B has a *different*
seed, the AEAD authentication fails and `session-start` simply skips the restore
(quiet no-op) — it never errors the session. Free/local users with no seed or no
mirror skip the hosted path entirely.

## Heuristics (context-monitor)

- **Loop detection**: warns when the last 3 `PostToolUse` events have the
  same `(tool_name, hash(tool_input))` signature. Critical-severity — bypasses
  debounce.
- **File scope**: warns once when more than 20 distinct files have been
  touched by `Edit` / `Write` / `NotebookEdit` in the session.
- **Debounce**: non-critical warnings fire at most once per 5 PostToolUse
  events.

Tunable constants live in [`src/state.rs`](src/state.rs):
`LOOP_DETECTION_THRESHOLD`, `FILE_SCOPE_WARN_THRESHOLD`, `WARNING_DEBOUNCE_CALLS`.

## State

Per-session debounce / history is persisted to
`${TMPDIR:-/tmp}/crux-hook-state-{sanitised_session_id}.json`. Session-id
sanitisation strips anything that is not `[A-Za-z0-9_-]` and caps at 64 chars
to prevent path traversal.

## Disable

To turn off in the current workspace, either:
1. Set the relevant `CRUX_HOOK_*=off` env var, or
2. Remove the `"hooks"` block from `.claude/settings.local.json`.

## Design rationale

Three lifecycle slots map to three Crux concerns. `PostToolUse` is the only
moment per turn when the operator has just executed something, so it's where
read-only loop/file-scope warnings belong — and it's deliberately read-only
because writing facts on every tool use would dilute recall. `PreCompact`
fires immediately before Claude Code summarises and discards history, so it's
the last chance to snapshot session state via MCP `save_session`. The hook is
best-effort and non-blocking because a hook that crashes a session is worse
than no hook. `SessionStart` runs once at the top of each session with a
500-token budget — enough to load current playbook patterns without blowing
the agent's output budget on a stale boot dump.

## Attribution

Lifecycle-hook design patterns inspired by
[`affaan-m/everything-claude-code`](https://github.com/affaan-m/everything-claude-code)
(MIT). Specifically: the PostToolUse anomaly-detection pattern from
`scripts/hooks/ecc-context-monitor.js`, and the `PreCompact` / `SessionStart`
snapshot-and-bootstrap pattern from `hooks/memory-persistence/`.

The Crux integration is original Rust and explicitly diverges from ECC where
the memory models differ: hooks do not *reflexively* call `store_fact` on every
tool use (CueCrux/CLAUDE.md §11.2 — that dilutes recall), and `$ cost` /
`context %` metrics are intentionally out of scope because the Claude Code
harness does not expose them to hook stdin. The one deliberate, gated exception
is the hosted encrypted snapshot: `pre-compact` stores a single
client-side-encrypted `session_snapshot` fact per compaction, only on a
configured hosted node — an explicit continuity write, not a reflexive one.

## Licence

CueCrux Community Licence (CCL v1.0). See `/home/myles/CueCrux/Crux/LICENCE.md`.
