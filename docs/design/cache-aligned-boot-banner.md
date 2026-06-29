# Cache-Aligned Boot Banner (M2)

> Token-efficiency learnings (Headroom *CacheAligner* port) — milestone **M2**.
> Source: [`crates/crux-claude-hooks/src/cmds/session_start.rs`](../../crates/crux-claude-hooks/src/cmds/session_start.rs).
>
> **Status (CO-5, 2026-06-30):** shipped behind `CRUX_BANNER_CACHE_ALIGN` (default-ON CO-2, 2026-06-25); the
> escape-hatch flag is now **removed** — the banner is **always** cache-aligned. The sections below describe the
> behaviour; the historical flag references are retained for context.

## Problem

The `SessionStart` hook injects a markdown banner as `additionalContext`. That
banner becomes a **prefix** of the model's context window. Providers serve a
byte-identical prefix from their KV cache at a steep discount (Anthropic cached
input is ~90% cheaper than fresh input), but the discount only applies up to the
**first byte that differs** from the previous request.

Pre-M2 the banner led with its most *volatile* section — `sync_status`
(timestamps, `local_fact_count`, sync mode) followed by the live-session coord
digest. A single changed fact count or a new live session shifts a byte near the
very front, so the whole prefix misses the cache on the next boot.

## Fix

Each banner section is tagged `Stable` or `Volatile`:

| Section | Class | Why |
|---|---|---|
| `get_bootstrap("patterns")` playbook | **Stable** | identical session-to-session |
| config-drift guidance | **Stable** | changes only when CLAUDE.md / bundled profiles change |
| `sync_status` | **Volatile** | timestamps, `local_fact_count`, sync mode |
| coord live-sessions digest | **Volatile** | live peers / work-in-flight churn constantly |
| config-audit warning | **Volatile** | lists unreviewed content hashes |

When `CRUX_BANNER_CACHE_ALIGN` is ON, all `Stable` sections are emitted first
(in their original relative order) then all `Volatile` ones — a stable
partition, so within-class order is preserved. The stable playbook then forms a
byte-identical prefix across boots; only the tail churns.

When the flag is **OFF**, sections emit in insertion order — **byte-identical to
pre-M2 behaviour** (the regression net).

## Gate

- **Prefix-diff (automated):** `gate_m2_two_boot_prefix_is_byte_identical_only_tail_churns`
  in `session_start.rs` builds two boots that differ only in volatile content and
  asserts (a) the aligned shared prefix carries the stable playbook and no
  volatile state, and (b) alignment strictly extends the shared-prefix byte count
  vs. unaligned. Run: `cargo test -p crux-claude-hooks --lib session_start`.
- **Cache-read ratio (deferred to host):** the end-to-end provider cache-read
  ratio (ties to the tokenburn `cache_read 369× output` observation) must be
  measured on a scripted two-turn session against a real provider. The local-only
  daemon has no provider round-trip, so — as with the M0 feature-registry
  pre-flight — this measurement is deferred to a host run before any default-ON
  cutover.
