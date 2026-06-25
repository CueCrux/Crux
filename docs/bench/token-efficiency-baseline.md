# Token-Efficiency Baseline (M0)

> ExecPlan: `PlanCrux/.agent/execplans/crux-headroom-token-efficiency-learnings-2026-06-24.md` — milestone **M0**.
> Harness: [`crates/crux-mcp/examples/token_bench.rs`](../../crates/crux-mcp/examples/token_bench.rs).
> Corpus: **`__synthetic__::token-bench`** (deterministic, in-process — no daemon/network/prod data).
> Baseline commit: `f9d8e6b` (origin/main at branch cut). All efficiency flags OFF (`lane_flags=baseline:all-off`).

## Reproduce

```bash
cd Crux
# Machine-parseable JSON records → stdout; human summary → stderr.
CRUX_BENCH_COMMIT=$(git rev-parse --short HEAD) CRUX_BENCH_RUN_ID=m0-baseline \
  cargo run -p crux-mcp --example token_bench
```

The harness seeds a deterministic corpus (30 segment docs of varied length + 30
facts + 8 bootstrap patterns) and measures the `content[0].text` token cost
(`token_estimate::estimate_tokens_str`, the daemon's own ~4-chars/token estimate)
of each retrieval surface at the three standard budgets. **Output is
byte-identical across runs** (the M0 reproducibility gate) — `commit_sha` /
`run_id` are the only inputs, supplied via env.

## Baseline numbers

| scenario | budget | inline_tokens | inline_bytes | inline_hits | candidates |
|---|---:|---:|---:|---:|---:|
| query | 500 | 348 | 1394 | 2 | 30 |
| query | 2000 | 467 | 1871 | 9 | 30 |
| query | 4000 | 740 | 2960 | 25 | 30 |
| query_facts | 500 | 747 | 2991 | 1 | 1 |
| query_facts | 2000 | 2432 | 9730 | 6 | 6 |
| query_facts | 4000 | 5481 | 21924 | 12 | 12 |
| query_scan | — | 801 | 3205 | 30 | 30 |
| get_bootstrap | — | 1196 | 4786 | 8 | — |

(`query`/`query_scan` use the CRC-v1 default contract — pointer tier.
`get_bootstrap` emits newline text, so `inline_hits` is the line count and
`candidates` is N/A.)

## Findings that sharpen the later milestones

1. **The segment `query` budget is charged at full-doc cost but only cheap
   pointers are emitted — so the agent pays the full price in *dropped recall*
   while receiving a pointer-cheap payload.** At budget 500, the `take_while`
   over `doc_length_tokens` ([`tools/query.rs:49-61`](../../crates/crux-mcp/src/tools/query.rs#L49-L61))
   keeps only **2 of 30** candidates inline; the other 28 are *dropped* and
   unrecoverable — even though each surviving pointer costs only ~40 est. tokens
   and the whole inline payload is just 348 tokens (well under 500). This is the
   strongest possible motivation for **M1 (reversible overflow)**: demoting all
   30 to pointers would still fit a small budget *and* preserve full recall,
   instead of dropping 93% of the result set.

2. **The CRC-v1 fact envelope can push `query_facts` over the asked budget.**
   At budget 500 the fact path emits **747** inline tokens for a *single* fact
   — the budget is measured on raw `fact.tokens`
   ([`tools/memory.rs:222`](../../crates/crux-mcp/src/tools/memory.rs#L222), first
   fact always kept) but the serialized envelope (pretty-printed JSON + freshness
   + memories_used) adds ~50% overhead on top. **M3 (payload compaction)** attacks
   the overhead directly; the 4× bytes:tokens ratio across every row shows
   `to_string_pretty` whitespace is a constant tax.

3. **`get_bootstrap` has no `token_budget` knob at all**
   ([`tools/facts.rs:686`](../../crates/crux-mcp/src/tools/facts.rs#L686),
   `FactQuery.token_budget = None`) — it returns every matching bootstrap fact
   (here 1196 tokens for 8 patterns). It is also the session-boot surface **M2**
   cache-aligns, so its ordering stability matters more than its size.

## Feature Registry note (QC pre-flight)

M0 calls for a `feature_coverage_report` check on the daemon retrieval
capability. The `feature_*` MCP tools are **not exposed on the current
local-only daemon surface** (`sync_status.mode = local_only`; the Features lens
lives on the MCP-wired host daemon per `PlanCrux/CLAUDE.md §5`). No critical/high
gap could be pulled in this environment — **deferred**: re-run the coverage check
against the host daemon before any default-ON cutover (the follow-up gated plan).

## Raw records

The full JSON record array (one `{metric, value, corpus, lane_flags,
commit_sha, run_id}`-style object per row) is emitted to stdout by the harness;
it is the input for the M3/M1 before/after deltas and the M5 holdout CI report.

---

# M3 — payload compaction result

Flag `CRUX_PAYLOAD_COMPACT` (default OFF). ON ⇒ retrieval payloads are minified
(`to_string`) instead of pretty (`to_string_pretty`) at the four wire sites:
`query` ×1, `query_scan` ×1, `query_expand` ×1 ([`tools/query.rs`](../../crates/crux-mcp/src/tools/query.rs)),
and the `query_facts` CRC-v1 text ([`tools/facts.rs:476`](../../crates/crux-mcp/src/tools/facts.rs#L476)).
Measured on `__synthetic__::token-bench`, commit `c4b0e17`:

| scenario | budget | tokens OFF | tokens ON | reduction | hits OFF→ON |
|---|---:|---:|---:|---:|---:|
| query | 500 | 348 | 259 | −25.6% | 2→2 |
| query | 2000 | 467 | 333 | −28.7% | 9→9 |
| query | 4000 | 740 | 501 | −32.3% | 25→25 |
| query_facts | 500 | 747 | 664 | −11.1% | 1→1 |
| query_facts | 2000 | 2432 | 2209 | −9.2% | 6→6 |
| query_facts | 4000 | 5481 | 5089 | −7.2% | 12→12 |
| query_scan | — | 801 | 539 | −32.7% | 30→30 |
| get_bootstrap | — | 1196 | 1196 | 0% (text surface, not JSON) | 8→8 |

**Reading:** the win scales with how many small JSON objects the payload holds —
pointer surfaces (`query`, `query_scan`) shed ~26–33% (mostly indentation +
newlines), while the full-content fact path sheds ~7–11% (content dominates, less
proportional whitespace). **Hits/candidates are identical in every row** — pure
wire reduction, zero semantic change. `get_bootstrap` emits newline text (not
JSON), so it is untouched by M3 (it is the M2 cache-align target instead).

Per QC.4/R5 these are corpus-named per-scenario measurements, **not** a single
counterfactual headline number — M5 turns them into a holdout-controlled CI
report. Gate M3: golden tests (`payload::tests`, flag-OFF byte-identical to
`to_string_pretty`; flag-ON identical parsed `Value`, strictly fewer bytes,
opaque-string whitespace preserved) + full crux-mcp lib suite green (651 tests).

---

# M1 — reversible overflow on `token_budget` (part 1: segment query path)

Flag `CRUX_BUDGET_REVERSIBLE` (default OFF). The segment `query` response is
pointer-only, so M1 **budgets the emitted pointer tier** (`budget / POINTER_TOKENS`,
`POINTER_TOKENS=40` mirroring CRC-v1's `cost_estimate.pointer`) instead of
charging the *full-doc* hydration cost and dropping the overflow
([`tools/query.rs:48-72`](../../crates/crux-mcp/src/tools/query.rs#L48-L72)). The
full price stays in `cost_estimate.full`; `total_candidates` discloses any capped
remainder; expand via `result_id` (`query_expand`), which now returns a typed
`error_kind:"evicted"` when a handle's segment is gone (T.2). OFF ⇒ the legacy
`take_while`-drop, byte-identical to pre-M1.

`query` hits (recall) at fixed budget on `__synthetic__::token-bench` (30 candidates):

| budget | OFF hits | ON hits | ON tokens | ON+M3 tokens |
|---:|---:|---:|---:|---:|
| 500 | 2 | **12** (6×) | 518 | **364** |
| 2000 | 9 | **30** (all) | 825 | 554 |
| 4000 | 25 | **30** (all) | 825 | 554 |

**Reading:** M1 converts `token_budget` from a *recall-destroying* cut into a
*recall lever* — at budget 500 the agent now sees 12 candidates instead of 2,
and at 2000+ the full set surfaces. M1 alone slightly overshoots the asked budget
(518 > 500) because emitted pointers carry envelope overhead beyond the 40-token
weight; **M1+M3 compose** to bring it back under budget (364 < 500) — full recall
*within* the budget. `query_facts` / `query_scan` / `get_bootstrap` are unchanged
(M1 part 1 is the segment path only; the fact-path full→epitome demotion is
deferred to M1 part 2). Gate M1: `budget::tests` (pointer-budget math,
env-truthy) + `query::tests::reversible_admits_more_than_full_doc_drop`
(flag-OFF→ON recall parity, total_candidates disclosure) +
`query_expand_evicted_error_kind` + full lib suite green (656 tests); flag-OFF
byte-identical (regression net).
