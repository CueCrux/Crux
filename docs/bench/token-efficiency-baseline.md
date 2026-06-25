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
