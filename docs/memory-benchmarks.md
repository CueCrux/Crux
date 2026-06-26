# Memory recall benchmarks

A deterministic, CPU-only harness that **measures** the Crux Daemon memory
stack instead of assuming it works — adapted from the LoCoMo,
MemoryAgentBench and HaluMem benchmarks catalogued in the
[Awesome-Agent-Memory](https://github.com/TeleAI-UAGI/Awesome-Agent-Memory)
survey (execplan `agent-memory-improvements-2026-06-26`, M4).

## Run it

```bash
cargo test -p crux-mcp --test memory_recall_bench -- --nocapture
```

The harness lives in [`crates/crux-mcp/tests/memory_recall_bench.rs`](../crates/crux-mcp/tests/memory_recall_bench.rs)
— `crux-mcp` is where the fact store (`corecrux-memory`) and the decay policy
(`corecrux-projections`) meet, the same pairing the real recall path uses. It
re-implements only the **public** ranking rule (`effective_confidence` over
salience-aware decay), so it tracks production ranking without touching private
internals.

## Metrics

| Metric | Source benchmark | What it measures | Gate |
|---|---|---|---|
| **recall@k** | LoCoMo / MemoryAgentBench | fraction of QA probes whose correct fact is in the top-k recalled | `>= 0.85` at k=3 |
| **stale-leak rate** | HaluMem | fraction of "value was corrected" probes where a decayed-stale prior value still outranks the fresh correction | `== 0` |
| bi-temporal as-of | (Graphiti, M1) | `query_as_of` recovers the world-state true at a past instant | exact |
| salience lift | (M2) | a heavily-recalled aged fact resists the stale demotion a cold one suffers | strict `>` |

Recall and stale-leak are real assertions: a recall regression or any rise in
stale leakage fails CI.

## Why these two headline metrics

- **recall@k** is the table-stakes question — can the store surface the right
  fact at all. It exercises lexical matching + confidence/decay ranking over a
  small multi-entity "long conversation" fixture with distractors.
- **stale-leak rate** is the one that justifies the whole freshness/decay
  subsystem. Without decay, a corrected value competes head-to-head with its
  stale predecessor on raw confidence; HaluMem shows that's exactly where
  memory-augmented agents hallucinate. The harness proves the decay ranking
  sinks the stale value below the fresh correction across volatile/medium/stable
  horizons.

## Future work — ScoreCrux TS harness

ScoreCrux is TypeScript and cannot run in the current Linux/WSL build
environment (no Linux Node), so the runnable harness is Rust. A follow-up
should port the **full** public LoCoMo and HaluMem datasets into ScoreCrux,
driving the daemon over its HTTP recall API (`POST` query_facts on port 14800)
so the numbers are comparable to the published leaderboards rather than the
hand-authored fixtures here. The Rust harness is the regression gate; the
ScoreCrux port is the external-comparability story.
