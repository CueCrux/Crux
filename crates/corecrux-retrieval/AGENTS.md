# corecrux-retrieval — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Fused retrieval over `.ccxi` companion indexes: loads them via `IndexManager`, scores
queries with BM25, then fuses graph signals from `ProjectionState` and an optional dense
(cosine) lane. This is the CPU path — the Community Edition's whole retrieval engine.

## Key symbols
- `fused_retrieve` (`fused.rs`) — the entry point: BM25 + graph boost + dense fusion into ranked `FusedHit`s.
- `FusionWeights` / `FusedHit` (`fused.rs`) — lane weighting and the scored-hit shape.
- `DenseProvider` (trait, `dense.rs`) — pluggable dense lane; CE ships `CosineDenseProvider`, the dataplane plugs a GPU `.ccxe` provider.
- `CosineDenseProvider` — exact, **uncapped** CPU cosine over bring-your-own-embedder vectors.
- `apply_graph_boost` / `GraphParams` / `EntityMatch` (`graph.rs`) — graph-signal lane.
- `IndexManager` / `IndexTier` / `TierStats` — `.ccxi` loading, hot-budget residency, eviction.

## Test & verify
- `cargo test -p corecrux-retrieval`
- `dense.rs` test `no_cap_holds_many_vectors` asserts the provider applies no corpus cap
  (10k vectors) — it is the guard for the local-rules item below.

## Local rules
- **Never add a clip/cap/quantisation to the local dense lane.** Per repo `CLAUDE.md` and
  ExecPlan `dense-lane-and-extraction-upsell-2026-06-26`, local dense is a free, uncapped,
  first-class capability; better dense (reranking/extraction) is the metered upsell.
  A corpus cap here is a product regression, not an optimisation.
- Keep everything CPU-only — no CUDA, no GPU readiness checks. GPU dense arrives only via
  the `DenseProvider` trait from a dataplane distribution.
- New scoring signals go through `fused_retrieve`'s fusion, not as post-hoc re-sorts in
  callers (`corecruxd`, `crux-mcp`) — the two consumers must rank identically.
