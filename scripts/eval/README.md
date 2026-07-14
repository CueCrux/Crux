# Buyer-Fit Evaluation — M0 (eval profile + baselines + knock-out demos)

Milestone **M0** of ExecPlan `crux-daemon-buyer-fit-buildout-2026-07-13`:
stand up a reproducible eval profile that flips on the shipped-but-hidden
capabilities, make the profile machine-verifiable, record baseline metrics as
regression gates for M1–M6, and prove knock-outs #3/#4/#5/#6 from existing
capabilities.

## Contents

| File | What it is |
|---|---|
| `../../examples/eval-profiles/buyer-fit-m0.env` | The curated eval profile — sets the six capability flags on. |
| `verify-profile.sh` | Authoritative gate check: asserts `/v1/version.capabilities` reports all six enabled + endpoint health. |
| `baseline-corpus.v1.json` | Named, labeled corpus (`buyer-fit-m0-baseline-v1`) — fixed identity, do not mutate in place. |
| `run-baseline.py` | Loads the corpus, runs labeled queries, records latency / recall@5 / recall-per-token / freshness ranking. |
| `baseline-metrics.v1.json` | Recorded M0 baselines (the regression gate for M1–M6). |
| `demo-3-cross-provider-pool.sh` | Knock-out #3 — one local MCP-mounted pool across Claude Code + Codex + open models. |
| `demo-4-memory-plus-coordination.sh` | Knock-out #4 — memory + coordination in one substrate. |
| `demo-5-token-budget-honest-accounting.sh` | Knock-out #5 — mandatory `token_budget` + deterministic 0-LLM lane + honest accounting. |
| `demo-6-restart-survival.sh` | Knock-out #6 — durable daemon; a fact survives a restart. |

## Running it

```bash
# 1. Build + boot the daemon under the eval profile (auth off, local dev):
source config.example.env                       # base config
source examples/eval-profiles/buyer-fit-m0.env  # flip the six capabilities on
CORECRUXD_AUTH_MODE=off ./target/debug/corecruxd

# 2. Verify the profile booted (machine check):
CRUX_URL=http://127.0.0.1:14800 scripts/eval/verify-profile.sh

# 3. Record baselines:
CRUX_URL=http://127.0.0.1:14800 python3 scripts/eval/run-baseline.py \
    --corpus scripts/eval/baseline-corpus.v1.json \
    --out scripts/eval/baseline-metrics.v1.json

# 4. Prove the knock-outs (#6 needs a CRUX_RESTART_CMD hook):
for d in scripts/eval/demo-*.sh; do CRUX_URL=http://127.0.0.1:14800 "$d"; done
```

## M0 baseline (corpus `buyer-fit-m0-baseline-v1`, keyword fact lane)

Recorded against the debug daemon under the eval profile, `token_budget=500`,
`top_k=5`. Retrieval lane is the existing **keyword fact lane**
(`GET /v1/facts`), *not* dense semantic (which table-stake #2 / M3 adds — named
so M3's lift is attributable).

| Metric | Baseline | Note |
|---|---|---|
| Latency p50 / p95 | 2.0 ms / 2.5 ms | client-side, local loopback |
| recall@5 | 1.00 (8/8 labeled queries) | small labeled corpus; keyword lane |
| mean returned tokens | 457 | under the 500 budget (honest accounting via `total_tokens`) |
| recall per 1k tokens | 2.19 | recall@5 / mean tokens |
| fresh ranked above stale | 2/2 | freshness ranking works on this lane |
| superseded suppression | **off on this HTTP lane** | `GET /v1/facts` returns superseded rows alongside fresh (fresh ranks first); MCP `query_facts` hides them. Signal for M1/M2/M3. |
| capture reliability | N/A (zero point) | auto-extraction is the M1 build; nothing to capture yet |

## Knock-out demo results (M0 local run, auth off)

All four demos + `verify-profile.sh` ran green against the debug daemon under the
eval profile. Honest SKIPs are noted where a local auth-off / empty-index setup
cannot reach the full proof (each SKIP prints exactly what it needs).

| Script | Result | Note |
|---|---|---|
| `verify-profile.sh` | **PROFILE OK** | all six capabilities `true`; all four routes mounted (not 404) |
| `demo-3-cross-provider-pool.sh` | PASS | degraded proof (write→read on one daemon); SKIP the two-token cross-identity proof (needs auth on + two `CRUX_AGENT{1,2}_TOKEN`) |
| `demo-4-memory-plus-coordination.sh` | PASS | `/v1/coord/active` + `/v1/facts` + `/v1/work` all on one daemon; SKIP work-item create (needs a project) |
| `demo-5-token-budget-honest-accounting.sh` | PASS | mandatory `token_budget` enforced (QC.2 contract error when missing); deterministic 0-LLM lane `backend=corecrux-v5-bm25`; SKIP token-accounting (needs a loaded `.ccxi` corpus) |
| `demo-6-restart-survival.sh` | PASS | a fact survived a real daemon restart via the persistence journal |

## Capability observability (the machine-checkable gate)

`GET /v1/version` now carries a `capabilities` block that reflects each gate's
live state (never hardcoded). Verified with a **positive** run (profile on → all
six `true`, routes live) and a **negative control** (defaults → `coordination`
and `local_ingest` `true` [both default-on], the other four `false`, and
`/v1/context` + `/v1/activity` return 404 while off).
