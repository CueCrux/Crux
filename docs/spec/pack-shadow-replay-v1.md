# Shadow-corpus staging + replay — `crux.pack.shadow_corpus.v1` and `crux.pack.replay_record.v1`

**Status:** M1 of ExecPlan `proof-carrying-adaptive-packs-2026-07-13`.
**Declaration format:** [`pack.conformance.v1`](pack-conformance-v1.md) — what the pack promises.
**Evidence hook:** [`corecruxd::pack_conformance`](../../crates/corecruxd/src/pack_conformance.rs) — what the pack did.
**This layer:** [`corecruxd::pack_replay`](../../crates/corecruxd/src/pack_replay.rs) — whether the two agree.
**Reference corpus:** [`integrations/community/ext.conformance.reference/0.2.0/replay-corpus.json`](../../integrations/community/ext.conformance.reference/0.2.0/replay-corpus.json).

## What this adds

M0 gave a pack a way to state, under its publisher's signature, what it does.
The staged-activation seam gave it a state to run in that commits nothing, and
the conformance hook gave it a place to be observed. None of them decides
anything: the hook deliberately reports **evidence** and no verdict.

This layer is the half that judges, and it runs **before the pack is enabled**:

1. **Stage** the pack (`POST /v1/extensions/{id}/lifecycle`, `state: "staged"`).
   A staged pack runs and is observed; nothing it writes reaches memory.
2. **Replay** its declared cases against its declared shadow corpus
   (`POST /v1/extensions/{id}/replay`). The cases run **twice** — reproducibility
   is only observable by running a pack more than once.
3. **Judge**: measure what the pack did to a local shadow store, compare all of
   it to the signed envelope and invariants, and store a
   `crux.pack.replay_record.v1` carrying the verdict.
4. **Enable** — or not. With `CORECRUXD_PACK_REPLAY_GATE` on, a declaring pack
   with no passing replay of *this exact build* cannot move to `active`.

## The corpus is bytes

`replay_corpus.sha256` in the signed declaration is a digest over the corpus
file. The replay route therefore takes the corpus as **verbatim text**
(`corpus_json`), hashes it, and refuses anything that does not match — along
with a corpus under the wrong schema, naming a different `corpus_id`, or whose
cases disagree with the cases the manifest declares under signature. "Replayed
against corpus X" then names bytes, not a filename someone can swap between the
declaration and the run.

```jsonc
{
  "schema": "crux.pack.shadow_corpus.v1",
  "corpus_id": "conformance-reference-v1",
  "description": "…",
  "seed_facts": [                       // the memory the pack is replayed against
    { "entity": "…", "key": "content", "value": "…", "confidence": 1.0, "private": false }
  ],
  "probes": [                           // recall / citation measurement
    { "probe_id": "…", "query": "…", "expect_entities": ["…"] }
  ],
  "cases": [                            // must equal replay_corpus.cases
    { "case_id": "…", "tool_name": "…", "args": {} }
  ]
}
```

The corpus is **local and offline by construction**: a document seeded into an
in-memory fact store the harness creates and drops. No network, no customer
data, and nothing in the operator's real store is read or touched. The shadow
store never has an embedder attached, so probe recall is the lexical path and a
pure function of the corpus plus the pack's writes.

A probe is *satisfied* when every entity in `expect_entities` is returned by the
query as a live, non-private, latest-version fact — mirroring what `query_facts`
and `GET /v1/facts` show. A pack that buries a corpus fact under its own writes
regresses the probe, and the regression is named per probe rather than rolled
into a score.

## What a replay measures

| Measurement | Source | Blocks? |
|---|---|---|
| Observed fact writes, per call and total | staged dispatch, post grant-filter and privacy gate | yes — `envelope.max_fact_writes_per_call` |
| Dropped fact writes | the grant filter's refusals | via `no_undeclared_capability_use` |
| Token cost | `ceil(response_bytes / 4)` — see below | yes — `max_tokens_per_call`, `max_tokens_per_run` |
| Response bytes | conformance observation | yes — `max_response_bytes_per_call` |
| Decay half-life | entity-derived `HorizonClass`, shortest across writes | yes — `decay.min_half_life_seconds` |
| Contradiction rate (ppm) | store contradiction candidates **plus** polarity flips | yes — `max_contradiction_rate_ppm` |
| Recall / citation | corpus probes, before and after the writes | via `no_new_contradictions` and the record |
| Rollback | apply the writes, reverse them, compare projections | yes — `undo.max_operations_per_call` |
| Latency, undo latency | wall clock | **no** — advisory only |

**Token cost is an estimate with a fixed divisor.** The daemon has no tokenizer
and must not acquire one for this: a signed envelope needs a cost that is a
pure, reproducible function of the observed bytes, and a tokenizer is a
model-specific dependency whose output moves under it.

**Contradictions are counted two ways.** The store's own pass finds two *active*
facts under one `(entity, key)` with opposite polarity. That shape cannot arise
from a pack write, because a same-key write supersedes its predecessor — so the
replay also counts **polarity flips**: writes that reverse the polarity of the
value they displace. A pack that silently rewrites `active` to `inactive` has
contradicted memory, and would otherwise read as clean.

## Determinism, and why latency never blocks

A replay must be reproducible bit-for-bit given the same pack and corpus, or
the receipt M2 signs over it attests to nothing. Two consequences:

- `record_digest` is BLAKE3 over an explicit projection that **excludes every
  clock-derived value**. Timings live in their own `timings` field so the
  exclusion is structural rather than a filter someone has to remember.
- A wall-clock bound cannot decide a verdict, because it differs on every run
  of even a perfectly deterministic pack. Latency overruns are recorded in
  `advisories` and reported; the right instrument for cost drift is the
  distribution over many runs, which is M3's continuous score. Every bound that
  *is* a function of behaviour blocks.

A replay that does not reproduce itself is blocked outright, whether or not the
pack declared a `deterministic_replay` invariant: a pack that is not a function
of its inputs cannot carry a proof of anything.

## Evaluating the seven invariants

`pack.conformance.v1` closes the invariant set so every declared property is
evaluable. What each one becomes at replay time:

| Kind | Checked as |
|---|---|
| `no_undeclared_fact_writes` | every observed write falls under a declared `entity_prefix`, key set and privacy posture |
| `no_private_fact_access` | the manifest holds no `data_access.private_facts` grant, **and** no private seed's content re-surfaces in a write |
| `no_undeclared_capability_use` | the grant filter refused nothing |
| `no_egress_outside_allowlist` | `network.allowed_hosts` is non-empty and covers the pack's own endpoint (the transport refuses anything else before the call leaves) |
| `deterministic_replay` | the two runs agree, per case, on everything except the clock |
| `reversible_writes` | applying and then reversing the writes returns the shadow store's active projection to its seeded state |
| `no_new_contradictions` | no new contradiction candidate and no polarity flip |

Two of these are proxies and say so: what happens *inside* a pack is not
observable from the daemon, so `no_private_fact_access` checks what the pack was
given and what came back out, and `no_egress_outside_allowlist` checks that the
allowlist is a real constraint rather than replaying an egress attempt the
transport already refuses.

## The record

`crux.pack.replay_record.v1` is stored as a new version of
`__extension__::{id}` / `replay` — the same reserved, privacy-gated entity the
install record uses, so a re-replay supersedes rather than erases the previous
verdict and no new on-disk artifact type is introduced. It carries the pack
attribution (id, version, install-time `manifest_hash`), the corpus id **and**
digest, every observation verbatim, the measurements, the violations, the
advisories, one result per declared invariant, the verdict, and
`record_digest`. `ReplayRecord::verdict_reasons()` renders the verdict as
ordered prose for an operator and for the `extension_replay_run` audit row.

## Rollout

`CORECRUXD_PACK_REPLAY_GATE` is **off by default**. The record, the verdict and
the audit row are produced either way; only the refusal is gated. That matches
the plan's advisory-first rollout — the behavioural trust surface shows the
evidence first and becomes the default enablement gate after M6's go/no-go.

A pack that ships **no** conformance block is never gated. It declared no
envelope, so there is nothing a replay could contradict, and every pack
installed before this milestone is in exactly that position.
