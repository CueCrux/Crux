# Conformance Reference Pack

A worked example of **`pack.conformance.v1`** — the signed block a Crux memory
pack uses to declare what it does, so a replay can later prove whether it did
that. Format spec: [`docs/spec/pack-conformance-v1.md`](../../../../docs/spec/pack-conformance-v1.md).
Schema (MIT): [`docs/spec/pack.conformance.v1.schema.json`](../../../../docs/spec/pack.conformance.v1.schema.json).

Tool names carry the `ext.` prefix on purpose: the MCP layer only surfaces an
extension tool whose name starts with `ext.`, so a pack that drops it ships
tools no agent ever sees.

This pack is **not installable against a live endpoint**: `external_tool_endpoint`
points at `reference.pack.invalid`, a name reserved by RFC 2606 that can never
resolve. It exists to be read, copied, and parsed.

## What it declares

| Part | This pack |
|---|---|
| Claimed capabilities | `facts:read`, `facts:write` — equal to the manifest's declared set, which the validator requires |
| Expected fact mutations | one write per call under `ext.conformance.reference::notes::`, key `content`, non-private |
| Expected receipt mutations | one `dispatch` and one `fact_write` per call |
| Replay corpus | `replay-corpus.json`, content-addressed by SHA-256: three declared cases plus the seeded shadow memory and recall probes the replay measures against |
| Invariants | writes stay in namespace, no private reads, egress pinned, reads are deterministic, the write is reversible |
| Behavioural envelope | 512 tokens/call (2048/run), 2000 ms/call (8000 ms/run), 16 KiB/call, 1 fact write/call, 7-day minimum half-life, zero new contradictions, one-operation undo within 500 ms |
| Compatibility | daemon >= 0.5.0, supersedes 0.1.0 with a reversible `supersede_facts` migration, rollback-safe |

## Trust and safety

Signed with a **fixed example identity** (a documented, non-production seed) so
the committed artefact is reproducible and validly self-signed for the CI gate.
A real publisher signs with their own key and gets their own passport
fingerprint. The declaration is inside the manifest's signing payload, so
widening a bound after signing invalidates the signature — that is the property
the whole trust layer rests on.

## The shadow corpus

`replay-corpus.json` is a `crux.pack.shadow_corpus.v1` document: the declared
cases, the `seed_facts` an M1 replay loads into a local in-memory store before
the pack runs, and the `probes` that measure whether the corpus's own facts stay
citable afterwards. One seed is `private`, so the `no_private_fact_access`
invariant has something real to catch. The corpus is offline by construction and
carries no customer data. Format:
[`docs/spec/pack-shadow-replay-v1.md`](../../../../docs/spec/pack-shadow-replay-v1.md).

## Regenerate

```bash
cargo test -p crux-integrations --test conformance_reference_pack -- --ignored regen_conformance_reference_pack
```
