# `pack.conformance.v1` — the conformance declaration a pack carries

**Status:** M0 of ExecPlan `proof-carrying-adaptive-packs-2026-07-13` — format frozen.
**Schema (MIT):** [`pack.conformance.v1.schema.json`](pack.conformance.v1.schema.json) — canonical path `docs/spec/pack.conformance.v1.schema.json`.
**Reference pack:** [`integrations/community/ext.conformance.reference/0.2.0/manifest.json`](../../integrations/community/ext.conformance.reference/0.2.0/manifest.json).
**Rust types:** [`crux_integrations::conformance`](../../crates/crux-integrations/src/conformance.rs).

## What it is

Every plugin ecosystem decides whether to trust an extension from a **static
scan plus a download count**. Neither survives the extension's next release.
`pack.conformance.v1` is the first half of a different answer: the block a Crux
memory pack uses to **declare what it does**, signed by its publisher, so a
replay against a local shadow corpus can later prove whether it did that.

The block lives inside a `crux.integration.v1` manifest, as the optional
`conformance` field, and declares six things:

| Field | What it pins down |
|---|---|
| `claimed_capabilities` | The capabilities the pack claims conformance for. **Must equal** the manifest's declared capability set. |
| `expected_mutations` | The fact writes (entity prefix, keys, operation, privacy, per-call bound) and receipt emissions the pack expects to cause. |
| `replay_corpus` | The named, content-addressed corpus its declared operations are replayed against, and the operations themselves. |
| `invariants` | Properties that must hold while those operations run, from a closed set a harness can actually evaluate. |
| `envelope` | Integer bounds on token cost, latency, response size, fact writes, decay behaviour, contradiction rate, and undo cost. |
| `compatibility` | Minimum daemon version, the manifest schema it was written against, superseded versions, migration steps, and whether rollback is data-safe. |

## Three design rules worth knowing before you implement it

**The declaration is inside the signature, not beside it.**
[`IntegrationManifest::signing_payload`](../../crates/crux-integrations/src/lib.rs) appends
the block, so widening an envelope after signing invalidates the signature and
changes `hashes.manifest`. A promise an attacker can edit after signing is not
evidence; it is a second, softer manifest. The field is skipped when absent, so
every manifest signed before the block existed hashes and verifies unchanged.

**Every bound is an integer.** Rates are parts-per-million and costs are whole
units. JSON has no canonical form for a float — `0.1`, `1e-1`, and
`0.1000000000000000055511151231257827` are the same IEEE-754 double and
different bytes — so a `f64` bound would make a signature depend on which
serialiser wrote it.

**`invariants[].kind` is a closed set.** There is no `custom` escape hatch,
because a declared invariant that is a sentence of prose cannot be evaluated by
any harness, and an unverifiable claim inside a proof-carrying format is worse
than no claim. Adding a property means a new schema version, which is a
reviewable diff. The same reasoning closes `expected_mutations.receipts[].receipt_kind`
and drops `delete` from `expected_mutations.facts[].operation`: the store is
append-only and reversal is supersession, so a delete would name an operation
the substrate cannot perform.

## Cross-field rules

The schema constrains shape; [`PackConformance::validate`](../../crates/crux-integrations/src/conformance.rs)
adds the rules that need the surrounding manifest. A declaration is refused when:

- `claimed_capabilities` is not set-equal to `capabilities` — a block narrower
  than the pack lets it carry a clean replay result for the half it chose to show.
- The block appears on an `entry.kind` that does not execute (anything other
  than `external_tool` or `wasm`).
- A case names a tool the manifest does not declare, a case id repeats, or the
  corpus declares more than 64 cases (the cap the daemon's conformance hook
  enforces, so a declaration can never be one the hook would refuse to run).
- `replay_corpus.corpus_id` is empty, its `path` escapes the pack directory, or
  its `sha256` is not 64 lowercase hex characters.
- Declared per-call fact writes exceed `envelope.max_fact_writes_per_call`, the
  pack declares writes without the `facts:write` capability, or declares a
  private write without `data_access.private_facts`.
- The pack declares fact writes but a zero `decay.min_half_life_seconds`,
  `undo.max_operations_per_call`, or `max_fact_writes_per_call` — or declares no
  writes and a non-zero value for any of the three. "Writes nothing" has to be a
  claim a replay can falsify, not a field left blank.
- A run bound is below its per-call bound, `max_contradiction_rate_ppm` exceeds
  1,000,000, or a per-call cost bound every call pays is zero.
- `compatibility.manifest_schema` disagrees with the manifest's own schema,
  `min_daemon_version` is not `MAJOR.MINOR.PATCH`, a migration targets a version
  other than this pack's, or its `from_version` is not listed in `supersedes`.

## Where it plugs in

The daemon's conformance hook (`corecruxd::pack_conformance`, the
`crux-daemon-buyer-fit-buildout-2026-07-13` M5 seam) replays a staged pack's
operations and reports **evidence, never a verdict**. `cases_from_manifest` now
takes its cases from this block when a pack ships one, falling back to the
one-empty-args-case-per-tool floor when it does not; `POST /v1/extensions/{id}/conformance`
defaults its `corpus_id` to the declared `replay_corpus.corpus_id`. Comparing
observed behaviour against the declared envelope, and signing the verdict into a
CROWN receipt, are M1 and M2 of `proof-carrying-adaptive-packs-2026-07-13`.

## Validate a block

The schema is a plain draft 2020-12 document, so any validator works:

```bash
python3 - <<'PY'
import json
from jsonschema import Draft202012Validator
schema = json.load(open("docs/spec/pack.conformance.v1.schema.json"))
Draft202012Validator.check_schema(schema)
manifest = json.load(open("integrations/community/ext.conformance.reference/0.2.0/manifest.json"))
Draft202012Validator(schema).validate(manifest["conformance"])
print("valid")
PY
```

In-tree, `cargo test -p crux-integrations` covers the same ground without the
dependency: the committed schema file is asserted byte-equal to
`conformance::json_schema()`, the reference pack is validated against it, and
the reference pack's signature is checked with its block both intact and
tampered.

## Licence

The Crux daemon is Apache-2.0. **This schema document —
`docs/spec/pack.conformance.v1.schema.json` — is published under the MIT
Licence**, so a registry, linter, SDK, or competing implementation can
implement and vendor `pack.conformance.v1` without taking on Apache-2.0
obligations. The format is meant to be copied; the daemon that enforces it is
not.

```
MIT License

Copyright (c) 2026 CueCrux Ltd.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
