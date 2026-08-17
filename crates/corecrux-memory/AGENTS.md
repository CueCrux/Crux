# corecrux-memory — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Versioned fact store + session store for the Crux Daemon: receipted entity/key/value
facts (BM25-searchable, private-scopable), structured session state, a Memento-style
`CaseStore` for procedural memory, and the `EntityStore`/`EdgeStore`/`KindRegistry`
domain substrate that lens crates (e.g. `crux-lens-features`) build on. Every write
produces a CROWN-compatible receipt.

## Key symbols
- `FactStore` / `Fact` (`fact_store.rs`) — the versioned fact store; `build_fact` assigns monotonic versions.
- `mark_superseded` / `supersede_prior_version` — flip `superseded_by` on the predecessor; journaled, never deleted.
- `HorizonClass` — freshness horizon per fact: `Volatile` (~24h) / `Medium` (~35d) / `Stable` (~365d) / `None`; defaulted per entity via `default_for_entity`.
- `consolidate_facts_v1` / `ContradictionCandidateV1` — consolidation that supersedes targets, preserving history.
- `CruxPack` / `build_manifest` / `verify_pack` (`cruxpack.rs`) — passport-signed memory-portability export envelope.
- `DEFAULT_PRIVATE_PREFIXES` / `DAEMON_OWNED_ENTITY_PREFIXES` /
  `GENERIC_CREATE_RESERVED_PREFIXES` (`fact_privacy.rs`) — canonical
  privacy/export policy, daemon control namespaces, and physical wrappers that
  generic callers cannot create.
- `EntityStore` / `EdgeStore` / `KindRegistry` — the `(kind, id, payload)` + labelled-edge substrate behind `/v1/entities/*`.

## Invariants
- Establishes I4 (monotonic fact versioning): a new value for `(entity, key)` gets
  `version = prev + 1` and marks the predecessor `superseded_by` — supersede, never delete.
  Recall filters on `superseded_by.is_none()` by default (checked in `crux-mcp`).

## Test & verify
- `cargo test -p corecrux-memory`
- Key tests: `consolidate_facts_v1_supersedes_targets_without_deleting_history`,
  `mark_superseded_persists_across_replay`,
  `export_excludes_private_and_reserved_by_default`,
  `verify_rejects_pack_carrying_deleted_facts` (CLAIMS.md claim 10).

## Local rules
- Never delete a fact row to "update" it — supersede (I4). Deleting breaks replay and recall history.
- `.cruxpack` export hygiene is a hard guard: `private: true` facts and
  `CRUXPACK_RESERVED_PREFIXES` entities stay home unless explicitly opted in; tombstoned/
  compacted facts are excluded *unconditionally* — do not add a flag that exports deleted facts.
- Generic HTTP, MCP, extension, sync, and pack-import paths must reject
  `DAEMON_OWNED_ENTITY_PREFIXES` plus direct creates in
  `GENERIC_CREATE_RESERVED_PREFIXES`; only the owning typed daemon workflow may
  write control records or assign physical private wrappers through the
  low-level `FactStore`.
- When adding a fact-write path, assign a `HorizonClass` (or let `default_for_entity`
  choose); `HorizonClass::None` is for identity/pinned facts, not a lazy default for new kinds.
- Add new born-private namespaces to `DEFAULT_PRIVATE_PREFIXES`; the drift
  test requires `CRUXPACK_RESERVED_PREFIXES` to cover that canonical slice.
  Add daemon-owned control namespaces to `DAEMON_OWNED_ENTITY_PREFIXES` as well;
  add storage wrappers to `GENERIC_CREATE_RESERVED_PREFIXES` without preventing
  owner-authorized mutation of their visible logical entity.
