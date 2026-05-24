# Quality + Threat Refs

A small, stable taxonomy of IDs that design facts cite in their `qc_ref` and `threat_ref` fields. IDs are stable: a `QC.1` cited in 2026 means the same thing in 2030. Refs themselves never change — they survive renaming, refactors, and time.

See [Citing Quality + Threat refs in design facts](./agent-guide.md#citing-quality--threat-refs-in-design-facts) in the agent guide for the sibling-tag fact-storage convention.

## QC.1..QC.5 — Quality contract

- **QC.1** — Every decision fact carries `commit_sha`.
- **QC.2** — Every retrieval call carries `token_budget` (defaults: 500 confirmation / 2000 scan / 4000 design pull).
- **QC.3** — Every mutation is passport-attributed (no anonymous writes through the substrate).
- **QC.4** — Every benchmark / retrieval result declares the corpus by name (`LME-S`, `LME-M`, `LME-500`, custom-name).
- **QC.5** — No unverified claims about file/symbol existence: file:line reference or `commit_sha` accompanies every claim that something exists.

## T.1..T.5 — Threat refs

- **T.1** — Cross-tenant fact leak (a fact written under tenant A becomes visible to tenant B).
- **T.2** — Stale-state decision (acting on a recalled memory whose underlying file/flag has since been renamed, removed, or never merged).
- **T.3** — Unauthenticated mutation (a write reaches the fact store without an attributable passport).
- **T.4** — Audit-trail gap (a mutation completes but no receipt / projection row is produced).
- **T.5** — Supply-chain compromise of agent tooling (an unaudited hook, unpinned `npx -y` / `uvx` / `@latest`, or pipe-to-shell installer reaches a dev machine).

## Adding new refs

Bump the version of any downstream document that enumerates these refs when adding a `QC.6` / `T.6`. Existing facts continue to resolve unchanged — new refs are additive. If a ref is retired, mark it deprecated here but do not reuse the number; old facts that cite it remain valid historically.
