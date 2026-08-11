# GitHub Action pinning — documented exceptions

Policy (ExecPlan `crux-audit-remediation-fail-closed-2026-06-17`, B8): every third-party
GitHub Action referenced from `.github/workflows/` is pinned to a full commit SHA with a
trailing `# vX.Y.Z` comment. First-party actions (`actions/*`, `github/*`) may be
tag-pinned, though in practice they are SHA-pinned here too. Anything that cannot be
SHA-pinned is listed below with owner, reason, and expiry.

| Reference | Where | Owner | Reason | Expiry / review |
|---|---|---|---|---|
| `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0` | `.github/workflows/release.yml` (`provenance` job) | release workflow maintainers (CODEOWNERS for `.github/workflows/`) | The slsa-github-generator project requires its reusable workflows to be referenced by semantic-version tag: the generator verifies its own release integrity internally, and referencing by commit SHA is explicitly unsupported (provenance verification fails). See the project's documentation on referencing builders. Tag `v2.1.0` currently resolves to commit `f7dd8c54c2067bafc12ca7a55595d5ee9b75204a`; the generator's internal verification detects tag tampering. | Review on each generator upgrade, and no later than 2027-02-11 (6 months) |

Adding a new exception requires: (1) evidence that SHA-pinning breaks the action,
(2) an owner, (3) an expiry or review date, and (4) a row in this table in the same PR
that introduces the unpinned reference.
