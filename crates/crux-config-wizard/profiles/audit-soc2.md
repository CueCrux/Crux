+++
name = "audit-soc2"
version = 1
description = "General audit + SOC 2-style hygiene: commit_sha attribution, write-agent isolation, retention windows, reproducibility."
targets = ["claude_md", "agents_md"]
order = 80
risk_class = "medium"
+++

## Audit Hygiene

### Attribution

- Every decision fact (`store_fact(entity="execplan:<slug>", key="decision:<topic>", ...)`) carries a `commit_sha` so the codebase state at decision time is recoverable.
- Every write through the substrate carries a passport (via `actor` field on `entity_upsert`). Anonymous writes are operator-tagged, not silently allowed.
- Pull requests reference the ExecPlan slug in the description; ExecPlan progress lines reference the PR / commit.

### Write-agent isolation

- One write-agent per source tree at a time. Spawn subagents for read-only research; the orchestrator is the only one that mutates the prod tree.
- For cross-session work, use `create_handoff` / `accept_handoff` rather than running parallel write-agents — the multi-agent-parallel anti-pattern produced 4+ collision incidents in past sessions.

### Reproducibility

- Build artefacts include their source `commit_sha` (cargo embeds this for crates; document for TS).
- Benchmark results include `corpus`, `commit_sha`, `lane_flags`, `run_id` (per `memory-practices` fact convention).
- A "we changed two things at once" attempt is rejected — either A/B clean attribution per change, or call out the bundling explicitly.

### Retention

- Receipts: 90 days minimum, configurable higher.
- ExecPlan facts: indefinite, deletable only by explicit operator action.
- Postgres / database dumps for migrations: 90 days post-cutover, archived encrypted.
- Conversation transcripts: per-workspace policy; if regulated content is involved, prefer per-session purge with structured facts retained.

### Separation of duties

- The agent that produces code is not the agent that signs off on its merge. Reviewer + author distinction is preserved in commit metadata.
- Production-touch operations (deploys, data migrations) need at least one human gate per the `eu-ai-act` profile.
- Read-only diagnostics need not be gated; mutation gates are.

### Change tracking

- All schema changes go through migrations checked into source control. No ad-hoc `ALTER TABLE` on prod.
- Profile changes (this very file, the workspace's CLAUDE.md) go through `crux-config-wizard regenerate` with a managed-section diff for review.
