+++
name = "eu-ai-act"
version = 1
description = "Engineering-best-practice posture aligned with EU AI Act Reg. 2024/1689 Art. 9, 10, 12, 13, 14, 15. NOT a legal opinion; operator review required for any conformity assessment."
targets = ["claude_md", "agents_md"]
order = 70
risk_class = "high"
+++

> **Banner.** The rules below are engineering best practice aligned with the EU AI Act. They are not a legal opinion. Conformity assessment for any specific deployment remains the operator's responsibility. This profile gives you the technical scaffolding (logging, attribution, human gates, PII handling); the legal mapping is yours.

## AI Act Posture

### Risk classification (Art. 9 — risk management)

- Every ExecPlan declares a **risk class** (`low | medium | high`) in its Purpose section.
- High-risk plans (prod deploys, data deletion, schema migrations touching PII, multi-tenant changes) require a passport-attributed human gate via `/v1/work/{id}/transitions` before the cutover step. The gate fact records the approving passport and a timestamp.
- Each high-risk decision stores: `entity="execplan:<slug>", key="decision:<topic>", value={..., commit_sha, actor, risk_class, mitigations}`.

### Data governance (Art. 10)

- PII facts MUST be stored with `private: true` so they never push to a remote during sync.
- Reserved entity prefixes are born private at ingest: `__agent::*`, `__ops::*`, `__bootstrap__::*`. Do not bypass this by stripping the prefix.
- Synthetic or test fixtures must be clearly named (`test-`, `fixture-`, `__synthetic__::`) so they aren't confused with prod data.

### Automatic logging (Art. 12 — record-keeping)

- Every state mutation produces a CROWN receipt + a `/v1/projections/entity/timeline` row. Do not bypass — never write to entity stores via raw filesystem.
- Every ExecPlan milestone gate stores a fact with `commit_sha` so the audit trail is replayable.
- Retention default: 90 days for receipts, indefinite for ExecPlan facts (deletable only by explicit operator action).

### Transparency (Art. 13)

- Commit messages on AI-authored changes include `Co-Authored-By: <agent>` or `agent:<name>` so the audit trail attributes authorship.
- Pull-request descriptions name the agent + the ExecPlan slug.
- When an agent's output is being shown to an end-user (not just a developer), include a brief AI-involvement notice. Skip the notice only when the consumer is provably another agent or system.

### Human oversight (Art. 14)

- Destructive actions (delete, force-push, drop, `rm -rf`, schema-destructive migrations) require explicit consent in the current conversation. Approval of one destructive action does not extend to others.
- "Operator already approved similar action yesterday" is not consent. Re-confirm.
- Gated transitions on `/v1/work` cannot be auto-approved past the configured timeout without a documented fallback policy.

### Accuracy + foresight (Art. 15)

- Before any high-risk action, call `/v1/actions/enrich` and surface predicted consequences + affected resources to the user.
- If the consequence prediction includes affected principals or resources the user didn't anticipate, stop and re-confirm.
- Benchmarks reported to users carry their corpus identity and commit_sha so the user can replay if results surprise.
