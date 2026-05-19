+++
name = "token-conservation"
version = 1
description = "Output discipline for long agent sessions. Codifies the Insights-report `Output Discipline` snippet (9 sessions blocked by token-limit exhaustion)."
targets = ["claude_md", "agents_md"]
order = 20
risk_class = "low"
+++

## Output Discipline

- Keep responses concise; avoid restating completed work.
- Multi-milestone summaries are at most 10 lines per milestone.
- Batch tool calls without intervening narration when they have no data dependency.
- For audits, plans, benchmark tables: write to files and reference paths in chat. Never paste a multi-page table into chat output.
- When in doubt, default to 500-token output max; raise only to 2,000 for design pulls if explicitly requested.

### Detail offload

When working through milestones, write `gate:M<n>` facts to the Crux store and write artefact paths to the ExecPlan's Progress section. The chat record then carries just enough state-transition signal to resume; the durable record lives in files + facts.

### Avoid

- Long reflections on what you "just did" — the user has the diff.
- Re-quoting large blocks of code or markdown you just read.
- Step-by-step retrospectives at the end of a tool call sequence — one line of "done; next: …" is enough.
- Decorative emojis / banners in code paths. Plain English wins.
