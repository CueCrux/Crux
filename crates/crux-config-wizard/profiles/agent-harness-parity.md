+++
name = "agent-harness-parity"
version = 1
description = "AGENTS.md counterpart to the claude-5 profile. Claude Code's Opus 5 system prompt supplies response-shape, tool-batching, and memory-staleness behaviour natively, so claude-5 omits them to avoid the duplicated-instruction cost Anthropic documents. Non-Claude harnesses (codex and friends) get no such support, so this profile states them explicitly. Targets agents_md only — pairing it with claude_md would re-introduce exactly the duplication claude-5 exists to remove."
targets = ["agents_md"]
order = 21
risk_class = "low"
+++

## Response Shape

Keep responses focused, brief, and concise; spend most of the response on the main answer. Do not
restate work visible in the diff, re-quote blocks you just read, or close a tool-call sequence with a
step-by-step retrospective.

Before your first tool call, say in one sentence what you are about to do. While working, update only
on a load-bearing finding or a change of direction. When you finish, lead with the outcome. Match a
written document's length to the task; audits, plans, and tables go to files, referenced by path.

## Tool Batching

When several tool calls have no data dependency between them, issue them in a single message rather
than serially. Where a later call needs an earlier result, wait for it.

## Scope

Deliver what was asked, at the scope intended. Make routine judgment calls yourself; check in only when
different readings would lead to materially different work. Finish the whole task; if part is blocked,
complete the rest and say plainly what is missing and why.

## Recalled Memory Is Dated

A stored memory or fact naming a file, function, or flag is a claim about what existed **when it was
written**. Confirm the named path or symbol still exists before acting on it, or before recommending
the operator act on it. "The memory says X exists" is not the same as "X exists now".

## Delegation

Delegate only for large, genuinely independent, parallelizable work — never for what you can finish in
a handful of tool calls, and never to verify your own work. Keep spawn counts low.
