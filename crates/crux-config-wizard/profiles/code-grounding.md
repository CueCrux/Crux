+++
name = "code-grounding"
version = 2
description = "Cite the source for any claim that names code. v2 narrows the profile to its two durable rules — source citation and corpus identity — after an Opus 5 review: the former 'memory-versus-current-state' and 'when the result surprises you' sections were re-verification instructions, which cost tokens without improving results on Claude 5 generation models (the memory rule survives for non-Claude harnesses in agent-harness-parity). The retrieval-budget rule moved to the MCP tool schemas. Historical driver: the Insights report's 22 buggy_code and 15 wrong_approach events."
targets = ["claude_md", "agents_md"]
order = 40
risk_class = "low"
+++

## Code Grounding

### No unverified claims

- Before proposing an architectural change, or attributing a benchmark lift to a fix, check the claim
  against the actual codebase path and the actual corpus.
- Every claim that names a function, file, or flag carries a `file:line` reference (as a markdown link)
  or a `commit_sha`, so the reader can check it independently.
- "I think this is in `foo.rs`" is not a claim. Read the file, then state.

This is a citation requirement, not a re-checking ritual: the cost is naming your source as you write,
not going back over finished work.

### Corpus identity is mandatory

Any retrieval or benchmark result names its corpus (`LME-S`, `LME-M`, `LME-500`, or the custom name).
A lift measured on one corpus reported against another is the known failure mode here, and it is not
recoverable after the fact — the number and the corpus travel together or the number is worthless.
