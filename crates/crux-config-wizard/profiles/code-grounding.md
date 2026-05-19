+++
name = "code-grounding"
version = 1
description = "Verify claims against the actual codebase before attribution. Codifies the Insights-report `Code Grounding` snippet (22 buggy_code + 15 wrong_approach events)."
targets = ["claude_md", "agents_md"]
order = 40
risk_class = "low"
+++

## Code Grounding

### No unverified claims

- Before proposing an architectural change or attributing a benchmark lift to a fix, verify the claim against the actual codebase path and the actual corpus.
- Every claim that names a function, file, or flag includes a `file:line` reference (markdown link) or a `commit_sha` so the reader can verify.
- "I think this is in `foo.rs`" is not a claim. Read the file first, then state.

### Corpus identity is mandatory

When reporting any retrieval / benchmark result, declare the corpus by name (`LME-S`, `LME-M`, `LME-500`, custom-name). Misattributing a lift on LME-S to LME-M is the failure mode the Insights report flagged.

### Substrate scans need budgets

Calls to `query`, `query_scan`, `query_facts`, `query_expand` are not free. Pass `token_budget` on every call, even exploratory ones. Default to 500 unless you've earned more.

### Memory-versus-current-state rule

A Crux memory record that names a specific function, file, or flag is a claim that it existed *when the memory was written*. Before recommending action based on a memory:

- If the memory names a file path: `Read` the file or grep for it.
- If the memory names a function or flag: grep for it.
- If the user is about to act on your recommendation, verify first.

"The memory says X exists" is not the same as "X exists now."

### When the result surprises you

If a benchmark or retrieval result contradicts what you expected, the first move is to verify the result, not to invent a theory for why it changed. Re-run with the same inputs. Confirm the corpus. Check the commit_sha.
