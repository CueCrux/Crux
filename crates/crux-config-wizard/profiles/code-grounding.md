+++
name = "code-grounding"
version = 3
description = "Cite the source for any claim that names code. v3 adds two rules earned in the gate-oversight work: read existence questions against `origin/main` rather than a shared checkout (four times a claim held in the working tree and not on main; two would have shipped a fix on a false premise, and one was a live privilege escalation nobody had noticed), and give a load-bearing doc claim an `enforced-by:` pointer so deleting its test breaks the build instead of quietly unmaking the promise. v2 narrows the profile to its two durable rules — source citation and corpus identity — after an Opus 5 review: the former 'memory-versus-current-state' and 'when the result surprises you' sections were re-verification instructions, which cost tokens without improving results on Claude 5 generation models (the memory rule survives for non-Claude harnesses in agent-harness-parity). The retrieval-budget rule moved to the MCP tool schemas. Historical driver: the Insights report's 22 buggy_code and 15 wrong_approach events."
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

### Existence questions go to `origin/main`, not the working tree

A shared checkout sits on whatever branch another session last used. `grep`, `ls`
and `Read` answer about *that* tree, and say nothing about which ref it is — so
"does X exist?" gets a confident answer about the wrong code.

- Create the worktree off `origin/main` **before** research, not before writing.
  The tree you read is then one you chose.
- To check a single claim without one: `git show origin/main:<path>` or
  `git grep <pattern> origin/main -- <pathspec>`.
- A file, symbol or contract seen only in the working tree is unverified until
  one of those confirms it.

The cost of getting this wrong is asymmetric. Believing something exists that
does not wastes a build; believing an enforcement exists that does not ships the
hole it was supposed to cover.

### Load-bearing doc claims carry `enforced-by:`

A doc comment asserting an invariant — especially a security one — is a promise,
and a promise nothing tests decays silently into a lie. Name the test:

    //! - **Tenant leakage (T.1):** issued scopes never exceed the approver's.
    //!   enforced-by: attack_device_approve_cannot_grant_scopes_the_approver_lacks

`scripts/check-enforced-by.sh` fails the build when a named test disappears. It
proves a test of that *name* exists, not that it tests the claim — the same bound
as the other citation lints here, and it buys the same thing: drift stops being
silent.

### Corpus identity is mandatory

Any retrieval or benchmark result names its corpus (`LME-S`, `LME-M`, `LME-500`, or the custom name).
A lift measured on one corpus reported against another is the known failure mode here, and it is not
recoverable after the fact — the number and the corpus travel together or the number is worthless.
