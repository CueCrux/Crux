# crux-config-wizard — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Composes `CLAUDE.md` and `AGENTS.md` from versioned profile fragments for
Crux-aligned workspaces. Ships as both a library (loaded by the
`crux-claude-hooks` `session-start` hook for drift detection) and the
`crux-config-wizard` binary (`init`, `regenerate`, `check`, `list`, `add`,
`remove`, `diff`).

## Key symbols
- `compose_file` (`compose.rs`) — rewrites only the spans between `<!-- BEGIN-CRUX-MANAGED:<name> v<n> -->` / `<!-- END-CRUX-MANAGED:<name> -->` marker pairs; text outside markers is preserved verbatim.
- `check_workspace` / `DriftReport` (`drift.rs`) — detects divergence between a workspace file and the bundled fragments.
- `load_bundled_profiles` / `ProfileFragment` (`profile.rs`) — versioned fragment loading.
- `Target` — `ClaudeMd` vs `AgentsMd` output selector.
- `DEFAULT_PROFILES` — default profile set for the CueCrux workspace.

## Test & verify
- `cargo test -p crux-config-wizard`

## Local rules
- Managed-section markers are the contract: never hand-edit inside a `BEGIN-CRUX-MANAGED`/`END-CRUX-MANAGED` span, and never emit output that breaks marker pairing (`ComposeError` covers unbalanced markers).
- `compose_file` refuses to overwrite a manually edited managed section without `force` — do not weaken that check; regenerating with `--force` clobbers manual edits by design.
- Profile content changes belong in the bundled fragments (with a version bump), not in ad-hoc string edits to composed files.
