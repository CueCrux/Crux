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
- `load_workspace_profiles` (`digest.rs`) — the loader every composing command goes through: bundled fragments with the `memory-digest` body replaced by the workspace's rendered `.crux/memory-digest.md`, when one is present and passes the budget + credential checks.
- `Target` — `ClaudeMd` vs `AgentsMd` output selector.
- `DEFAULT_PROFILES` — default profile set (`init --profiles=all`); `workspace-cuecrux` is deliberately not in it.
- `hooks_install` — Claude Code hook scripts + `settings.json` merge. `ContinuityOwner` decides whether the SessionStart banner and PreCompact save are wired: not when the mod is installed.
- `mods_install` — the `crux-desktop` Claude Code mod: files embedded from `assets/mods/crux-desktop/`, `CLAUDE_CODE_PLUGIN_DIRS` + `pluginConfigs` in `settings.json`, user-scope MCP server in `~/.claude.json`.
- `paths` — home/Claude-config resolution (`USERPROFILE` on Windows) and `shell_word`, which every hook command path goes through.

## Test & verify
- `cargo test -p crux-config-wizard`

## Local rules
- Managed-section markers are the contract: never hand-edit inside a `BEGIN-CRUX-MANAGED`/`END-CRUX-MANAGED` span, and never emit output that breaks marker pairing (`ComposeError` covers unbalanced markers).
- `compose_file` refuses to overwrite a manually edited managed section without `force` — do not weaken that check; regenerating with `--force` clobbers manual edits by design.
- Profile content changes belong in the bundled fragments (with a version bump), not in ad-hoc string edits to composed files.
- The mod under `assets/mods/crux-desktop/` is the source of truth; `~/.claude/mods/crux-desktop` is an install of it. Edit here, bump `version` in its `plugin.json`, and check it with `claude plugin validate crates/crux-config-wizard/assets/mods/crux-desktop`.
- `memory-digest` is the one fragment whose body is not fixed text: `corecruxctl memory digest` renders it. It is prompt-prefix content in every session in the workspace, so it must stay byte-stable between catalog changes — never make its composed form depend on a timestamp, a count, or the order a directory happened to be read in.
