# Agent Config Wizard

`crux-config-wizard` composes `CLAUDE.md` and `AGENTS.md` from versioned profile fragments. It's how a Crux-aligned workspace keeps its agent guardrails reproducible, audit-friendly, and re-runnable.

## Why this exists

A four-week internal Claude Code session review (2026-04-12 → 2026-05-13) identified three recurring frictions: output-token-limit exhaustion (9 blocked sessions), late-surfacing bugs in agent code (22 buggy-code + 15 wrong-approach events), and prerequisite-state mismatches that wasted ~978 hours of compute. Each of those frictions has a "if only the rule were in CLAUDE.md" answer. The wizard ships those rules as version-pinned, source-controlled profile fragments so they actually load into every Claude session.

The same shape supports EU AI Act-aligned posture (Articles 9, 10, 12, 13, 14, 15) and SOC 2-style audit hygiene without manual upkeep.

## Quick start

```bash
# First run — interactive prompts.
crux-config-wizard init

# Or non-interactive (CI, scripted setup).
crux-config-wizard init --non-interactive --profiles=all
crux-config-wizard init --non-interactive --profiles=memory-practices,token-conservation

# Re-compose from the saved choice.
crux-config-wizard regenerate

# CI: exit non-zero if files are stale.
crux-config-wizard check

# Discover available profiles + which are enabled.
crux-config-wizard list

# Enable / disable one profile.
crux-config-wizard add eu-ai-act
crux-config-wizard remove audit-soc2
```

## The 14 bundled profiles

| Name | Risk | Default | What it carries |
|---|---|---|---|
| `memory-practices` | low | yes | Crux memory + retrieval discipline and tool routing. |
| `memory-digest` | medium | yes | Always-loaded curated-memory index, one line per engram. |
| `claude-5` | low | yes | Response shape for Claude 5 generation models (CLAUDE.md only). |
| `agent-harness-parity` | low | yes | The AGENTS.md counterpart of `claude-5` for non-Claude harnesses. |
| `execplan-discipline` | low | yes | ExecPlans for multi-milestone work; the workspace-green milestone gate. |
| `code-grounding` | low | yes | Cite the source for any claim that names code. |
| `scratchpad-survival` | low | yes | Archive durable work out of the ephemeral session scratchpad. |
| `boot-banner` | low | yes | The boot-banner channel contract (statusline, agent brief, first-reply card). |
| `pre-deploy-gate` | medium | yes | Preflight discipline before production deploys. |
| `eu-ai-act` | high | yes | EU AI Act Reg. 2024/1689 Art. 9–15 posture. Engineering practice, not a legal opinion. |
| `audit-soc2` | medium | yes | Audit hygiene: commit_sha attribution, write-agent isolation, retention. |
| `code-minimalism` | low | no | Write the least code that actually works. |
| `token-conservation` | low | no | Fixed output caps for pre-Claude-5 models; superseded by `claude-5`. |
| `workspace-cuecrux` | low | no | CueCrux-internal endpoints and conventions. Only for the CueCrux monorepo. |

`init --profiles=all` enables the 11 defaults. `workspace-cuecrux` is not one of them because it names CueCrux's private daemon; enable it with `crux-config-wizard add workspace-cuecrux` inside the CueCrux workspace. Other workspaces pick whichever subset matches their posture.

## Claude Code hooks, mod and skills

Unless `--no-hooks` is passed, `init` also sets up Claude Code for the user (`regenerate --hooks` refreshes it):

- **Mod** (`--no-mod` to skip): the `crux-desktop` mod, which owns session continuity. It loads Crux context into the first prompt and saves the session after every turn, before compaction and at session end. It also registers the daemon as a user-scope `crux` MCP server. Manage it with `crux-config-wizard mods install|uninstall|status` (or `corecruxctl mods …`). See [integrations/claude-code/README.md](../integrations/claude-code/README.md#the-crux-mod-session-continuity).
- **Hooks**: observe capture, file-modification ledger, coordination, cost and scratchpad hooks in `~/.claude/settings.json`. When the mod is installed, the SessionStart banner and PreCompact save are left out, since the mod does that work.
- **Skills** (`--no-skills` to skip): the bundled skills in `~/.claude/skills/`.

## How it works

Each profile is a markdown file with TOML frontmatter in `crates/crux-config-wizard/profiles/<name>.md`:

```markdown
+++
name = "memory-practices"
version = 1
description = "Crux daemon memory + retrieval discipline."
targets = ["claude_md", "agents_md"]
order = 10
risk_class = "low"
+++

## Body

The rule text that lands in CLAUDE.md / AGENTS.md.
```

The composer parses your existing `CLAUDE.md` and `AGENTS.md` into spans:

- **Free spans** — text outside any marker. Preserved verbatim across regenerates.
- **Managed spans** — text between `<!-- BEGIN-CRUX-MANAGED:<name> v<n> -->` and `<!-- END-CRUX-MANAGED:<name> -->`. Replaced from the bundled fragment.

Profile-version drift, content drift, and missing/extra profiles are all detected. A `regenerate` that would silently overwrite a hand-edited managed section refuses to proceed without `--force` (see the **Drift refusal** section below).

## Drift detection

After `init`, the wizard records the chosen profiles and their versions in `.crux/agent-profile.toml` (a committed file).

The `crux-claude-hooks session-start` lifecycle hook calls `crux_config_wizard::drift::check_workspace(cwd)` on every Claude session boot. If the workspace's `CLAUDE.md` is out of date — version mismatch, content drift, or hand-edited managed sections — the hook surfaces an `additionalContext` advisory:

```text
[crux-config-wizard] CLAUDE.md or AGENTS.md is out of date.
profile 'memory-practices' is at v1 in config but v2 in the crate

Run `crux-config-wizard regenerate` to refresh.
```

Set `CRUX_HOOK_WIZARD_CHECK=off` in env to disable the check (the session-start hook still runs the other §11.1 boot steps).

### Drift refusal

The composer hashes each managed section's body against the bundled fragment. If you've hand-edited inside the markers and run `regenerate`, you get:

```text
error: manual edit detected inside managed section 'memory-practices' in CLAUDE.md; refuse to overwrite without --force
```

This is intentional. To accept the bundled version and overwrite your edit: `crux-config-wizard regenerate --force`. To keep your edit instead, move it outside the markers (anywhere in the file works — the composer only touches managed spans).

## Advisory lints (duplication + size)

Beyond managed-section drift, `check` / `diff` and the session-start advisory surface two **advisory warnings**. These are *not* drift: `regenerate` cannot fix them (it only touches managed spans), so they are reported separately and do not, by themselves, make `check` fail — unless you pass `--strict` (for CI).

- **Free-span duplication.** When text *outside* the managed markers substantially restates an enabled profile's body — e.g. a hand-written "§11" section that repeats the `memory-practices` rules — the wizard flags it:

  ```text
  CLAUDE.md: free-span text restates managed profile 'memory-practices'
  (7/16 distinctive lines duplicated, e.g. "When calling `store_fact`, …").
  Replace the duplicated prose with a pointer to the managed section.
  ```

  Heuristic: flagged when ≥3 of a profile's "distinctive" lines (non-blank/heading/table/marker, ≥24 chars, bullet-marker-normalised) appear in the free spans, **or** ≥30% of a ≥4-line body does. Fix by replacing the duplicated prose with a one-line pointer to the managed section below it.

- **Composed size.** A large `CLAUDE.md` inflates every session prefix and risks the boot load cap. Over the soft byte budget (default ≈ 48 KB ≈ ~24 K tokens for dense markdown — a margin under the ~25 K-token cap), the wizard warns and names the byte split:

  ```text
  CLAUDE.md is 51,200 B (soft budget 49,152 B); free-span text is 18,000 B of
  that. Trim free spans or split content.
  ```

  Tune per-workspace via the `[limits]` section (see [Configuration file](#configuration-file)).

`crux-config-wizard check --strict` (or `diff --strict`) makes either warning exit non-zero so CI can enforce them.

## Authoring a new profile

Add `crates/crux-config-wizard/profiles/<your-name>.md`:

```markdown
+++
name = "your-name"
version = 1
description = "One-line description shown by `list` and `init`."
targets = ["claude_md", "agents_md"]   # or just one
order = 60                              # numeric sort position in the output file
risk_class = "low"                      # informational
conflicts_with = []                     # other profiles that can't co-exist with this one
requires = []                           # other profiles this one depends on
+++

## Body

Whatever rules you want to encode. Markdown rendered as-is.
```

Then:

1. Add the `include_str!` line in `crates/crux-config-wizard/src/profile.rs` so the binary embeds it.
2. (Optional) Add to `DEFAULT_PROFILES` in `crates/crux-config-wizard/src/lib.rs` if it should be on by default.
3. Bump the version on any subsequent edit — the wizard will surface "v1 in config but v2 in the crate" as drift advice to existing workspaces.
4. Add a test in `crates/crux-config-wizard/profile.rs` if the fragment exercises new frontmatter fields.

## CLI reference

| Subcommand | Behaviour | Exit code |
|---|---|---|
| `init` | First-run; writes `.crux/agent-profile.toml` + composes target files | 0 ok, 2 if already initialised, 1 on error |
| `regenerate [--force]` | Re-compose from saved choice | 0 ok, 1 on drift without `--force` |
| `check [--strict]` | CI mode; reports drift **and** advisory lints | 0 clean, 1 stale; with `--strict`, also 1 on advisory warnings |
| `list` | Show available + enabled | 0 |
| `add <name>` | Enable + regenerate | 0 ok, 1 on error |
| `remove <name>` | Disable + regenerate | 0 ok, 2 if not enabled |
| `diff [--strict]` | Same as check, more verbose output | 0 clean, 1 stale; with `--strict`, also 1 on advisory warnings |

Global flag: `--workspace <path>` to operate on a directory other than the current one.

## Configuration file

The wizard writes `.crux/agent-profile.toml` at the workspace root:

```toml
schema_version = 1
workspace_fingerprint = "blake3:..."

[profiles.memory-practices]
version = 1
enabled_at = "2026-05-19T11:29:50Z"

# … one section per enabled profile …

[targets]
claude_md = "CLAUDE.md"
agents_md = "AGENTS.md"

[limits]                       # optional — soft size budgets in bytes
claude_md_max_bytes = 49152    # default ≈ 48 KB; over budget → advisory warning
agents_md_max_bytes = 49152
```

The file is meant to be committed. The fingerprint is a stable hash of the workspace's absolute path; useful when the same Crux daemon serves multiple workspaces and the drift facts need to distinguish them. The `[limits]` section is optional — omit it for the defaults.

## Tests

```bash
cargo test -p crux-config-wizard
```

The lib and end-to-end tests cover:

- Frontmatter parsing (round-trip, missing fields, invalid version, default targets).
- Config TOML save/load + atomic write + workspace fingerprint stability.
- Composer fresh-write, idempotent regenerate, manual-section preservation, drift refusal without `--force`, drift acceptance with `--force`, disabled profile removal, unbalanced-marker rejection.
- End-to-end init → regenerate → add → remove loop.
- Bundled profiles parse cleanly and include all 11 defaults.
- Hooks: block shape, merge idempotency, foreign-hook preservation, and the banner and PreCompact save stepping aside when the mod owns continuity.
- Mod: files, `CLAUDE_CODE_PLUGIN_DIRS` and `pluginConfigs` merge, MCP registration (foreign same-name server left alone, token refresh, project-scope shadow warning), uninstall and status.

The `crux-claude-hooks session-start` integration test exercises the drift advisory via the hook's standard input/output.

## Relationship to lenses

The wizard is a sibling pattern to [lens crates](./lens-cookbook.md):

- A **lens** adds domain-shaped data (entities, edges, analytics, MCP tools) to the Crux daemon.
- The **wizard** adds workflow-shaped guardrails (CLAUDE.md / AGENTS.md profiles) to the workspace.

Both ship as separate crates with version-pinned content; both leverage the same "substrate generic + per-domain opt-in" philosophy.

## See also

- Source: [crates/crux-config-wizard/](../crates/crux-config-wizard/)
- Hook wiring: [crates/crux-claude-hooks/src/cmds/session_start.rs](../crates/crux-claude-hooks/src/cmds/session_start.rs)
- Quality + Threat refs taxonomy: [docs/quality-threat-refs.md](./quality-threat-refs.md)
