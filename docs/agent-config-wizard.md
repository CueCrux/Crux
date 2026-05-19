# Agent Config Wizard

`crux-config-wizard` composes `CLAUDE.md` and `AGENTS.md` from versioned profile fragments. It's how a Crux-aligned workspace keeps its agent guardrails reproducible, audit-friendly, and re-runnable.

## Why this exists

The [Claude Code Insights report](../../PlanCrux/docs/insights/report.html) for 2026-04-12 → 2026-05-13 showed three recurring frictions: output-token-limit exhaustion (9 blocked sessions), late-surfacing bugs in agent code (22 buggy_code + 15 wrong_approach events), and prerequisite-state mismatches that wasted ~978 hours of compute. Each of those frictions has a "if only the rule were in CLAUDE.md" answer. The wizard ships those rules as version-pinned, source-controlled profile fragments so they actually load into every Claude session.

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

## The 8 bundled profiles

| Name | Risk | Source signal |
|---|---|---|
| `memory-practices` | low | Crux daemon §11 (session boot, `token_budget`, fact-storage conventions). |
| `token-conservation` | low | Insights report friction #1 — 9 sessions blocked by output-token exhaustion. |
| `execplan-discipline` | low | Insights big win — M1..Mn pattern in 15+ sessions. |
| `code-grounding` | low | Insights friction — 22 buggy_code + 15 wrong_approach events. |
| `pre-deploy-gate` | medium | Insights friction — 978 wasted compute hours from prerequisite mismatches. |
| `eu-ai-act` | high | EU AI Act Reg. 2024/1689 Art. 9, 10, 12, 13, 14, 15. Engineering best practice; not a legal opinion. |
| `audit-soc2` | medium | General audit hygiene — commit_sha attribution, write-agent isolation, retention. |
| `workspace-cuecrux` | low | CueCrux workspace specifics — ExecPlan paths, daemon ports, Chainguard, JobClaw/MirrorClaw. |

For the CueCrux workspace, the recommended set is all 8 (default for `init --profiles=all`). Other workspaces pick whichever subset matches their posture.

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

After `init`, the wizard records the chosen profiles + their versions as both:

- `.crux/agent-profile.toml` (committed file).
- A Crux fact at `entity="agent-config:<workspace-fingerprint>"`, `key="profile:enabled"`.

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
| `check` | CI mode | 0 clean, 1 stale |
| `list` | Show available + enabled | 0 |
| `add <name>` | Enable + regenerate | 0 ok, 1 on error |
| `remove <name>` | Disable + regenerate | 0 ok, 2 if not enabled |
| `diff` | Same as check, more verbose output | 0 clean, 1 stale |

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
```

The file is meant to be committed. The fingerprint is a stable hash of the workspace's absolute path; useful when the same Crux daemon serves multiple workspaces and the drift facts need to distinguish them.

## Tests

```bash
cargo test -p crux-config-wizard
```

14 lib + 3 end-to-end tests cover:

- Frontmatter parsing (round-trip, missing fields, invalid version, default targets).
- Config TOML save/load + atomic write + workspace fingerprint stability.
- Composer fresh-write, idempotent regenerate, manual-section preservation, drift refusal without `--force`, drift acceptance with `--force`, disabled profile removal, unbalanced-marker rejection.
- End-to-end init → regenerate → add → remove loop.
- Bundled profiles parse cleanly and include all 8 defaults.

The `crux-claude-hooks session-start` integration test exercises the drift advisory via the hook's standard input/output.

## Relationship to lenses

The wizard is a sibling pattern to [lens crates](./lens-cookbook.md):

- A **lens** adds domain-shaped data (entities, edges, analytics, MCP tools) to the Crux daemon.
- The **wizard** adds workflow-shaped guardrails (CLAUDE.md / AGENTS.md profiles) to the workspace.

Both ship as separate crates with version-pinned content; both leverage the same "substrate generic + per-domain opt-in" philosophy.

## See also

- ExecPlan: [PlanCrux/.agent/execplans/agent-config-wizard-2026-05-19.md](../../PlanCrux/.agent/execplans/agent-config-wizard-2026-05-19.md)
- Source: [Crux/crates/crux-config-wizard/](../crates/crux-config-wizard/)
- Hook wiring: [Crux/crates/crux-claude-hooks/src/cmds/session_start.rs](../crates/crux-claude-hooks/src/cmds/session_start.rs)
