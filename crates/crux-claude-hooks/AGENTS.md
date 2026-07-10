# crux-claude-hooks — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Claude Code lifecycle hook binaries for the Crux Daemon: `crux-hook`
(`src/main.rs`) with subcommands `session-start`, `context-monitor`,
`pre-compact`, plus `crux-llm-shim` (`src/bin/crux_llm_shim.rs`). Hooks are
installed and wired into Claude Code settings by `corecruxctl`
(`crates/corecruxctl/src/hooks.rs`, via the `crux-hook-env.sh` launcher).

## Key symbols
- `cmds` — the subcommand implementations (session-start banner, context-monitor warnings, pre-compact snapshot).
- `mcp_client` / `daemon_client` — MCP (`DEFAULT_MCP_URL`, override `CRUX_MCP_URL`) and HTTP (`DEFAULT_HTTP_URL`, override `CRUX_HTTP_URL`) transports; audit-capture writes go to `/v1/observe/*` over HTTP.
- `hook_input` / `hook_output` — the stdin/stdout JSON contract with the Claude Code harness (`additionalContext` etc.).
- `observe_capture` / `observe_filemod` — PostToolUse capture paths, gated by `CRUX_HOOK_OBSERVE_CAPTURE`.

## Test & verify
- `cargo test -p crux-claude-hooks`

## Local rules
- Hooks are best-effort and must NEVER block the user's session: `main.rs` logs errors to stderr and always `std::process::exit(0)` — a non-zero exit would block tool execution in the harness. Preserve this posture in every new code path.
- Keep hooks cheap on the PostToolUse path (short MCP timeouts are deliberate); no slow or unbounded work.
- Installed binaries are wired by `corecruxctl` — after changing hook behaviour, remember the deployed copy in `~/.local/bin` is stale until rebuilt/reinstalled.
