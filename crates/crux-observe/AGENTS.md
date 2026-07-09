# crux-observe — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Self-observation layer for the Crux Daemon: captures operational events (errors,
warnings, metrics, health) and bootstrap documentation as facts in the CoreCrux
memory subsystem, so the system can reason about its own state. Gated by the
`CRUX_SELF_OBSERVE` env var (off unless set to `1`/`true`/`yes` — see
`self_observe_enabled` in `config.rs`).

## Key symbols
- `Redactor` / `Redactor::redact_line` (`redact.rs`) — scrubs secrets/PII from a line before it is persisted or logged.
- `RedactMakeWriter` (`redact_writer.rs`) — sink-boundary `MakeWriter` adapter; redacts formatted tracing output before it reaches stdout/stderr/JSON sinks.
- `OpsObserveLayer` (`ops_layer.rs`) — tracing layer that turns ops events into facts (ring-buffered via `max_facts`).
- `BootstrapSeeder` (`bootstrap.rs`) — seeds docs/patterns/resolutions/tool-output facts from `bootstrap_data/*.json` (compiled in via `include_str!`).
- `ops_entity` / `bootstrap_entity` (`schema.rs`) — canonical entity-name builders for observe facts.

## Test & verify
- `cargo test -p crux-observe`
- Redaction leak-canary tests live alongside `redact.rs` / `redact_writer.rs` — run them after any redaction change.

## Local rules
- Redaction happens BEFORE persistence, always. Never add a code path that writes an event to the fact store or a log sink without going through `Redactor` (visitor-level in `OpsObserveLayer`) or `RedactMakeWriter` (sink-level).
- Bootstrap content changes go in `bootstrap_data/*.json`, not inline strings — the JSON is validated at seed time and `expect`s on parse failure.
