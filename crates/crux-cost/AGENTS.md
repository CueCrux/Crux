# crux-cost — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

The ground-truth token-burn cost lens. Given a Claude Code transcript
(`<session>.jsonl`), it measures real spend from `message.usage`, attributes carried
context cost per source (a block re-read `k − e` times costs `est × (k − e)`, reconciled
exactly to the measured total), and emits grounded reduction levers. Output is a single
`CostReport` — the shared contract between the `corecruxctl session cost` CLI (producer),
the daemon `/v1/cost/report` endpoint (reader/store), and the console `cx-cost` page.

## Key symbols
- `analyze_file` / `analyze_str` — transcript → `CostReport`; `source` names the corpus (QC.4).
- `CostReport` / `COST_REPORT_SCHEMA` (`report.rs`) — the versioned wire contract (`crux.cost.report.v1`); readers reject stale shapes on the schema string.
- `transcript::parse_file` / `parse_str` — ground-truth usage extraction from the JSONL.
- `attribution::analyze` — the carried-cost apportionment model.
- `Lever` / `Severity` (`report.rs`) — the "what to do about it" advice entries.
- `TOP_BLOCKS` / `MAX_EXECPLAN_SLUGS` (`lib.rs`) — report bounds; the slug bound is a sanity bound, not a precision cap (OD-30 v2).

## Test & verify
- `cargo test -p crux-cost`
- `lib.rs` tests build a structurally-real transcript fixture;
  `measured_and_headline_are_ground_truth` pins the measure step.

## Local rules
- **`CostReport` is a cross-binary contract**: `corecruxctl` produces it, `corecruxd`
  (`src/http/cost.rs`, `src/cost.rs`) stores and re-reads it. A field rename or semantic
  change breaks both plus the console — evolve additively or bump `COST_REPORT_SCHEMA`
  and handle both versions on the read side.
- Headline numbers are always the transcript's real `usage`; chars/4 estimation exists
  only to *apportion* the measured spend. Never surface an estimate as a headline.
- Crate is `#![deny(clippy::unwrap_used)]` — keep it panic-free on malformed transcripts.
