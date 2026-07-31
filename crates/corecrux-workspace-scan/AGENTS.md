# corecrux-workspace-scan — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Repository scanning: walk a checkout, parse its sources and manifests, and return
the structural facts the daemon's code lenses are built from. Pure analysis — it
reads a checkout and returns data, holds no daemon state, opens no sockets, and
persists nothing. Persistence and HTTP belong to the caller.

## Key symbols
- `workspace_scan` — the walk, the Rust-side `syn` analysis, and the result types
  the daemon consumes (16 modules in `corecruxd` depend on these)
- `workspace_scan_ast` — Rust AST extraction: items, signatures, call edges
- `workspace_scan_manifests::ExternalDep` — one dependency shape across
  `Cargo.toml` / `package.json` / `pyproject.toml` / `pom.xml` / …
- `workspace_scan_polyglot` — tree-sitter extraction for the ten non-Rust
  languages behind a single grammar-dispatch surface

## Invariants
- Read-only with respect to the scanned checkout. Never write into a repo being
  scanned.
- A parse failure in one file must degrade to "no facts for that file", never
  abort the scan — a scan crosses untrusted, arbitrarily-malformed source.
- `workspace_scan_polyglot` handles the ten grammars; Rust goes through `syn` in
  `workspace_scan_ast`. Do not add a Rust tree-sitter grammar — two Rust parsers
  would drift.

## Test & verify
- `cargo test -p corecrux-workspace-scan`
- `cargo build -p corecrux-workspace-scan` standalone — must compile with no
  daemon present; that is the check that no `AppState` coupling has crept in.

## Local rules
- **This crate parses Rust source, so `crate::` appears throughout its test
  fixtures** (`crate::a`, `crate::b`, `crate::holder`, and a literal
  `"use crate::http::admin;"`). Those are fixture *data*, not dependencies —
  a `grep 'crate::'` over this crate reads as coupling that is not there. Read the
  hit before counting it.
- Module names deliberately keep their `workspace_scan_*` prefix rather than being
  shortened. The four files carry many intra-group `crate::workspace_scan_*` paths;
  the prefix is what let the extraction stay a pure file move.
- Adding a language means a grammar dep plus a dispatch arm in
  `workspace_scan_polyglot` — pin it with `=` like its siblings, since tree-sitter
  grammar crates break node-name compatibility across minor versions.
- `test_support::EnvVarGuard` is a deliberate copy of the daemon's helper, not a
  shared dep. It restores on drop but does not serialise: env is process-global and
  shared with every other test thread. Prefer a parameter over an env override.
