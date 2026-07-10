# crux-integration-tests — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Test-only crate: cross-crate integration harness for the Crux Daemon. Spawns a
real `corecruxd` process per test group and drives it over the wire (consumes
`corecrux-proto` for the gRPC data plane). No production code lives here —
clippy `unwrap_used`/`expect_used`/`panic` are allowed crate-wide.

## Key symbols
- `repo_root` / `build_corecruxd_binary` (`lib.rs`) — locate the workspace and build the daemon binary, with retry on transient `ETXTBSY`/`EAGAIN` from concurrent test builds.
- `CORECRUXD_BINARY` env var — overrides the daemon binary path so the harness skips its nested `cargo build`.

## Test & verify
- Preferred (per `CONTRIBUTING.md`): pre-build the daemon, then
  `CORECRUXD_BINARY=target/debug/corecruxd cargo test -p crux-integration-tests`.
  Without the env var the harness runs a nested `cargo build` inside the test process, which is slow and race-prone under `cargo test --workspace`.

## Local rules
- Keep this crate free of production logic — if a helper is useful outside tests, it belongs in a real crate.
- Do not memoise a failed daemon build/start as permanent: the retry-on-transient-error behaviour in `build_corecruxd_binary` exists because a single `Text file busy` once failed every test in the process.
