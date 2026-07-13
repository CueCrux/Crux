# M1 — Free adoption unblock report

Date: 2026-07-13  
Worktree: `/home/myles/CueCrux/Crux-tierpkg-m1-wt`  
Branch supplied by operator: `feat/ingest-loader-m1`  
Git commands run: none

## Outcome

Implemented `corecruxctl ingest <path>` as a top-level command. It accepts one
file or recursively walks a directory, turns supported content into local prose
documents, optionally embeds each chunk, batches safe requests, posts them to
`POST /v1/local/ingest`, reports sealed segment/receipt identifiers, and prints
the exact follow-up text-search command.

The preserved default-on work was audited and made consistent: local ingest and
HTTP text search now share one parser where only trimmed `0` or case-insensitive
`false` disables a route. Graph-expand and time-range remain opt-in. Health and
version feature reporting use the same text-search decision.

The existing bootstrap seeder and daemon startup wiring were not changed. Two
new embedded bootstrap patterns document one-command ingest and default-on text
search.

## CLI behavior built

- Supported inputs: `.md`, `.markdown`, `.txt`, and `.json`.
- JSON objects/arrays are recursively flattened to their non-empty string values;
  numeric, boolean, and null values are not indexed as prose.
- Hidden directories, `.git`, `node_modules`, and `target` are pruned. Symlinks,
  unsupported extensions, NUL-bearing content, non-UTF-8 content, and empty
  supported files are skipped and counted.
- Markdown is split at ATX headings before long sections are windowed. Plain
  text uses paragraph/whitespace-aware windows targeting 1,800 characters with
  a 180-character overlap.
- Every request document carries its relative source path in `title`/`url`, its
  RFC3339 mtime in `source_timestamp`, and a stable document ID containing the
  BLAKE3 file hash. Every chunk carries `source_path`, `file_hash`, `mtime`,
  `chunk_index`, and `chunk_count` metadata.
- Request batching enforces the public 4,096-document and 65,536-chunk limits.
  It also fragments document appends at the storage layer's 1,024-event limit
  and conservatively keeps serialized requests below 12 MiB so they remain
  under the route's ordinary 16 MiB body ceiling.
- `--tenant` defaults to `local`, consistent with other corecruxctl portability
  commands; `--corpus` defaults to `docs`; `--daemon-url` defaults to
  `http://127.0.0.1:14800`.
- Daemon authentication follows the existing memory CLI convention by sending
  `CRUX_AGENT_TOKEN` as a bearer token when present. The ingest route requires
  `admin:write` when daemon authentication is enabled.
- `--dry-run` performs no network calls, including no embedding calls. It walks,
  parses, chunks, constructs batches, and prints counts only.
- `--embed` requires `CORECRUXD_EMBEDDING_URL`, uses
  `CORECRUXD_EMBEDDING_MODEL` (default `nomic-embed-text`), and POSTs each chunk
  to the OpenAI-compatible `/v1/embeddings` shape. `OPENAI_API_KEY` is forwarded
  when present. Empty, non-finite, or inconsistent-dimension vectors fail closed.
- BM25-only ingest is the default and needs no embedding endpoint.

Observed fixture dry-run output:

```text
files walked: 3
files ingested: 2
skipped: 1 files, 0 directories
chunks: 3
dry run: 2 documents prepared in 1 batches; nothing sealed
query next:
curl -sS -X POST 'http://127.0.0.1:14800/v1/query/text-search' -H 'Content-Type: application/json' -H "Authorization: Bearer $CRUX_AGENT_TOKEN" --data '{"tenant_id":"local","query":"YOUR QUERY","limit":10}'
```

The authorization header is printed only when `CRUX_AGENT_TOKEN` is present.

## Default changes

- `CORECRUXD_LOCAL_INGEST`: ON when unset; only `0` or `false` (trimmed,
  case-insensitive for `false`) disables and makes the route return 404.
- `CORECRUXD_QUERY_TEXT_SEARCH`: the same default-on/explicit-off parsing; both
  text-search and text-search-expand return 404 when disabled.
- `CORECRUXD_QUERY_GRAPH_EXPAND` and `CORECRUXD_QUERY_TIME_RANGE`: unchanged,
  still opt-in.
- `/v1/version` and admin health feature reporting call the same text-search
  parser, so reported state matches route state.

## Files authored or updated

CLI and tests:

- `crates/corecruxctl/src/ingest.rs`
- `crates/corecruxctl/src/lib.rs`
- `crates/corecruxctl/src/main.rs`
- `crates/corecruxctl/tests/ingest_dry_run.rs`
- `crates/corecruxctl/tests/fixtures_ingest/guide.md`
- `crates/corecruxctl/tests/fixtures_ingest/records.json`
- `crates/corecruxctl/tests/fixtures_ingest/image.bin`

Default-on audit and coverage:

- `crates/corecruxd/src/config.rs`
- `crates/corecruxd/src/http/mod.rs`
- `crates/corecruxd/src/http/query.rs`
- `crates/corecruxd/src/http/local_ingest.rs`
- `crates/corecruxd/src/http/tests.rs`
- `config.example.env`

Bootstrap and generated documentation aggregate:

- `crates/crux-observe/bootstrap_data/patterns.json`
- `llms-full.txt` (regenerated because a preserved linked-doc edit had made the
  aggregate stale)

Preserved M1 files reviewed but not rewritten during this completion pass:

- `docs/agent-guide.md`
- `examples/rust/append_and_query.rs`

Explicitly untouched per the correction:

- `crates/crux-observe/src/bootstrap.rs`
- `crates/corecruxd/src/main.rs` bootstrap seeding/startup logic

Both untouched files are byte-identical by SHA-256 to the independent sibling
`Crux-tierpkg-m2-wt` worktree.

## Tests added

- Markdown heading-aware split.
- Plain-text window size and overlap bounds.
- JSON string-value flattening.
- Hidden/build directory pruning and unsupported-file counting.
- Supported-extension binary-byte skipping.
- Local-ingest request shape and provenance fields.
- Document/chunk/storage/request-size batching behavior.
- OpenAI-compatible embedding endpoint and request shape.
- Clap defaults for top-level `ingest`.
- Fixture-directory dry run with `--embed` proving that dry-run performs no
  embedding or daemon network call.
- Shared default-on parser values, stock text-search/local-ingest routes,
  explicit-off 404 behavior, and version feature reporting.
- Bootstrap pattern JSON parsing through the existing seeder tests.

## Quality gates and exact summaries

### Formatting

`cargo fmt --all -- --check` — PASS (exit 0, no output).

### Clippy

`cargo clippy --workspace --all-targets -- -D warnings` — BLOCKED by existing,
out-of-scope all-target warnings. The first failures are in
`crates/crux-session/tests/{invocation_chain,end_to_end,ce_full_parity}.rs` and
`crates/crux-session/examples/generate_fixtures.rs` for existing
`unwrap`/`expect`/`println`, plus an existing deprecated-call warning in
`crux-session/src/generator.rs`.

These files were verified against an independent unmodified state without git:
their SHA-256 hashes are byte-for-byte identical to the sibling
`Crux-tierpkg-m2-wt` worktree. The earlier corecruxctl all-target check likewise
found two existing `needless_raw_string_hashes` warnings in `code_chain.rs`,
which is also byte-identical to that sibling worktree.

Changed production targets and the new integration test are clean:

```text
cargo clippy -p corecruxctl --lib --bin corecruxctl -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 6.07s

cargo clippy -p corecruxd --bin corecruxd -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 16.78s

cargo clippy -p corecruxctl --test ingest_dry_run -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.48s
```

### Requested package tests

`cargo test -p corecruxctl -p corecruxd -p crux-observe` compiled all requested
packages, then Cargo stopped after the first package failed because this managed
sandbox denies every loopback `TcpListener::bind`. Exact first-package summary:

```text
test result: FAILED. 764 passed; 44 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.73s
```

All 44 failures terminate at mock-server bind with
`Os { code: 1, kind: PermissionDenied, message: "Operation not permitted" }`.
No ingest test failed. Representative failing mock files (`benchmark.rs` and
`extensions.rs`) are byte-identical to the sibling worktree.

The packages Cargo did not reach were run separately:

```text
cargo test -p corecruxd
test result: FAILED. 1814 passed; 20 failed; 2 ignored; 0 measured; 0 filtered out; finished in 63.56s

cargo test -p crux-observe
test result: ok. 61 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.04s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

All 20 daemon failures are also loopback-bind denials in existing mock/proxy,
server-shutdown, MCP bridge, and witness-submit tests. Representative files
`corecruxd/src/{main,mcp_stdio,witness_submit}.rs` and
`corecruxd/src/http/engine_console.rs` are byte-identical to the sibling
worktree. The new default and health tests passed in this run.

Focused M1 tests are green:

```text
cargo test -p corecruxctl ingest::tests --lib
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 793 filtered out; finished in 0.63s

cargo test -p corecruxctl parse_ingest_defaults --bin corecruxctl
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 184 filtered out; finished in 0.00s

cargo test -p corecruxctl dry_run_chunks_fixture_directory_without_network --test ingest_dry_run
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

The `ingest::tests` filter also selects five pre-existing `observe_ingest` tests;
all ten new ingest unit tests are present in the passing set.

### Rustdoc

`cargo doc --no-deps -p corecruxctl -p corecruxd` — PASS.

```text
Finished `dev` profile [unoptimized + debuginfo] target(s) in 6.55s
Generated /home/myles/CueCrux/Crux-tierpkg-m1-wt/target/doc/corecruxctl/index.html and 1 other file
```

### Repository documentation integrity

`scripts/check-agent-docs.sh` — PASS after regenerating `llms-full.txt`.

```text
PASS: every agent-doc reference resolves in the tree.
```

## Deferred or constrained

- No requested CLI behavior is deferred.
- A live non-dry ingest was not attempted: the requested tests explicitly avoid
  a live daemon, and this managed sandbox prohibits loopback sockets. Request
  serialization, limits, auth header behavior, response parsing, and the
  no-network dry run are covered without a daemon.
- The daemon's existing local-ingest handler deserializes but discards optional
  document/chunk metadata when mapping to its raw-text seal model. M1 sends all
  required provenance in the wire request, but daemon-side persistence of that
  optional metadata remains a pre-existing follow-up. Persisting it would change
  the sealed prose payload/metadata model and was not broadened into this CLI
  deliverable.
- The two mandated workspace-wide gates cannot be made green inside this turn
  without either granting loopback-bind permission or expanding scope into
  unrelated repository-wide test/example lint cleanup. Their exact failures and
  independent-file verification are recorded above.
