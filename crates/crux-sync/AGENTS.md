# crux-sync — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Offline-first outbox sync client for the VaultCrux API: contributions are
written to a local outbox, then pushed on connectivity, with auth, retry with
exponential backoff, and cursor tracking. Push is opt-in — the daemon only
starts background sync when `CORECRUXD_SYNC_ENABLED` is truthy AND
`CORECRUXD_SYNC_REMOTE_URL` is set (see `corecruxd` config); default is off.

## Key symbols
- `Outbox` / `OutboxEntry` (`outbox.rs`) — local append + `pending()` queue under a data dir.
- `push_contributions` / `query_commons` (`sync_client.rs`) — the two remote calls against the VaultCrux API.
- `build_contributions_body` / `build_commons_query_body` (`sync_client.rs`) — request-body builders (pure, unit-testable).
- `authenticate` / `SyncToken` (`auth.rs`) — email-based auth handshake and token parsing.

## Test & verify
- `cargo test -p crux-sync`

## Local rules
- Preserve offline-first semantics: writes land in the outbox first; the network is never on the local write path.
- Do not make push implicit or on-by-default — sync stays opt-in via the daemon's env config.
