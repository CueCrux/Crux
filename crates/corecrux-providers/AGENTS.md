# corecrux-providers — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Third-party **provider accounts**: the GitHub PAT and OpenAI API key a daemon
operator connects, plus the GitHub→fact sync. Not to be confused with
`crux-integrations`, which owns integration *packs* (manifests, trust tiers, C2PA
signing, the Studio index). Only the word is shared.

## Key symbols
- `github::{read,write,delete}_credentials` / `decrypt_pat` / `verify_pat` — PAT custody
- `github::{select_repo, unselect_repo, list_selected_repos, fetch_accessible_repos}`
- `github_sync::run_sync_with_key` — blocking; pulls commits/PRs/issues/comments into
  the fact store. Caller dispatches via `tokio::task::spawn_blocking`.
- `github_sync::COMMIT_ENTITY_TEMPLATE` — `github::{owner}/{repo}::commit/{sha}`
- `openai::{read,write,delete}_credentials` / `decrypt_api_key` / `verify_api_key`

## Invariants
- Credentials are only ever written sealed, as `corecrux_secrets::EncryptedEnvelope`.
  No plaintext PAT or API key reaches disk, a log line, or an error string.
- The 32-byte encryption key is a *parameter*. This crate never sources it — the
  daemon derives it from the daemon-root passport and passes it in.
- Sync is incremental: `last_synced_at` drives `since=`; a first sync is capped at
  `PER_REPO_MAX_PAGES * PER_REPO_PAGE_SIZE`.
- Sync is idempotent — a commit/comment already present is skipped, not re-stored.

## Test & verify
- `cargo test -p corecrux-providers`
- `cargo build -p corecrux-providers` standalone — it must compile with no daemon
  present; that is the check that no `AppState` coupling has crept back in.

## Local rules
- Tests use `crate::github::…`, never `crate::integrations_github::…` (the pre-split
  path). A rebase that reintroduces the old spelling compiles inside `corecruxd` but
  not here, and a plain `cargo build --workspace` will not catch it — the affected
  lines sit in `#[cfg(test)]`. Use `cargo build --workspace --tests`.
- Never import from `corecruxd`. Anything needing daemon state belongs in the
  handler, not here.
- Real network calls belong behind `verify_*` / `fetch_*` only; do not add outbound
  calls to the credential read/write paths.
