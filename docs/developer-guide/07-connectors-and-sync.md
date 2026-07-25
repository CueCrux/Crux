# 7. Connectors and scheduled work

Extensions are pull-based: something calls a tool. Connectors are push-based:
the daemon wakes up on a cadence and does work. Both live in the same process
and both write facts, but the machinery is different.

## 7.1 The scheduler

`SyncScheduler` ([crates/corecruxd/src/sync_scheduler.rs:242](../../crates/corecruxd/src/sync_scheduler.rs#L242))
is one driver task for all periodic jobs. It sleeps to the earliest deadline
rather than ticking every second.

```rust
let mut scheduler = SyncScheduler::new(fact_store.clone());
scheduler.register("my-job", Duration::from_secs(900), move || async { /* JobResult */ });
scheduler.spawn(shutdown_tx.subscribe());
```

([sync_scheduler.rs:264](../../crates/corecruxd/src/sync_scheduler.rs#L264),
[main.rs:1491](../../crates/corecruxd/src/main.rs#L1491))

Contract you must know before registering anything:

- **The first attempt is one full interval after `spawn`, never at boot**
  ([sync_scheduler.rs:258](../../crates/corecruxd/src/sync_scheduler.rs#L258)). A restart
  storm cannot stampede an upstream.
- A zero interval is clamped to one second. A job that should be off is simply
  not registered ([sync_scheduler.rs:269](../../crates/corecruxd/src/sync_scheduler.rs#L269)).
- The job closure must be re-callable.

### `JobResult` — three outcomes, not two

([sync_scheduler.rs:80](../../crates/corecruxd/src/sync_scheduler.rs#L80))

| Outcome | Status fact | Backoff |
|---|---|---|
| `Ok(JobOutcome::Ran(detail))` | written, `last_status: "ok"` | reset to zero failures |
| `Ok(JobOutcome::Skipped(reason))` | **not written** | untouched |
| `Err(message)` | written, `last_status: "error"`, `last_error` set | `consecutive_failures += 1` |

`Skipped` is the important one. A job that is inert this cycle — connector not
connected, feature not configured — returns `Skipped`, which writes nothing and
touches no state. An unconfigured daemon stays exactly as quiet as it was before
the job existed ([sync_scheduler.rs:33](../../crates/corecruxd/src/sync_scheduler.rs#L33)).
Copy that discipline in your own jobs.

### Backoff

The effective interval doubles per consecutive failure, capped at 4×, and resets
on the first success ([sync_scheduler.rs:154](../../crates/corecruxd/src/sync_scheduler.rs#L154)).
The configured `interval` is never mutated — backoff is derived.

### Status facts

One fact per job: entity `__sync__::<job_id>`, key `status`, schema
`crux.sync_job_status.v1`
([sync_scheduler.rs:70](../../crates/corecruxd/src/sync_scheduler.rs#L70)).

```json
{
  "schema": "crux.sync_job_status.v1",
  "job_id": "github-sync",
  "last_run_unix_ms": 1753440000000,
  "last_status": "ok",
  "last_error": null,
  "consecutive_failures": 0,
  "interval_secs": 900,
  "effective_interval_secs": 900,
  "next_run_unix_ms": 1753440900000,
  "detail": { "repos": 3, "commits_added": 12 }
}
```

`__sync__::` is a born-private prefix, written with `private: true` and
`horizon_class: Volatile`, actor `sync-scheduler`
([sync_scheduler.rs:210](../../crates/corecruxd/src/sync_scheduler.rs#L210)). Node-local
operational state is never push-eligible to a remote.

Read it with the ordinary facts routes — the scheduler deliberately adds no HTTP
surface of its own ([sync_scheduler.rs:24](../../crates/corecruxd/src/sync_scheduler.rs#L24)):

```bash
curl -s "http://127.0.0.1:14800/v1/facts/entity/__sync__::vault-watcher" \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"
```

Persisting the status is best-effort: a store failure is warn-logged and never
propagated ([sync_scheduler.rs:225](../../crates/corecruxd/src/sync_scheduler.rs#L225)).

### The two registered jobs

| `job_id` | Interval | Registration | Condition |
|---|---|---|---|
| `github-sync` | `CORECRUXD_GITHUB_SYNC_INTERVAL_SECS`, default 900 | [main.rs:1506](../../crates/corecruxd/src/main.rs#L1506) | always registered; returns `Skipped("github not connected")` when idle |
| `vault-watcher` | `CORECRUXD_VAULT_WATCH_INTERVAL_SECS`, default 300 | [main.rs:1569](../../crates/corecruxd/src/main.rs#L1569) | only when the double gate passes |

## 7.2 The markdown-vault watcher

This is the reference implementation of the `file_watcher` entry kind, and the
one runtime that binds the pack model to daemon behaviour.

### The double gate

Nothing runs unless **both** are true
([vault_watcher.rs:18](../../crates/corecruxd/src/vault_watcher.rs#L18)):

1. A pack whose `entry.kind` is `file_watcher` is installed **and granted** on
   this node — checked via `enabled_packs_of_kind`. The first-party pack is
   `vault.markdown-watcher`.
2. `CORECRUXD_VAULT_WATCH_ROOTS` names at least one absolute, readable
   directory.

`activation()` ([vault_watcher.rs:193](../../crates/corecruxd/src/vault_watcher.rs#L193))
returns one of three states, and half-configured is diagnosable from the boot
log rather than from silence:

| State | Log line |
|---|---|
| `Active { pack_ids, roots }` | job registered |
| `Inactive` | silent — the ordinary default |
| `HalfConfigured(reason)` | `vault-watcher inactive` with the reason ([main.rs:1575](../../crates/corecruxd/src/main.rs#L1575)) |

The two half-configured messages are explicit about which half is missing
([vault_watcher.rs:220](../../crates/corecruxd/src/vault_watcher.rs#L220)):

```text
file-watcher pack(s) ["vault.markdown-watcher"] are granted but
CORECRUXD_VAULT_WATCH_ROOTS is unset — nothing to watch; set it to
colon-separated absolute directories

CORECRUXD_VAULT_WATCH_ROOTS names 2 directories but no file-watcher
integration pack is installed+granted — grant `vault.markdown-watcher`
to activate
```

A corrupt integrations directory is treated as "no packs granted", not a boot
panic ([vault_watcher.rs:199](../../crates/corecruxd/src/vault_watcher.rs#L199)).

### Configuration

| Env var | Default | Meaning |
|---|---|---|
| `CORECRUXD_VAULT_WATCH_ROOTS` | unset | Colon-separated absolute directories, `PATH`-style ([vault_watcher.rs:105](../../crates/corecruxd/src/vault_watcher.rs#L105)) |
| `CORECRUXD_VAULT_WATCH_INTERVAL_SECS` | 300 | Scan cadence; zero or unparseable falls back to the default ([vault_watcher.rs:261](../../crates/corecruxd/src/vault_watcher.rs#L261)) |
| `CORECRUXD_VAULT_WATCH_TENANT` | `local` | Tenant the notes are sealed under |
| `CORECRUXD_VAULT_WATCH_CORPUS` | `docs` | Corpus the notes are sealed under |

`parse_watch_roots` ([vault_watcher.rs:148](../../crates/corecruxd/src/vault_watcher.rs#L148))
keeps only entries that are absolute, canonicalisable, and directories. Rejects
are collected with a reason (`(not absolute)`, `(not readable)`,
`(not a directory)`) and warn-logged once — operator intent is never silently
dropped. Duplicates that canonicalise to the same path are deduped.

### Walkthrough

```bash
# 1. Install and grant the first-party watcher pack.
curl -s -X POST http://127.0.0.1:14800/v1/console/integrations/vault.markdown-watcher/install \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"version":"0.1.0"}'

curl -s -X POST http://127.0.0.1:14800/v1/console/integrations/vault.markdown-watcher/grant \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"version":"0.1.0","capabilities":["facts:read","facts:write"]}'

# 2. Point the daemon at your notes and restart it.
export CORECRUXD_VAULT_WATCH_ROOTS=/home/me/notes:/srv/shared/notes
export CORECRUXD_VAULT_WATCH_INTERVAL_SECS=120
export CORECRUXD_VAULT_WATCH_CORPUS=notes

# 3. After one interval, read the job status.
curl -s "http://127.0.0.1:14800/v1/facts/entity/__sync__::vault-watcher" \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"
```

Step 2 requires a restart: `activation()` runs once during startup.

### Scan safety properties

([vault_watcher.rs:284](../../crates/corecruxd/src/vault_watcher.rs#L284))

- Hidden directories — anything whose name starts with `.`, which covers `.git`
  and editor state directories — are never descended; hidden files are skipped.
- **Symlinks are refused**, files and directories alike. The walk uses
  `symlink_metadata`, which does not follow, so a link planted inside a vault
  cannot pull `/etc` into the corpus.
- Every candidate is canonicalised and re-checked to be under the canonical
  root before it is read — belt and braces on top of the symlink refusal.
- Only `*.md` (case-insensitive) is considered.
- Files above `MAX_FILE_BYTES` (4 MiB) are skipped
  ([vault_watcher.rs:121](../../crates/corecruxd/src/vault_watcher.rs#L121)).
- At most `MAX_FILES_PER_CYCLE` (500) files are ingested per cycle; the
  remainder is reported as `pending` and picked up next cycle
  ([vault_watcher.rs:123](../../crates/corecruxd/src/vault_watcher.rs#L123)).

### Frontmatter

A leading `---` line terminated by `---` or `...` is parsed as YAML
([vault_watcher.rs:376](../../crates/corecruxd/src/vault_watcher.rs#L376)). Two fields are
understood: `title` (string) and `tags` (a YAML sequence, or an inline
comma/space-separated string). A block that fails to parse yields empty
frontmatter and is **still stripped**, so malformed YAML never leaks into the
BM25 text. An unterminated block is treated as body, not frontmatter. A leading
byte-order mark is tolerated.

### The cursor

Second fact under the same entity: `__sync__::vault-watcher` key `cursor`,
schema `crux.vault_watcher.cursor.v1`
([vault_watcher.rs:102](../../crates/corecruxd/src/vault_watcher.rs#L102)).

```json
{
  "schema": "crux.vault_watcher.cursor.v1",
  "updated_at_unix_ms": 1753440000000,
  "truncated": false,
  "entries": {
    "/vault/note.md": {
      "mtime_ms": 1753439000000,
      "size": 2048,
      "content_hash": "b3:9f86d0…",
      "seen_at_unix_ms": 1753440000000,
      "title": "Note",
      "tags": ["project", "crux"]
    }
  }
}
```

Change detection is two-stage
([vault_watcher.rs:529](../../crates/corecruxd/src/vault_watcher.rs#L529)): `(mtime, size)`
decides whether to read the file at all; the content hash decides whether to
re-seal it. A `touch` or an editor rewrite that leaves bytes identical refreshes
the stat fields and skips the seal
([vault_watcher.rs:679](../../crates/corecruxd/src/vault_watcher.rs#L679)).

The serialised cursor is capped at 256 KiB. Over that, the most recently seen
entries are kept, the rest are dropped, and `truncated` goes true. A dropped
entry is re-ingested the next time it is seen — truncation costs work, never
correctness ([vault_watcher.rs:72](../../crates/corecruxd/src/vault_watcher.rs#L72)).

### Deletions are recorded, not applied

A note that disappears is removed from the cursor and listed in the status
detail. **No destructive store operation is performed** — sealed segments are
append-only and retracting a document needs a tombstone design that does not
exist yet ([vault_watcher.rs:77](../../crates/corecruxd/src/vault_watcher.rs#L77)). The
status detail says so explicitly in a `deleted_note` field.

### Per-cycle report

`JobOutcome::Ran` carries this detail object
([vault_watcher.rs:769](../../crates/corecruxd/src/vault_watcher.rs#L769)): `roots`,
`tenant_id`, `corpus_id`, `scanned`, `added`, `modified`, `unchanged_content`,
`deleted`, `deleted_note`, `pending`, `ingested_chunks`, `sealed_batches`,
`cursor_entries`, `cursor_truncated`, `cursor_dropped`, `scan_errors`,
`read_errors`.

Failure semantics: all roots unreadable is an `Err` (drives backoff); some roots
unreadable is reported in `scan_errors` and the cycle continues. A batch seal
failure aborts the cycle, leaving those notes out of the cursor for retry
([vault_watcher.rs:745](../../crates/corecruxd/src/vault_watcher.rs#L745)).

### Where the notes land

The watcher uses the same local prose ingest path as `POST /v1/local/ingest`
([local_ingest.rs:685](../../crates/corecruxd/src/local_ingest.rs#L685)). Notes are chunked
by `chunk_markdown` — split at ATX headings, then windowed at about 1800
characters with 180 characters of overlap, preferring paragraph boundaries
([local_ingest.rs:598](../../crates/corecruxd/src/local_ingest.rs#L598)). `doc_id` is the
canonical absolute path; `chunk_id` is `<path>::<index padded to 6>`
([vault_watcher.rs:718](../../crates/corecruxd/src/vault_watcher.rs#L718)).

Notes become BM25-searchable, and vector-searchable when a dense embedder is
configured. `tenant_id` is the isolation key; `corpus_id` groups documents
within it.

## 7.3 The GitHub connector

Nine routes ([http/mod.rs:1275](../../crates/corecruxd/src/http/mod.rs#L1275)), handlers in
[http/integrations_github.rs](../../crates/corecruxd/src/http/integrations_github.rs):

| Route | Method | Scope |
|---|---|---|
| `/v1/integrations/github/status` | GET | `admin:read` |
| `/v1/integrations/github/connect` | POST | `integrations:install` |
| `/v1/integrations/github/disconnect` | POST | `integrations:disable` |
| `/v1/integrations/github/sync` | POST | `integrations:install` |
| `/v1/integrations/github/repos` | GET | `admin:read` |
| `/v1/integrations/github/repos/accessible` | GET | `admin:read` |
| `/v1/integrations/github/repos/{owner}/{repo}/select` | POST | `integrations:install` |
| `/v1/integrations/github/repos/{owner}/{repo}/select` | DELETE | `integrations:disable` |
| `/v1/integrations/github/repos/{owner}/{repo}/planning` | PUT | `integrations:install` |

```bash
# Connect once. The PAT is sealed immediately and never read back.
curl -s -X POST http://127.0.0.1:14800/v1/integrations/github/connect \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"pat":"ghp_..."}'

# Choose repos, then sync on demand (the scheduler also runs it every 15 min).
curl -s -X POST http://127.0.0.1:14800/v1/integrations/github/repos/CueCrux/Crux/select \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"
curl -s -X POST http://127.0.0.1:14800/v1/integrations/github/sync \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"
```

`run_sync_with_key` ([integrations_github_sync.rs:58](../../crates/corecruxd/src/integrations_github_sync.rs#L58))
walks each selected repo and syncs four object types in order — commits, pull
requests, issues, then issue and PR comments — writing facts with key `record`:

| Object | Entity |
|---|---|
| Commit | `github::{owner}/{repo}::commit/{sha}` |
| Pull request | `github::{owner}/{repo}::pr/{number}` |
| Issue | `github::{owner}/{repo}::issue/{number}` |
| Comment | `github::{owner}/{repo}::comment/{id}` |

Paging is capped at 100 per page and 10 pages per repo per sync — at most 1000
commits per repo per run
([integrations_github_sync.rs:25](../../crates/corecruxd/src/integrations_github_sync.rs#L25)).
The cursor is `last_synced_at_unix_ms` per repo, converted to a `since=`
parameter. Commits and comments are deduplicated by entity before writing;
pull requests and issues are re-stored on each run.

Note that `github::` is on the ungrantable prefix list
([extension_grants.rs:120](../../crates/corecruxd/src/extension_grants.rs#L120)) — a
community extension can never be granted read or write access to connector data.

## 7.4 The OpenAI-compatible connector

Five routes ([http/mod.rs:1312](../../crates/corecruxd/src/http/mod.rs#L1312)), handlers in
[http/integrations_openai.rs](../../crates/corecruxd/src/http/integrations_openai.rs):
`status` (GET), `connect` (POST), `disconnect` (POST), `settings` (PATCH), and
`chat` (POST).

`chat` proxies a chat-completions call, returning the upstream body plus a
`_proxy` envelope. Model selection falls back `body.model` → the stored
`default_model` → `gpt-4o-mini`
([http/integrations_openai.rs:191](../../crates/corecruxd/src/http/integrations_openai.rs#L191)).
Calling it while disconnected returns **412** with detail
`OpenAI not connected; POST /v1/integrations/openai/connect first`.

## 7.5 How connector credentials are protected

There is **no generic secrets HTTP surface**. Credentials are sealed envelopes
written as fields inside per-connector JSON files.

- Cipher: XChaCha20-Poly1305, scheme tag `xchacha20poly1305-v1`, 24-byte random
  nonce ([encrypted_secrets.rs:19](../../crates/corecruxd/src/encrypted_secrets.rs#L19)).
- Envelope: `{scheme, nonce_hex, ciphertext_hex}`
  ([encrypted_secrets.rs:34](../../crates/corecruxd/src/encrypted_secrets.rs#L34)).
- **The key is not in any environment variable.** It is derived from the
  daemon-root passport via BLAKE3 `derive_key` with the context string
  `integration-token-encryption-v1`
  ([main.rs:856](../../crates/corecruxd/src/main.rs#L856),
  [crux-session/src/passport.rs:191](../../crates/crux-session/src/passport.rs#L191)).
- Rotating the passport key invalidates every existing envelope, by design
  ([encrypted_secrets.rs:8](../../crates/corecruxd/src/encrypted_secrets.rs#L8)).

Files: `<data_dir>/integrations/github/credentials.json`,
`<data_dir>/integrations/openai/credentials.json`.

For your own connector: seal through `encrypted_secrets::seal` with
`state.integration_encryption_key` ([http/mod.rs:435](../../crates/corecruxd/src/http/mod.rs#L435)),
accept the secret over one POST, never echo it in a status response, and never
write it to a file you construct yourself.

## 7.6 Building your own scheduled job

1. Write the job body as an async closure returning `JobResult`. Return
   `Skipped` when unconfigured — never `Ran` with an empty summary.
2. Register it with a stable `job_id`; that id becomes the public fact entity
   `__sync__::<job_id>` and is effectively an API.
3. Gate activation on something explicit. The vault watcher's double gate is the
   pattern: a granted pack expresses "this may run here", an environment
   variable expresses "here is the input".
4. Put a structured summary in `Ran(Some(detail))`. That is what an operator
   sees; it is the whole observability surface.
5. Keep the body idempotent and re-callable. It will be retried on backoff.

## Ground truth

- [crates/corecruxd/src/sync_scheduler.rs:39](../../crates/corecruxd/src/sync_scheduler.rs#L39) — status fact schema
- [crates/corecruxd/src/sync_scheduler.rs:80](../../crates/corecruxd/src/sync_scheduler.rs#L80) — `JobOutcome`
- [crates/corecruxd/src/sync_scheduler.rs:154](../../crates/corecruxd/src/sync_scheduler.rs#L154) — backoff
- [crates/corecruxd/src/sync_scheduler.rs:264](../../crates/corecruxd/src/sync_scheduler.rs#L264) — `register`
- [crates/corecruxd/src/vault_watcher.rs:18](../../crates/corecruxd/src/vault_watcher.rs#L18) — the double gate
- [crates/corecruxd/src/vault_watcher.rs:193](../../crates/corecruxd/src/vault_watcher.rs#L193) — `activation`
- [crates/corecruxd/src/vault_watcher.rs:284](../../crates/corecruxd/src/vault_watcher.rs#L284) — `scan_root`
- [crates/corecruxd/src/vault_watcher.rs:639](../../crates/corecruxd/src/vault_watcher.rs#L639) — `run_cycle`
- [crates/corecruxd/src/main.rs:1491](../../crates/corecruxd/src/main.rs#L1491) — scheduler wiring
- [crates/corecruxd/src/integrations_github_sync.rs:58](../../crates/corecruxd/src/integrations_github_sync.rs#L58) — `run_sync_with_key`
- [crates/corecruxd/src/encrypted_secrets.rs:19](../../crates/corecruxd/src/encrypted_secrets.rs#L19) — envelope scheme
- [crates/corecruxd/src/local_ingest.rs:685](../../crates/corecruxd/src/local_ingest.rs#L685) — `ingest_prose_documents`
