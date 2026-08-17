# 9. The registry and publishing rail

The distribution model is deliberately thin: a curator-signed JSON index in a
git repo, plus content-addressed manifests fetched from wherever the author
hosts them. There is no hosted store, no upload endpoint, and no binary the
project serves on your behalf.

## 9.1 End to end

```text
author writes manifest.json
   └─ signs with an Ed25519 passport key
        └─ opens a PR to integrations/community/<id>/<version>/
             └─ CI gate: cargo test -p crux-integrations --test community_packs
                  └─ curator adds an entry to index.json and re-signs the index
                       └─ operator: corecruxctl extensions sync   (verify + cache)
                            └─ operator: corecruxctl extensions list-registry  (review)
                                 └─ operator: corecruxctl extensions install <id>
                                      └─ daemon: re-verify index, fetch manifest,
                                         enforce manifest_sha256, validate signature
                                           └─ operator: POST .../grants  (scope a passport)
```

Two independent integrity layers, doing different jobs:

| Layer | Binds | Who signs |
|---|---|---|
| Manifest signature | The policy surface — capabilities, network, data access, safety | The author |
| `manifest_sha256` in the index | The **entire** manifest file, byte for byte | The curator |

The second closes the gap the first leaves (see §2.4).

## 9.2 Authoring and signing

Sign with `sign_manifest`
([crates/crux-integrations/src/signing.rs:163](../../crates/crux-integrations/src/signing.rs#L163)),
which also fills `hashes.manifest`. In Rust:

```rust
use crux_integrations::{sign_manifest, fingerprint_from_public_key};
use ed25519_dalek::SigningKey;

let key = SigningKey::from_bytes(&seed);              // your 32-byte seed
let fpr = fingerprint_from_public_key(&key.verifying_key());  // "p_<32 hex>"
sign_manifest(&mut manifest, &key, fpr)?;
```

For a Studio board, `POST /v1/studio/pack/build` will sign for you when
`CORECRUXD_STUDIO_SIGNING_KEY_HEX` is set (chapter 8).

Keep `signature.public_key_hex` in the published manifest. The community CI gate
needs it — at PR time no operator keyring exists yet, so the gate builds a policy
trusting the manifest's own inline key and proves the pack is validly
self-signed ([tests/community_packs.rs:44](../../crates/crux-integrations/tests/community_packs.rs#L44)).
Curator endorsement and operator keyring trust happen later, at install.

## 9.3 The PR layout

```text
integrations/community/<pack-id>/<version>/manifest.json
integrations/community/<pack-id>/<version>/README.md
integrations/community/<pack-id>/<version>/review.json   # only if dangerous caps
```

([integrations/README.md](../../integrations/README.md))

### What the CI gate asserts

`community_pack_manifests_are_safe_and_reviewable`
([tests/community_packs.rs:29](../../crates/crux-integrations/tests/community_packs.rs#L29))
walks the tree recursively and, for every `manifest.json`
([tests/community_packs.rs:68](../../crates/crux-integrations/tests/community_packs.rs#L68)):

| Assertion | Failure message |
|---|---|
| `manifest.validate()` passes against the inline-key policy | the library error |
| `publisher_passport_fpr != "cuecrux:first-party"` | `<path> must not claim first-party publisher identity` |
| `hashes.manifest` present | `<path> must include hashes.manifest` |
| `signature` present | `<path> must include an Ed25519 Passport signature` |
| `entry.kind != external_helper` | `<path> uses external_helper; community v1 packs are declarative only` |
| `entry.path` is a safe relative path | `<path> has unsafe entry.path '<p>'` |
| `README.md` exists beside the manifest | `<dir> must include README.md with setup and safety notes` |
| Dangerous capability ⇒ `review.json` with `maintainer_approval: true` and a non-empty `rationale` | `<review.json> must set maintainer_approval=true` / `must include a non-empty rationale` |

Run it locally before opening the PR:

```bash
cargo test -p crux-integrations --test community_packs
```

The gate proves the pack is well-formed and validly self-signed. A tampered
payload still fails here — the signature will not verify, or the hash will not
match.

## 9.4 The curator index

Schema and verification are covered in §4.6. The curator's job is to:

1. Compute `manifest_sha256` — SHA-256 over the exact manifest bytes that will
   be served at `manifest_url`.
2. Add a `CommunityExtensionEntry` with `id`, `name`, `version`, `summary`,
   `manifest_url`, `manifest_sha256`, `repo_url`, `kind`, `trust_tier`.
3. Re-sign the whole index with the curator key
   ([lib.rs:738](../../crates/crux-integrations/src/lib.rs#L738)).
4. Publish it at a stable HTTPS URL.

The `trust_tier` the curator assigns is advisory — an operator's local keyring
overrides it at install time
([lib.rs:681](../../crates/crux-integrations/src/lib.rs#L681)).

## 9.5 Operator: sync

```bash
corecruxctl extensions sync \
  --url https://raw.githubusercontent.com/CueCrux/community-extensions/main/index.json \
  --pubkey-fpr p_curator \
  --pubkey-hex 4c00e9689fc124fbdf7d4afb2d43632cf529eae10234c17f08ecb3a2f569bedf \
  --data-dir /srv/crux/data
```

([corecruxctl/src/main.rs:1356](../../crates/corecruxctl/src/main.rs#L1356),
[corecruxctl/src/extensions.rs:73](../../crates/corecruxctl/src/extensions.rs#L73))

What it does, in order:

1. Rejects a `--pubkey-hex` that is not exactly 64 lowercase hex characters:
   `public_key_hex must be 64 lowercase hex chars`.
2. HTTPS GET with a 30-second global timeout, capped at 1 MiB
   (`REGISTRY_INDEX_DOWNLOAD_LIMIT_BYTES`,
   [extensions.rs:61](../../crates/corecruxctl/src/extensions.rs#L61)).
3. Parses, then verifies the signature against a policy holding **only** the
   supplied curator key.
4. Writes the verified bytes atomically to
   `<data-dir>/extensions/registry/index.json`.

**On a verification failure the cache is not written at all.** That is pinned by
`sync_rejects_index_signed_by_wrong_key`
([extensions.rs:282](../../crates/corecruxctl/src/extensions.rs#L282)), which asserts the
cache path does not exist after a bad sync. The daemon can never be serving a
half-trusted index.

Output lists curator, timestamp, entry count, the cache path, and one line per
entry with id, version, kind and trust tier
([corecruxctl/src/main.rs:4089](../../crates/corecruxctl/src/main.rs#L4089)).

## 9.6 Operator: review

```bash
corecruxctl extensions list-registry --data-dir /srv/crux/data
```

Prints each entry in full — id, kind, trust tier, summary, repo URL, manifest
URL and sha256 ([corecruxctl/src/main.rs:4115](../../crates/corecruxctl/src/main.rs#L4115)).

This subcommand reads the cached file directly and does **not** re-verify the
signature ([extensions.rs:136](../../crates/corecruxctl/src/extensions.rs#L136)) — the
bytes were verified when `sync` wrote them. To browse a verified view over HTTP,
use the daemon route, which re-verifies on every call:

```bash
curl -s http://127.0.0.1:14800/v1/extensions/registry \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"
```

```json
{
  "schema": "crux.extensions.registry_list.v1",
  "curator_passport_fpr": "p_curator",
  "updated_at_unix_ms": 1753440000000,
  "entries": [
    { "id": "ext.example.quote", "...": "...",
      "installed": true, "installed_version": "0.1.0" }
  ]
}
```

Each row is joined against the installed set, so a console can render
"installed / update available" without a second round trip
([http/extensions.rs:250](../../crates/corecruxd/src/http/extensions.rs#L250)). Scope:
`admin:read`. No network is touched — it is a read-only twin of the install path
over the same cache ([http/extensions.rs:221](../../crates/corecruxd/src/http/extensions.rs#L221)).

On a fresh daemon this returns **404** with a detail that names the fix:
`registry index read failed: <io error> (run \`corecruxctl extensions sync\` to populate the cached registry index)`
([http/extensions.rs:237](../../crates/corecruxd/src/http/extensions.rs#L237)).

## 9.7 Operator: install

```bash
corecruxctl extensions install ext.example.quote \
  --http-url http://127.0.0.1:14800 \
  --token "$CRUX_AGENT_TOKEN"
```

Or directly:

```bash
curl -s -X POST http://127.0.0.1:14800/v1/extensions/install-from-registry \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H "X-Corecrux-Passport-Id: p_operator" \
  -H 'Content-Type: application/json' \
  -d '{"id":"ext.example.quote"}'
```

The CLI never reads the index itself — the daemon does the verifying
([corecruxctl/src/extensions.rs:21](../../crates/corecruxctl/src/extensions.rs#L21)). Daemon
base URL resolves `--http-url` → `CORECRUXD_HTTP_URL` → `http://127.0.0.1:14800`;
the token resolves `--token` → `CRUX_AGENT_TOKEN`
([extensions.rs:156](../../crates/corecruxctl/src/extensions.rs#L156)).

`install_from_registry` ([http/extensions.rs:284](../../crates/corecruxd/src/http/extensions.rs#L284))
runs this sequence:

| # | Step | Failure |
|---|---|---|
| 1 | Scopes `admin:read` + `facts:write` | 403 |
| 2 | Load and **re-verify** the cached index against the local keyring | 404 read failure, 400 decode failure, 403 `registry index signature verification failed: <err>` |
| 3 | Find the entry by id | 404 `extension '<id>' not found in registry index` |
| 4 | Check `manifest_url` is HTTPS, or loopback HTTP | 400 `manifest_url must be https://, or loopback http:// for local tests` |
| 5 | Fetch it — 30 s timeout, 2 MiB cap | 502 on transport or non-2xx, 413 `manifest exceeds the 2097152-byte cap` |
| 6 | SHA-256 must equal the curator's `manifest_sha256` | 409 `manifest_sha256 mismatch for '<id>': registry=<a>, downloaded=<b>` |
| 7 | Decode as a manifest | 502 `manifest JSON decode failed: <err>` |
| 8 | `id` and `version` must match the index entry | 409 `registry entry mismatch: expected <a>@<b>, manifest is <c>@<d>` |
| 9 | Delegate to the same installer as `/v1/extensions/register` — signature validated against the keyring | 400 with the library error |

The `index_path` body field lets an operator point at a private mirror. Relative
paths resolve under the daemon's data dir; absolute paths are taken as-is
([http/extensions.rs:373](../../crates/corecruxd/src/http/extensions.rs#L373)).

Success is 201:

```json
{
  "schema": "crux.extensions.registry_install.v1",
  "registry_entry": { },
  "manifest_sha256": "9f86…",
  "installed": { "manifest": { }, "manifest_hash": "blake3:…", "trust_tier": "community_reviewed", "installed_at_unix_ms": 1753440000000, "installed_by_passport": "p_operator" }
}
```

The CLI closes with the honest next step:
`grants: none yet — POST /v1/extensions/{id}/grants to scope a passport`
([corecruxctl/src/main.rs:4156](../../crates/corecruxctl/src/main.rs#L4156)).

## 9.8 Installing without a registry

`POST /v1/extensions/register` takes a manifest inline:

```bash
curl -s -X POST http://127.0.0.1:14800/v1/extensions/register \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H "X-Corecrux-Passport-Id: p_operator" \
  -H 'Content-Type: application/json' \
  -d '{"manifest": '"$(cat manifest.json)"'}'
```

Scopes `admin:read` + `facts:write`
([http/extensions.rs:121](../../crates/corecruxd/src/http/extensions.rs#L121)). The signing
key must already be in the trusted keyring, or
`CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED` must be on.

Extension id rules are stricter than manifest id rules: **lowercase** ASCII,
digits, `.`, `-`, `_` only, at most 128 characters
([extension_registry.rs:80](../../crates/corecruxd/src/extension_registry.rs#L80)). A
violation gives
`manifest id '<id>' contains invalid characters; expected lowercase alphanumerics + . - _`.

Re-installing an existing id is a **409** `extension id already installed`
([http/extensions.rs:201](../../crates/corecruxd/src/http/extensions.rs#L201)). Upgrades are
uninstall then install; the error text says so:
`extension '<id>' already installed (use DELETE first to replace)`.

## 9.9 The second rail: the Studio template library

Everything above distributes **code**. The Studio template library distributes
**dashboards**, over the same rails, with one extra hop at the end: the daemon
applies the artefact itself instead of handing you a manifest to grant.

```text
author builds a board in Studio
   └─ POST /v1/studio/pack/build   (manifest + both hashes, signed if a key is set)
        └─ publishes the pack JSON at a stable HTTPS URL
             └─ curator adds a row (pack_url + pack_sha256) to a
                crux.studio.index.v1 index and signs the whole index
                  └─ operator: corecruxctl studio sync         (verify + cache)
                       └─ operator: corecruxctl studio list-library   (review)
                            └─ operator: corecruxctl studio install <id>
                               or the console Library panel
                                 └─ daemon: re-verify index, fetch pack,
                                    pin pack_sha256, REQUIRE the pack be signed,
                                    write console facts with provenance
```

Chapter 8 covers the index schema, the install invariants and the response.
This section is the operator-facing command rail.

### Sync

```bash
corecruxctl studio sync \
  --url https://example.com/studio-library/index.json \
  --pubkey-fpr p_curator_studio \
  --pubkey-hex 4c00e9689fc124fbdf7d4afb2d43632cf529eae10234c17f08ecb3a2f569bedf \
  --data-dir /srv/crux/data
```

([corecruxctl/src/main.rs:1401](../../crates/corecruxctl/src/main.rs#L1401),
[corecruxctl/src/studio.rs:73](../../crates/corecruxctl/src/studio.rs#L73))

A deliberate mirror of `extensions sync` — same fetch/verify/cache ceremony,
same 1 MiB index cap, same atomic write, same
`public_key_hex must be 64 lowercase hex chars` guard. Only the schema and the
cache directory differ ([corecruxctl/src/studio.rs:10](../../crates/corecruxctl/src/studio.rs#L10)).

The cache lands at `<data-dir>/studio/library/index.json`
([corecruxctl/src/studio.rs:66](../../crates/corecruxctl/src/studio.rs#L66)). A verify
failure leaves any previously cached index untouched — the same fail-closed
property as the extensions rail.

Because `StudioLibraryIndex::verify` runs shape validation after the signature
check, `sync` also rejects a validly-signed index carrying a malformed row: a
non-HTTPS `pack_url`, a bad `pack_sha256`, a non-semver `version`, a duplicate
id. The error names the offending entry.

Output lists curator, timestamp, entry count, the cache path, then one line per
entry with id, version, kind and advisory tier
([corecruxctl/src/main.rs:4169](../../crates/corecruxctl/src/main.rs#L4169)).

### Review

```bash
corecruxctl studio list-library --data-dir /srv/crux/data
```

Prints each row in full — id, kind, publisher, summary, tags, advisory tier,
preview, repo, `pack_url` and `pack_sha256`
([corecruxctl/src/main.rs:4188](../../crates/corecruxctl/src/main.rs#L4188)). Like its
extensions twin, it reads the cached file and does not re-verify; the bytes were
verified when `sync` wrote them. The tier line is printed with its honesty
suffix: `(advisory — enforced by the catalog server, not the daemon)`.

For a re-verified view over HTTP, use `GET /v1/studio/library` (§8.9), which
also joins against what is already installed.

### Install

```bash
corecruxctl studio install studio.ops-overview \
  --http-url http://127.0.0.1:14800 \
  --token "$CRUX_AGENT_TOKEN"
```

([corecruxctl/src/studio.rs:189](../../crates/corecruxctl/src/studio.rs#L189)) The CLI
never reads the index itself. The daemon re-verifies the index signature, pins
`pack_sha256`, and requires the pack to be signed
([corecruxctl/src/studio.rs:25](../../crates/corecruxctl/src/studio.rs#L25)). URL and
token precedence match the extensions CLI: `--http-url` →
`CORECRUXD_HTTP_URL` → `http://127.0.0.1:14800`, and `--token` →
`CRUX_AGENT_TOKEN` ([corecruxctl/src/studio.rs:158](../../crates/corecruxctl/src/studio.rs#L158)).

`--index-path` forwards a **daemon-side** override for a private mirror;
relative paths resolve under the daemon's data dir
([corecruxctl/src/main.rs:1428](../../crates/corecruxctl/src/main.rs#L1428)).

Output names every artefact written and every id that had to be remapped
([corecruxctl/src/main.rs:4232](../../crates/corecruxctl/src/main.rs#L4232)):

```text
Installed studio.ops-overview from the cached Studio library index.
  schema:          crux.studio.library_install.v1
  version:         0.1.0
  pack_sha256:     9f86…
  signed:          true
  required_tier:   pro (advisory)
  + board console:tileboard:studio.ops-overview (key doc)
  + page console:page:ws-ops-facts-2 (key def)
  ~ page id remapped ws-ops-facts -> ws-ops-facts-2 (existing artifact preserved)
```

### Two indexes, one keyring

| | Community extensions | Studio library |
|---|---|---|
| Schema | `crux.community-extensions.index.v1` | `crux.studio.index.v1` |
| Cache | `<data_dir>/extensions/registry/index.json` | `<data_dir>/studio/library/index.json` |
| Per-row pin | `manifest_sha256` | `pack_sha256` |
| Browse route | `GET /v1/extensions/registry` (`admin:read`) | `GET /v1/studio/library` (`query:read`) |
| Install route | `POST /v1/extensions/install-from-registry` | `POST /v1/studio/library/{id}/install` |
| CLI | `corecruxctl extensions sync\|list-registry\|install` | `corecruxctl studio sync\|list-library\|install` |
| Unsigned dev bypass | `CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED` | `CORECRUXD_STUDIO_ALLOW_UNSIGNED` |
| Shape validation | at point of use | inside `verify()`, at the trust boundary |
| Result of install | a manifest record; **still needs a grant** | console facts, written immediately |

Both verify against the same `<data_dir>/extensions/trusted-keys.json`
([studio_library.rs:741](../../crates/corecruxd/src/http/studio_library.rs#L741)), so one
`POST /v1/extensions/keys` call admits a curator to both rails. Give the two
curators separate fingerprints unless they really are the same authority.

Note the asymmetry in the last row: an extension install is inert until granted;
a library install writes artefacts straight away. That is why the library
install is require-signed by default while the extension install is not.

## 9.10 The full route reference

| Route | Method | Scopes | Handler |
|---|---|---|---|
| `/v1/extensions` | GET | `admin:read` | [extensions.rs:76](../../crates/corecruxd/src/http/extensions.rs#L76) |
| `/v1/extensions/register` | POST | `admin:read`, `facts:write` | [extensions.rs:121](../../crates/corecruxd/src/http/extensions.rs#L121) |
| `/v1/extensions/install-from-registry` | POST | `admin:read`, `facts:write` | [extensions.rs:284](../../crates/corecruxd/src/http/extensions.rs#L284) |
| `/v1/extensions/registry` | GET | `admin:read` | [extensions.rs:228](../../crates/corecruxd/src/http/extensions.rs#L228) |
| `/v1/extensions/keys` | GET | `admin:read` | [extensions.rs:503](../../crates/corecruxd/src/http/extensions.rs#L503) |
| `/v1/extensions/keys` | POST | `admin:read`, `facts:write` | [extensions.rs:522](../../crates/corecruxd/src/http/extensions.rs#L522) |
| `/v1/extensions/keys/{passport_fpr}` | DELETE | `admin:read`, `facts:write` | [extensions.rs:870](../../crates/corecruxd/src/http/extensions.rs#L870) |
| `/v1/extensions/{id}` | GET | `admin:read` | [extensions.rs:95](../../crates/corecruxd/src/http/extensions.rs#L95) |
| `/v1/extensions/{id}` | DELETE | `admin:read`, `facts:write` | [extensions.rs:464](../../crates/corecruxd/src/http/extensions.rs#L464) |
| `/v1/extensions/{id}/grants` | GET | `admin:read` | [extensions.rs:587](../../crates/corecruxd/src/http/extensions.rs#L587) |
| `/v1/extensions/{id}/grants` | POST | `admin:read`, `facts:write` | [extensions.rs:610](../../crates/corecruxd/src/http/extensions.rs#L610) |
| `/v1/extensions/{id}/grants/{passport_fpr}` | DELETE | `admin:read`, `facts:write` | [extensions.rs:837](../../crates/corecruxd/src/http/extensions.rs#L837) |
| `/v1/extensions/{id}/tools/{tool_name}/invoke` | POST | `admin:read`, `facts:write` | [extensions.rs:686](../../crates/corecruxd/src/http/extensions.rs#L686) |
| `/v1/studio/library` | GET | `query:read` | [studio_library.rs:116](../../crates/corecruxd/src/http/studio_library.rs#L116) |
| `/v1/studio/library/{id}/install` | POST | `admin:read`, `facts:write` | [studio_library.rs:287](../../crates/corecruxd/src/http/studio_library.rs#L287) |

Router registrations run from
[http/mod.rs:1061](../../crates/corecruxd/src/http/mod.rs#L1061) to
[http/mod.rs:1117](../../crates/corecruxd/src/http/mod.rs#L1117). Note the ordering
comment there: `/v1/extensions/registry` is a static segment, so it is
registered ahead of `/v1/extensions/{id}` and wins the match.

Uninstall is a tombstone write, not a file delete
([extension_registry.rs:222](../../crates/corecruxd/src/extension_registry.rs#L222)). It
returns 204, or 404 `extension '<id>' not found`. It does **not** cascade to
grants — revoke those separately if you intend to reinstall a different build
under the same id.

## Ground truth

- [integrations/README.md](../../integrations/README.md) — the publishing rules
- [crates/crux-integrations/tests/community_packs.rs:29](../../crates/crux-integrations/tests/community_packs.rs#L29) — the CI gate
- [crates/crux-integrations/src/lib.rs:686](../../crates/crux-integrations/src/lib.rs#L686) — index sync flow
- [crates/corecruxctl/src/extensions.rs:73](../../crates/corecruxctl/src/extensions.rs#L73) — `sync`
- [crates/corecruxctl/src/extensions.rs:136](../../crates/corecruxctl/src/extensions.rs#L136) — `list_registry`
- [crates/corecruxctl/src/extensions.rs:186](../../crates/corecruxctl/src/extensions.rs#L186) — `install`
- [crates/corecruxctl/src/main.rs:1352](../../crates/corecruxctl/src/main.rs#L1352) — CLI definition
- [crates/corecruxd/src/http/extensions.rs:221](../../crates/corecruxd/src/http/extensions.rs#L221) — `list_registry_entries`
- [crates/corecruxd/src/http/extensions.rs:284](../../crates/corecruxd/src/http/extensions.rs#L284) — `install_from_registry`
- [crates/corecruxd/src/extension_registry.rs:124](../../crates/corecruxd/src/extension_registry.rs#L124) — `install_extension`
- [crates/corecruxctl/src/studio.rs:73](../../crates/corecruxctl/src/studio.rs#L73) — `studio sync`
- [crates/corecruxctl/src/studio.rs:138](../../crates/corecruxctl/src/studio.rs#L138) — `studio list-library`
- [crates/corecruxctl/src/studio.rs:189](../../crates/corecruxctl/src/studio.rs#L189) — `studio install`
- [crates/corecruxctl/src/main.rs:1400](../../crates/corecruxctl/src/main.rs#L1400) — `StudioCommand` CLI definition
- [crates/crux-integrations/src/studio_index.rs:28](../../crates/crux-integrations/src/studio_index.rs#L28) — the sync flow, stated in the module header
