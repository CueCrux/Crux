# 8. Studio packs and workspaces

The console's Canvas Studio lets an operator assemble tile boards and workspace
navigation out of facts. A **Studio pack** makes one of those portable: a
`crux.studio.v1` payload wrapped in a valid `crux.integration.v1` manifest, so it
rides the same signed-extension trust rails as everything else in this guide
([http/studio_pack.rs:9](../../crates/corecruxd/src/http/studio_pack.rs#L9)).

If you are building a client that ships dashboards, this is the format. From
§8.7 the chapter covers the second half: the curator-signed **template library**
an operator syncs and installs from.

## 8.1 The fact schemas underneath

Everything the console persists is a fact under tenant `default` with a
canonical, key-sorted JSON value.

| Entity | Key | Contents |
|---|---|---|
| `console:tileboard:<id>` | `doc` | A board document — nodes, links, texts, pan, zoom ([render.js:5516](../../crates/corecruxd/console/v2/render.js#L5516)) |
| `console:tiledesign:<slug>` | `def` | A saved tile design: `{name, config}` ([render.js:5517](../../crates/corecruxd/console/v2/render.js#L5517)) |
| `console:workspace:<uid>` | `def` | A workspace: ordered destinations, each holding page uids ([docs/agent/console-workspaces.md:22](../agent/console-workspaces.md)) |
| `console:page:<uid>` | `def` | A page instance: a typed page with title, sub, dest, config |

Default board id is `default`; the board document version is 1
([render.js:5521](../../crates/corecruxd/console/v2/render.js#L5521)).

### Workspace definition

```json
{
  "schema_version": 1,
  "uid": "ws-ops",
  "name": "My ops board",
  "icon": "meters",
  "order": 100,
  "source": "user",
  "dests": [
    { "id": "ops", "label": "Ops", "icon": "meters",
      "pages": ["ws-ops-execplans", "ws-ops-facts"] }
  ]
}
```

### Page definition

```json
{
  "schema_version": 1,
  "uid": "ws-ops-execplans",
  "type": "cx-work",
  "title": "ExecPlans",
  "sub": "read-time projection over the work board",
  "dest": "ops",
  "config": { "query": { "source": "all" } },
  "source": "user"
}
```

Rules from [docs/agent/console-workspaces.md](../agent/console-workspaces.md):

- uid convention: `ws-<slug>` for workspaces, `ws-<slug>-<page-slug>` for pages.
- `command` and `explore` are **reserved** built-ins. Writing
  `console:workspace:command` forks the built-in rather than replacing it;
  the fork carries `"source": "builtin-fork"` and `"forked_from": "command"`.
- `dests[].pages` holds ordered page uids, or bare registry page ids.
- `order` sorts ascending.
- `type` is any registry page id (`cx-overview`, `cx-work`, `cx-facts`,
  `cx-cost`, and so on) plus `canvas/board`, `canvas/graph`, `canvas/tree`,
  `explorer`, `sitemap`, `rings`.
- `config.query` merges into the page's load query string for exactly three page
  types: `cx-work` takes `source`, `cx-memory` takes `top_k`, `cx-review` takes
  `limit`. Unknown keys are preserved but not forwarded.
- Reverting a fork writes a tombstone def:
  `{"schema_version": 1, "uid": "<uid>", "reverted": true}`.

**Tolerant-reader contract**: unknown keys survive a Studio round trip, and a
newer `schema_version` renders an honest "newer configuration" panel instead of
failing. Honour it in your own clients.

## 8.2 Canonical JSON

Both the console and the daemon canonicalise before hashing: object keys sorted
deeply, array order preserved, no whitespace
([studio_pack.rs:523](../../crates/corecruxd/src/http/studio_pack.rs#L523)).

That determinism is exactly what makes an export/import round trip verify. The
payload passes through several parse/stringify hops — browser download, file
save, re-import — and key order is not preserved across them
([studio_pack.rs:508](../../crates/corecruxd/src/http/studio_pack.rs#L508)).

Both hashes are BLAKE3 with a `blake3:` prefix
([studio_pack.rs:501](../../crates/corecruxd/src/http/studio_pack.rs#L501)):

| Hash | Covers |
|---|---|
| `hashes.manifest` | The manifest signing payload — the same 11-field subset as any other pack |
| `hashes.bundle` | The canonical bytes of the `studio` payload |

The bundle hash is what integrity-binds the board to the manifest, because the
`studio` key sits outside the signing payload.

## 8.3 The `crux.studio.v1` payload

```json
{
  "schema": "crux.studio.v1",
  "version": 1,
  "created_at_unix_ms": 1753000000000,
  "board": { "id": "studio-board-example", "doc": { "nodes": [], "links": [], "texts": [], "pan": {"x":0,"y":0}, "zoom": 1, "version": 1 } },
  "designs": [],
  "settings": { "title": "Example board", "description": "…", "accent": "cool", "grid": 20, "refresh": "live" }
}
```

A pack may additionally carry `workspaces[]` and `pages[]` arrays of the
definitions from §8.1 ([docs/agent/console-workspaces.md](../agent/console-workspaces.md)).

A worked example ships in-tree:
[integrations/community/studio-board-example/0.1.0/manifest.json](../../integrations/community/studio-board-example/0.1.0/manifest.json).

## 8.4 Build

`POST /v1/studio/pack/build`, scope `query:read`
([studio_pack.rs:96](../../crates/corecruxd/src/http/studio_pack.rs#L96),
[http/mod.rs:667](../../crates/corecruxd/src/http/mod.rs#L667)).

```bash
curl -s -X POST http://127.0.0.1:14800/v1/studio/pack/build \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "studio": { "schema": "crux.studio.v1", "version": 1, "board": {}, "designs": [], "settings": {} },
        "id": "my-board",
        "name": "My Board",
        "version": "0.1.0",
        "publisher_passport_fpr": "p_6ca61039700c94bf57c2e158d282ef1e"
      }'
```

Required body fields: `studio`, `id`, `name`, `version`,
`publisher_passport_fpr`; `summary` is optional and auto-generated as
`Studio board pack '<id>' — N tile(s).` when blank
([studio_pack.rs:124](../../crates/corecruxd/src/http/studio_pack.rs#L124)).

Rejections:

- `studio.schema` not `crux.studio.v1` → 400
  `studio.schema must be 'crux.studio.v1', got '<x>'`.
- Blank `id`, `version` or `publisher_passport_fpr` → 400
  `id, version, and publisher_passport_fpr are required`.

Response ([studio_pack.rs:81](../../crates/corecruxd/src/http/studio_pack.rs#L81)):

```json
{
  "pack": { "schema": "crux.integration.v1", "...": "...", "studio": { } },
  "signed": false,
  "capabilities": ["facts:read", "integrations:read", "sessions:read"],
  "manifest_hash": "blake3:…",
  "bundle_hash": "blake3:…",
  "sign_instructions": ["This pack is UNSIGNED. …"],
  "trust_note": "Unsigned. This pack is inert on any daemon until it carries an Ed25519 Passport signature and the operator grants its capabilities."
}
```

The pack object **is** the manifest, with a `studio` key attached
([studio_pack.rs:540](../../crates/corecruxd/src/http/studio_pack.rs#L540)). `entry.kind`
is stamped `sdk_recipe` and `entry.path` is `studio-board.json`
([studio_pack.rs:147](../../crates/corecruxd/src/http/studio_pack.rs#L147)).

### Capabilities are derived, not declared

`derive_capabilities` ([studio_pack.rs:604](../../crates/corecruxd/src/http/studio_pack.rs#L604))
computes the minimal read set from the board's tiles. `integrations:read` is
always the baseline; each tile adds according to the route it binds
([studio_pack.rs:576](../../crates/corecruxd/src/http/studio_pack.rs#L576)):

| Tile route prefix | Capability |
|---|---|
| `/v1/facts`, `/v1/console/facts`, `/v1/query` | `facts:read` |
| `/v1/console/sessions`, `/v1/sessions` | `sessions:read` |
| `/v1/passports`, `/v1/console/passports` | `passport:read` |
| `/v1/receipts` | `admin:read` |
| `/v1/console/tenants` | `tenant:metadata:read` |
| anything else | `integrations:read` |

Plus, by tile kind: `search` → `facts:read`, `receipts` → `admin:read`,
otherwise `integrations:read`
([studio_pack.rs:592](../../crates/corecruxd/src/http/studio_pack.rs#L592)). The result is
sorted and deduped, so it is deterministic — the same board always yields the
same capability set, and therefore the same manifest hash.

Note that `admin:read` is a dangerous capability under the community rail
(chapter 3), so a board with a receipts tile will need a `review.json` to be
published.

### Signing at build time

If `CORECRUXD_STUDIO_SIGNING_KEY_HEX` holds a 64-hex-character Ed25519 seed, the
build signs for real and `signed` comes back true
([studio_pack.rs:627](../../crates/corecruxd/src/http/studio_pack.rs#L627)). A malformed
value is a 400 naming the variable — not a silent fallback to unsigned.

Unsigned is the normal state on a bare daemon, and the response says exactly
what to do about it ([studio_pack.rs:639](../../crates/corecruxd/src/http/studio_pack.rs#L639)):

1. `This pack is UNSIGNED. It is inert on any daemon until signed + capability-granted.`
2. Set `CORECRUXD_STUDIO_SIGNING_KEY_HEX` in the daemon env and re-export.
3. Open a PR adding `integrations/community/<id>/<version>/manifest.json` — the
   `cargo test -p crux-integrations --test community_packs` CI gate validates
   it, then the curator-signed index endorses it for install.

The daemon-held key is a local convenience. The canonical publishing rail is the
PR, which never needs a private key on a daemon
([studio_pack.rs:61](../../crates/corecruxd/src/http/studio_pack.rs#L61)).

## 8.5 Verify

`POST /v1/studio/pack/verify`, scope `query:read`
([studio_pack.rs:429](../../crates/corecruxd/src/http/studio_pack.rs#L429)).

```bash
curl -s -X POST http://127.0.0.1:14800/v1/studio/pack/verify \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"pack\": $(cat my-board.cruxstudio.json)}"
```

```json
{
  "ok": true,
  "schema_ok": true,
  "manifest_hash_ok": true,
  "bundle_hash_ok": true,
  "signature": { "present": true, "verdict": "valid", "error": "" },
  "manifest": { },
  "capabilities": [],
  "studio": { "schema_ok": true, "tile_count": 4, "kinds": ["api","note","search"], "board_title": "Example board", "design_count": 0 },
  "errors": []
}
```

Behaviours to design around:

- Verify **always returns 200** with a verdict, except for a non-object `pack`
  (400 `pack must be a JSON object`). A malformed manifest comes back as
  `ok: false` with `not a valid crux.integration.v1 manifest: <err>` in `errors`
  ([studio_pack.rs:344](../../crates/corecruxd/src/http/studio_pack.rs#L344)).
- The `signature.verdict` is one of `valid`, `unsigned`, `invalid`, and on
  failure `error` carries the library message **verbatim** — the console shows
  it as-is rather than paraphrasing
  ([studio_pack.rs:394](../../crates/corecruxd/src/http/studio_pack.rs#L394)).
- Signature verification runs against the daemon's own trusted keyring
  ([studio_pack.rs:443](../../crates/corecruxd/src/http/studio_pack.rs#L443)). An
  unsigned pack is not an error; `ok` is computed as schema, manifest hash,
  bundle hash, studio schema all true **and** signature not `invalid`
  ([studio_pack.rs:295](../../crates/corecruxd/src/http/studio_pack.rs#L295)).
- A missing `hashes.manifest` or `hashes.bundle` fails verification with
  `hashes.manifest is missing` /
  `hashes.bundle is missing (studio payload is not integrity-bound)`.
- **Neither route writes anything.** Both are pure transforms, classified
  alongside `/v1/query/text-search`
  ([studio_pack.rs:16](../../crates/corecruxd/src/http/studio_pack.rs#L16)) and listed in
  `READ_POST_ROUTES` rather than `GATED_MUTATIONS`
  ([tests/route_spec_drift.rs:228](../../crates/corecruxd/tests/route_spec_drift.rs#L228)).

## 8.6 Apply a pack the operator uploaded

For a pack a human drags into the console there is no apply endpoint. Importing
means writing its board doc, designs, workspaces and pages back as facts through
the operator-gated `POST /v1/console/facts/add`
([studio_pack.rs:34](../../crates/corecruxd/src/http/studio_pack.rs#L34),
[render.js:7193](../../crates/corecruxd/console/v2/render.js#L7193)).

That is a deliberate split: transform and verify are free and unprivileged;
mutation goes through the one audited, operator-gated write path.

A pack that arrives from the **central template library** takes a different
route — the daemon applies it itself, under stricter rules. That is §8.7.

## 8.7 The central template library

`crux.studio.index.v1` is the catalogue half: a curator-signed JSON document
listing installable Studio packs, synced to disk and re-verified by the daemon
on every read ([studio_index.rs:6](../../crates/crux-integrations/src/studio_index.rs#L6)).

It is a field-for-field mirror of the community-extensions registry (chapter 9)
— same Ed25519 envelope, same keyring rule, same cache-then-install ceremony.
Nothing about it is a new trust model. What differs is the payload each row
points at: a community-extension row points at a manifest that installs
executable surface; a library row points at a Studio pack, and installing one
**writes console facts, never code**
([studio_index.rs:20](../../crates/crux-integrations/src/studio_index.rs#L20)).

### The index

```json
{
  "schema": "crux.studio.index.v1",
  "updated_at_unix_ms": 1753440000000,
  "curator_passport_fpr": "p_curator_studio",
  "entries": [
    {
      "id": "studio.ops-overview",
      "kind": "pack",
      "name": "Ops Overview",
      "version": "0.1.0",
      "summary": "Retrieval latency + receipt freshness board.",
      "publisher_passport_fpr": "p_publisher",
      "tags": ["ops", "retrieval"],
      "required_tier": "pro",
      "pack_url": "https://example.com/packs/ops-overview.json",
      "pack_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "repo_url": "https://github.com/CueCrux/studio-library",
      "preview": "12 tiles: retrieval latency, receipt freshness, lane weights."
    }
  ],
  "signature": { "alg": "ed25519", "passport_fpr": "p_curator_studio", "sig": "…" }
}
```

`StudioLibraryEntry` ([studio_index.rs:93](../../crates/crux-integrations/src/studio_index.rs#L93)):

| Field | Type | Required | Rule |
|---|---|---|---|
| `id` | string | yes | Lowercase `[a-z0-9]` with `-` and `.` separators, 1–128 chars, must start and end alphanumeric, no adjacent separators ([studio_index.rs:377](../../crates/crux-integrations/src/studio_index.rs#L377)) |
| `kind` | `board`\|`design`\|`workspace`\|`pack` | yes | Descriptive metadata for the console badge — **not an authorisation input**; the payload decides what gets written ([studio_index.rs:66](../../crates/crux-integrations/src/studio_index.rs#L66)) |
| `name` | string | yes | 1–128 chars |
| `version` | string | yes | Real semver `MAJOR.MINOR.PATCH`, optional `-prerelease` / `+build` ([studio_index.rs:404](../../crates/crux-integrations/src/studio_index.rs#L404)) |
| `summary` | string | yes | ≤2048 chars |
| `publisher_passport_fpr` | string | yes | Whoever built and signed the pack — may differ from the index curator |
| `tags` | string[] | no | ≤16 tags, each ≤32 chars, lowercase `[a-z0-9-]` |
| `required_tier` | `RcxTier` | no | **Advisory.** See below |
| `pack_url` | string | yes | HTTPS, or loopback HTTP for local mirrors ([studio_index.rs:424](../../crates/crux-integrations/src/studio_index.rs#L424)) |
| `pack_sha256` | string | yes | 64 lowercase hex chars |
| `repo_url` | string | no | Must be HTTPS |
| `preview` | string | no | ≤512 chars of **plain text**, no control characters. It is a one-line hint, never an asset, never a data URI ([studio_index.rs:53](../../crates/crux-integrations/src/studio_index.rs#L53)) |

Index-level limits: at most 2048 entries, no duplicate ids, non-empty
`curator_passport_fpr` ([studio_index.rs:265](../../crates/crux-integrations/src/studio_index.rs#L265)).

### `verify()` also validates shape

The deliberate difference from the community index: `StudioLibraryIndex::verify`
runs the signature check and **then** `validate()`, so a signed index carrying a
non-HTTPS `pack_url` or a malformed `pack_sha256` dies at the trust boundary
rather than at the point of use — no caller can forget to call it
([studio_index.rs:225](../../crates/crux-integrations/src/studio_index.rs#L225)).

`validate()` is also callable on an unsigned draft, which is what a curator tool
does: build, validate, then sign
([studio_index.rs:265](../../crates/crux-integrations/src/studio_index.rs#L265)).

### `required_tier` is advisory — say so in your client

The tier vocabulary is the RCX one, re-exported rather than forked, so a catalogue
server and a daemon never disagree about what `"pro"` means
([studio_index.rs:42](../../crates/crux-integrations/src/studio_index.rs#L42)). It rides
the wire as `RcxTier`'s canonical `as_str()` tokens so sign → publish → verify
stays byte-stable ([studio_index.rs:138](../../crates/crux-integrations/src/studio_index.rs#L138)).

**The daemon does not enforce it.** The reasoning is stated in the module docs
([studio_library.rs:41](../../crates/corecruxd/src/http/studio_library.rs#L41)): this is a
open-source daemon, so any operator can rebuild it with the check removed —
a local tier gate would be theatre that only inconveniences honest users. The
enforcement point is the **catalogue server**, which decides whether to serve the
signed row and the `pack_url` bytes to a given subscriber at all.

Both daemon responses therefore stamp `tier_enforcement: "advisory"`
([studio_library.rs:175](../../crates/corecruxd/src/http/studio_library.rs#L175),
[studio_library.rs:469](../../crates/corecruxd/src/http/studio_library.rs#L469)), and the CLI
prints `(advisory — enforced by the catalog server, not the daemon)`
([corecruxctl/src/main.rs:4204](../../crates/corecruxctl/src/main.rs#L4204)). Echo the
value if you like; never present it as a gate.

## 8.8 Installing from the library

`POST /v1/studio/library/{id}/install`, scopes `admin:read` + `facts:write`
([studio_library.rs:287](../../crates/corecruxd/src/http/studio_library.rs#L287),
[http/mod.rs:681](../../crates/corecruxd/src/http/mod.rs#L681)).

```bash
curl -s -X POST http://127.0.0.1:14800/v1/studio/library/studio.ops-overview/install \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H "X-Corecrux-Passport-Id: p_operator" \
  -H 'Content-Type: application/json' -d '{}'
```

The sequence ([studio_library.rs:287](../../crates/corecruxd/src/http/studio_library.rs#L287)):

| # | Step | Failure |
|---|---|---|
| 1 | Scopes, then resolve the calling passport context | 403 |
| 2 | Load and **re-verify** the cached signed index | 404 / 400 / 403 (§12.4) |
| 3 | Find the entry by id | 404 `template '<id>' not found in the Studio library index` |
| 4 | Fetch `pack_url` — HTTPS or loopback, 30 s timeout, 2 MiB cap | 400 / 502 / 413 |
| 5 | **Pin `pack_sha256` before parsing anything** | 409 `pack_sha256 mismatch for '<id>': index=<a>, downloaded=<b>` |
| 6 | Run the same `evaluate_pack` pipeline `/v1/studio/pack/verify` uses | 409 `pack for '<id>' failed verification: <errors joined>` |
| 7 | **Require signed** unless the dev bypass is on | 403 (§8.9) |
| 8 | Manifest `id`@`version` must equal the index row | 409 `library entry mismatch: expected <a>@<b>, pack manifest is <c>@<d>` |
| 9 | Plan the writes against the live store | 409 on collision exhaustion |
| 10 | Refuse an empty pack | 400 `pack for '<id>' carries no installable artifacts (no board tiles, designs, workspaces, or pages)` |
| 11 | Per-write category enforcement against the calling passport, then the global privacy gate, then store | 403 |

Step 11 is the same write discipline as `post_console_fact_add`
([studio_library.rs:419](../../crates/corecruxd/src/http/studio_library.rs#L419)) — the
library install does not get a private write path.

### Install can only ever add

Three invariants, stated in the module header
([studio_library.rs:22](../../crates/corecruxd/src/http/studio_library.rs#L22)):

**Never overwrite.** Every artifact id or uid that collides with a live console
fact is remapped to a free `-2` / `-3` / … suffix, up to 64 attempts
([studio_library.rs:505](../../crates/corecruxd/src/http/studio_library.rs#L505)). The
operator's existing board is never touched.

**Consistent remaps.** Pages are allocated first, then every installed
workspace's `dests[].pages[]` reference is rewritten through the page remap, so
a remapped workspace points at *its own* pages and never at a pre-existing
operator page. A reference to a uid the pack does not carry — a built-in page,
say — is left untouched
([studio_library.rs:709](../../crates/corecruxd/src/http/studio_library.rs#L709)).

Per-artifact target ids ([studio_library.rs:569](../../crates/corecruxd/src/http/studio_library.rs#L569)):

| Artifact | Target id | Notes |
|---|---|---|
| board | the **library entry id** | A board doc with no `nodes`/`links`/`texts` is skipped, not written as an empty board |
| design | the pack's `slug`, console-slugified | `slug` is dropped from the stored def — it is the entity suffix, not part of the definition |
| page | the pack's `uid` | `uid` is rewritten in the def to the allocated value |
| workspace | the pack's `uid` | plus the `dests[].pages[]` rewrite above |

Slugification matches the console's own rule: lowercase, non-alphanumerics
collapsed to `-`, trimmed, capped at 48 characters, falling back to `item`
([studio_library.rs:524](../../crates/corecruxd/src/http/studio_library.rs#L524)).

**Provenance on every write.** Each written def or doc gains an `installed_from`
object ([studio_library.rs:492](../../crates/corecruxd/src/http/studio_library.rs#L492)):

```json
"installed_from": {
  "library_id": "studio.ops-overview",
  "version": "0.1.0",
  "pack_sha256": "9f86…",
  "publisher_passport_fpr": "p_publisher",
  "installed_at_unix_ms": 1753440000000
}
```

Merging is additive — existing keys are preserved
([studio_library.rs:549](../../crates/corecruxd/src/http/studio_library.rs#L549)). This is
exactly why the tolerant-reader contract in §8.1 matters: the console's readers
spread before coercing, so provenance survives Studio round trips, and
`GET /v1/studio/library` reads it back to compute the installed join.

### The response

Schema `crux.studio.library_install.v1`, status 201
([studio_library.rs:458](../../crates/corecruxd/src/http/studio_library.rs#L458)):

```json
{
  "schema": "crux.studio.library_install.v1",
  "library_id": "studio.ops-overview",
  "version": "0.1.0",
  "kind": "pack",
  "pack_sha256": "9f86…",
  "publisher_passport_fpr": "p_publisher",
  "signed": true,
  "allow_unsigned_dev": false,
  "required_tier": "pro",
  "tier_enforcement": "advisory",
  "provenance": { },
  "written": [
    { "artifact": "board", "entity": "console:tileboard:studio.ops-overview",
      "key": "doc", "fact_id": "…" }
  ],
  "remaps": [
    { "artifact": "page", "from": "ws-ops-facts", "to": "ws-ops-facts-2" }
  ],
  "entry": { }
}
```

Always read `remaps` before telling a user where their new board is. A non-empty
`remaps` array means the ids in the catalogue are not the ids on disk.

## 8.9 Browsing the library

`GET /v1/studio/library`, scope `query:read` — read class, no network
([studio_library.rs:116](../../crates/corecruxd/src/http/studio_library.rs#L116)):

```bash
curl -s http://127.0.0.1:14800/v1/studio/library \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"
```

```json
{
  "schema": "crux.studio.library_list.v1",
  "curator_passport_fpr": "p_curator_studio",
  "updated_at_unix_ms": 1753440000000,
  "entries": [
    { "id": "studio.ops-overview", "...": "...",
      "installed": true,
      "installed_version": "0.1.0",
      "installed_entities": ["console:tileboard:studio.ops-overview"],
      "installed_at_unix_ms": 1753440000000 }
  ],
  "tier_enforcement": "advisory"
}
```

The installed join is computed by scanning the four console artifact prefixes
for facts carrying an `installed_from` stamp and grouping by `library_id`
([studio_library.rs:192](../../crates/corecruxd/src/http/studio_library.rs#L192)). "Latest
wins" is by fact `version`, matching the console's own rule
([studio_library.rs:250](../../crates/corecruxd/src/http/studio_library.rs#L250)). The scan
is bounded by the console fact count — dashboards, not ingest.

### Require-signed, and its dev bypass

An install refuses a pack that is unsigned, or whose signature does not validate
against the operator's trusted keyring, with **403**
([studio_library.rs:364](../../crates/corecruxd/src/http/studio_library.rs#L364)):

```text
refusing to install '<id>': pack is unsigned. Add the publisher's key to the
trusted keyring (POST /v1/extensions/keys), or set
CORECRUXD_STUDIO_ALLOW_UNSIGNED=1 to bypass the require-signed policy in dev.
```

When the signature was present but invalid, the reason reads
`signature did not validate: <verbatim library error>` instead.

`CORECRUXD_STUDIO_ALLOW_UNSIGNED` accepts `1`, `true`, `yes`, `on`
(case-insensitive, trimmed) ([studio_library.rs:89](../../crates/corecruxd/src/http/studio_library.rs#L89)).
It is process-wide, and the install response echoes its state as
`allow_unsigned_dev` so a client can badge the result honestly. Note this is a
**different** variable from `CORECRUXD_STUDIO_SIGNING_KEY_HEX` (§8.4) and from
`CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED` (chapter 4) — three separate switches
covering three separate decisions.

### A read token can never install

`/v1/studio/*` is read class, but the install route is carved out ahead of that
prefix rule and classified **write**, requiring any of `facts:write` /
`admin:write` ([route_auth.rs:144](../../crates/corecruxd/src/http/route_auth.rs#L144)).
The comment says why plainly: this is the one `/v1/studio/` route that mutates,
so it must not be swept into the read-class rule. The handler's own
`require_http_scopes(admin:read, facts:write)` applies regardless of the
middleware mode.

## 8.10 The console's write harness

Worth understanding even if you never touch the console, because it is the
enforcement model the whole surface is built on.

Every mutating call the console can make is a row in `GATED_MUTATIONS`
([tests/route_spec_drift.rs:106](../../crates/corecruxd/tests/route_spec_drift.rs#L106)) —
40 tuples of `(method, path, js_method_name)`. That constant is the **input to a
code generator**: `generate_api_js` emits a frozen `CruxApiGated` client with
exactly one method per row, and `generated_api_js_is_in_sync`
([tests/route_spec_drift.rs:784](../../crates/corecruxd/tests/route_spec_drift.rs#L784))
asserts `console/v2/api.js` is byte-equal to the generated output. Adding a row
is the only way to widen what the console can mutate, and it fails CI until the
client is regenerated.

The integration and extension rows:

| Method | Path | Client method |
|---|---|---|
| POST | `/v1/integrations/github/connect` | `githubConnect` |
| POST | `/v1/integrations/github/disconnect` | `githubDisconnect` |
| POST | `/v1/integrations/github/sync` | `githubSync` |
| POST | `/v1/integrations/openai/connect` | `openaiConnect` |
| POST | `/v1/integrations/openai/disconnect` | `openaiDisconnect` |
| POST | `/v1/integrations/openai/chat` | `openaiChat` |
| POST | `/v1/console/integrations/{packId}/install` | `integrationPackInstall` |
| POST | `/v1/console/integrations/{packId}/grant` | `integrationPackGrant` |
| POST | `/v1/console/integrations/{packId}/disable` | `integrationPackDisable` |
| POST | `/v1/extensions/install-from-registry` | `extensionInstallFromRegistry` |
| DELETE | `/v1/extensions/{id}` | `extensionUninstall` |
| POST | `/v1/extensions/{id}/grants` | `extensionGrantAdd` |
| DELETE | `/v1/extensions/{id}/grants/{passport_fpr}` | `extensionGrantRemove` |
| POST | `/v1/extensions/keys` | `extensionAddKey` |
| DELETE | `/v1/extensions/keys/{passport_fpr}` | `extensionRemoveKey` |
| POST | `/v1/extensions/{id}/tools/{tool_name}/invoke` | `extensionInvoke` |
| POST | `/v1/studio/library/{id}/install` | `studioLibraryInstall` |
| POST | `/v1/console/facts/add` | `consoleFactsAdd` |

Each row is gated twice: the UI refuses unless the session holds operator
posture, and the daemon enforces its own scopes regardless
([tests/route_spec_drift.rs:46](../../crates/corecruxd/tests/route_spec_drift.rs#L46)).
Destructive rows additionally require a two-step in-DOM confirmation.

The Studio Integrations home
(`renderIntegrationsStudio`, [render.js:8624](../../crates/corecruxd/console/v2/render.js#L8624))
paints four sections — Connectors, Packs, Extensions and catalog, Trusted keys —
and its section subtitles state the model plainly, including
`Install is not grant — a pack does nothing until a passport grant names its capabilities.`

## Ground truth

- [crates/corecruxd/src/http/studio_pack.rs:57](../../crates/corecruxd/src/http/studio_pack.rs#L57) — `STUDIO_SCHEMA_V1`
- [crates/corecruxd/src/http/studio_pack.rs:96](../../crates/corecruxd/src/http/studio_pack.rs#L96) — `post_build_pack`
- [crates/corecruxd/src/http/studio_pack.rs:429](../../crates/corecruxd/src/http/studio_pack.rs#L429) — `post_verify_pack`
- [crates/corecruxd/src/http/studio_pack.rs:523](../../crates/corecruxd/src/http/studio_pack.rs#L523) — `canonicalize`
- [crates/corecruxd/src/http/studio_pack.rs:604](../../crates/corecruxd/src/http/studio_pack.rs#L604) — `derive_capabilities`
- [crates/corecruxd/src/http/mod.rs:667](../../crates/corecruxd/src/http/mod.rs#L667) — studio routes
- [crates/corecruxd/console/v2/render.js:5516](../../crates/corecruxd/console/v2/render.js#L5516) — board and design entities
- [crates/corecruxd/console/v2/render.js:8624](../../crates/corecruxd/console/v2/render.js#L8624) — `renderIntegrationsStudio`
- [crates/corecruxd/tests/route_spec_drift.rs:106](../../crates/corecruxd/tests/route_spec_drift.rs#L106) — `GATED_MUTATIONS` (40 rows)
- [crates/crux-integrations/src/studio_index.rs:45](../../crates/crux-integrations/src/studio_index.rs#L45) — `crux.studio.index.v1`
- [crates/crux-integrations/src/studio_index.rs:93](../../crates/crux-integrations/src/studio_index.rs#L93) — `StudioLibraryEntry`
- [crates/crux-integrations/src/studio_index.rs:225](../../crates/crux-integrations/src/studio_index.rs#L225) — `verify` (signature then shape)
- [crates/corecruxd/src/http/studio_library.rs:116](../../crates/corecruxd/src/http/studio_library.rs#L116) — `get_studio_library`
- [crates/corecruxd/src/http/studio_library.rs:287](../../crates/corecruxd/src/http/studio_library.rs#L287) — `post_studio_library_install`
- [crates/corecruxd/src/http/studio_library.rs:569](../../crates/corecruxd/src/http/studio_library.rs#L569) — `plan_install`, remap rules
- [crates/corecruxd/src/http/route_auth.rs:144](../../crates/corecruxd/src/http/route_auth.rs#L144) — the install write-class carve-out
- [docs/agent/console-workspaces.md](../agent/console-workspaces.md) — workspace and page fact schemas
- [integrations/community/studio-board-example/0.1.0/manifest.json](../../integrations/community/studio-board-example/0.1.0/manifest.json) — worked example
