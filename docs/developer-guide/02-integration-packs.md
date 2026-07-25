# 2. Integration packs — the `crux.integration.v1` manifest

An integration pack is one JSON document. The daemon reads it, validates it, and
stores it. Nothing in a pack executes in the daemon process unless its
`entry.kind` names a runtime the daemon actually ships (three do today; see the
table below).

The manifest type is `IntegrationManifest`
([crates/crux-integrations/src/lib.rs:98](../../crates/crux-integrations/src/lib.rs#L98)).
`validate()` is the single gate every install path runs
([lib.rs:481](../../crates/crux-integrations/src/lib.rs#L481)).

## 2.1 Minimal valid manifest

```json
{
  "schema": "crux.integration.v1",
  "id": "example.hello",
  "name": "Hello",
  "version": "0.1.0",
  "publisher_passport_fpr": "p_6ca61039700c94bf57c2e158d282ef1e",
  "summary": "Does nothing, correctly.",
  "entry": { "kind": "http_recipe", "path": "recipes/hello.json" },
  "capabilities": ["facts:read"]
}
```

Everything below `capabilities` has a `serde` default. `summary` does **not** —
it is a required key at deserialisation time, not at validation time, so a
missing `summary` fails as a JSON decode error rather than a validation error
([lib.rs:104](../../crates/crux-integrations/src/lib.rs#L104)).

## 2.2 Field reference

| Field | Type | Required | Validation rule (and where) |
|---|---|---|---|
| `schema` | string | yes | Must equal `crux.integration.v1`; else `invalid integration schema '<x>'` ([lib.rs:482](../../crates/crux-integrations/src/lib.rs#L482)) |
| `id` | string | yes | Non-empty, and every char in `[A-Za-z0-9._-]`; else `invalid identifier '<id>'` ([lib.rs:485](../../crates/crux-integrations/src/lib.rs#L485), [lib.rs:1400](../../crates/crux-integrations/src/lib.rs#L1400)) |
| `name` | string | yes | Non-empty after trim ([lib.rs:486](../../crates/crux-integrations/src/lib.rs#L486)) |
| `version` | string | yes | Non-empty after trim. **No semver check exists** ([lib.rs:487](../../crates/crux-integrations/src/lib.rs#L487)) |
| `publisher_passport_fpr` | string | yes | Non-empty. The value `cuecrux:first-party` is reserved for packs compiled into the daemon ([lib.rs:31](../../crates/crux-integrations/src/lib.rs#L31), [lib.rs:488](../../crates/crux-integrations/src/lib.rs#L488)) |
| `summary` | string | yes (serde) | No content rule ([lib.rs:104](../../crates/crux-integrations/src/lib.rs#L104)) |
| `entry.kind` | enum, snake_case | yes | One of the nine variants in §2.3 ([lib.rs:186](../../crates/crux-integrations/src/lib.rs#L186)) |
| `entry.path` | string | yes | Non-empty. Relative-path safety is enforced by the community CI gate, not by `validate()` ([lib.rs:490](../../crates/crux-integrations/src/lib.rs#L490)) |
| `capabilities` | string[] | no (`[]`) | Every entry must be in the 14-item allowlist; else `unknown capability '<c>'` ([lib.rs:492](../../crates/crux-integrations/src/lib.rs#L492)) |
| `network.allowed_hosts` | string[] | no (`[]`) | Literal host names, optional `:port`. Enforced at dispatch, not at validate ([lib.rs:217](../../crates/crux-integrations/src/lib.rs#L217)) |
| `network.requires_user_token` | bool | no (`false`) | Declarative only — no daemon code branches on it |
| `data_access.tenant_scopes` | string[] | no (`["selected"]`) | Declarative; feeds risk scoring only ([lib.rs:232](../../crates/crux-integrations/src/lib.rs#L232)) |
| `data_access.content_preview` | bool | no (`false`) | Raises `risk_level` to `high` ([lib.rs:1461](../../crates/crux-integrations/src/lib.rs#L1461)) |
| `data_access.private_facts` | bool | no (`false`) | Raises `risk_level` to `high` ([lib.rs:1462](../../crates/crux-integrations/src/lib.rs#L1462)) |
| `safety.sandbox` | `none`\|`command`\|`wasm` | no (`none`) | Declarative label; the WASM sandbox is selected by `entry.kind`, not by this field ([lib.rs:265](../../crates/crux-integrations/src/lib.rs#L265)) |
| `safety.max_runtime_ms` | u64 | no (`0`) | `0` = daemon default. Non-zero **tightens only** the outbound timeout ([lib.rs:243](../../crates/crux-integrations/src/lib.rs#L243), [extension_outbound.rs:462](../../crates/corecruxd/src/extension_outbound.rs#L462)) |
| `safety.max_output_bytes` | u64 | no (`0`) | `0` = daemon default. Non-zero **tightens only** the response cap ([extension_outbound.rs:469](../../crates/corecruxd/src/extension_outbound.rs#L469)) |
| `hashes.manifest` | string | no | When present must equal the recomputed hash; else `manifest hash mismatch: expected <a>, actual <b>` ([lib.rs:612](../../crates/crux-integrations/src/lib.rs#L612)) |
| `hashes.bundle` | string | no | Not checked by `validate()`. Studio pack verify checks it ([studio_pack.rs:379](../../crates/corecruxd/src/http/studio_pack.rs#L379)) |
| `signature` | object | conditional | Required unless a policy bypass applies (§2.5) |
| `external_tool_endpoint` | string | `external_tool` only | Must start `https://` or `http://`; forbidden on every other kind ([lib.rs:505](../../crates/crux-integrations/src/lib.rs#L505)) |
| `tools[]` | object[] | `external_tool`, `wasm` | Non-empty; each entry needs non-empty `name` + `description` ([lib.rs:518](../../crates/crux-integrations/src/lib.rs#L518)) |
| `wasm_module_path` | string | `wasm` (xor URL) | Must not start `/` nor contain `..` ([lib.rs:577](../../crates/crux-integrations/src/lib.rs#L577)) |
| `wasm_module_url` | string | `wasm` (xor path) | Must start `https://` ([lib.rs:584](../../crates/crux-integrations/src/lib.rs#L584)) |
| `wasm_module_sha256` | string | `wasm` | Exactly 64 lowercase hex chars ([lib.rs:564](../../crates/crux-integrations/src/lib.rs#L564)) |

### `tools[]` entry

`ExternalToolDefinition` ([lib.rs:154](../../crates/crux-integrations/src/lib.rs#L154)):

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | yes | Becomes the MCP tool name verbatim. Must be globally unique across the daemon's catalogue. The MCP layer only treats a name as an extension tool when it starts with `ext.` ([crux-mcp/src/tools/extensions.rs:180](../../crates/crux-mcp/src/tools/extensions.rs#L180)) |
| `description` | string | yes | Non-empty |
| `input_schema` | JSON | yes | Passed through to MCP `tools/list` unmodified. **The daemon never validates arguments against it** ([lib.rs:160](../../crates/crux-integrations/src/lib.rs#L160)) |
| `consequence_metadata` | JSON | no | Surfaced to MCP discovery; when absent the daemon substitutes its own derived metadata ([extensions.rs:69](../../crates/crux-mcp/src/tools/extensions.rs#L69)) |
| `auth_shared_secret_id` | string | no | Names an entry in the daemon's encrypted-secrets store, forwarded as `Authorization: Bearer`. **Forbidden for `wasm`** ([lib.rs:546](../../crates/crux-integrations/src/lib.rs#L546)). See §5.6 for its current wiring status |

## 2.3 Entry kinds and their runtime status

Nine variants exist ([lib.rs:186](../../crates/crux-integrations/src/lib.rs#L186)). Only three
have a daemon-side runtime. The rest are declared vocabulary: the daemon stores
them, the console lists them, and a client (an SDK, an editor, an installer
script) is expected to act on the recipe at `entry.path`.

| `entry.kind` | Runtime in this repo | What actually happens |
|---|---|---|
| `mcp_config` | none | Declarative. Two first-party packs use it to describe MCP client wiring |
| `http_recipe` | none | Declarative |
| `sdk_recipe` | none (carrier) | Declarative. Also the carrier kind for Studio packs — `POST /v1/studio/pack/build` stamps `sdk_recipe` ([studio_pack.rs:147](../../crates/corecruxd/src/http/studio_pack.rs#L147)) |
| `cli_recipe` | none | Declarative |
| `file_watcher` | **yes** | [crates/corecruxd/src/vault_watcher.rs](../../crates/corecruxd/src/vault_watcher.rs) — a granted pack of this kind plus a roots env var activates the markdown-vault watcher (chapter 7) |
| `webhook_adapter` | none | Declarative |
| `external_helper` | **blocked** | `validate()` rejects it unless `policy.allow_executable_helpers` is true (default false): `external helpers are disabled by policy`. `risk_level` is `blocked` ([lib.rs:498](../../crates/crux-integrations/src/lib.rs#L498), [lib.rs:1458](../../crates/crux-integrations/src/lib.rs#L1458)) |
| `external_tool` | **yes** | Daemon proxies `tools/call` to `external_tool_endpoint` (chapter 5) |
| `wasm` | **yes, feature-gated** | In-process wasmtime sandbox; requires building `corecruxd` with `--features wasm-extensions`, else the invoke route returns 501 (chapter 6) |

## 2.4 Derived fields the daemon computes for you

| Field | Values | Rule |
|---|---|---|
| `manifest_hash` | `blake3:<hex>` | BLAKE3 over the canonical signing payload — an 11-field subset, **not** the whole document ([lib.rs:650](../../crates/crux-integrations/src/lib.rs#L650)) |
| `trust_tier` | `first_party`, `locally_signed`, `community_reviewed`, `unknown` | Chapter 4 |
| `install_state` | `available`, `installed`, `enabled`, `blocked`, `update_available` | `enabled` means at least one grant exists and is enabled ([lib.rs:844](../../crates/crux-integrations/src/lib.rs#L844)) |
| `risk_level` | `low`, `medium`, `high`, `blocked` | `external_helper` → blocked; `content_preview` / `private_facts` / `admin:read` → high; any `*:write`, `integrations:grant`, `integrations:install` → medium; else low ([lib.rs:1457](../../crates/crux-integrations/src/lib.rs#L1457)) |

### The signing payload is a subset — read this before you sign

`manifest_hash()` hashes `ManifestSigningPayload`
([lib.rs:466](../../crates/crux-integrations/src/lib.rs#L466)): `schema`, `id`, `name`,
`version`, `publisher_passport_fpr`, `summary`, `entry`, `capabilities`,
`network`, `data_access`, `safety`.

Fields **outside** the signature: `external_tool_endpoint`, `tools[]`,
`wasm_module_path`, `wasm_module_url`, `wasm_module_sha256`, `hashes`,
`signature`.

Consequences you must design around:

- A signature does not bind the endpoint URL or the tool list of an
  `external_tool` pack. What binds them is the registry's
  `manifest_sha256` — a SHA-256 over the whole manifest file, published by the
  curator and enforced at install ([http/extensions.rs:310](../../crates/corecruxd/src/http/extensions.rs#L310)).
- A WASM module's bytes are bound by `wasm_module_sha256`, which is itself
  outside the signature — again, the registry `manifest_sha256` is the binding
  layer.
- Install by pasting a manifest into `POST /v1/extensions/register` therefore
  gives you signature integrity over the *policy surface* only. Install from a
  curated registry gives you integrity over the *whole document*.

## 2.5 When a signature is required

`validate()` requires a signature unless one of two policy flags lets it through
([lib.rs:622](../../crates/crux-integrations/src/lib.rs#L622)):

| Policy flag | Default | Effect |
|---|---|---|
| `allow_unsigned_first_party` | `true` | An unsigned manifest passes **iff** `publisher_passport_fpr == "cuecrux:first-party"`. This is what lets the compiled-in packs load ([lib.rs:443](../../crates/crux-integrations/src/lib.rs#L443)) |
| `allow_unsigned` | `false` | An unsigned manifest passes regardless of publisher. Dev only; the HTTP layer wires it to `CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED` ([lib.rs:449](../../crates/crux-integrations/src/lib.rs#L449)) |

The extension installer sets `allow_unsigned_first_party: false` explicitly, so
the first-party bypass never applies to the `/v1/extensions/*` family
([extension_registry.rs:142](../../crates/corecruxd/src/extension_registry.rs#L142)).

Missing signature with no bypass gives `signature is required`.

## 2.6 The four built-in packs

`builtin_manifests()` ([lib.rs:1132](../../crates/crux-integrations/src/lib.rs#L1132)) returns
four first-party manifests, asserted by
`builtin_manifests_validate` ([lib.rs:1520](../../crates/crux-integrations/src/lib.rs#L1520)):

| id | version | kind | capabilities |
|---|---|---|---|
| `mcp.claude-desktop` | 0.1.0 | `mcp_config` | `integrations:read`, `passport:read` |
| `mcp.cursor` | 0.1.0 | `mcp_config` | `integrations:read`, `passport:read` |
| `sdk.typescript.quickstart` | 0.1.0 | `sdk_recipe` | `integrations:read`, `facts:read`, `facts:write`, `sessions:read` |
| `vault.markdown-watcher` | 0.1.0 | `file_watcher` | `facts:write`, `facts:read` |

`vault.markdown-watcher` is the only one with a runtime. It is inert until both
its grant and its roots environment variable are present (chapter 7).

A `github.pr-facts` recipe used to ship here and was removed in favour of the
live GitHub connector ([lib.rs:1236](../../crates/crux-integrations/src/lib.rs#L1236)).

## 2.7 Pack registry on disk

Packs installed through the console pack API live as flat files under
`<data_dir>/integrations/` ([lib.rs:818](../../crates/crux-integrations/src/lib.rs#L818)):

```text
<data_dir>/integrations/
  index.json                                  # schema crux.integration.index.v1
  packs/<pack_id>/<version>/manifest.json     # verbatim manifest
  grants/<passport_fpr>/<pack_id>.json        # one grant per pack per passport
  audit.jsonl                                 # append-only event log
```

Every path component (`pack_id`, `version`, `passport_fpr`) is passed through
`safe_path_component`, which permits only `[A-Za-z0-9._-]` and rejects `.` and
`..`; a violation gives `invalid path component '<x>'`
([lib.rs:1363](../../crates/crux-integrations/src/lib.rs#L1363)). Writes are atomic —
serialise to `<name>.json.tmp`, then rename
([lib.rs:1352](../../crates/crux-integrations/src/lib.rs#L1352)).

`index.json` carries `schema`, `updated_at_unix_ms`, and a `packs[]` array of
`InstalledPackRecord` (`id`, `version`, `manifest_hash`, `trust_tier`,
`installed_at_unix_ms`) ([lib.rs:326](../../crates/crux-integrations/src/lib.rs#L326)). A
wrong `schema` value gives `invalid index schema '<x>'`
([lib.rs:1255](../../crates/crux-integrations/src/lib.rs#L1255)).

`audit.jsonl` is one `IntegrationAuditEvent` per line
([lib.rs:350](../../crates/crux-integrations/src/lib.rs#L350)). Appending is best-effort:
a broken audit path is warn-logged and never changes the outcome of the primary
operation ([lib.rs:1320](../../crates/crux-integrations/src/lib.rs#L1320)), which the
test `audit_append_failure_does_not_fail_install` pins
([extension_registry.rs:430](../../crates/corecruxd/src/extension_registry.rs#L430)).

Extensions installed through `/v1/extensions/*` do **not** live here — they are
facts. See chapter 3.

## 2.8 Installing and granting a pack

Three console routes back the pack model
([http/mod.rs:1422](../../crates/corecruxd/src/http/mod.rs#L1422)):

```bash
# List the library: builtins + installed, with grants and the audit tail.
curl -s http://127.0.0.1:14800/v1/console/integrations \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"

# Install a builtin by id (version defaults to "0.1.0").
curl -s -X POST http://127.0.0.1:14800/v1/console/integrations/vault.markdown-watcher/install \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"version":"0.1.0"}'

# Grant capabilities to the daemon's own passport.
curl -s -X POST http://127.0.0.1:14800/v1/console/integrations/vault.markdown-watcher/grant \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"version":"0.1.0","capabilities":["facts:read","facts:write"],"reason":"vault ingest"}'

# Revoke.
curl -s -X POST http://127.0.0.1:14800/v1/console/integrations/vault.markdown-watcher/disable \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H 'Content-Type: application/json' -d '{"reason":"done testing"}'
```

Scopes: `integrations:install`, `integrations:grant`, `integrations:disable`
respectively ([console.rs:2216](../../crates/corecruxd/src/http/console.rs#L2216),
[console.rs:2251](../../crates/corecruxd/src/http/console.rs#L2251),
[console.rs:2289](../../crates/corecruxd/src/http/console.rs#L2289)).

Install accepts either a `manifest` object (whose `id` must equal the path id) or
a bare `version` naming a builtin
([console.rs:3231](../../crates/corecruxd/src/http/console.rs#L3231)). Trust tier is
assigned by `manifest_trust_tier`: first-party publisher → `first_party`,
otherwise signed → `locally_signed`, otherwise `unknown`
([console.rs:3255](../../crates/corecruxd/src/http/console.rs#L3255)).

Grant rules ([lib.rs:963](../../crates/crux-integrations/src/lib.rs#L963)):

- The pack must be installed on disk, else `pack '<id>' version '<v>' is not installed`.
- Each requested capability must be in the global allowlist **and** declared by
  the manifest, else `capability '<c>' is not declared by pack '<id>'`.
- Capabilities are sorted and deduped before storage.
- `disable` flips `enabled` to false and stamps `disabled_at_unix_ms`; it does
  not delete the file ([lib.rs:1011](../../crates/crux-integrations/src/lib.rs#L1011)).

### Three operator switches

| Env var | Default | Effect |
|---|---|---|
| `CORECRUXD_INTEGRATIONS_ENABLED` | on (unset = on) | Off → install and grant return 403 `integrations are disabled` ([config.rs:1377](../../crates/corecruxd/src/config.rs#L1377)) |
| `CORECRUXD_INTEGRATIONS_SAFE_MODE` | off | On → install returns 403 `integration safe mode blocks install`, grant returns 403 `integration safe mode blocks grants`, and every non-first-party `enabled` pack is reported as `blocked` ([config.rs:1380](../../crates/corecruxd/src/config.rs#L1380), [console.rs:3211](../../crates/corecruxd/src/http/console.rs#L3211)) |
| `CORECRUXD_INTEGRATIONS_ALLOW_EXECUTABLE_HELPERS` | off | On → `external_helper` manifests validate instead of being rejected ([config.rs:1383](../../crates/corecruxd/src/config.rs#L1383)) |

Accepted truthy values for all three are exactly `1`, `true`, `TRUE`, `yes`,
`YES`.

## Ground truth

- [crates/crux-integrations/src/lib.rs:30](../../crates/crux-integrations/src/lib.rs#L30) — schema constants, first-party fingerprint
- [crates/crux-integrations/src/lib.rs:98](../../crates/crux-integrations/src/lib.rs#L98) — `IntegrationManifest`
- [crates/crux-integrations/src/lib.rs:154](../../crates/crux-integrations/src/lib.rs#L154) — `ExternalToolDefinition`
- [crates/crux-integrations/src/lib.rs:186](../../crates/crux-integrations/src/lib.rs#L186) — `EntryKind`
- [crates/crux-integrations/src/lib.rs:438](../../crates/crux-integrations/src/lib.rs#L438) — `ValidationPolicy`
- [crates/crux-integrations/src/lib.rs:466](../../crates/crux-integrations/src/lib.rs#L466) — `ManifestSigningPayload`
- [crates/crux-integrations/src/lib.rs:481](../../crates/crux-integrations/src/lib.rs#L481) — `validate`
- [crates/crux-integrations/src/lib.rs:802](../../crates/crux-integrations/src/lib.rs#L802) — `builtin_packs`
- [crates/crux-integrations/src/lib.rs:894](../../crates/crux-integrations/src/lib.rs#L894) — `install_pack`
- [crates/crux-integrations/src/lib.rs:963](../../crates/crux-integrations/src/lib.rs#L963) — `grant_pack`
- [crates/crux-integrations/src/lib.rs:1132](../../crates/crux-integrations/src/lib.rs#L1132) — `builtin_manifests`
- [crates/crux-integrations/src/lib.rs:1457](../../crates/crux-integrations/src/lib.rs#L1457) — `risk_level`
- [crates/corecruxd/src/http/console.rs:2210](../../crates/corecruxd/src/http/console.rs#L2210) — pack install/grant/disable handlers
- [crates/corecruxd/src/config.rs:1377](../../crates/corecruxd/src/config.rs#L1377) — integration env switches
- [crates/corecruxd/src/http/studio_pack.rs:147](../../crates/corecruxd/src/http/studio_pack.rs#L147) — Studio packs stamp `sdk_recipe`
