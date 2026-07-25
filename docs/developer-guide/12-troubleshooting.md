# 12. Troubleshooting

Every message below is quoted from the code that emits it. Search this page for
the string you actually saw.

The general daemon error catalogue is
[docs/error-catalogue.md](../error-catalogue.md); this page covers the extension
and integration surface.

## 12.1 Nothing happens — no error at all

The most common failure mode, because most of the surface fails silent by
design.

| Symptom | Cause | Fix |
|---|---|---|
| A tool is absent from MCP `tools/list` | No grant for the calling passport, or the tool is not in `allowed_tool_names` | Issue or widen the grant (§3.4) |
| A tool is absent even with a grant | The caller has no passport-bound context — `list_extension_tools` returns empty ([extensions.rs:40](../../crates/crux-mcp/src/tools/extensions.rs#L40)) | Bind a passport, or send an RCX token |
| A tool is absent, grant and passport both fine | The RCX capability token lacks `crux-extension.<tool_name>` ([tools/mod.rs:2499](../../crates/crux-mcp/src/tools/mod.rs#L2499)) | Mint a token carrying that capability |
| `tools/call` says unknown tool although `tools/list` shows it | The name does not start with `ext.`, so dispatch never routes to it ([extensions.rs:179](../../crates/crux-mcp/src/tools/extensions.rs#L179)) | Rename the tool; there is no other fix |
| Vault watcher never runs | Half the double gate is missing | Check the boot log for `vault-watcher inactive` (§7.2) |
| A `file_watcher` pack is installed but nothing runs | Installed is not granted — `enabled_packs_of_kind` only sees enabled grants | POST the grant route |
| No `__sync__::<job>` fact exists | The job returned `Skipped` — no fact is written ([sync_scheduler.rs:176](../../crates/corecruxd/src/sync_scheduler.rs#L176)) | Expected when unconfigured |
| A first status fact does not appear | The first run is one full interval after boot, never at boot ([sync_scheduler.rs:258](../../crates/corecruxd/src/sync_scheduler.rs#L258)) | Wait one interval |
| Fact writes silently vanish | Entity outside `allowed_prefixes_write` | Read `dropped_fact_writes` and `drop_reasons` in the response |

## 12.2 Validation rejections (400)

From `IntegrationError` ([lib.rs:58](../../crates/crux-integrations/src/lib.rs#L58)):

| Message | Meaning |
|---|---|
| `invalid integration schema '<x>'` | `schema` is not `crux.integration.v1` |
| `field '<f>' is required` | Empty after trim. Fields: `id`, `name`, `version`, `publisher_passport_fpr`, `entry.path`, `external_tool_endpoint`, `tools`, `tools[].name`, `tools[].description`, `wasm_module_sha256`, `wasm_module_path or wasm_module_url` |
| `invalid identifier '<id>'` | `id` contains a character outside `[A-Za-z0-9._-]` |
| `unknown capability '<c>'` | Not in the 14-item allowlist (§3.1) |
| `external helpers are disabled by policy` | `entry.kind: external_helper` without `CORECRUXD_INTEGRATIONS_ALLOW_EXECUTABLE_HELPERS` |
| `manifest hash mismatch: expected <a>, actual <b>` | `hashes.manifest` does not match the recomputed value. Usually: edited after signing |
| `signature is required` | Unsigned, and no bypass applies |
| `unsupported signature algorithm '<alg>'` | Only `ed25519` |
| `no trusted public key for passport '<fpr>'` | The signing fingerprint is not in `trusted-keys.json` |
| `invalid signature material: signature public_key_hex does not match trusted keyring entry` | The manifest's inline key differs from the keyring's |
| `invalid signature material: signature must be 64 bytes` | Bad base64 length in `sig` |
| `signature verification failed` | The signature does not verify. Usually: payload edited after signing |
| `pack '<id>' version '<v>' is not installed` | Granting before installing |
| `grant for pack '<id>' and passport '<fpr>' was not found` | Disabling a grant that does not exist |
| `capability '<c>' is not declared by pack '<id>'` | Granting more than the manifest asks for |
| `invalid path component '<x>'` | A pack id, version or fingerprint containing something outside `[A-Za-z0-9._-]` |
| `invalid index schema '<x>'` | `<data_dir>/integrations/index.json` has the wrong schema tag |

Kind-specific ones:

| Message | Fix |
|---|---|
| `external_tool_endpoint must be an http(s) URL, got '<u>'` | Use a full URL with a scheme |
| `wasm_module_* fields only valid when entry.kind=wasm` | Remove them from a non-wasm manifest |
| `external_tool_endpoint, tools[], or wasm_module_* fields are only valid when entry.kind in {external_tool, wasm}, got <Kind>` | Same, for the other kinds |
| `external_tool_endpoint must be unset for entry.kind=wasm` | Remove it |
| `wasm tools must not set tools[].auth_shared_secret_id; use crux::get_secret_decrypted in-module instead` | Remove it — and note the host function is a stub (§6.5) |
| `wasm_module_sha256 must be 64 lowercase hex chars, got N chars` | Lowercase, no `0x` |
| `wasm_module_path must be relative to <data_dir>/extensions/{id}/, got '<p>'` | No leading `/`, no `..` |
| `wasm_module_url must be an https:// URL, got '<u>'` | HTTPS only |
| `wasm_module_path and wasm_module_url are mutually exclusive` | Pick one |

Plus the extension-registry id rule:
`manifest id '<id>' contains invalid characters; expected lowercase alphanumerics + . - _`
([extension_registry.rs:45](../../crates/corecruxd/src/extension_registry.rs#L45)). Note
this is **stricter** than the manifest rule — an id valid in a pack can be
rejected as an extension.

## 12.3 Install failures by status

| Status | Message | Cause |
|---|---|---|
| 400 | `<validation error> (set CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED=true to bypass signature requirement in dev)` | Validation failed and the bypass is off. The hint is appended only when the bypass is off ([http/extensions.rs:209](../../crates/corecruxd/src/http/extensions.rs#L209)) |
| 409 | `extension id already installed` | Uninstall first — there is no upgrade in place |
| 409 | `manifest_sha256 mismatch for '<id>': registry=<a>, downloaded=<b>` | The hosted manifest changed since the curator signed the index. Do not proceed |
| 409 | `registry entry mismatch: expected <a>@<b>, manifest is <c>@<d>` | The manifest's id or version disagrees with the index row |
| 409 | `downloaded module sha256 mismatch: manifest=<a>, downloaded=<b>` | The hosted WASM module changed |
| 413 | `manifest exceeds the 2097152-byte cap` | 2 MiB limit |
| 413 | `wasm module exceeds the 16777216-byte cap` | 16 MiB limit |
| 502 | `manifest fetch failed: <err>` / `manifest URL returned status <n>` | Upstream unreachable or non-2xx |
| 502 | `manifest JSON decode failed: <err>` | Served bytes are not a manifest |
| 502 | `module URL returned status <n>` | WASM module URL non-2xx |

## 12.4 Registry problems

**404 on `GET /v1/extensions/registry`**

```text
registry index read failed: <io error> (run `corecruxctl extensions sync` to
populate the cached registry index)
```

There is no cached index. This is the expected state on a fresh daemon
([http/extensions.rs:237](../../crates/corecruxd/src/http/extensions.rs#L237)).

**403 on any registry route**

```text
registry index signature verification failed: <library error>
```

The cached index cannot be verified against the current keyring
([http/extensions.rs:395](../../crates/corecruxd/src/http/extensions.rs#L395)). Usual
causes: the curator key was removed or replaced; the index was rotated and needs
a re-sync; the file was edited by hand. Re-run `corecruxctl extensions sync`.

**400 `registry index JSON decode failed: <err>`** — the cached file is corrupt.
Delete it and re-sync.

**400 `trusted keyring read failed: <err>`** — `trusted-keys.json` is malformed,
or a `public_key_hex` is not 32 bytes. The error names the offending fingerprint
([signing.rs:98](../../crates/crux-integrations/src/signing.rs#L98)).

**CLI: `public_key_hex must be 64 lowercase hex chars`** — the fingerprint flag
and the key flag are different things. `--pubkey-fpr` is the identifier,
`--pubkey-hex` is 64 hex characters.

**CLI sync failed and `list-registry` shows the old data** — correct. A failed
verification never overwrites the cache
([extensions.rs:282](../../crates/corecruxctl/src/extensions.rs#L282)).

## 12.4a Studio library problems

**404 on `GET /v1/studio/library` or on an install**

```text
Studio library index read failed: <io error> (run `corecruxctl studio sync` to
populate the cached Studio library index)
```

No cached index — the expected state on a fresh daemon
([studio_library.rs:128](../../crates/corecruxd/src/http/studio_library.rs#L128),
[studio_library.rs:308](../../crates/corecruxd/src/http/studio_library.rs#L308)). Note this
is a *different* cache from the extensions registry: syncing one does not
populate the other.

**404 `template '<id>' not found in the Studio library index`** — the id is not a
row in the cached index. Re-run `corecruxctl studio list-library` and copy the
`id` field exactly; it is not the display `name`
([studio_library.rs:318](../../crates/corecruxd/src/http/studio_library.rs#L318)).

**403 `Studio library index signature verification failed: <library error>`**

The cached index does not verify against the current keyring
([studio_library.rs:762](../../crates/corecruxd/src/http/studio_library.rs#L762)). Same
causes as the extensions equivalent — curator key removed or rotated, index
re-signed upstream, file edited by hand. Re-run `corecruxctl studio sync`.

Because shape validation runs *inside* `verify()`, this 403 also fires on a
validly-signed index carrying a malformed row. The library error text names the
entry — for example
`entry 'studio.ops': pack_url must be https://, or loopback http:// for local mirrors (got 'ftp://…')`
or `entry 'studio.ops': version '1.0' must be semver MAJOR.MINOR.PATCH`
([studio_index.rs:295](../../crates/crux-integrations/src/studio_index.rs#L295)). The fix
belongs to the curator, not the operator.

**403 refusing to install (require-signed)**

```text
refusing to install '<id>': pack is unsigned. Add the publisher's key to the
trusted keyring (POST /v1/extensions/keys), or set
CORECRUXD_STUDIO_ALLOW_UNSIGNED=1 to bypass the require-signed policy in dev.
```

Or, when a signature was present but did not validate,
`signature did not validate: <verbatim library error>` in place of
`pack is unsigned` ([studio_library.rs:364](../../crates/corecruxd/src/http/studio_library.rs#L364)).
Look the inner error up in §12.2. Do not reach for the bypass on a shared
daemon — it is process-wide.

**409 conflicts**

| Message | Cause |
|---|---|
| `pack_sha256 mismatch for '<id>': index=<a>, downloaded=<b>` | The hosted pack changed since the curator signed the index. Do not proceed — ask the curator to re-sign ([studio_library.rs:330](../../crates/corecruxd/src/http/studio_library.rs#L330)) |
| `pack for '<id>' failed verification: <errors joined with "; ">` | The pack fails the same checks `/v1/studio/pack/verify` runs — schema, `hashes.manifest`, `hashes.bundle`, studio schema. See §12.8 ([studio_library.rs:353](../../crates/corecruxd/src/http/studio_library.rs#L353)) |
| `library entry mismatch: expected <a>@<b>, pack manifest is <c>@<d>` | The pack's own manifest disagrees with the catalogue row, even though the hash matched ([studio_library.rs:384](../../crates/corecruxd/src/http/studio_library.rs#L384)) |
| `no free board id for '<base>' after 64 attempts` (also design / page / workspace) | 64 colliding artefacts already exist. Delete some, or install under a different library id ([studio_library.rs:594](../../crates/corecruxd/src/http/studio_library.rs#L594)) |

**400 `pack for '<id>' carries no installable artifacts (no board tiles, designs, workspaces, or pages)`**

The pack parsed and verified but has nothing to write — commonly a board doc
with empty `nodes`, `links` and `texts`, which is skipped rather than written as
an empty board ([studio_library.rs:408](../../crates/corecruxd/src/http/studio_library.rs#L408),
[studio_library.rs:559](../../crates/corecruxd/src/http/studio_library.rs#L559)).

**400 `pack_url must be https://, or loopback http:// for local mirrors`** — the
row points somewhere the daemon will not fetch from
([studio_library.rs:772](../../crates/corecruxd/src/http/studio_library.rs#L772)).

**502 / 413 on the pack fetch** — `pack fetch failed: <err>`,
`pack URL returned status <n>`, `pack JSON decode failed: <err>`, or the 2 MiB
cap. Same shape as the extensions manifest fetch.

**403 on a per-write category check** — the calling passport may not write that
console entity. The install stops at the first refusal
([studio_library.rs:424](../../crates/corecruxd/src/http/studio_library.rs#L424)); artefacts
already written in this call remain.

### The install "succeeded" but my board is not where I expected

Read `remaps` in the response. An install **never overwrites**: a colliding id
is remapped to `-2`, `-3`, and so on, and the pre-existing artefact is left
alone (§8.8). The response's `written[].entity` values are authoritative.

### Which library entries are installed?

`GET /v1/studio/library` computes the join from the `installed_from` provenance
stamp on each console fact. If a def lost that key, the entry will report
`installed: false` even though its artefacts exist
([studio_library.rs:188](../../crates/corecruxd/src/http/studio_library.rs#L188)). The
console's tolerant readers preserve unknown keys, so this only happens if
something rewrote the def without spreading it.

## 12.5 Invoke failures

| Status | Message | Cause |
|---|---|---|
| 400 | `passport_fpr required (body field or X-Corecrux-Passport-Id header)` | No calling passport |
| 400 | `extension '<id>' has unsupported entry.kind <Kind> for tool dispatch` | Only `external_tool` and `wasm` dispatch |
| 403 | `passport '<fpr>' has no grant for extension '<id>'` | Issue a grant |
| 403 | `tool '<t>' is not in the grant's allowed_tool_names` | Widen the grant, or clear the list to mean "all" |
| 403 | `scope violation` | The dispatcher's own grant re-check failed. Deliberately terse |
| 429 | `rate limited (cap N/min)` | Sliding 60-second window per (extension, passport) |
| 502 | `plain http endpoint blocked (set CORECRUXD_EXTENSIONS_ALLOW_PLAIN_HTTP=true for dev)` | Non-HTTPS endpoint |
| 502 | `endpoint '<authority>' is not allowed by extension '<id>' network.allowed_hosts` | Host or port outside the allowlist. Remember: literal matching, no wildcards |
| 502 | `invalid external tool endpoint '<u>'` | The URL does not parse or has no host |
| 502 | `tool '<t>' not declared by extension '<id>'` | Not in the manifest's `tools[]` |
| 502 | `request payload too large: N bytes (max M)` | Shrink `args` |
| 502 | `response payload too large: N bytes (max M)` | Your response exceeded the effective cap. Check `safety.max_output_bytes` — it tightens, and may be lower than the daemon default |
| 502 | `upstream returned <status>: <body truncated to 512 chars>` | Your endpoint returned non-2xx |
| 502 | `upstream returned malformed response: <serde error>` | Your body is not `{result, fact_writes?}` |
| 502 | `transport: <err>` | Connection, TLS or timeout failure |

WASM-specific:

| Status | Message | Cause |
|---|---|---|
| 404 | `wasm module file missing at '<path>'` | The cached module was removed. Reinstall |
| 409 | `module sha256 mismatch: manifest=<a>, on-disk=<b>` | The cached bytes were altered. Reinstall |
| 408 | `EXT_WASM_FUEL_EXHAUSTED` | Raise `CORECRUXD_WASM_FUEL_DEFAULT`, or make the module cheaper |
| 408 | `EXT_WASM_DEADLINE_EXCEEDED` | Raise `CORECRUXD_WASM_WALL_MS_DEFAULT` |
| 507 | `EXT_WASM_OOM` | Raise `CORECRUXD_WASM_MEMORY_BYTES_DEFAULT` |
| 501 | `wasm extensions require building corecruxd with --features wasm-extensions` | Rebuild the daemon |
| 503 | `wasm engine init failed at startup; restart the daemon and check logs` | Engine construction failed at boot |
| 502 | `missing export: extension_call` / `missing export: memory` | The module does not satisfy the contract (§6.4) |
| 502 | `response buffer overflow` | Your module returned `-1`; the response exceeded `resp_cap` (≤64 KiB) |
| 502 | `response is not valid utf-8` / `response is not valid JSON: <err>` | Bad response bytes |
| 502 | `module returned reserved code <n>` | A negative return other than `-1` |

Inside the module, negative host-function returns are ABI codes, not traps: `-2`
means no grant is bound, `-3` means the entity or query prefix is outside your
grant, `-4` means your buffer was too small, `-6` means the function is a stub
(§6.5).

## 12.6 Pack (console) route failures

| Status | Message | Cause |
|---|---|---|
| 403 | `integrations are disabled` | `CORECRUXD_INTEGRATIONS_ENABLED=0` |
| 403 | `integration safe mode blocks install` | `CORECRUXD_INTEGRATIONS_SAFE_MODE=1` |
| 403 | `integration safe mode blocks grants` | Same switch |
| 400 | `capabilities must not be empty` | The grant body needs at least one capability |
| 400 | `manifest id must match path pack id` | Body manifest id versus URL path id |
| 400 | `body pack_id must match path pack id` | Same for the optional `pack_id` field |
| 404 | `integration pack not found` | No builtin with that id and version. Version defaults to `0.1.0` |

Safe mode also rewrites the reported state: every non-first-party pack that is
`enabled` is displayed as `blocked`
([console.rs:3211](../../crates/corecruxd/src/http/console.rs#L3211)). The pack still has
its grant; the display is telling you the operator posture, not the stored state.

## 12.7 Grant failures

| Status | Message | Cause |
|---|---|---|
| 404 | `extension '<id>' not installed` | Install first |
| 409 | `grant already exists; revoke first to replace` | No update in place |
| 400 | `invalid prefix '<p>': community extensions cannot grant access to a privacy-gated prefix` | Reserved prefix (§3.3) |
| 400 | `invalid extension_id '<id>'` | Not lowercase, or over 128 characters |
| 400 | `invalid passport_fpr '<f>': cannot be empty` | Missing `passport_fpr` |
| 404 | `grant for '<id>' + '<fpr>' not found` | Revoking a grant that does not exist |

## 12.8 Studio pack failures

| Status | Message | Cause |
|---|---|---|
| 400 | `studio.schema must be 'crux.studio.v1', got '<x>'` | Wrong payload schema |
| 400 | `id, version, and publisher_passport_fpr are required` | Blank required field |
| 400 | `CORECRUXD_STUDIO_SIGNING_KEY_HEX: not valid hex: <err>` | Malformed signing key |
| 400 | `CORECRUXD_STUDIO_SIGNING_KEY_HEX: must be 64 hex chars (32-byte Ed25519 seed)` | Wrong length |
| 400 | `pack must be a JSON object` | Verify body shape |
| 200 | `ok: false`, `errors: ["hashes.bundle mismatch: declared <a>, actual <b>"]` | The studio payload changed after build, or a client reserialised it non-canonically |
| 200 | `ok: false`, `errors: ["hashes.bundle is missing (studio payload is not integrity-bound)"]` | The pack was hand-assembled |
| 200 | `signature.verdict: "invalid"` with a verbatim `error` | The library message is the diagnosis; look it up in §12.2 |

Verify returns 200 with a verdict for almost everything — check `ok`, not the
status code.

## 12.9 Auth failures

| Status | Body | Cause |
|---|---|---|
| 401 | `"detail": "missing auth scopes"`, `"hint": "set X-Corecrux-Scopes or Authorization: Bearer <scopes>"` | Dev mode, no scopes supplied |
| 403 | `"detail": "insufficient scopes"`, `"missingScopes": [...]` | The named scopes are missing |
| 403 | `"code": "PASSPORT_HEADER_MISMATCH"` | `X-Corecrux-Passport-Id` disagrees with the JWT's `passport_id` |
| 403 | `"code": "PASSPORT_HEADER_UNBOUND"` | The header was sent under a JWT mode with no passport claim |

Daemon refuses to start with
`CORECRUXD_AUTH_MODE must be set explicitly; see config.example.env`, or on a
typo `unknown CORECRUXD_AUTH_MODE '<bad>'; valid values: off, dev_scopes, jwt_hs256, jwt_jwks`
([main.rs:307](../../crates/corecruxd/src/main.rs#L307)).

## 12.10 Diagnostic recipes

```bash
# Is the unsigned dev bypass on?
curl -s http://127.0.0.1:14800/v1/extensions \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" | jq .allow_unsigned_dev

# What does the daemon think is installed, and at what tier?
curl -s http://127.0.0.1:14800/v1/extensions \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  | jq '.extensions[] | {id: .manifest.id, version: .manifest.version, trust_tier, manifest_hash}'

# Which keys will verify a signature? (both rails share this keyring)
curl -s http://127.0.0.1:14800/v1/extensions/keys \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" | jq .

# Is the Studio library index cached and verifiable, and what is installed?
curl -s http://127.0.0.1:14800/v1/studio/library \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  | jq '{curator: .curator_passport_fpr, tier_enforcement,
         entries: [.entries[] | {id, version, installed, installed_entities}]}'

# Scheduler health for every job.
curl -s "http://127.0.0.1:14800/v1/facts/list?entity_prefix=__sync__::" \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"

# The audit trail, newest last.
tail -n 50 "$CORECRUXD_DATA_DIR/integrations/audit.jsonl" | jq -c '{ts_unix_ms, action, actor, pack_id, outcome}'

# Recompute a manifest hash and compare with the declared one.
jq -S . manifest.json | head -1   # sanity: the file parses
```

A gap in the audit tail under heavy invoke traffic is expected — the family is
capped at 60 events per extension per minute, with one `audit_suppressed` marker
carrying the count (§5.6).

## 12.11 When the fix is a restart

| Change | Restart needed |
|---|---|
| `CORECRUXD_EXTENSIONS_*` outbound knobs | No — read per call |
| `CORECRUXD_WASM_*` limits | No — read per call |
| `CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED` | No — read per request |
| `CORECRUXD_STUDIO_ALLOW_UNSIGNED` | No — read per request |
| `CORECRUXD_STUDIO_SIGNING_KEY_HEX` | No — read per build call |
| `CORECRUXD_VAULT_WATCH_*` | **Yes** — activation runs once at startup |
| `CORECRUXD_INTEGRATIONS_*` | **Yes** — read into config at startup |
| `CORECRUXD_AUTH_MODE`, ports, data dir | **Yes** |
| Granting a `file_watcher` pack | **Yes** — the double gate is evaluated at boot |
| Adding a trusted key | No — the keyring is loaded per operation |
| Installing or granting an extension | No |

## Ground truth

- [crates/crux-integrations/src/lib.rs:58](../../crates/crux-integrations/src/lib.rs#L58) — `IntegrationError` messages
- [crates/corecruxd/src/extension_registry.rs:35](../../crates/corecruxd/src/extension_registry.rs#L35) — `ExtensionsError`
- [crates/corecruxd/src/extension_grants.rs:40](../../crates/corecruxd/src/extension_grants.rs#L40) — `GrantError`
- [crates/corecruxd/src/extension_outbound.rs:53](../../crates/corecruxd/src/extension_outbound.rs#L53) — `OutboundError`
- [crates/corecruxd/src/wasm_host.rs:111](../../crates/corecruxd/src/wasm_host.rs#L111) — `WasmError`
- [crates/corecruxd/src/wasm_dispatcher.rs:38](../../crates/corecruxd/src/wasm_dispatcher.rs#L38) — `WasmDispatchError`
- [crates/corecruxctl/src/extensions.rs:38](../../crates/corecruxctl/src/extensions.rs#L38) — `ExtensionsCliError`
- [crates/corecruxctl/src/studio.rs:42](../../crates/corecruxctl/src/studio.rs#L42) — `StudioCliError`
- [crates/corecruxd/src/http/studio_library.rs:287](../../crates/corecruxd/src/http/studio_library.rs#L287) — library install status mapping
- [crates/crux-integrations/src/studio_index.rs:295](../../crates/crux-integrations/src/studio_index.rs#L295) — per-entry shape errors
- [crates/corecruxd/src/http/extensions.rs:199](../../crates/corecruxd/src/http/extensions.rs#L199) — install status mapping
- [crates/corecruxd/src/http/console.rs:3265](../../crates/corecruxd/src/http/console.rs#L3265) — pack error status mapping
- [crates/corecruxd/src/auth.rs:857](../../crates/corecruxd/src/auth.rs#L857) — 401 body
