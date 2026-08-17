# 3. Capabilities and grants

Two grant models exist in this repo. They share vocabulary, they do **not** share
storage, code, or enforcement. Getting them confused is the single most common
way to build something that silently does nothing.

## 3.1 The 14 capabilities

`ALLOWED_CAPABILITIES` is a fixed array
([crates/crux-integrations/src/lib.rs:40](../../crates/crux-integrations/src/lib.rs#L40)).
Anything else in a manifest's `capabilities[]` fails validation with
`unknown capability '<c>'`.

| Capability | Meaning as declared | Risk contribution |
|---|---|---|
| `integrations:read` | Read the integrations library | low |
| `integrations:install` | Install packs | medium ([lib.rs:1470](../../crates/crux-integrations/src/lib.rs#L1470)) |
| `integrations:grant` | Issue grants | medium |
| `integrations:disable` | Revoke grants | low |
| `facts:read` | Read facts | low |
| `facts:write` | Write facts | medium (ends `:write`) |
| `facts:private:read` | Read private facts | **high** ([lib.rs:1461](../../crates/crux-integrations/src/lib.rs#L1461)) via `data_access.private_facts` |
| `sessions:read` | Read sessions | low |
| `sessions:write` | Write sessions | medium |
| `passport:read` | Read passport identity | low |
| `tenant:metadata:read` | Read tenant metadata | low |
| `tenant:chunks:read` | Read tenant chunk-level data | low |
| `tenant:content:preview` | Preview stored content | **high** via `data_access.content_preview` |
| `admin:read` | Administrative reads | **high** ([lib.rs:1463](../../crates/crux-integrations/src/lib.rs#L1463)) |

Six of these are classed **dangerous** by the community publishing rail and
require a maintainer-signed `review.json` alongside the manifest:
`admin:read`, `facts:private:read`, `integrations:grant`, `integrations:install`,
`sessions:write`, `tenant:content:preview`
([tests/community_packs.rs:13](../../crates/crux-integrations/tests/community_packs.rs#L13),
[integrations/README.md:22](../../integrations/README.md)).

Read the list back from a live daemon rather than hard-coding it:

```bash
curl -s http://127.0.0.1:14800/v1/console/integrations \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" | jq .allowed_capabilities
```

The field is emitted by the console integrations handler
([console.rs:2201](../../crates/corecruxd/src/http/console.rs#L2201)).

### Capabilities are not HTTP scopes

The 14 strings above are a *manifest vocabulary*. They constrain what an operator
may grant a pack. They are **not** checked by `require_http_scopes`, and holding
`facts:write` as a manifest capability grants you nothing at the HTTP layer.
Several strings appear in both namespaces (`facts:write`, `admin:read`,
`integrations:install`); that is a naming coincidence with two enforcement
points, not one shared check.

## 3.2 Model A — pack grants (flat files)

Used by: declarative packs and the `file_watcher` runtime.
Storage: `<data_dir>/integrations/grants/<passport_fpr>/<pack_id>.json`.
Type: `IntegrationGrant` ([lib.rs:335](../../crates/crux-integrations/src/lib.rs#L335)).

```json
{
  "passport_fpr": "p_agent",
  "pack_id": "vault.markdown-watcher",
  "version": "0.1.0",
  "capabilities": ["facts:read", "facts:write"],
  "enabled": true,
  "granted_by_passport_fpr": "p_operator",
  "granted_at_unix_ms": 1753440000000,
  "disabled_at_unix_ms": null,
  "reason": "vault ingest"
}
```

Rules enforced by `grant_pack` ([lib.rs:963](../../crates/crux-integrations/src/lib.rs#L963)):

- The pack must be installed on disk, else
  `pack '<id>' version '<v>' is not installed`.
- Every capability must be in the global allowlist, else
  `unknown capability '<c>'`.
- Every capability must also be declared by the manifest, else
  `capability '<c>' is not declared by pack '<id>'`.
- A capability containing `/` or `\` is rejected
  ([lib.rs:1383](../../crates/crux-integrations/src/lib.rs#L1383)).
- The list is sorted and deduped before writing.

Revocation (`disable_pack`, [lib.rs:1011](../../crates/crux-integrations/src/lib.rs#L1011))
sets `enabled: false` and stamps `disabled_at_unix_ms`. The file stays, so the
history is legible.

### What consumes a pack grant

Exactly one runtime does today: `enabled_packs_of_kind`
([lib.rs:1070](../../crates/crux-integrations/src/lib.rs#L1070)). It scans grants across
**all** passports, because a background daemon job has no calling passport — the
operator's intent is expressed by *any* enabled grant on the node. Its
robustness rules matter if you build on it:

- Missing integrations root, missing grants directory, or zero grants all return
  an empty vector, never an error.
- A grant file that fails to parse is skipped, not fatal — one corrupt file
  cannot wedge an unrelated runtime.
- A first-party builtin granted without an on-disk manifest copy still counts;
  the compiled-in manifest is used.
- Results are deduped by `(pack_id, version)` across passports
  ([lib.rs:1109](../../crates/crux-integrations/src/lib.rs#L1109)).

The declarative kinds (`mcp_config`, `http_recipe`, `sdk_recipe`, `cli_recipe`,
`webhook_adapter`) have no consumer inside the daemon. Their grants are an
operator record and a signal to client-side tooling.

## 3.3 Model B — extension grants (facts)

Used by: `external_tool` and `wasm` extensions, and the MCP tool catalogue.
Storage: fact `__extension_grant__::<extension_id>::<passport_fpr>` key `record`.
Type: `ExtensionGrant` ([extension_grants.rs:62](../../crates/corecruxd/src/extension_grants.rs#L62)).

```json
{
  "extension_id": "ext.example.quote",
  "passport_fpr": "p_alice",
  "allowed_tool_names": ["ext.example.quote.daily"],
  "allowed_prefixes_read": ["personal::quotes::"],
  "allowed_prefixes_write": ["personal::quotes::"],
  "rate_limit_per_min": 30,
  "granted_at_unix_ms": 1753440000000,
  "granted_by_passport": "agent-claude"
}
```

| Field | Semantics |
|---|---|
| `allowed_tool_names` | Subset of the manifest's tools. **Empty means every tool the manifest declares** ([extension_grants.rs:65](../../crates/corecruxd/src/extension_grants.rs#L65)) |
| `allowed_prefixes_read` | Fact-entity prefixes the extension may read (WASM host ABI only) |
| `allowed_prefixes_write` | Fact-entity prefixes whose writes the daemon will persist. Empty means **no** write is accepted — the filter is `any(prefix)` over an empty list ([extension_outbound.rs:314](../../crates/corecruxd/src/extension_outbound.rs#L314)) |
| `rate_limit_per_min` | Per-(extension, passport) cap. `null` falls back to the daemon default of 10/min ([extension_outbound.rs:50](../../crates/corecruxd/src/extension_outbound.rs#L50)) |

Note the asymmetry: an empty `allowed_tool_names` is permissive, an empty
`allowed_prefixes_write` is restrictive. This is intentional — tools are already
bounded by the signed manifest; fact prefixes are not.

### Privacy-gated prefixes can never be granted

`is_prefix_grantable` ([extension_grants.rs:92](../../crates/corecruxd/src/extension_grants.rs#L92))
rejects any read or write prefix starting with one of the daemon's reserved,
born-private prefixes. Attempting it fails at issue time with
`invalid prefix '<p>': community extensions cannot grant access to a privacy-gated prefix`.

The reserved list (verbatim, [extension_grants.rs:95](../../crates/corecruxd/src/extension_grants.rs#L95)):

```text
__ax__::            __ax_session::       __constraints__::    __project_layer__::
__plane__::         __plane_layer__::    __workspace__::      __workspace_scan__::
__repo_registry__:: __repo_scan__::      __repo_codegraph_ids__::  __repo_extdeps__::
__storybook__::     __dossier__::        __project_repo_link__::   __extension__::
__extension_grant__:: __work__::         __work_transition__::     __passport__::
__mint_request__::  __bootstrap__::      __project__::        decisions::
github::
```

Even if a grant somehow named one, the privacy gate runs again at storage time
on every accepted write
([http/extensions.rs:827](../../crates/corecruxd/src/http/extensions.rs#L827),
[wasm_dispatcher.rs:198](../../crates/corecruxd/src/wasm_dispatcher.rs#L198)).

### Why facts and not capability tokens

The design note is in the module header
([extension_grants.rs:14](../../crates/corecruxd/src/extension_grants.rs#L14)): tokens travel
between agents, so a grant inside a bearer token would let any agent re-mint it
with a different scope. Grants are operator-managed central state; issuance and
revocation must be an operator authority, not a bearer property.

## 3.4 Managing extension grants over HTTP

```bash
# List grants for one extension.
curl -s http://127.0.0.1:14800/v1/extensions/ext.example.quote/grants \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"

# Issue a grant.
curl -s -X POST http://127.0.0.1:14800/v1/extensions/ext.example.quote/grants \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H "X-Corecrux-Passport-Id: p_operator" \
  -H 'Content-Type: application/json' \
  -d '{
        "passport_fpr": "p_alice",
        "allowed_tool_names": ["ext.example.quote.daily"],
        "allowed_prefixes_read": ["personal::quotes::"],
        "allowed_prefixes_write": ["personal::quotes::"],
        "rate_limit_per_min": 30
      }'

# Revoke.
curl -s -X DELETE http://127.0.0.1:14800/v1/extensions/ext.example.quote/grants/p_alice \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"
```

| Route | Method | Scopes | Handler |
|---|---|---|---|
| `/v1/extensions/{id}/grants` | GET | `admin:read` | [extensions.rs:587](../../crates/corecruxd/src/http/extensions.rs#L587) |
| `/v1/extensions/{id}/grants` | POST | `admin:read` + `facts:write` | [extensions.rs:610](../../crates/corecruxd/src/http/extensions.rs#L610) |
| `/v1/extensions/{id}/grants/{passport_fpr}` | DELETE | `admin:read` + `facts:write` | [extensions.rs:837](../../crates/corecruxd/src/http/extensions.rs#L837) |

Behaviours worth knowing:

- Issuing a grant for an extension that is not installed returns **404**
  `extension '<id>' not installed` — the HTTP layer checks before delegating,
  to give a more specific status than the domain error would
  ([extensions.rs:624](../../crates/corecruxd/src/http/extensions.rs#L624)).
- A duplicate grant returns **409** `grant already exists; revoke first to replace`
  ([extensions.rs:649](../../crates/corecruxd/src/http/extensions.rs#L649)). There is no
  update-in-place; revoke, then re-issue.
- The acting passport comes from `X-Corecrux-Passport-Id` and is recorded as
  `granted_by_passport` and in the audit event
  ([extensions.rs:619](../../crates/corecruxd/src/http/extensions.rs#L619)).

## 3.5 Operator posture — what an operator should actually check

Before granting anything, an operator has four honest signals:

| Signal | Where it comes from |
|---|---|
| `trust_tier` | Resolved against the local keyring at install (chapter 4) |
| `risk_level` | Derived from capabilities and `data_access` ([lib.rs:1457](../../crates/crux-integrations/src/lib.rs#L1457)) |
| Declared `capabilities[]` | The manifest, covered by the signature |
| `network.allowed_hosts` | The manifest, covered by the signature, enforced at dispatch |

And two switches to fall back on:

- `CORECRUXD_INTEGRATIONS_SAFE_MODE=1` blocks pack install and grant, and reports
  every non-first-party enabled pack as `blocked`
  ([console.rs:3211](../../crates/corecruxd/src/http/console.rs#L3211)).
- `CORECRUXD_INTEGRATIONS_ENABLED=0` turns the pack plane off entirely
  ([config.rs:1377](../../crates/corecruxd/src/config.rs#L1377)).

Neither switch affects the `/v1/extensions/*` family. Extensions are gated by
signature, keyring, and grant.

## 3.6 Audit

Both models append to the same `<data_dir>/integrations/audit.jsonl`. Action
constants ([lib.rs:401](../../crates/crux-integrations/src/lib.rs#L401)):

| Action | Emitted by |
|---|---|
| `install` / `grant` / `disable` | Pack model ([lib.rs:939](../../crates/crux-integrations/src/lib.rs#L939), [lib.rs:994](../../crates/crux-integrations/src/lib.rs#L994), [lib.rs:1034](../../crates/crux-integrations/src/lib.rs#L1034)) |
| `extension_install` / `extension_uninstall` | [extension_registry.rs:179](../../crates/corecruxd/src/extension_registry.rs#L179) |
| `extension_grant_added` / `extension_grant_removed` | [extension_grants.rs:207](../../crates/corecruxd/src/extension_grants.rs#L207) |
| `trusted_key_added` / `trusted_key_removed` | [http/extensions.rs:552](../../crates/corecruxd/src/http/extensions.rs#L552) |
| `extension_invoke_ok` / `extension_invoke_rejected` | [extension_outbound.rs:553](../../crates/corecruxd/src/extension_outbound.rs#L553) |
| `audit_suppressed` | Rate-limit marker, see chapter 5 |

The last 50 events are returned inline by `GET /v1/console/integrations` as
`audit_tail` ([lib.rs:890](../../crates/crux-integrations/src/lib.rs#L890)).

## Ground truth

- [crates/crux-integrations/src/lib.rs:40](../../crates/crux-integrations/src/lib.rs#L40) — `ALLOWED_CAPABILITIES`
- [crates/crux-integrations/src/lib.rs:335](../../crates/crux-integrations/src/lib.rs#L335) — `IntegrationGrant`
- [crates/crux-integrations/src/lib.rs:963](../../crates/crux-integrations/src/lib.rs#L963) — `grant_pack`
- [crates/crux-integrations/src/lib.rs:1070](../../crates/crux-integrations/src/lib.rs#L1070) — `enabled_packs_of_kind`
- [crates/crux-integrations/src/lib.rs:1457](../../crates/crux-integrations/src/lib.rs#L1457) — `risk_level`
- [crates/corecruxd/src/extension_grants.rs:62](../../crates/corecruxd/src/extension_grants.rs#L62) — `ExtensionGrant`
- [crates/corecruxd/src/extension_grants.rs:92](../../crates/corecruxd/src/extension_grants.rs#L92) — `is_prefix_grantable`
- [crates/corecruxd/src/extension_grants.rs:155](../../crates/corecruxd/src/extension_grants.rs#L155) — `issue_grant`
- [crates/corecruxd/src/http/extensions.rs:587](../../crates/corecruxd/src/http/extensions.rs#L587) — grant routes
- [crates/crux-integrations/tests/community_packs.rs:13](../../crates/crux-integrations/tests/community_packs.rs#L13) — dangerous-capability list
