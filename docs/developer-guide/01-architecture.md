# 1. Architecture — what you are building against

## 1.1 One process, three listeners

`corecruxd` is a single Rust binary. It opens three sockets, all configured in
`load_config` ([crates/corecruxd/src/config.rs:793](../../crates/corecruxd/src/config.rs#L793)):

| Plane | Default | Host env | Port env | Notes |
|---|---|---|---|---|
| HTTP (axum) | `127.0.0.1:14800` | `CORECRUXD_HTTP_HOST` | `CORECRUXD_HTTP_PORT` | The surface this guide uses ([config.rs:801](../../crates/corecruxd/src/config.rs#L801)) |
| MCP (HTTP transport) | `127.0.0.1:14801` | `CORECRUXD_MCP_HOST` | `CORECRUXD_MCP_PORT` | Toggled by `CORECRUXD_MCP_ENABLED`, default true ([config.rs:817](../../crates/corecruxd/src/config.rs#L817)) |
| gRPC (tonic) | `127.0.0.1:4007` | `CORECRUXD_GRPC_HOST` | `CORECRUXD_GRPC_PORT` | ([config.rs:812](../../crates/corecruxd/src/config.rs#L812)) |

Do not change the HTTP port default. It is a fixed contract for every client in
the ecosystem.

## 1.2 The data directory

Resolution order ([config.rs:834](../../crates/corecruxd/src/config.rs#L834)):

1. `CORECRUXD_DATA_DIR` (tilde-expanded)
2. file config `daemon.data_dir`
3. file config `daemon.state_dir`
4. default `../CoreCruxData/v1`

Everything this guide touches lives under that root:

```text
<data_dir>/
  integrations/
    index.json                              # installed pack index
    packs/<pack_id>/<version>/manifest.json
    grants/<passport_fpr>/<pack_id>.json
    audit.jsonl                             # pack + extension audit trail
    github/credentials.json                 # sealed PAT envelope
    github/selected_repos.json
    openai/credentials.json                 # sealed API-key envelope
  extensions/
    trusted-keys.json                       # operator Ed25519 keyring (both rails)
    registry/index.json                     # cached curator-signed extension index
    <extension_id>/extension.wasm           # cached WASM module bytes
  studio/
    library/index.json                      # cached curator-signed Studio library index
```

Sources: [crux-integrations/src/lib.rs:818](../../crates/crux-integrations/src/lib.rs#L818),
[extension_registry.rs:76](../../crates/corecruxd/src/extension_registry.rs#L76),
[http/extensions.rs:35](../../crates/corecruxd/src/http/extensions.rs#L35),
[wasm_dispatcher.rs:61](../../crates/corecruxd/src/wasm_dispatcher.rs#L61),
[integrations_github.rs:177](../../crates/corecruxd/src/integrations_github.rs#L177),
[integrations_openai.rs:187](../../crates/corecruxd/src/integrations_openai.rs#L187),
[studio_library.rs:68](../../crates/corecruxd/src/http/studio_library.rs#L68).

Two things are deliberately **not** files:

- **Installed extension records** are facts under `__extension__::<id>` key
  `record` ([extension_registry.rs:29](../../crates/corecruxd/src/extension_registry.rs#L29)).
- **Extension grants** are facts under
  `__extension_grant__::<extension_id>::<passport_fpr>` key `record`
  ([extension_grants.rs:37](../../crates/corecruxd/src/extension_grants.rs#L37)).

Both prefixes are on the daemon's born-private list, so those records are never
push-eligible to a remote.

## 1.3 The fact store is the extension database

There is no separate extensions table. An extension install is a fact write, an
extension grant is a fact write, and a scheduler job's health is a fact write.
That has three practical consequences for you:

1. Anything you can read with `GET /v1/facts` you can use to inspect extension
   state — no new endpoint needed. Scheduler status is deliberately surfaced
   this way ([sync_scheduler.rs:24](../../crates/corecruxd/src/sync_scheduler.rs#L24)).
2. Deletion is a tombstone, not a row removal: an uninstall writes an
   empty-valued fact with confidence 0
   ([extension_registry.rs:231](../../crates/corecruxd/src/extension_registry.rs#L231)).
3. Reads take the latest fact per `(entity, key)` — `dedup_latest`
   ([extension_registry.rs:208](../../crates/corecruxd/src/extension_registry.rs#L208)).

## 1.4 Authentication and scopes

`CORECRUXD_AUTH_MODE` has **no default**. The daemon refuses to start without it:
`CORECRUXD_AUTH_MODE must be set explicitly; see config.example.env`
([main.rs:307](../../crates/corecruxd/src/main.rs#L307)).

| Mode | Meaning |
|---|---|
| `off` | `require_http_scopes` returns `Ok(())` immediately — every scope check passes ([auth.rs:1321](../../crates/corecruxd/src/auth.rs#L1321)) |
| `dev_scopes` | Scopes come from the `X-Corecrux-Scopes` header, or from the bearer token parsed *as a scope list* ([auth.rs:385](../../crates/corecruxd/src/auth.rs#L385)) |
| `jwt_hs256` | HS256 JWT; secret in `CORECRUXD_JWT_HS256_SECRET`, issuer/audience via `CORECRUXD_JWT_ISS` / `CORECRUXD_JWT_AUD` ([auth.rs:35](../../crates/corecruxd/src/auth.rs#L35)) |
| `jwt_jwks` | JWKS/OIDC; `CORECRUXD_JWT_JWKS_URL`, `CORECRUXD_JWT_OIDC_DISCOVERY_URL`, and friends ([auth.rs:44](../../crates/corecruxd/src/auth.rs#L44)) |

Mode strings are parsed leniently — `dev`, `dev-scopes`, `jwt`, `jwks`, `oidc`
and several casings all resolve ([auth.rs:58](../../crates/corecruxd/src/auth.rs#L58)).

`require_http_scopes(auth, headers, required)` requires **all** of `required`
([auth.rs:1320](../../crates/corecruxd/src/auth.rs#L1320)). Failure is a 403 whose body
carries `"code": "MISSING_SCOPE"` and `"missingScopes": [...]`
([auth.rs:1331](../../crates/corecruxd/src/auth.rs#L1331)). A request with no scopes at all
in dev mode gets a 401 with
`"hint": "set X-Corecrux-Scopes or Authorization: Bearer <scopes>"`
([auth.rs:857](../../crates/corecruxd/src/auth.rs#L857)).

### Headers the daemon reads

| Header | Purpose |
|---|---|
| `Authorization: Bearer <token>` | Token or, in `dev_scopes`, a literal scope list ([auth.rs:373](../../crates/corecruxd/src/auth.rs#L373)) |
| `X-Corecrux-Scopes` | Scope list, comma- or whitespace-separated ([auth.rs:363](../../crates/corecruxd/src/auth.rs#L363)) |
| `X-Corecrux-Passport-Id` | Acting passport. Trusted verbatim under `off`/`dev_scopes`; under JWT modes it must match the token's `passport_id` claim or you get 403 `PASSPORT_HEADER_MISMATCH` ([auth.rs:1186](../../crates/corecruxd/src/auth.rs#L1186)) |
| `X-Corecrux-Tenant-Id` | Tenant selector ([auth.rs:1151](../../crates/corecruxd/src/auth.rs#L1151)) |

### Scopes you will meet in this guide

There is **no canonical scope enum in the codebase** — scopes are string
literals at each call site. The set the daemon actually uses:

`admin:read`, `admin:write`, `events:read`, `events:write`, `exports:read`,
`facts:read`, `facts:write`, `integrations:disable`, `integrations:grant`,
`integrations:install`, `integrations:read`, `passport:impersonate`,
`passport:read`, `provenance:write`, `query:read`, `receipts:read`,
`replication:write`, `sessions:read`, `sessions:write`, `tenant:chunks:read`,
`tenant:content:preview`, `tenant:metadata:read`, `tool:invoke:read`.

The 14-item **capability** allowlist in a manifest is a different, smaller
namespace that overlaps these strings. Do not conflate them — see chapter 3.

### The route-auth middleware

Independent of the per-handler `require_http_scopes` calls, a middleware
classifies routes by method and matched route template.
`CORECRUXD_ROUTE_AUTH` selects `off`, `shadow`, or `enforce`
([route_auth.rs:692](../../crates/corecruxd/src/http/route_auth.rs#L692)).
When unset it derives `enforce` for authenticated or non-loopback operation and
`shadow` only for auth-off loopback development; malformed explicit values fail
safe to `enforce`.

| Prefix | Class | Any-of scopes |
|---|---|---|
| `/v1/studio/library/` POST | **write** | `facts:write`, `admin:write` ([route_auth.rs:169](../../crates/corecruxd/src/http/route_auth.rs#L169)) |
| `/v1/studio/` (everything else) | read | `query:read`, `admin:read` ([route_auth.rs:181](../../crates/corecruxd/src/http/route_auth.rs#L181)) |
| `/v1/extensions` GET | read | `admin:read`, `facts:read`, `query:read`, `sessions:read` ([route_auth.rs:492](../../crates/corecruxd/src/http/route_auth.rs#L492)) |
| `/v1/extensions` non-GET | write | `admin:write`, `facts:write`, `integrations:install` |
| `/v1/integrations/` | write | `integrations:install`, `integrations:disable` ([route_auth.rs:356](../../crates/corecruxd/src/http/route_auth.rs#L356)) |

In `shadow` the middleware logs; in `enforce` it rejects. Shipped packaging
sets `enforce` explicitly. The handler's own
`require_http_scopes` always applies.

The Studio carve-out is worth noting as a pattern: the install route is the one
`/v1/studio/` route that mutates, so it is classified ahead of the read-class
prefix rule to guarantee a read token can never authorise an install
([route_auth.rs:169](../../crates/corecruxd/src/http/route_auth.rs#L169)). If you add a
mutating route under a read-class prefix, do the same.

## 1.5 Errors are RFC 7807

Every failure path in the routes this guide covers goes through
`problem_response` ([http/mod.rs:1788](../../crates/corecruxd/src/http/mod.rs#L1788)),
which serialises `ProblemDetails`
([corecrux-types/src/lib.rs:783](../../crates/corecrux-types/src/lib.rs#L783)) with
`Content-Type: application/problem+json`
([problem.rs:27](../../crates/corecruxd/src/problem.rs#L27)).

```json
{
  "type": "https://errors.cuecrux.com/forbidden",
  "title": "Forbidden",
  "status": 403,
  "detail": "insufficient scopes",
  "code": "MISSING_SCOPE",
  "missingScopes": ["facts:write"]
}
```

`type`, `title`, `status` are always present. `detail` and `instance` are
omitted when absent. Extension members (`code`, `missingScopes`) are **flattened
to the top level**, not nested
([corecrux-types/src/lib.rs:798](../../crates/corecrux-types/src/lib.rs#L798)).

Read `detail` — the daemon puts genuinely actionable text there, including which
environment variable to flip
([http/extensions.rs:210](../../crates/corecruxd/src/http/extensions.rs#L210)) and which CLI
command to run ([http/extensions.rs:240](../../crates/corecruxd/src/http/extensions.rs#L240)).

## 1.6 Four ways to extend the daemon

| Mechanism | Runs where | Trust anchor | Chapter |
|---|---|---|---|
| Integration pack (declarative) | Nowhere — a client reads the recipe | Manifest signature + operator grant | 2 |
| External tool | Your own HTTPS service | Manifest signature + registry sha + per-passport grant | 5 |
| WASM extension | In-process wasmtime sandbox | Module SHA-256 pin + grant + fuel/memory/epoch limits | 6 |
| File-watcher pack | In-process daemon runtime | Operator grant **and** an environment variable | 7 |

Three design rules run through all four, and they are worth internalising before
you write anything:

1. **Install is not enable.** Every path requires a second, explicit operator
   action naming exactly what the code may do.
2. **Artefacts are content-addressed and pinned.** Nothing is fetched "latest";
   the daemon verifies a hash the operator's trust chain endorsed before bytes
   are persisted.
3. **Capability surface is declared, then enforced.** The manifest says what it
   wants; the grant says what it gets; the dispatcher enforces the intersection.

## 1.7 Reading the daemon's own route manifest

`crates/corecruxd/src/http/openapi.rs` holds a `ROUTES` table, and
`route_manifest_matches_router`
([tests/route_spec_drift.rs:757](../../crates/corecruxd/tests/route_spec_drift.rs#L757))
asserts it is set-equal to the routes actually mounted on the router. If you
need the authoritative list of endpoints, that table is it — it cannot drift
without failing CI.

## Ground truth

- [crates/corecruxd/src/config.rs:793](../../crates/corecruxd/src/config.rs#L793) — `load_config`, ports, data dir
- [crates/corecruxd/src/auth.rs:24](../../crates/corecruxd/src/auth.rs#L24) — `AuthMode`
- [crates/corecruxd/src/auth.rs:1320](../../crates/corecruxd/src/auth.rs#L1320) — `require_http_scopes`
- [crates/corecruxd/src/main.rs:307](../../crates/corecruxd/src/main.rs#L307) — auth-mode-required abort
- [crates/corecruxd/src/http/route_auth.rs:181](../../crates/corecruxd/src/http/route_auth.rs#L181) — studio route class
- [crates/corecruxd/src/http/route_auth.rs:492](../../crates/corecruxd/src/http/route_auth.rs#L492) — extensions route class
- [crates/corecruxd/src/http/mod.rs:1788](../../crates/corecruxd/src/http/mod.rs#L1788) — `problem_response`
- [crates/corecrux-types/src/lib.rs:783](../../crates/corecrux-types/src/lib.rs#L783) — `ProblemDetails`
- [crates/corecruxd/src/extension_registry.rs:29](../../crates/corecruxd/src/extension_registry.rs#L29) — extension fact prefix
- [crates/corecruxd/src/extension_grants.rs:37](../../crates/corecruxd/src/extension_grants.rs#L37) — grant fact prefix
- [crates/corecruxd/tests/route_spec_drift.rs:757](../../crates/corecruxd/tests/route_spec_drift.rs#L757) — route manifest parity test
