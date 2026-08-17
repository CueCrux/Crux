# Crux Daemon developer guide

How to build on the Crux Daemon: extend it with packs, tools and sandboxed
modules; connect it to external systems; ship what you build to other operators.

Every claim on these pages carries a `file:line` reference into this repository.
Where a surface is declared but has no runtime, or is stubbed pending later
work, it says so. Nothing here is aspirational.

## Who this is for

| You are | Start at |
|---|---|
| An agent or SDK author calling the daemon | Quickstart A, then [chapter 1](01-architecture.md) and [chapter 10](10-mcp-surface.md) |
| Shipping a dashboard or board other people install | Quickstart B, then [chapter 8](08-studio-packs-and-workspaces.md) and [chapter 9](09-registry-and-publishing.md) |
| Adding a tool the daemon can call | Quickstart C, then [chapter 5](05-external-tools.md) |
| Wanting in-process, sandboxed code | [chapter 6](06-wasm-extensions.md) |
| Connecting a data source on a schedule | [chapter 7](07-connectors-and-sync.md) |
| An operator deciding what to allow | [chapter 3](03-capabilities-and-grants.md), [chapter 4](04-signing-and-trust.md), [chapter 11](11-security-model.md) |
| Debugging | [chapter 12](12-troubleshooting.md) |

## Reading map

| # | Chapter | Covers |
|---|---|---|
| 1 | [Architecture](01-architecture.md) | Planes, ports, data-dir layout, auth modes, scopes, error shape |
| 2 | [Integration packs](02-integration-packs.md) | The `crux.integration.v1` manifest, every field, all nine entry kinds |
| 3 | [Capabilities and grants](03-capabilities-and-grants.md) | The 14 capabilities, the two grant models, operator posture |
| 4 | [Signing and trust](04-signing-and-trust.md) | Ed25519, the keyring, trust tiers, the community index, dev bypasses |
| 5 | [External tools](05-external-tools.md) | HTTPS extensions: wire contract and the full enforcement pipeline |
| 6 | [WASM extensions](06-wasm-extensions.md) | The sandbox, the host ABI, hash pinning, resource limits |
| 7 | [Connectors and sync](07-connectors-and-sync.md) | The scheduler, status facts, the vault watcher, GitHub and OpenAI |
| 8 | [Studio packs and workspaces](08-studio-packs-and-workspaces.md) | `crux.studio.v1`, canonical JSON, build/verify, fact schemas, the `crux.studio.index.v1` template library |
| 9 | [Registry and publishing](09-registry-and-publishing.md) | Both rails end to end — author, sign, curate, sync, install — plus the CLI reference |
| 10 | [MCP surface](10-mcp-surface.md) | How extension tools reach an agent's tool list |
| 11 | [Security model](11-security-model.md) | Enforced versus advisory versus not-yet-wired |
| 12 | [Troubleshooting](12-troubleshooting.md) | Real error strings, and what each one means |

## Three principles the whole surface follows

1. **Install is not enable.** Every path needs a second, explicit operator
   action naming exactly what the code may do. A pack installed and never
   granted does nothing at all, silently and by design.
2. **Artefacts are pinned and content-addressed.** Nothing is fetched "latest".
   The daemon verifies a hash your trust chain endorsed before any byte is
   persisted, and re-verifies a WASM module on every dispatch.
3. **Capability surface is declared, then enforced.** The manifest declares what
   it wants, the grant decides what it gets, and the dispatcher enforces the
   intersection on every call.

## Before you start

```bash
export CRUX_AGENT_TOKEN="…"            # your token, or a scope list in dev mode
export CORECRUXD_HTTP_URL="http://127.0.0.1:14800"
curl -s http://127.0.0.1:14800/readyz  # public, no auth
```

`CORECRUXD_AUTH_MODE` has no default — the daemon will not start without it
([main.rs:307](../../crates/corecruxd/src/main.rs#L307)). For local development,
`dev_scopes` lets a bearer token *be* the scope list
([auth.rs:385](../../crates/corecruxd/src/auth.rs#L385)):

```bash
export CORECRUXD_AUTH_MODE=dev_scopes
export CRUX_AGENT_TOKEN="admin:read admin:write facts:read facts:write query:read"
```

---

## Quickstart A — call the daemon from your agent (10 minutes)

**Goal:** read and write memory, and see the MCP tool catalogue.

```bash
# 1. Write a fact.
curl -s -X PUT http://127.0.0.1:14800/v1/facts \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"entity":"demo::hello","key":"greeting","value":"world"}'

# 2. Read it back by entity.
curl -s "http://127.0.0.1:14800/v1/facts/entity/demo::hello" \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"

# 3. List a prefix.
curl -s "http://127.0.0.1:14800/v1/facts/list?entity_prefix=demo::&limit=20" \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN"
```

Routes: [http/mod.rs:685](../../crates/corecruxd/src/http/mod.rs#L685),
[:717](../../crates/corecruxd/src/http/mod.rs#L717),
[:719](../../crates/corecruxd/src/http/mod.rs#L719).

For MCP, point your client at the MCP listener — `127.0.0.1:14801`, path `/mcp`
([config.rs:817](../../crates/corecruxd/src/config.rs#L817),
[console.rs:2327](../../crates/corecruxd/src/http/console.rs#L2327)). Your
`tools/list` will show the built-in tools plus any extension tools your passport
has been granted (chapter 10).

**Next:** [chapter 1](01-architecture.md) for the auth model and error shape.

---

## Quickstart B — ship your first pack (10 minutes)

**Goal:** turn a Studio board into a portable, verifiable artefact.

```bash
# 1. Build a pack around a studio payload.
curl -s -X POST http://127.0.0.1:14800/v1/studio/pack/build \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "studio": {"schema":"crux.studio.v1","version":1,
                   "board":{"id":"my-board","doc":{"nodes":[],"links":[],"version":1}},
                   "designs":[],"settings":{"title":"My board"}},
        "id": "my-board",
        "name": "My Board",
        "version": "0.1.0",
        "publisher_passport_fpr": "p_6ca61039700c94bf57c2e158d282ef1e"
      }' > pack.json

# 2. Verify it — schema, both hashes, signature verdict.
jq '{pack: .pack}' pack.json > verify-body.json
curl -s -X POST http://127.0.0.1:14800/v1/studio/pack/verify \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H 'Content-Type: application/json' --data @verify-body.json | jq '{ok, signature, studio}'
```

Both routes need only `query:read` and neither writes anything
([studio_pack.rs:101](../../crates/corecruxd/src/http/studio_pack.rs#L101),
[studio_pack.rs:434](../../crates/corecruxd/src/http/studio_pack.rs#L434)).

Unsigned is the expected result on a bare daemon, and the response's
`sign_instructions` tells you the two ways forward: set
`CORECRUXD_STUDIO_SIGNING_KEY_HEX` locally, or publish via a PR to
`integrations/community/` — the canonical rail, which never needs a private key
on a daemon.

A complete worked example is in-tree at
[integrations/community/studio-board-example/0.1.0/](../../integrations/community/studio-board-example/0.1.0/manifest.json).

To go from one pack to a catalogue other operators install by id, publish it in
a curator-signed `crux.studio.index.v1` index and let them run
`corecruxctl studio sync` then `corecruxctl studio install <id>`. The daemon
pins your `pack_sha256`, requires the pack to be signed, and writes the board
without ever overwriting one of theirs
([chapter 8 §8.7](08-studio-packs-and-workspaces.md#87-the-central-template-library)).

**Next:** [chapter 8](08-studio-packs-and-workspaces.md), then
[chapter 9](09-registry-and-publishing.md).

---

## Quickstart C — wire an external tool (10 minutes)

**Goal:** have the daemon call your HTTPS service as an MCP tool.

```bash
# 1. Write the manifest.
cat > manifest.json <<'JSON'
{
  "schema": "crux.integration.v1",
  "id": "ext.demo.echo",
  "name": "Echo",
  "version": "0.1.0",
  "publisher_passport_fpr": "p_dev_local",
  "summary": "Echoes its arguments back.",
  "entry": { "kind": "external_tool", "path": "tools/echo.json" },
  "capabilities": ["facts:write"],
  "network": { "allowed_hosts": ["127.0.0.1:8099"] },
  "external_tool_endpoint": "http://127.0.0.1:8099/invoke",
  "tools": [
    { "name": "ext.demo.echo.say",
      "description": "Echo the args.",
      "input_schema": { "type": "object" } }
  ]
}
JSON

# 2. Install it. Dev only: unsigned + plain HTTP both need explicit flags
#    in the DAEMON's environment, not in this shell.
#      CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED=true
#      CORECRUXD_EXTENSIONS_ALLOW_PLAIN_HTTP=true
curl -s -X POST http://127.0.0.1:14800/v1/extensions/register \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H "X-Corecrux-Passport-Id: p_operator" \
  -H 'Content-Type: application/json' \
  -d "{\"manifest\": $(cat manifest.json)}"

# 3. Grant a passport. Nothing is callable until this exists.
curl -s -X POST http://127.0.0.1:14800/v1/extensions/ext.demo.echo/grants \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H "X-Corecrux-Passport-Id: p_operator" \
  -H 'Content-Type: application/json' \
  -d '{"passport_fpr":"p_alice",
       "allowed_tool_names":["ext.demo.echo.say"],
       "allowed_prefixes_write":["demo::echo::"],
       "rate_limit_per_min":30}'

# 4. Call it.
curl -s -X POST \
  http://127.0.0.1:14800/v1/extensions/ext.demo.echo/tools/ext.demo.echo.say/invoke \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H "X-Corecrux-Passport-Id: p_alice" \
  -H 'Content-Type: application/json' \
  -d '{"args":{"hello":"world"}}'
```

Your service receives
`{tool, args, calling_passport_id, request_id}` and must return
`{result, fact_writes?}`. Writes outside `allowed_prefixes_write` are dropped and
reported in `drop_reasons` — not an error, just a count.

Two things that trip people up on the first attempt: the tool name **must**
start with `ext.` or MCP dispatch will never route to it
([crux-mcp/src/tools/extensions.rs:179](../../crates/crux-mcp/src/tools/extensions.rs#L179)),
and both dev flags belong in the daemon's environment, not your shell.

**Next:** [chapter 5](05-external-tools.md) for the full pipeline, then
[chapter 4](04-signing-and-trust.md) to sign it properly.

---

## Related documents

- [getting started](../getting-started.md) — install paths and the first loop
- [developer portal](../developer-portal.md) — base URLs, OpenAPI, SDKs
- [API reference](../api-reference.md) — route notes
- [agent guide](../agent-guide.md) — budgets, sessions, handoffs
- [architecture](../architecture.md) — daemon planes and crate boundaries
- [threat model](../THREAT_MODEL.md) — trust boundaries and stated limitations
- [error catalogue](../error-catalogue.md) — daemon-wide error reference
- [console workspaces](../agent/console-workspaces.md) — workspace and page fact schemas
- [integrations/README.md](../../integrations/README.md) — community publishing rules

## Ground truth

- [crates/corecruxd/src/config.rs:793](../../crates/corecruxd/src/config.rs#L793) — ports, data dir
- [crates/corecruxd/src/auth.rs:385](../../crates/corecruxd/src/auth.rs#L385) — dev-scope extraction
- [crates/corecruxd/src/http/mod.rs:685](../../crates/corecruxd/src/http/mod.rs#L685) — facts routes
- [crates/corecruxd/src/http/mod.rs:667](../../crates/corecruxd/src/http/mod.rs#L667) — studio routes
- [crates/corecruxd/src/http/mod.rs:1061](../../crates/corecruxd/src/http/mod.rs#L1061) — extension routes
- [crates/corecruxd/src/http/studio_pack.rs:96](../../crates/corecruxd/src/http/studio_pack.rs#L96) — pack build
- [crates/corecruxd/src/http/studio_library.rs:116](../../crates/corecruxd/src/http/studio_library.rs#L116) — template library browse
- [crates/corecruxd/src/http/extensions.rs:121](../../crates/corecruxd/src/http/extensions.rs#L121) — extension register
