# Console Workspaces — the fact-driven nav/page config (M16b)

> How an agent (via MCP `store_fact` / `PUT /v1/facts`) or the console Studio
> produces the SAME workspace/page configuration. The console reads these facts
> at boot and renders identically regardless of who wrote them — "one artifact,
> two editors". Enforcing code: `crates/corecruxd/console/v2/render.js` (`cws*`
> helpers) + `shell.html` (nav runtime). Proving test: `smoke.cjs` Check 52.

Operator-named **Workspaces**: a signed **pack** installs a **workspace** (of
**pages**) built in the **Studio**. Configurable Workspaces generalise the old
binary Command | Explorer surface toggle into N workspaces, where the two
built-ins stay auto-generated from the page registry and user workspaces are
config facts that overlay them.

## Entities

Two fact entities, each with key `def`, value = **canonical key-sorted JSON**
(see Canonicalization). Tenant = `default` (the console tenant).

| Entity | Purpose |
|---|---|
| `console:workspace:<uid>` | A workspace: an ordered set of destinations (nav groups), each holding page uids. |
| `console:page:<uid>` | A page instance: a typed page (any registry page id) with title/sub/dest/config. |

`<uid>` is a stable slug. User workspace uids are conventionally `ws-<slug>`;
user page uids `ws-<slug>-<page-slug>`. The uids `command` and `explore` are
**reserved** for the two built-ins (writing a `console:workspace:command` fact
*forks* that built-in — see Take control).

## Schemas (schema_version 1)

### Workspace `def`

```json
{
  "schema_version": 1,
  "uid": "ws-ops",
  "name": "My ops board",
  "icon": "meters",
  "order": 100,
  "source": "user",
  "dests": [
    { "id": "ops", "label": "Ops", "icon": "meters", "pages": ["ws-ops-execplans", "ws-ops-facts"] }
  ]
}
```

- `source`: `"user"` | `"builtin-fork"` (a forked built-in also carries
  `"forked_from": "command"|"explore"`).
- `dests[].pages`: an ordered list of page uids. A page uid may reference a
  `console:page:<uid>` fact OR, in a forked built-in, a bare registry page id
  used directly as a type (e.g. `"cx-facts"`).
- `order`: switcher/rail ordering (ascending).

### Page `def`

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

- `type`: **any page type that exists in the console** — every registry page id
  (`cx-overview`, `cx-work`, `cx-facts`, `cx-cost`, …) plus the
  destination-IS-the-page surfaces (`canvas/board`, `canvas/graph`,
  `canvas/tree`, `explorer`, `sitemap`, `rings`). The page renders through the
  SAME builder as the built-in console, so "whatever exists now is generatable".
- `config.query`: for endpoint-driven types with declared options (currently
  `cx-work` → `source`, `cx-memory` → `top_k`, `cx-review` → `limit`), these
  merge into the load endpoint's query string. Other types ignore config and
  render their registry default. Unknown config keys are preserved (tolerant
  reader) but not interpreted.

### Tolerant reader (CONTRACT)

- Unknown keys — top-level and nested — **survive untouched** through a Studio
  round-trip (the reader spreads/merges; it never rebuilds field-by-field). Add
  fields freely; older consoles preserve them.
- A `schema_version` **newer** than the console understands is returned
  verbatim and rendered as an honest "newer configuration" panel — never
  destroyed or reinterpreted. The daemon (not the SPA) owns migrations.

## Canonicalization (byte-stable — one artifact, two editors)

The value string is JSON with **keys sorted deeply**, arrays order-preserved, no
whitespace. The Studio writes exactly this; an MCP writer must produce the same
to get byte-identical storage. Because the reader parses JSON (order-independent)
and renders from the parsed def, ANY valid JSON with the right fields renders
identically — canonicalization only matters for byte-equality / diffs.

Reference (render.js): `cwsCanonical(v)` — recursively sorts object keys, then
`JSON.stringify`. Equivalent to: sort every object's keys ascending, emit
compact JSON.

## Take control (reversible fork) + revert

- Built-in workspaces/pages render from the registry until an operator **forks**
  one in the Studio: the fork copies the generated def into an overlay fact with
  `source: "builtin-fork"`, `forked_from: <builtin-uid>`. A provenance chip
  ("forked from built-in · revert") shows in the Studio.
- **Revert** = write a **tombstone** def through the same gated fact-add path:
  `{ "schema_version": 1, "uid": "<uid>", "reverted": true }`. The reader treats
  a reverted overlay as absent → auto-generation resumes for a built-in, or the
  user workspace/page drops out. (There is no gated fact-DELETE client method;
  the tombstone is a soft-delete matching the daemon's own model, and re-forking
  overwrites it.)

## Writing a workspace via MCP / HTTP (parity proof)

The daemon fact surface is the MCP-equivalent write. Either `PUT /v1/facts` (or
MCP `store_fact`) or the console route `POST /v1/console/facts/add` works. Value
must be the canonical JSON **string**.

```bash
# 1. the workspace
curl -sX POST http://<host>:14800/v1/console/facts/add -H 'content-type: application/json' -d '{
  "entity":"console:workspace:ws-mcp",
  "key":"def",
  "value":"{\"dests\":[{\"icon\":\"work\",\"id\":\"main\",\"label\":\"Main\",\"pages\":[\"ws-mcp-facts\"]}],\"icon\":\"work\",\"name\":\"MCP demo\",\"order\":100,\"schema_version\":1,\"source\":\"user\",\"uid\":\"ws-mcp\"}"
}'
# 2. a page of an existing type (renders the real facts store)
curl -sX POST http://<host>:14800/v1/console/facts/add -H 'content-type: application/json' -d '{
  "entity":"console:page:ws-mcp-facts",
  "key":"def",
  "value":"{\"config\":{},\"dest\":\"main\",\"schema_version\":1,\"source\":\"user\",\"sub\":\"the durable record\",\"title\":\"Facts\",\"type\":\"cx-facts\",\"uid\":\"ws-mcp-facts\"}"
}'
```

Refresh the console → the workspace appears in the switcher and rail, and
`#/w/ws-mcp/ws-mcp-facts` renders the real facts browser. (On an authenticated
daemon these are admin-write routes; the console uses its operator-gated
`consoleFactsAdd` path.)

## Packs (additive)

A Studio pack (`crux.studio.v1`, wrapped in a signed `crux.integration.v1`
manifest via `/v1/studio/pack/{build,verify}`) may carry two **optional** arrays
alongside `board`/`designs`/`settings`:

```json
{ "schema": "crux.studio.v1", "board": {…}, "workspaces": [ <workspace def> … ], "pages": [ <page def> … ] }
```

Older importers ignore the extra arrays (the daemon hashes the whole studio
value as an opaque object, so integrity holds). Import applies workspaces/pages
as a defaults layer with provenance (the pack uid); operator edits overlay them.
Export from Studio › Pages includes the selected workspace + its page facts.

## Grepable symbols (render.js)

`cwsCanonical` · `cwsReadWorkspaceDef` · `cwsReadPageDef` · `cwsBuiltinWorkspaces`
· `cwsEffectiveWorkspaces` · `cwsForkWorkspace` · `cwsTombstone` ·
`cwsStarterTemplates` · `cwsPageTypes` · `cwsPackEmbed` / `cwsPackExtract` ·
`cwsLoadOverlays` / `cwsBuildModel` · `renderWorkspacePage` ·
`renderWorkspaceStudio` · `renderIntegrationsStudio`. Nav runtime in `shell.html`:
`loadWorkspaceModel` · `activateWorkspace` · `renderWorkspace` ·
`buildWorkspaceRail` · `window.CRUX_WS_MODEL` / `window.CRUX_WS_RELOAD`.
