# 10. The MCP surface

An installed, granted extension appears in the daemon's MCP `tools/list` beside
the built-in tools. From an agent's point of view there is no difference — same
catalogue, same call shape.

## 10.1 How a tool reaches the catalogue

`list_extension_tools`
([crates/crux-mcp/src/tools/extensions.rs:39](../../crates/crux-mcp/src/tools/extensions.rs#L39)):

1. Resolve the calling passport. **No passport, no extension tools** — the
   function returns an empty vector
   ([extensions.rs:40](../../crates/crux-mcp/src/tools/extensions.rs#L40)). The passport
   comes from the RCX router token's `subject.passport_fpr`, falling back to the
   agent name ([extensions.rs:192](../../crates/crux-mcp/src/tools/extensions.rs#L192)).
2. Read every installed extension from the `__extension__::` prefix and every
   grant held by that passport from `__extension_grant__::`
   ([extensions.rs:200](../../crates/crux-mcp/src/tools/extensions.rs#L200),
   [extensions.rs:217](../../crates/crux-mcp/src/tools/extensions.rs#L217)).
3. For each grant, find its extension and emit its tools, skipping any not in
   `allowed_tool_names` (empty means all).
4. Sort by name.

So the catalogue is per-caller. Two agents on the same daemon see different tool
lists, determined entirely by their grants.

## 10.2 The double filter

Grant filtering is only the first pass. In
`list_tools_json_for_context_with_mode`
([crux-mcp/src/tools/mod.rs:2497](../../crates/crux-mcp/src/tools/mod.rs#L2497)), when an
RCX capability token is present, extension tools are mapped to capability names
and filtered again through the router:

```rust
let capabilities = extension_tools.iter().map(|t| rcx_mcp_tool_capability(&t.name)).collect();
let allowed = router.filter_mcp_tools(&capabilities, now_unix_seconds);
extension_tools.retain(|tool| allowed.contains(&tool.name));
```

A tool must pass **both** the operator's grant and the caller's capability token.
The capability name is `crux-extension.<tool_name>`
([extensions.rs:175](../../crates/crux-mcp/src/tools/extensions.rs#L175)) — for example
`crux-extension.ext.example.quote.daily`. This is pinned by
`rcx_capability_name_is_stable`
([extensions.rs:262](../../crates/crux-mcp/src/tools/extensions.rs#L262)) and exercised
end-to-end by `dynamic_extension_tools_are_grant_and_rcx_filtered`
([extensions.rs:272](../../crates/crux-mcp/src/tools/extensions.rs#L272)).

Merge order matters and is documented at the call site
([crux-mcp/src/tools/mod.rs:2510](../../crates/crux-mcp/src/tools/mod.rs#L2510)): base
tools are authz-filtered, extension tools are merged, and only then does the
dynamic tool-surface shaping run — so shaping can narrow the authorised set but
never widen it.

## 10.3 What a tool looks like to a client

The `input_schema` from your manifest is passed through with two annotations
added ([extensions.rs:57](../../crates/crux-mcp/src/tools/extensions.rs#L57)):

```json
{
  "name": "ext.example.quote.daily",
  "description": "[tier:local][extension:ext.example.quote][trust:CommunityReviewed] Return today's quote.",
  "inputSchema": {
    "type": "object",
    "properties": { "topic": { "type": "string" } },
    "x-crux-extension": {
      "extension_id": "ext.example.quote",
      "manifest_hash": "blake3:…",
      "trust_tier": "community_reviewed",
      "rcx_capability": "crux-extension.ext.example.quote.daily"
    },
    "x-crux-consequence-metadata": { }
  }
}
```

| Element | Purpose |
|---|---|
| Description prefix | `[tier:local][extension:<id>][trust:<Tier>]` — provenance is visible in the tool list itself |
| `x-crux-extension.manifest_hash` | Lets a client detect that the extension changed under it |
| `x-crux-extension.trust_tier` | Snake-case slug ([extensions.rs:183](../../crates/crux-mcp/src/tools/extensions.rs#L183)) |
| `x-crux-consequence-metadata` | Your `consequence_metadata` if you set one; otherwise the daemon's derived metadata for the tool name ([extensions.rs:69](../../crates/crux-mcp/src/tools/extensions.rs#L69)) |

Note the description prefix uses the Rust `Debug` form of the tier
(`CommunityReviewed`) while `x-crux-extension.trust_tier` uses the slug
(`community_reviewed`). Parse the structured field, not the prose.

Provide `consequence_metadata` in your manifest if the tool is irreversible,
material, or non-idempotent. It flows to MCP discovery so an agent can reason
about blast radius before calling
([crux-integrations/src/lib.rs:164](../../crates/crux-integrations/src/lib.rs#L164)).

## 10.4 Dispatch

`tools/call` routing is by name prefix: a tool name starting with `ext.` is an
extension tool ([extensions.rs:179](../../crates/crux-mcp/src/tools/extensions.rs#L179)),
matched in the dispatcher at
[crux-mcp/src/tools/mod.rs:3020](../../crates/crux-mcp/src/tools/mod.rs#L3020).

**Name your tools `ext.<something>`.** A manifest tool called `quote.daily`
validates fine and appears in `tools/list`, but `tools/call` will never route to
it. There is no validation catching this — it is a naming convention with
behavioural teeth.

`call_extension_tool` ([extensions.rs:89](../../crates/crux-mcp/src/tools/extensions.rs#L89))
does not dispatch in-process. It looks up which extension declares the tool, then
POSTs over the daemon's own loopback URL to
`/v1/extensions/{id}/tools/{name}/invoke`, with a 30-second timeout, sending both
`X-Corecrux-Scopes: admin:read facts:write` (for `dev_scopes` mode) and a bearer
token when one is available (for JWT modes)
([extensions.rs:136](../../crates/crux-mcp/src/tools/extensions.rs#L136)).

So the MCP path is a thin client over the HTTP path in chapters 5 and 6. Every
check in those chapters applies unchanged — grant, allowed hosts, rate limit,
safety budgets, fact-write filtering.

Errors:

| Condition | JSON-RPC error |
|---|---|
| No passport-bound context | `INVALID_PARAMS`, `extension tool call requires an RCX passport-bound context` |
| No installed extension declares the name | `METHOD_NOT_FOUND`, `unknown extension tool: <name>` |
| Loopback URL unconfigured | `METHOD_NOT_FOUND`, `daemon loopback URL is not configured for extension dispatch` |
| Transport or upstream failure | `INTERNAL_ERROR`, `extension dispatch failed: <message>` |

Success wraps the whole daemon response as MCP text content, with a `_meta.crux`
block carrying `extension_id` and `rcx_capability`
([extensions.rs:155](../../crates/crux-mcp/src/tools/extensions.rs#L155)):

```json
{
  "content": [{ "type": "text", "text": "{\"result\":{...},\"accepted_fact_writes\":1,...}" }],
  "_meta": { "crux": { "extension_id": "ext.example.quote",
                       "rcx_capability": "crux-extension.ext.example.quote.daily" } }
}
```

The `text` is the serialised `DispatchOutcome` (or `WasmDispatchOutcome`), not
just your `result`. A client wanting the payload alone must parse it and read
`.result`.

## 10.5 Checklist for a discoverable tool

1. Name it `ext.<publisher>.<tool>` — the `ext.` prefix is load-bearing.
2. Write a `description` that survives being prefixed with
   `[tier:local][extension:<id>][trust:<tier>]`.
3. Supply a real `input_schema`. Nothing validates against it, so it is
   documentation for the agent — make it accurate.
4. Add `consequence_metadata` for anything irreversible or material.
5. Confirm the grant covers the tool name; an absent grant means the tool is
   invisible, not forbidden — there is no error to debug, just an empty list.
6. If the caller uses an RCX capability token, ensure it carries
   `crux-extension.<tool_name>`.

## Ground truth

- [crates/crux-mcp/src/tools/extensions.rs:39](../../crates/crux-mcp/src/tools/extensions.rs#L39) — `list_extension_tools`
- [crates/crux-mcp/src/tools/extensions.rs:89](../../crates/crux-mcp/src/tools/extensions.rs#L89) — `call_extension_tool`
- [crates/crux-mcp/src/tools/extensions.rs:175](../../crates/crux-mcp/src/tools/extensions.rs#L175) — `rcx_capability_name`
- [crates/crux-mcp/src/tools/extensions.rs:179](../../crates/crux-mcp/src/tools/extensions.rs#L179) — `is_extension_tool_name`
- [crates/crux-mcp/src/tools/mod.rs:2497](../../crates/crux-mcp/src/tools/mod.rs#L2497) — catalogue merge and RCX filter
- [crates/crux-mcp/src/tools/mod.rs:3020](../../crates/crux-mcp/src/tools/mod.rs#L3020) — `tools/call` routing
- [crates/crux-integrations/src/lib.rs:154](../../crates/crux-integrations/src/lib.rs#L154) — `ExternalToolDefinition`
