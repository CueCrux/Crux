# 5. External tools — the HTTPS extension path

An external tool is your own HTTPS service. The daemon proxies `tools/call`
payloads to it, enforces a pipeline of checks on the way out and back, and
persists only the fact writes your grant allows.

Nothing of yours runs in the daemon process. This is the lowest-risk way to
extend the platform and the one to reach for first.

## 5.1 The manifest

```json
{
  "schema": "crux.integration.v1",
  "id": "ext.example.quote",
  "name": "Quote of the Day",
  "version": "0.1.0",
  "publisher_passport_fpr": "p_community_alice",
  "summary": "Returns a quote and records it as a fact.",
  "entry": { "kind": "external_tool", "path": "tools/quote.json" },
  "capabilities": ["facts:read", "facts:write"],
  "network": { "allowed_hosts": ["tools.example.com:443"] },
  "safety": { "sandbox": "none", "max_runtime_ms": 3000, "max_output_bytes": 65536 },
  "external_tool_endpoint": "https://tools.example.com/crux/invoke",
  "tools": [
    {
      "name": "ext.example.quote.daily",
      "description": "Return today's quote.",
      "input_schema": { "type": "object", "properties": { "topic": { "type": "string" } } }
    }
  ]
}
```

Validation rules specific to this kind
([lib.rs:505](../../crates/crux-integrations/src/lib.rs#L505)):

- `external_tool_endpoint` is required and non-empty, else
  `field 'external_tool_endpoint' is required`.
- It must start `https://` or `http://`, else
  `invalid identifier 'external_tool_endpoint must be an http(s) URL, got '<url>''`.
- `tools[]` must be non-empty, else `field 'tools' is required`.
- Each tool needs a non-empty `name` and `description`, else
  `field 'tools[].name' is required` / `field 'tools[].description' is required`.
- No `wasm_module_*` field may be set, else
  `invalid identifier 'wasm_module_* fields only valid when entry.kind=wasm'`.

`http://` passes *validation* but is blocked at *dispatch* unless
`CORECRUXD_EXTENSIONS_ALLOW_PLAIN_HTTP` is on. Two different layers, two
different rules.

## 5.2 The wire contract

The daemon POSTs a JSON object to your endpoint
([extension_outbound.rs:254](../../crates/corecruxd/src/extension_outbound.rs#L254)) with
`Content-Type: application/json` and `Accept: application/json`
([extension_outbound.rs:635](../../crates/corecruxd/src/extension_outbound.rs#L635)).

**Request**

```json
{
  "tool": "ext.example.quote.daily",
  "args": { "topic": "engineering" },
  "calling_passport_id": "p_alice",
  "request_id": "req-1753440000000000000"
}
```

`request_id` is `req-<nanoseconds since epoch>`
([http/extensions.rs:675](../../crates/corecruxd/src/http/extensions.rs#L675)). Treat it as
an opaque idempotency key.

**Response — you must return exactly this shape**
([extension_outbound.rs:264](../../crates/corecruxd/src/extension_outbound.rs#L264)):

```json
{
  "result": { "quote": "Simplicity is a discipline.", "author": "anon" },
  "fact_writes": [
    {
      "entity": "personal::quotes::2026-07-25",
      "key": "quote",
      "value": "Simplicity is a discipline.",
      "confidence": 0.9
    }
  ]
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `result` | any JSON | yes | Returned to the caller verbatim |
| `fact_writes` | array | no (`[]`) | Proposed writes, filtered against the grant |
| `fact_writes[].entity` | string | yes | Must start with a granted write prefix |
| `fact_writes[].key` | string | yes | |
| `fact_writes[].value` | string | yes | Strings only — not arbitrary JSON |
| `fact_writes[].confidence` | f32 | no (`1.0`) | ([extension_outbound.rs:279](../../crates/corecruxd/src/extension_outbound.rs#L279)) |

A missing `result` key, or a body that is not JSON, gives
`upstream returned malformed response: <serde error>` → HTTP 502.

### Authentication towards your endpoint

If a tool declares `auth_shared_secret_id`, the intent is that the daemon
decrypts that secret and sends `Authorization: Bearer <secret>`
([lib.rs:170](../../crates/crux-integrations/src/lib.rs#L170),
[extension_outbound.rs:637](../../crates/corecruxd/src/extension_outbound.rs#L637)).

**Honest status:** the transport supports the header, but the HTTP invoke handler
currently passes `None` for the resolved secret, with the comment
`M5 will pull the auth secret via encrypted_secrets`
([http/extensions.rs:784](../../crates/corecruxd/src/http/extensions.rs#L784)). Until that
lands, no `Authorization` header is sent. Authenticate by other means — a
per-extension path segment, a network allowlist on your side, or mTLS at your
edge.

## 5.3 The enforcement pipeline, in execution order

Two layers run. The HTTP handler does a coarse pre-check, then
`dispatch_external_tool_inner`
([extension_outbound.rs:405](../../crates/corecruxd/src/extension_outbound.rs#L405)) does the
full sequence.

**Handler pre-checks** ([http/extensions.rs:686](../../crates/corecruxd/src/http/extensions.rs#L686)):

| # | Check | Failure |
|---|---|---|
| 0a | Scopes `admin:read` + `facts:write` | 403 `insufficient scopes` |
| 0b | Calling passport present (body `passport_fpr` or `X-Corecrux-Passport-Id`) | 400 `passport_fpr required (body field or X-Corecrux-Passport-Id header)` |
| 0c | Extension installed | 404 `extension '<id>' not installed` |
| 0d | Grant exists for that passport | 403 `passport '<fpr>' has no grant for extension '<id>'` |
| 0e | Tool in `allowed_tool_names` (unless empty) | 403 `tool '<t>' is not in the grant's allowed_tool_names` |
| 0f | `entry.kind` is `external_tool` or `wasm` | 400 `extension '<id>' has unsupported entry.kind <Kind> for tool dispatch` |

**Dispatcher pipeline:**

| # | Check | Error variant → HTTP |
|---|---|---|
| 1 | `entry.kind == ExternalTool` | `NotExternalTool` → 502 |
| 2 | `external_tool_endpoint` present | `NotExternalTool` → 502 |
| 3 | HTTPS, or HTTP with the dev flag | `PlainHttpBlocked` → 502, text `plain http endpoint blocked (set CORECRUXD_EXTENSIONS_ALLOW_PLAIN_HTTP=true for dev)` |
| 4 | URL parses and has a host | `InvalidEndpoint` → 502 |
| 5 | Host matches `network.allowed_hosts` | `EndpointNotAllowed` → 502, text `endpoint '<authority>' is not allowed by extension '<id>' network.allowed_hosts` |
| 6 | Tool declared in the manifest | `ToolNotInManifest` → 502 |
| 7 | Grant's `extension_id` and `passport_fpr` match this call | `NoGrant` → **403 `scope violation`** |
| 8 | Tool in the grant's `allowed_tool_names` | `ToolNotInGrant` → **403 `scope violation`** |
| 9 | Timeout and response cap tightened by `safety` | — |
| 10 | Rate limit | `RateLimited` → **429 `rate limited (cap N/min)`** |
| 11 | Request body ≤ `max_request_bytes` | `RequestTooLarge` → 502 |
| 12 | POST to the endpoint | `Transport` → 502 |
| 13 | Response body ≤ effective cap | `ResponseTooLarge` → 502 |
| 14 | Upstream status in 200..=299 | `UpstreamError` → 502, body truncated to 512 chars |
| 15 | Body parses as `ExternalToolResponse` | `MalformedResponse` → 502 |
| 16 | Each `fact_writes[]` entity matched against `allowed_prefixes_write` | Non-fatal — see §5.5 |

Status mapping is at [http/extensions.rs:789](../../crates/corecruxd/src/http/extensions.rs#L789).
Everything not explicitly mapped becomes 502 with the error's `Display` text.

### `allowed_hosts` matching is deliberately literal

`parse_allowed_host_entry` ([extension_outbound.rs:323](../../crates/corecruxd/src/extension_outbound.rs#L323)):

- An empty list means "no host restriction" — endpoint pinning alone
  ([extension_outbound.rs:349](../../crates/corecruxd/src/extension_outbound.rs#L349)).
- Entries containing `://`, `/`, `?`, `#` or `*` never match. No wildcards, no
  schemes, no paths.
- `host` alone matches any port. `host:port` requires the endpoint's effective
  port (explicit or scheme default) to match
  ([extension_outbound.rs:363](../../crates/corecruxd/src/extension_outbound.rs#L363)).
- IPv6 must be bracketed: `[::1]` or `[::1]:8443`.
- Host comparison is ASCII case-insensitive.
- A malformed entry does not error — it simply never matches, so a typo fails
  closed.

### Safety budgets tighten, never raise

```text
effective_timeout        = min(daemon_timeout,        safety.max_runtime_ms)     if non-zero
effective_max_response   = min(daemon_max_response,   safety.max_output_bytes)   if non-zero
```

([extension_outbound.rs:462](../../crates/corecruxd/src/extension_outbound.rs#L462)). A pack
declaring `max_runtime_ms: 600000` on a daemon configured for 5 s still gets 5 s.
Zero means "use the daemon value". `max_output_bytes` above `usize::MAX`
saturates rather than wrapping
([extension_outbound.rs:367](../../crates/corecruxd/src/extension_outbound.rs#L367)).

Note `max_request_bytes` is **not** tightenable by the manifest — only the
daemon config applies ([extension_outbound.rs:487](../../crates/corecruxd/src/extension_outbound.rs#L487)).

### Daemon-wide knobs

| Env var | Default | Constant |
|---|---|---|
| `CORECRUXD_EXTENSIONS_TIMEOUT_SECONDS` | 5 | [extension_outbound.rs:47](../../crates/corecruxd/src/extension_outbound.rs#L47) |
| `CORECRUXD_EXTENSIONS_MAX_REQUEST_BYTES` | 262144 | [extension_outbound.rs:48](../../crates/corecruxd/src/extension_outbound.rs#L48) |
| `CORECRUXD_EXTENSIONS_MAX_RESPONSE_BYTES` | 262144 | [extension_outbound.rs:49](../../crates/corecruxd/src/extension_outbound.rs#L49) |
| `CORECRUXD_EXTENSIONS_DEFAULT_RATE_PER_MIN` | 10 | [extension_outbound.rs:50](../../crates/corecruxd/src/extension_outbound.rs#L50) |
| `CORECRUXD_EXTENSIONS_ALLOW_PLAIN_HTTP` | off | [extension_outbound.rs:151](../../crates/corecruxd/src/extension_outbound.rs#L151) |

Config is read from the process environment **per call**
(`OutboundConfig::from_env()` at
[http/extensions.rs:762](../../crates/corecruxd/src/http/extensions.rs#L762)), so a change
takes effect without a restart. A malformed value is ignored and the default
stands — the parse is `if let Ok(n) = s.parse()`.

### Rate limiting

A sliding 60-second window keyed by `(extension_id, passport_fpr)`
([extension_outbound.rs:191](../../crates/corecruxd/src/extension_outbound.rs#L191)). The cap
is the grant's `rate_limit_per_min`, falling back to the daemon default. The
check happens **before** the outbound call, so a rate-limited call costs your
endpoint nothing.

The limiter tolerates mutex poisoning by design — it is best-effort, not a
security control ([extension_outbound.rs:198](../../crates/corecruxd/src/extension_outbound.rs#L198)).
Treat it as a courtesy budget, not a hard quota.

## 5.4 Invoking a tool

```bash
curl -s -X POST \
  http://127.0.0.1:14800/v1/extensions/ext.example.quote/tools/ext.example.quote.daily/invoke \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H "X-Corecrux-Passport-Id: p_alice" \
  -H 'Content-Type: application/json' \
  -d '{"args": {"topic": "engineering"}}'
```

Route: `POST /v1/extensions/{id}/tools/{tool_name}/invoke`, scopes
`admin:read` + `facts:write`
([http/mod.rs:1116](../../crates/corecruxd/src/http/mod.rs#L1116)).

Response is a `DispatchOutcome`
([extension_outbound.rs:287](../../crates/corecruxd/src/extension_outbound.rs#L287)):

```json
{
  "result": { "quote": "Simplicity is a discipline." },
  "accepted_fact_writes": 1,
  "dropped_fact_writes": 1,
  "drop_reasons": [
    "fact_writes[1] entity 'secrets::api-key' not covered by grant.allowed_prefixes_write"
  ],
  "upstream_status": 200,
  "elapsed_ms": 143,
  "request_id": "req-1753440000000000000"
}
```

`elapsed_ms` covers the transport call only, not the surrounding checks
([extension_outbound.rs:494](../../crates/corecruxd/src/extension_outbound.rs#L494)).

## 5.5 How `fact_writes` filtering actually works

This is the part people get wrong, so read it twice.

1. The dispatcher classifies each proposed write against
   `grant.allowed_prefixes_write` using `entity.starts_with(prefix)` and counts
   accepted versus dropped
   ([extension_outbound.rs:520](../../crates/corecruxd/src/extension_outbound.rs#L520)).
   It does **not** persist anything.
2. The HTTP handler then re-applies the identical filter and persists the
   survivors ([http/extensions.rs:810](../../crates/corecruxd/src/http/extensions.rs#L810)).
3. Every persisted write passes through `fact_privacy::enforce_global` before
   storage — the final say on private prefixes
   ([http/extensions.rs:827](../../crates/corecruxd/src/http/extensions.rs#L827)).
4. All writes land under `tenant_hash: "default"`. An extension cannot choose a
   tenant.

Design consequences:

- Dropped writes are **not** an error. Your `result` still comes back. Check
  `dropped_fact_writes` and `drop_reasons` if you care.
- Prefix matching is a raw string prefix, not a namespace match. A grant on
  `personal::quotes::` also permits `personal::quotes::anything::deeper`, and a
  grant on `personal::q` would permit `personal::quotesomething`. Grant precise
  prefixes ending in `::`.
- An empty `allowed_prefixes_write` drops every write.

## 5.6 Auditing

Every dispatch appends one event
([extension_outbound.rs:542](../../crates/corecruxd/src/extension_outbound.rs#L542)):
`extension_invoke_ok` on success, `extension_invoke_rejected` on failure with a
stable machine reason from `audit_reason`
([extension_outbound.rs:596](../../crates/corecruxd/src/extension_outbound.rs#L596)):

`not_external_tool`, `tool_not_in_manifest`, `no_grant`, `tool_not_in_grant`,
`rate_limited`, `request_too_large`, `response_too_large`, `plain_http_blocked`,
`invalid_endpoint`, `endpoint_not_allowed`, `transport`, `upstream_error`,
`malformed_response`, `json`.

Audit itself is rate-limited to 60 events per extension per minute
([extension_outbound.rs:51](../../crates/corecruxd/src/extension_outbound.rs#L51)). On
crossing the threshold the daemon writes **one** `audit_suppressed` marker
carrying `{event_family: "extension_invoke", count, limit_per_min}` and then goes
quiet for the rest of the window
([extension_outbound.rs:577](../../crates/corecruxd/src/extension_outbound.rs#L577)). A gap
in the audit tail under load is expected behaviour, not a lost write.

## 5.7 A minimal endpoint

```python
# Flask sketch. Any HTTPS server that speaks the two shapes above works.
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.post("/crux/invoke")
def invoke():
    body = request.get_json(force=True)
    tool = body["tool"]
    args = body.get("args") or {}
    passport = body["calling_passport_id"]

    if tool != "ext.example.quote.daily":
        return jsonify({"error": f"unknown tool {tool}"}), 400

    quote = pick_quote(args.get("topic"))
    return jsonify({
        "result": {"quote": quote},
        # Only prefixes the operator granted survive. Anything else is
        # counted as dropped and reported back to the caller.
        "fact_writes": [{
            "entity": f"personal::quotes::{passport}",
            "key": "latest",
            "value": quote,
            "confidence": 0.9,
        }],
    })
```

Checklist for a production endpoint:

- Validate `args` yourself. The daemon passes `input_schema` through to MCP
  clients but never validates against it
  ([lib.rs:160](../../crates/crux-integrations/src/lib.rs#L160)).
- Stay inside the response cap — the daemon truncates nothing, it rejects.
- Return within the effective timeout. A slow response is a 502, not a partial
  result.
- Do not assume an `Authorization` header (§5.2).
- Treat `request_id` as an idempotency key; the daemon may retry at the client's
  discretion, and it does not deduplicate for you.

## Ground truth

- [crates/corecruxd/src/extension_outbound.rs:6](../../crates/corecruxd/src/extension_outbound.rs#L6) — the pipeline, stated in the module header
- [crates/corecruxd/src/extension_outbound.rs:254](../../crates/corecruxd/src/extension_outbound.rs#L254) — `ExternalToolRequest`
- [crates/corecruxd/src/extension_outbound.rs:264](../../crates/corecruxd/src/extension_outbound.rs#L264) — `ExternalToolResponse`
- [crates/corecruxd/src/extension_outbound.rs:287](../../crates/corecruxd/src/extension_outbound.rs#L287) — `DispatchOutcome`
- [crates/corecruxd/src/extension_outbound.rs:323](../../crates/corecruxd/src/extension_outbound.rs#L323) — `parse_allowed_host_entry`
- [crates/corecruxd/src/extension_outbound.rs:405](../../crates/corecruxd/src/extension_outbound.rs#L405) — `dispatch_external_tool_inner`
- [crates/corecruxd/src/extension_outbound.rs:542](../../crates/corecruxd/src/extension_outbound.rs#L542) — `audit_dispatch_result`
- [crates/corecruxd/src/http/extensions.rs:686](../../crates/corecruxd/src/http/extensions.rs#L686) — `invoke_extension_tool`
- [crates/crux-integrations/src/lib.rs:505](../../crates/crux-integrations/src/lib.rs#L505) — external-tool validation
