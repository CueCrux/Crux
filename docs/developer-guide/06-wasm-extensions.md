# 6. WASM extensions — the in-process sandbox

Where an external tool runs on your infrastructure, a WASM extension runs inside
the daemon process, inside a wasmtime sandbox with fuel, memory and wall-clock
limits. No network, no filesystem, no syscalls — only the host functions the
daemon exports.

## 6.1 Build the daemon with the feature

The whole path is behind a Cargo feature:

```toml
wasm-extensions = ["dep:wasmtime"]
```

([crates/corecruxd/Cargo.toml:21](../../crates/corecruxd/Cargo.toml#L21))

```bash
cargo build --release -p corecruxd --features wasm-extensions
```

Without it, the invoke route answers **501**:
`wasm extensions require building corecruxd with --features wasm-extensions`
([http/extensions.rs:986](../../crates/corecruxd/src/http/extensions.rs#L986)).

With the feature on but engine construction failed at startup, the route answers
**503** `wasm engine init failed at startup; restart the daemon and check logs`
([http/extensions.rs:926](../../crates/corecruxd/src/http/extensions.rs#L926)). The engine
is built once into `AppState`
([main.rs:802](../../crates/corecruxd/src/main.rs#L802),
[http/mod.rs:394](../../crates/corecruxd/src/http/mod.rs#L394)) and shared across all
extensions — the wasmtime-recommended pattern.

## 6.2 The manifest

```json
{
  "schema": "crux.integration.v1",
  "id": "ext.example.summarise",
  "name": "Summarise",
  "version": "0.1.0",
  "publisher_passport_fpr": "p_community_alice",
  "summary": "Summarises a note in-process.",
  "entry": { "kind": "wasm", "path": "tools/summarise.json" },
  "capabilities": ["facts:read", "facts:write"],
  "safety": { "sandbox": "wasm", "max_runtime_ms": 0, "max_output_bytes": 0 },
  "wasm_module_url": "https://example.com/summarise-0.1.0.wasm",
  "wasm_module_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "tools": [
    { "name": "ext.example.summarise.note",
      "description": "Summarise a note.",
      "input_schema": { "type": "object" } }
  ]
}
```

Validation rules specific to `wasm`
([lib.rs:534](../../crates/crux-integrations/src/lib.rs#L534)):

| Rule | Error text |
|---|---|
| `tools[]` non-empty, each with name + description | `field 'tools' is required` |
| No `auth_shared_secret_id` on any tool | `invalid identifier 'wasm tools must not set tools[].auth_shared_secret_id; use crux::get_secret_decrypted in-module instead'` |
| `external_tool_endpoint` unset | `invalid identifier 'external_tool_endpoint must be unset for entry.kind=wasm'` |
| `wasm_module_sha256` present, 64 lowercase hex | `field 'wasm_module_sha256' is required` / `invalid identifier 'wasm_module_sha256 must be 64 lowercase hex chars, got N chars'` |
| Exactly one of path or URL | `invalid identifier 'wasm_module_path and wasm_module_url are mutually exclusive'` / `field 'wasm_module_path or wasm_module_url is required'` |
| Path is relative, no `..` | `invalid identifier 'wasm_module_path must be relative to <data_dir>/extensions/{id}/, got '<p>''` |
| URL is HTTPS | `invalid identifier 'wasm_module_url must be an https:// URL, got '<u>''` |

Note the `auth_shared_secret_id` rule points at `crux::get_secret_decrypted`,
which is currently a stub — see §6.6.

## 6.3 Hash pinning — the module is content-addressed twice

**At install** ([http/extensions.rs:142](../../crates/corecruxd/src/http/extensions.rs#L142)):

1. The URL form triggers a download, capped at 16 MiB
   (`WASM_MODULE_DOWNLOAD_LIMIT_BYTES`,
   [wasm_dispatcher.rs:235](../../crates/corecruxd/src/wasm_dispatcher.rs#L235)) with a
   30-second global timeout.
2. SHA-256 is verified **before any byte is written to the destination**, so a
   mismatch leaves no partial file
   ([wasm_dispatcher.rs:295](../../crates/corecruxd/src/wasm_dispatcher.rs#L295)).
3. On success the bytes land at `<data_dir>/extensions/<id>/extension.wasm` via
   tmp + rename, and the manifest is **rewritten** to the path form with the URL
   dropped ([http/extensions.rs:163](../../crates/corecruxd/src/http/extensions.rs#L163)).
   Once cached, the daemon never re-fetches. A new module version means
   uninstall and reinstall.

Install-time failure statuses:

| Condition | Status | Detail |
|---|---|---|
| Hash mismatch | 409 | `downloaded module sha256 mismatch: manifest=<a>, downloaded=<b>` |
| Over the cap | 413 | `wasm module exceeds the 16777216-byte cap` |
| Upstream non-2xx | 502 | `module URL returned status <n>` |

**At every dispatch** ([wasm_dispatcher.rs:119](../../crates/corecruxd/src/wasm_dispatcher.rs#L119)):
the on-disk bytes are read and re-hashed. A mismatch is 409
`module sha256 mismatch: manifest=<a>, on-disk=<b>`. Someone swapping the cached
file cannot get it executed.

If a persisted record still carries a URL (the install flow was bypassed by
writing the fact directly), dispatch refuses rather than downloading mid-call:
`wasm_module_url is set but never resolved to a cached path; install path may have skipped the M6.4 download step`
([wasm_dispatcher.rs:44](../../crates/corecruxd/src/wasm_dispatcher.rs#L44)).

## 6.4 The module contract

Your module exports:

```text
extension_call(req_ptr: i32, req_len: i32, resp_ptr: i32, resp_cap: i32) -> i32
memory                      // standard linear memory, required
_initialize()               // optional, called once after instantiation
```

([wasm_host.rs:32](../../crates/corecruxd/src/wasm_host.rs#L32),
[wasm_host.rs:462](../../crates/corecruxd/src/wasm_host.rs#L462))

Return value: bytes written into the response buffer, or `-1` if `resp_cap` was
too small (surfaced as `response buffer overflow`). Other negative values are
reserved and produce `module returned reserved code <n>`
([wasm_host.rs:514](../../crates/corecruxd/src/wasm_host.rs#L514)).

**Request** written at `req_ptr` — the same JSON shape as the external-tool path,
deliberately, so templates can share struct definitions
([wasm_host.rs:363](../../crates/corecruxd/src/wasm_host.rs#L363)):

```json
{ "tool": "...", "args": {}, "calling_passport_id": "p_alice", "request_id": "req-..." }
```

**Response** you write at `resp_ptr`, UTF-8 JSON
([wasm_host.rs:372](../../crates/corecruxd/src/wasm_host.rs#L372)):

```json
{ "result": { }, "fact_writes": [] }
```

Invalid UTF-8 gives `response is not valid utf-8`; invalid JSON gives
`response is not valid JSON: <err>`.

### `fact_writes[]` in the WASM response is ignored

The type accepts the field for envelope symmetry, but `dispatch_wasm_via_http`
discards the parsed response and returns only the outcome
([wasm_dispatcher.rs:156](../../crates/corecruxd/src/wasm_dispatcher.rs#L156)). A WASM
module writes facts by calling `crux::store_fact` during the call, not by
returning them. Do not design around the returned array.

### Memory layout

The host lays request and response out flat in linear memory: request at offset
0, response 8-byte-aligned just past it, `resp_cap` capped at 64 KiB
([wasm_host.rs:497](../../crates/corecruxd/src/wasm_host.rs#L497)). Memory is grown by
whole 64 KiB pages if needed. The module is not asked to allocate — the comment
notes this keeps test fixtures tiny
([wasm_host.rs:488](../../crates/corecruxd/src/wasm_host.rs#L488)). Design for a response
under 64 KiB.

Each call compiles and instantiates a fresh instance, which is dropped at the
end. State does not persist between calls
([wasm_host.rs:415](../../crates/corecruxd/src/wasm_host.rs#L415)).

## 6.5 The host ABI

All imports are in the `crux` module. Signatures from
[wasm_host.rs:592](../../crates/corecruxd/src/wasm_host.rs#L592) onward.

| Import | Signature | Behaviour |
|---|---|---|
| `now_unix_ms` | `() -> i64` (u64) | Wall-clock milliseconds ([wasm_host.rs:601](../../crates/corecruxd/src/wasm_host.rs#L601)) |
| `log` | `(level_ptr, level_len, msg_ptr, msg_len)` | Appends a `HostLogEntry {level, message, at_unix_ms}` to per-call state, returned in the outcome ([wasm_host.rs:608](../../crates/corecruxd/src/wasm_host.rs#L608), [wasm_host.rs:163](../../crates/corecruxd/src/wasm_host.rs#L163)) |
| `current_passport_json` | `(ptr, cap) -> i32` | Writes the bound passport as JSON; bytes written, or `-1` if `cap` too small ([wasm_host.rs:629](../../crates/corecruxd/src/wasm_host.rs#L629)) |
| `read_fact` | `(entity_ptr, entity_len, key_ptr, key_len, resp_ptr, resp_cap) -> i32` | Grant-scoped single fact read ([wasm_host.rs:665](../../crates/corecruxd/src/wasm_host.rs#L665)) |
| `store_fact` | `(entity_ptr, entity_len, key_ptr, key_len, value_ptr, value_len, confidence_thousandths, resp_ptr, resp_cap) -> i32` | Grant-scoped write ([wasm_host.rs:714](../../crates/corecruxd/src/wasm_host.rs#L714)) |
| `query_facts` | `(prefix_ptr, prefix_len, query_ptr, query_len, top_k, resp_ptr, resp_cap) -> i32` | Grant-scoped prefix query ([wasm_host.rs:777](../../crates/corecruxd/src/wasm_host.rs#L777)) |
| `get_secret_decrypted` | `(id_ptr, id_len, resp_ptr, resp_cap) -> i32` | **Stub. Always returns `-6`** ([wasm_host.rs:858](../../crates/corecruxd/src/wasm_host.rs#L858)) |
| `emit_receipt` | `(...) -> i32` | **Stub. Always returns `-6`** ([wasm_host.rs:868](../../crates/corecruxd/src/wasm_host.rs#L868)) |

Confidence crosses the boundary as `i32` thousandths clamped to `0..=1000`, so
the ABI stays float-free; 1000 means 1.0
([wasm_host.rs:743](../../crates/corecruxd/src/wasm_host.rs#L743)).

### Return codes — a stable, do-not-renumber contract

([wasm_host.rs:253](../../crates/corecruxd/src/wasm_host.rs#L253), re-exported as
`wasm_host::rc`)

| Code | Name | Meaning |
|---|---|---|
| `-1` | `NOT_FOUND` | No such fact |
| `-2` | `NO_GRANT` | No grant bound to this call |
| `-3` | `SCOPE_VIOLATION` | Entity or prefix outside the grant |
| `-4` | `BUFFER_TOO_SMALL` | Your `resp_cap` was too small |
| `-5` | `FACT_STORE_UNAVAILABLE` | This build does not wire fact ops |
| `-6` | `NOT_IMPLEMENTED` | The two stubs above |
| `-7..-9` | reserved | Future scoped errors |
| `-10` | `HOST_INTERNAL` | Host-side failure |
| `-11` | `BAD_INPUT` | Pointer or length invalid, or non-UTF-8 |
| `-12` | `SERIALISE_ERR` | Host could not serialise the reply |

A non-negative return is the byte count written into your buffer.

### Grant scoping inside the ABI

- `read_fact` and `store_fact` check `entity_matches_any_prefix` against
  `allowed_prefixes_read` / `allowed_prefixes_write`; failure is `-3`
  ([wasm_host.rs:281](../../crates/corecruxd/src/wasm_host.rs#L281),
  [wasm_host.rs:748](../../crates/corecruxd/src/wasm_host.rs#L748)).
- `query_facts` requires a prefix argument that is **at least as specific as** a
  granted prefix (`query_prefix.starts_with(granted)`). The empty string never
  satisfies this, so a module cannot enumerate the store
  ([wasm_host.rs:289](../../crates/corecruxd/src/wasm_host.rs#L289)).
- Results are filtered again after fetch, in case the underlying store is loose
  about prefixes ([wasm_host.rs:828](../../crates/corecruxd/src/wasm_host.rs#L828)).
- Every write still passes `fact_privacy::enforce_global` before storage
  ([wasm_dispatcher.rs:198](../../crates/corecruxd/src/wasm_dispatcher.rs#L198)), and lands
  under `tenant_hash: "default"`.
- With no grant bound, every fact host function returns `-2`
  ([wasm_host.rs:147](../../crates/corecruxd/src/wasm_host.rs#L147)).

## 6.6 Resource limits

`WasmConfig::from_env()` ([wasm_host.rs:87](../../crates/corecruxd/src/wasm_host.rs#L87)),
read per call:

| Env var | Default | Meaning |
|---|---|---|
| `CORECRUXD_WASM_FUEL_DEFAULT` | 1000000 | Fuel budget, roughly instructions. About 10 ms of integer work |
| `CORECRUXD_WASM_MEMORY_BYTES_DEFAULT` | 16000000 | Linear-memory ceiling |
| `CORECRUXD_WASM_WALL_MS_DEFAULT` | 1000 | Wall clock, enforced by epoch interruption |
| `CORECRUXD_WASM_EPOCH_TICK_MS` | 10 | Epoch tick — the worst-case resolution of the wall-clock trap |

The manifest's `safety.max_runtime_ms` and `max_output_bytes` are **not** applied
on the WASM path; they only tighten the external-tool path. WASM limits come
from the daemon environment alone.

Traps are classified into typed errors
([wasm_host.rs:542](../../crates/corecruxd/src/wasm_host.rs#L542)) and mapped to HTTP
([http/extensions.rs:957](../../crates/corecruxd/src/http/extensions.rs#L957)):

| Error | Display | HTTP |
|---|---|---|
| `FuelExhausted` | `EXT_WASM_FUEL_EXHAUSTED` | 408 |
| `DeadlineExceeded` | `EXT_WASM_DEADLINE_EXCEEDED` | 408 |
| `OutOfMemory` | `EXT_WASM_OOM` | 507 |
| `ModuleFileMissing` | — | 404 `wasm module file missing at '<path>'` |
| `Sha256Mismatch` | — | 409 |
| anything else | `EXT_WASM_TRAP: <detail>` and friends | 502 |

Fuel and wall clock are enforced independently. A tight loop exhausts fuel; a
long host-call-free spin hits the epoch deadline.

## 6.7 Invoking

Identical route and body to the external-tool path — the handler branches on
`entry.kind` ([http/extensions.rs:739](../../crates/corecruxd/src/http/extensions.rs#L739)):

```bash
curl -s -X POST \
  http://127.0.0.1:14800/v1/extensions/ext.example.summarise/tools/ext.example.summarise.note/invoke \
  -H "Authorization: Bearer $CRUX_AGENT_TOKEN" \
  -H "X-Corecrux-Passport-Id: p_alice" \
  -H 'Content-Type: application/json' \
  -d '{"args": {"doc_id": "note-1"}}'
```

Response is a `WasmDispatchOutcome`
([wasm_host.rs:350](../../crates/corecruxd/src/wasm_host.rs#L350)) — same spirit as the
external-tool outcome, different telemetry:

```json
{
  "result": { "summary": "..." },
  "elapsed_ms": 12,
  "fuel_consumed": 84210,
  "log": [{ "level": "info", "message": "chunked 4 sections", "at_unix_ms": 1753440000000 }],
  "request_id": "req-1753440000000000000"
}
```

There are no `accepted_fact_writes` / `dropped_fact_writes` counters on this
path — writes happened synchronously through the host ABI, and their per-call
outcome is whatever `store_fact` returned to your module.

## 6.8 Choosing between external tool and WASM

| | External tool | WASM |
|---|---|---|
| Language | anything | anything targeting `wasm32` |
| Network access | yours, unrestricted | none |
| Latency | network round trip | in-process |
| Failure blast radius | your service | sandboxed, fuel/memory/epoch-capped |
| Fact access | proposed writes, filtered post-hoc | direct, grant-scoped, synchronous |
| Secrets | intended via shared secret (not yet wired) | intended via `get_secret_decrypted` (stub) |
| Operator build requirement | none | `--features wasm-extensions` |
| Availability today | fully wired | wired, feature-gated, two ABI stubs |

Start with an external tool. Move to WASM when the round trip or the operator's
egress policy makes it worth the constraints.

## Ground truth

- [crates/corecruxd/Cargo.toml:21](../../crates/corecruxd/Cargo.toml#L21) — the feature
- [crates/corecruxd/src/wasm_host.rs:29](../../crates/corecruxd/src/wasm_host.rs#L29) — wire contract
- [crates/corecruxd/src/wasm_host.rs:72](../../crates/corecruxd/src/wasm_host.rs#L72) — `WasmConfig`
- [crates/corecruxd/src/wasm_host.rs:111](../../crates/corecruxd/src/wasm_host.rs#L111) — `WasmError`
- [crates/corecruxd/src/wasm_host.rs:253](../../crates/corecruxd/src/wasm_host.rs#L253) — return-code legend
- [crates/corecruxd/src/wasm_host.rs:350](../../crates/corecruxd/src/wasm_host.rs#L350) — `WasmDispatchOutcome`
- [crates/corecruxd/src/wasm_host.rs:427](../../crates/corecruxd/src/wasm_host.rs#L427) — `dispatch_wasm_tool_with_context`
- [crates/corecruxd/src/wasm_host.rs:592](../../crates/corecruxd/src/wasm_host.rs#L592) — host ABI registration
- [crates/corecruxd/src/wasm_dispatcher.rs:61](../../crates/corecruxd/src/wasm_dispatcher.rs#L61) — `module_path_for`
- [crates/corecruxd/src/wasm_dispatcher.rs:263](../../crates/corecruxd/src/wasm_dispatcher.rs#L263) — `download_module_to_cache`
- [crates/corecruxd/src/http/extensions.rs:915](../../crates/corecruxd/src/http/extensions.rs#L915) — wasm dispatch branch
- [crates/crux-integrations/src/lib.rs:534](../../crates/crux-integrations/src/lib.rs#L534) — wasm validation
