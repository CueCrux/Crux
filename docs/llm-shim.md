# crux-llm-shim — local-LLM context injection (EXPERIMENTAL)

> Status: experimental v1 (G17, ExecPlan `context-mediation-injection-2026-06-11`, M4).
> Default-OFF. Local-only. The ONE sanctioned proxy in the mediation plane.

## What it is

A thin, opt-in OpenAI-compatible proxy in front of a **local** model server
(Ollama, vLLM, llama.cpp server) that:

1. **Injects** the rendered `context_bundle/v1` markdown as a NEW first
   `system` message on every `chat/completions` (and Ollama `/api/chat`)
   request — stable region first, so the injected prefix is byte-identical
   across requests and provider/runtime prompt caches hit (the G21a lever).
2. **Mints mediation receipt records** — `context_injected` per mediated
   request, `stream_completed` / `stream_aborted` per response end-state,
   linked by `stable_hash` / `bundle_digest` (the two-sided trail from the
   streaming-receipts spec). Records carry an `output_digest`
   (`sha256:<hex>` of the emitted bytes), never response content.
3. **Passes everything else through unmodified** — params, tools, streaming
   bytes, non-chat routes.

Why a proxy is acceptable HERE and nowhere else: the user owns both ends, no
provider ToS is in play, and a bare `ollama serve` has no hook system — the
shim is the only viable injection point. The normative rationale (and the
4-reason rejection of cloud-call interception) lives in
`PlanCrux docs/master-plan/shared/Context-Mediation-Points.md`.

## Guardrails (enforced in code)

- **Default-OFF**: refuses to start unless `CRUX_LLM_SHIM=1`.
- **Upstream allowlist**: `localhost`, loopback, and RFC1918 literal IPs only;
  plain `http://` only (TLS upstreams refused); no DNS resolution of other
  hostnames (no rebinding surface). Cloud proxying is structurally blocked.
- **Loopback listen only**: the shim refuses to bind a non-loopback address.
- **Free-tier / local-only**: zero network beyond your own upstream. Receipt
  posting to the daemon (`POST /v1/mediation/receipts`) is best-effort; on
  failure records append to a local JSONL spool
  (`~/.local/state/crux/llm-shim/receipts.jsonl` by default).

## Cloud witness mode

Cloud witness mode is a separate, explicit operating mode for observing
Anthropic and OpenAI traffic. **Witnessing is not injection:** the witness
never adds Crux context and never modifies a request or response payload. It
forwards the call, hashes the exact payload bytes it observes, and emits a
signed metadata-only trail.

The mode is default-OFF and requires `CRUX_CLOUD_WITNESS=1` plus
`--cloud-witness`. Its production upstream allowlist is pinned to exactly
`https://api.anthropic.com` and `https://api.openai.com`; there is no arbitrary
cloud-host option. The client-facing listener remains loopback-only, and the
upstream connection uses TLS certificate verification. Redirects are not
followed, and only origin-form request targets beginning with one `/` are
accepted, so the pinned authority cannot be replaced by a crafted request
line. Authentication headers
(`x-api-key` and `Authorization`) are forwarded to the selected provider but
are never logged, persisted, or included in a digest.

Witnessed calls are:

- Anthropic `POST /v1/messages`;
- OpenAI `POST /v1/chat/completions`;
- OpenAI `POST /v1/responses`.

Other paths are still forwarded and produce only a lightweight
`passthrough_unwitnessed` record containing the path and timestamp. No request
or response content is stored for any path.

For a witnessed call, the shim emits linked `cloud_request_witnessed` and
`cloud_response_witnessed` records under
`cuecrux.mediation.witness.v1`. They contain SHA-256 request/output digests,
provider and model metadata, tool names without arguments, stream state,
timing, status, and usage/stop metadata when parseable. Each record is signed
with a dedicated Ed25519 witness key. The key is created with mode `0600` on
first use at `~/.local/state/crux/llm-shim/witness.key`, then reused; override
the location with `--witness-key <path>`. The signed envelope carries its key
id and public key so records can be checked offline against the expected,
pinned witness public key. A symlink/non-regular key, a key that is
group/world-accessible when loaded, or a group/world-writable key directory
degrades the witness instead of silently reusing unsafe custody.

What this proves: the holder of the pinned witness key observed bytes matching
the committed request and response digests and linked them to the recorded
request/response lifecycle and end-state while connecting to the selected
pinned TLS upstream. Altering a signed record or committed digest invalidates
verification.

What this does **not** prove: that the provider used a particular internal
model or tool, that an answer is correct, that the local host or witness key
was uncompromised, or that every cloud call was routed through the witness.
The witness cannot prevent bypass. A bypass instead creates a detectable
absence when the witness trail is reconciled with an independently known
session or invocation sequence; a standalone receipt set cannot prove that
unrecorded calls never occurred.

Witnessing is fail-soft. A key, signing, daemon-delivery, or spool failure must
not turn into a model outage: the provider call is still forwarded and the
shim best-effort emits a `witness_degraded` record. Receipt delivery uses the
same `POST /v1/mediation/receipts` then JSONL-spool fallback as local mode.
The cloud delivery queue is bounded and non-blocking; concurrent processes
lock each JSONL append so separate local/Anthropic/OpenAI instances cannot
interleave record framing.

### Anthropic quickstart

Run a witness instance on a port distinct from any local injection shim, then
point the Anthropic client at its loopback listener:

```bash
CRUX_CLOUD_WITNESS=1 crux-llm-shim \
  --cloud-witness \
  --cloud-upstream anthropic \
  --listen 127.0.0.1:11436

export ANTHROPIC_BASE_URL=http://127.0.0.1:11436
# Run the Anthropic client normally; keep ANTHROPIC_API_KEY configured as usual.
```

### OpenAI quickstart

```bash
CRUX_CLOUD_WITNESS=1 crux-llm-shim \
  --cloud-witness \
  --cloud-upstream openai \
  --listen 127.0.0.1:11437

export OPENAI_BASE_URL=http://127.0.0.1:11437/v1
# Run the OpenAI client normally; keep OPENAI_API_KEY configured as usual.
```

Local injection mode and cloud witness mode have independent enable flags and
can run concurrently as separate instances of the same binary on different
loopback ports. The insecure HTTP test-upstream override is intentionally not
a production escape hatch: it requires the loud
`--insecure-test-upstream` opt-in and stamps every resulting record
`test_upstream: true`. The override URL must be supplied separately as
`CRUX_CLOUD_WITNESS_TEST_UPSTREAM=http://127.0.0.1:<port>` and is restricted
to loopback HTTP.

## Install & run

```bash
cargo build --release -p crux-claude-hooks --bin crux-llm-shim

CRUX_LLM_SHIM=1 ./target/release/crux-llm-shim \
    --upstream http://localhost:11434 \
    --listen 127.0.0.1:11435 \
    --bundle-file ~/.local/state/crux/context-bundle.md
```

Then point any OpenAI-compatible client at the shim:

```bash
curl -N http://127.0.0.1:11435/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"llama3.2","stream":true,"messages":[{"role":"user","content":"hi"}]}'
```

Bundle sources (pick one):

- `--bundle-file <path>` — rendered bundle markdown, read once at startup.
- `--context-endpoint http://127.0.0.1:14800/v1/context` — fetch from the
  local daemon (plan A transport); picks up `stable_hash` for receipt linkage.
  The endpoint must itself be local (same allowlist).
- Neither — passthrough mode: no injection, end-state receipts still minted.

Other flags: `--session-id`, `--receipts-spool <path>`, `--no-daemon-receipts`.

## v1 protocol limitations (deliberate)

- One request per connection; responses are `Connection: close` +
  EOF-delimited (no keep-alive, no chunked re-encoding). OpenAI SDKs and curl
  handle this fine.
- Chunked request bodies → `411 Length Required`.
- The bundle is read once at startup — restart the shim to pick up a new
  bundle. (Per-request re-fetch would churn the stable prefix and defeat
  prompt caching; deliberate, not a TODO.)

## Receipt record shapes

JSON drafts with field names mirroring `corecrux-receipts::stream_v1` (the
daemon-side signer), schema-tagged `cuecrux.mediation.shim.v1`:

```json
{"schema":"cuecrux.mediation.shim.v1","kind":"context_injected","receipt_id":"shim-…-1",
 "session_id":"…","bundle_version":"context_bundle/v1","stable_hash":"blake3:…",
 "bundle_digest":"sha256:…","injection_point":"llm_shim","upstream":"http://127.0.0.1:11434",
 "path":"/v1/chat/completions","created_at":"…"}

{"schema":"cuecrux.mediation.shim.v1","kind":"stream_completed","receipt_id":"shim-…-2",
 "session_id":"…","provider":"llm_shim","model":"llama3.2","stream":true,
 "first_token_at":"…","ended_at":"…","output_digest":"sha256:…",
 "injected_stable_hash":"blake3:…","injected_bundle_digest":"sha256:…","created_at":"…"}
```

Digests are algorithm-prefixed because the canonical daemon-side hash is
blake3 — an unlabeled hex string would invite cross-algorithm comparison bugs.

## Smoke

`crates/crux-claude-hooks/tests/llm_shim_e2e.rs` boots the real shim against
a stub upstream and covers: injection + passthrough fidelity (params/tools),
verbatim SSE streaming, truncated-upstream and unreachable-upstream
end-states, 411 on chunked bodies, allowlist refusals, and the two-sided
receipt trail. For a live check against a local Ollama:

```bash
CRUX_LLM_SHIM=1 crux-llm-shim --upstream http://localhost:11434 \
  --bundle-file /tmp/bundle.md --receipts-spool /tmp/shim-receipts.jsonl &
curl -s http://127.0.0.1:11435/v1/chat/completions -d \
  '{"model":"llama3.2","messages":[{"role":"user","content":"what context were you given?"}]}'
tail -2 /tmp/shim-receipts.jsonl   # context_injected + stream_completed
```
