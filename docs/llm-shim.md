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
