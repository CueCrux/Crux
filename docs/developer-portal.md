# Developer Portal

This page is the stable entrypoint for building against the local-first Crux
daemon. Start here when you need the HTTP API, MCP surface, SDK lifecycle, or
offline receipt verification path.

## API Contract

- HTTP base: `http://127.0.0.1:14800`
- MCP base: `http://127.0.0.1:14801/mcp`
- OpenAPI: `GET /v1/openapi.json`
- Human route notes: [api-reference.md](api-reference.md)
- Error format: [RFC 7807 Problem Details](api-reference.md#error-format)

The launch-default single-user loopback rail is `dev_scopes`. Local examples
use explicit scope headers so the same requests fail closed when you switch to
JWT auth:

```bash
curl -s http://127.0.0.1:14800/v1/openapi.json | jq '.info.title'

curl -s "http://127.0.0.1:14800/v1/facts?query=hello&token_budget=500" \
  -H "X-Corecrux-Scopes: query:read" | jq .
```

Every retrieval call should carry an explicit `token_budget`. Use `500` for
small confirmations and raise it only when the caller needs more context.

## Agent And MCP Integration

- [Agent guide](agent-guide.md) covers install UUIDs, bootstraps, fact writes,
  retrieval, and handoff posture.
- [MCP system prompt](mcp-system-prompt.md) is the recommended runtime protocol
  for agents connected to the daemon.
- [Session handshake](session-handshake.md) documents the plan and invocation
  receipts that bind an agent session to its local identity.
- [LLM shim](llm-shim.md) documents the local shim for context injection and
  mediation receipts.

## Receipt Verification

Crux verification is offline-first. The CLI can check the on-disk store, inspect
individual receipts, and verify typed receipt bodies without calling a hosted
service.

```bash
corecruxctl verify-store --data-dir ./data --scope recent
corecruxctl verify-store --data-dir ./data --scope all --mode full --strict
corecruxctl inspect-receipt <receipt-id> --data-dir ./data
corecruxctl receipts verify-external-anchor --body receipt-body.cbor
corecruxctl receipts verify-rfc3161-timestamp --body receipt-body.cbor
corecruxctl receipts verify-chain-reanchor --body receipt-body.cbor
```

The bytes-first receipt contract is in [spec/receipt-v1.md](spec/receipt-v1.md).
Release artifact verification is separate and lives in
[verify-release.md](verify-release.md).

## SDKs

The in-repo SDKs are the supported public SDK surface:

- [sdks/python](../sdks/python)
- [sdks/typescript](../sdks/typescript)
- [sdk-release-lifecycle.md](sdk-release-lifecycle.md)

Generated clients should be pinned to the daemon release they target and
regenerated from `/v1/openapi.json` when the HTTP API moves.

## Contracts

- [contracts/README.md](contracts/README.md) documents the CRC-v1 response
  envelope.
- [contracts/crc-v1.schema.json](contracts/crc-v1.schema.json) is the JSON
  schema used by the contract fixtures.
- [error-catalogue.md](error-catalogue.md) lists stable problem details.
