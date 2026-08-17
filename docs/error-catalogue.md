# Error Catalogue

## Error Codes

| Code | HTTP | gRPC | Retryable | Description | Resolution |
|---|---|---|---|---|---|
| IO_READ_FAILED | 503 | UNAVAILABLE | Yes | Segment read failed | Check disk health, permissions |
| IO_WRITE_FAILED | 503 | UNAVAILABLE | Yes | Segment write failed | Check disk space, permissions |
| IO_FSYNC_FAILED | 503 | UNAVAILABLE | Yes | fsync failed | Check filesystem health |
| SEGMENT_CORRUPT | 500 | INTERNAL | No | BLAKE3 hash mismatch | Run `corecruxctl verify-store --mode full --strict` |
| INVALID_FRAME | 500 | INTERNAL | No | Frame header hash mismatch | Usually auto-recovered on restart |
| INVALID_TOC | 500 | INTERNAL | No | Table of contents invalid | Run `verify-store --mode full` |
| SHARD_NOT_OWNER | 412 | FAILED_PRECONDITION | Yes | Wrong shard for this stream | Re-fetch shard map, retry |
| EPOCH_MISMATCH | 412 | FAILED_PRECONDITION | Yes | Shard epoch changed | Retry with updated epoch |
| BACKPRESSURE | 429 | RESOURCE_EXHAUSTED | Yes | System under load | Wait, retry with backoff |
| TIMEOUT | 504 | DEADLINE_EXCEEDED | Yes | Operation exceeded deadline | Retry, check disk latency |
| TOO_EARLY | 425 | FAILED_PRECONDITION | Yes | A mandatory waiting period has not elapsed (e.g. the escrow custodian-share release delay) | Retry after the time given in the response detail; there is no override |
| INTERNAL | 500 | INTERNAL | No | Unexpected error | Report at github.com/CueCrux/Crux |

## MCP Tool Errors

| Code | Tool | Message Pattern | Resolution |
|---|---|---|---|
| -32602 | Any | "missing required param: X" | Check tool inputSchema |
| -32601 | Any | "unknown tool: X" | Call tools/list to discover available tools |
| -32603 | query | "index is empty" | Ingest data first |
| -32603 | accept_handoff | "content hash mismatch" | Package was tampered — reject it |
| -32603 | accept_handoff | "signature verification failed" | Wrong signing key or corruption |

## Retry Strategy

For retryable errors, use exponential backoff:

1. Wait 100ms, retry.
2. Wait 200ms, retry.
3. Wait 400ms, retry.
4. Wait 800ms, retry.
5. Give up and surface the error.

For `BACKPRESSURE` (429), respect the `Retry-After` header if present.

## Diagnostic Commands

| Error | Diagnostic |
|---|---|
| SEGMENT_CORRUPT | `corecruxctl verify-store --scope all --mode full --strict` |
| IO_READ_FAILED | `corecruxctl verify-store --scope recent` |
| SHARD_NOT_OWNER | `corecruxctl shard-map` |
| EPOCH_MISMATCH | `corecruxctl shard-map --show-epochs` |
