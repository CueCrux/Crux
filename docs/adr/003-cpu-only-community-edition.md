# ADR-003: CPU-Only Community Edition

**Status:** Accepted
**Date:** 2026-04-07

## Context

CoreCrux has a proprietary edition with GPU-accelerated data-plane operations (append, read, replay) via CUDA. The Community Edition is source-available under CCL v1.0 and must be fully functional without GPU hardware or CUDA dependencies.

## Decision

The Community Edition ships CPU-only. All GPU/CUDA code has been stripped:

1. **`dataplane_store.rs` and `pool.rs`** are type-compatible stubs. They provide the type definitions (`AppendError`, `DataPlanePool`, etc.) needed for API compatibility, but `DataPlanePool` is unconstructable and `DataPlaneStore` methods are `unreachable!()`.

2. **gRPC data-plane RPCs** (AppendBatch, ReadStream, etc.) return `Status::UNIMPLEMENTED` with the message "requires the proprietary edition".

3. **HTTP handlers** behind `if let Some(pool)` guards return 501 Not Implemented.

4. **Community Edition features** work without the data-plane: fact store, session store, BM25 text search (via `.ccxi` companion indexes), CROWN receipts, Prometheus metrics, and the MCP tool server.

The `gpu_id: Option<i32>` field in shard routing metadata is retained — it's an architectural routing concept, not a CUDA dependency.

## Consequences

- Contributors cannot reconstruct the proprietary data-plane from the Community Edition source.
- The gRPC proto contract is identical between editions — clients can target either without code changes.
- CPU-only text search via BM25 is functional but does not include the GPU-accelerated vector paths available in the proprietary edition.
- The stub pattern means `Option<DataPlanePool>` appears throughout the codebase; this is intentional scaffolding, not dead code.
