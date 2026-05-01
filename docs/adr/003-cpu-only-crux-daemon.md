# ADR-003: CPU-Only Crux Daemon

**Status:** Accepted
**Date:** 2026-04-07

## Context

CoreCrux has dataplane-enabled distributions with GPU-accelerated operations (append, read, replay) via CUDA. The Crux Daemon is source-available under CCL v1.0 and must be fully functional without GPU hardware or CUDA dependencies.

## Decision

The Crux Daemon ships CPU-only. All GPU/CUDA code has been stripped:

1. **`dataplane_store.rs` and `pool.rs`** are type-compatible stubs. They provide the type definitions (`AppendError`, `DataPlanePool`, etc.) needed for API compatibility, but `DataPlanePool` is unconstructable and `DataPlaneStore` methods are `unreachable!()`.

2. **gRPC data-plane RPCs** (AppendBatch, ReadStream, etc.) return `Status::UNIMPLEMENTED` with a clear data-plane-required message.

3. **HTTP handlers** behind `if let Some(pool)` guards return 501 Not Implemented.

4. **Crux Daemon features** work without the data-plane: fact store, session store, BM25 text search (via `.ccxi` companion indexes), CROWN receipts, Prometheus metrics, and the MCP tool server.

The `gpu_id: Option<i32>` field in shard routing metadata is retained — it's an architectural routing concept, not a CUDA dependency.

## Consequences

- Contributors cannot reconstruct the hosted data-plane from the Crux Daemon source.
- The gRPC proto contract is identical between Crux Daemon and dataplane-enabled deployments — clients can target either without code changes.
- CPU-only text search via BM25 is functional but does not include the GPU-accelerated vector paths available in dataplane-enabled distributions.
- The stub pattern means `Option<DataPlanePool>` appears throughout the codebase; this is intentional scaffolding, not dead code.
