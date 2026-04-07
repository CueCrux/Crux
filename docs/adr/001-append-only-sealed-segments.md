# ADR-001: Append-Only Storage with Sealed Segments

**Status:** Accepted
**Date:** 2026-04-01

## Context

CoreCrux stores events for long-term memory retrieval. The storage engine must support high-throughput appends, crash recovery, and cryptographic integrity verification. Traditional mutable databases allow in-place updates, which complicates integrity proofs and replay auditing.

## Decision

Events are written to an append-only log within **segments**. Once a segment reaches its size threshold, it is **sealed**: a BLAKE3 hash of the entire segment is computed, a trailer index is written, and the segment becomes immutable. Sealed segments are never modified.

Key properties:
- **Append path:** New events are written to the head (unsealed) segment. Commit markers record durable write boundaries.
- **Seal path:** When the head segment exceeds `segment_target_bytes`, it is sealed and a new head segment is created.
- **Crash recovery:** On startup, the daemon replays from the last commit marker. Partially-written frames after the marker are discarded.
- **Integrity:** `corecruxctl verify-store` walks sealed segments and recomputes BLAKE3 hashes. Any mismatch is flagged.

## Consequences

- Events cannot be deleted or modified after write. This is intentional — it ensures the CROWN receipt chain is verifiable.
- Storage grows monotonically. Operators must provision sufficient disk or use segment rotation policies.
- Replay is deterministic — given the same sealed segments, any instance will produce identical state.
