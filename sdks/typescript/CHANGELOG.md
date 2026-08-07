# Changelog

## 0.3.0 — 2026-08-07

- Cover the context, review, consolidation, ingest, extension and event
  surfaces — previously the client stopped at facts, sessions and query.
- Add `streamEvents()`, a `fetch`-based async iterator over
  `GET /v1/events/stream`. Unlike `subscribeEvents()` it needs no `EventSource`
  global (still absent in Node 22.x) and can send the `Authorization` header,
  so it works against a daemon with auth on. `subscribeEvents()` is unchanged.
- Declare `"type": "module"`. The build has always emitted ESM, but without
  this Node only loaded it through syntax-detection fallback, with a warning
  and a documented performance cost.
- `consolidate()` sends `consolidation_id: ""` when the caller omits it: the
  daemon has no serde default for the field, so an absent key is rejected (422)
  even though a blank one is filled in with `console-<uuid>`.
- Complete the `CruxEvent` union — it named 4 of the daemon's 9 event types.
  `CruxEventType` is now derived from the exported `CRUX_EVENT_TYPES`.
- Add a wire-shape test suite (`npm test`, stdlib `node:test`, no new
  dependencies) and run it in CI.

## 0.2.0 — 2026-07-22

- Add optional update-comparison basis and checkout/binary commit fields to
  `VersionResponse`, matching the current daemon response while retaining
  compatibility with older daemons.

## 0.1.0 — 2026-06-12

- Initial public release.
