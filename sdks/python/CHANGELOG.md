# Changelog

## 0.3.0 — 2026-08-08

**Renamed.** This package was published as `corecrux-client` through 0.2.0.
`corecrux` is an internal crate and database namespace, not a product, and it
should never have been the name a user types. The distribution is now
`cuecrux-client`, matching `@cuecrux/client` on npm, and the import is
`cuecrux_client`.

- `pip install cuecrux-client` (was `corecrux-client`)
- `from cuecrux_client import CueCruxClient` (was `from corecrux_client import CoreCruxClient`)
- `CoreCruxClient` → `CueCruxClient`, `AsyncCoreCruxClient` → `AsyncCueCruxClient`,
  `CoreCruxError` → `CueCruxError`

No behaviour changes. Versions continue from 0.2.0 rather than restarting, so
the number still reads forward for anyone moving across. `corecrux-client` is
yanked on PyPI and receives no further releases.

## 0.2.0 — 2026-08-07

- Cover the context, review, consolidation, ingest, extension and event
  surfaces — previously the client stopped at facts, sessions and query.
- Add `subscribe_events()` to both clients (sync generator and async
  generator), reaching parity with the TypeScript SDK's event support.
- `consolidate()` sends `consolidation_id: ""` when the caller omits it: the
  daemon has no serde default for the field, so an absent key is rejected (422)
  even though a blank one is filled in with `console-<uuid>`.
- Add a wire-shape test suite (stdlib `unittest`, no new dependencies),
  including a test that the sync and async surfaces never drift apart, and run
  it in CI.

## 0.1.0 — 2026-06-12

- Initial public release.
