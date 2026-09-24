# Changelog

## 0.4.0 — 2026-09-22

- Add `post_mediation_receipt(draft)` to both clients: `POST
  /v1/mediation/receipts`, which mints a signed receipt from a draft
  (`model_invocation` and the other stream kinds need
  `CORECRUXD_STREAM_RECEIPTS=1` on the daemon). Callers no longer have to
  reach for the private `_request`.
- Add `verify_receipt(receipt_id, tenant_id=...)` to both clients:
  `GET /v1/receipts/{id}/verification`. `tenant_id` is required, as it is
  daemon-side; stream-kind receipts are minted under `"local"`.
- Add `aggregate_observations(kind=..., limit=..., ...)` to both clients:
  `GET /v1/observations/aggregate`, where a daemon without a dataplane serves
  stream receipts' signed bodies (`payload.body_cbor_hex`).
- Fix: values interpolated into a URL path (`get_facts_by_entity(entity)`,
  session, fact, receipt, candidate and extension ids) were sent unencoded, so
  an entity containing `/` got a 404 and one containing `?`, `#` or `%` quietly
  read a different entity (usually an empty list). Each is now
  percent-encoded as a single path segment; the daemon decodes it back. A
  value of `.` or `..` is sent as `%2E` / `%2E%2E`, since httpx resolves bare
  dot-segments (`get_facts_by_entity("..")` would otherwise read
  `GET /v1/facts`, other entities' facts). Non-string ids (a `UUID`, an
  `int`) are sent as `str(value)`, as before the encoding change.
- Fix: `query_facts(..., token_budget=...)` raised `KeyError: 'value'` once
  the result crossed the budget's hydration boundary, because the daemon drops
  `value` from those rows and sets `value_omitted: true`. `Fact.value` is now
  `None` on such rows and the new `Fact.value_omitted` flag says why.

0.3.0 was never tagged or published to PyPI (the last `sdk-python-v*` tag is
0.2.0), so 0.4.0 is the first `cuecrux-client` release and carries the 0.3.0
rename below as well — the same path `@cuecrux/client` took to its 0.4.0.

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
