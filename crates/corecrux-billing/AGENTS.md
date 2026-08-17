# corecrux-billing — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

The comped-wallet **credit ledger** — an append-only journal of wallet seeds,
reservations, spends and voids. Not to be confused with `crux-cost`, which analyses
transcripts into cost *reports* (what a session appears to have cost); this crate
owns what a tenant was actually granted and debited.

## Key symbols
- `credit_meter::CreditMeterStore::open` / `open_with_reservation_ttl`
- `seed_comped_wallet` — grant credit to a tenant
- `reserve` → `spend` — the two-phase debit; `void_reservation` releases an unspent hold
- `available_balance` — granted minus spent minus outstanding reservations
- `CreditMeterError` — every refusal path (insufficient credit, conflict, mismatch)

## Invariants
- Money path. The journal is **append-only**: never rewrite or delete a prior event;
  a correction is a new event.
- A reservation is pinned to its quote by a BLAKE3 payload hash. A spend whose
  payload does not match its reservation is refused (`OperationPayloadMismatch`),
  never silently re-priced.
- `reserve` is idempotent per `(tenant, operation_id)` — a retry returns the existing
  reservation instead of double-holding. Same for `spend`.
- A tenant can never overspend: concurrent reserves are checked against
  `available_balance`, not the raw grant.

## Test & verify
- `cargo test -p corecrux-billing`
- `cargo build -p corecrux-billing` standalone — must compile with no daemon present.
- The fail-closed behaviour is tested in the *daemon*, not here:
  `corecruxd`'s `http::credit_meter::tests::poisoned_meter_fails_closed_without_spending`.

## Local rules
- **Do not add poison recovery to this crate.** When the caller's `Mutex` is poisoned,
  the fail-closed decision (500, no debit) lives with the lock owner in
  `corecruxd/src/http/credit_meter.rs`. A store that recovered its own poisoned state
  would be serving from state whose last writer panicked mid-update — on a money path
  that can permit an untracked debit.
- Every new ledger event needs a schema tag and must round-trip through the journal;
  an event that cannot be replayed from disk is a data-loss bug.
- No pricing policy here. This crate records debits; what something *costs* is decided
  upstream and arrives as a pinned quote.
