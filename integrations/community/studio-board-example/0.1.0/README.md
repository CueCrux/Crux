# Example Studio Board pack

A portable **Canvas Studio** board, exported as a `crux.studio.v1` payload
wrapped in a signed `crux.integration.v1` manifest. Import it from the console
Studio ("Import pack"), or install it as a community integration.

## What it contains

- A **Facts** stat tile (`/v1/console/summary` → `stores.facts`, live-refresh).
- A **Sessions** stat tile (`/v1/console/sessions` → `count`).
- A **text-search** tile (`/v1/query/text-search`, honest coverage score).
- A **note** describing the board.

## Trust + safety

- `publisher_passport_fpr` is a deterministic **example identity**, not a real
  publisher. Re-sign with your own Passport key before publishing your own pack.
- Capabilities are the minimal read set the tiles need: `integrations:read`,
  `facts:read`, `sessions:read` — no dangerous capabilities, so no `review.json`
  is required. The pack is inert until an operator grants those capabilities.
- Both hashes are bound: `hashes.manifest` (blake3 over the manifest signing
  payload) and `hashes.bundle` (blake3 over the canonical studio payload).

## Regenerate

```bash
cargo test -p crux-integrations --test community_packs -- --ignored regen_studio_board_example
```

## Publish (the real rail)

Open a PR adding this directory under `integrations/community/`. CI runs
`cargo test -p crux-integrations --test community_packs`; once merged, the
curator-signed community index endorses it for one-click install. There is no
"upload" endpoint — the community registry PR + curator index IS the rail.
