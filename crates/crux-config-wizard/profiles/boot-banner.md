+++
name = "boot-banner"
version = 1
description = "Crux boot-banner three-channel contract: statusline, agent brief, conditional first-reply card."
targets = ["claude_md", "agents_md"]
order = 47
risk_class = "low"
+++

## Crux Boot Banner

The session-boot banner is three channels, not one blob. Each has its own
audience and a strict cost budget — do not merge them or echo one into another.
`corecruxctl hooks install` wires all three.

### Channel 1 — statusline (persistent human surface, 0 model tokens)

`~/.local/bin/crux-statusline`, wired via `statusLine` in `settings.json`. It
renders under the input box on every transcript change and NEVER enters model
context. The hot path reads a 60s-TTL cache (`~/.cache/crux/statusline.json`); a
stale/missing cache renders the last snapshot immediately and spawns a detached
`--refresh` that does the network I/O — so boot never blocks on the daemon.
Colour grammar: green healthy, amber behind/degraded, red blocked/down. A dead
daemon shows `CRUX ✗ unreachable` (today a dead daemon is otherwise
indistinguishable from a quiet one).

### Channel 2 — agent brief (additionalContext, ≤400 tokens)

`~/.local/bin/crux-claude-banner` emits the §11.1 boot-ritual result as terse
`key: value` lines — no markdown tables, no console URLs (agents can't click).
Cache-aligned per the M2 design: **stable lines first** (pattern NAMES only —
never bodies; pull those on demand via `get_bootstrap`), volatile lines (counts,
live sessions) last, so the shared prefix stays cache-hot across the session.
This is the model's context; keep it lean (~350 tokens, not ~1,500).

### Channel 3 — conditional first-reply card (human, ~120 tokens)

The brief ends with an echo instruction that fires a 7-line CRUX card in the
first reply **only when attention is needed**: `need_you > 0` (blocked items +
pending gates), a degraded daemon, or binary-drift-behind. Otherwise a single
`⧉ Crux engaged` line. The card is signal, not chrome — src-clone drift alone
never triggers it.

### Switches (`~/.config/cuecrux/env`)

- `CRUX_BANNER_AGENT=brief|off` (default `brief`) — throwaway `-p` runs set
  `off`; the hook then emits nothing.
- `CRUX_BANNER_CARD=auto|always|off` (default `auto` = attention-conditional).
- `CRUX_STATUSLINE=on|off` (default `on`).

### Update-drift semantics (don't deploy-gate on the wrong basis)

`update_status` reports a `basis`:

- `basis=binary` — real drift of the **running daemon** (post-M6a daemons).
  Trustworthy: amber `▲n` chip, "binary behind by n — rebuild/redeploy before
  relying on new features".
- `basis=checkout` (or absent) — drift of the **source clone** `update_status`
  tracks, NOT the deployed binary. Labelled `▲n src` (dim), never presented as
  daemon staleness. Do not deploy-gate on a checkout-basis number — verify the
  binary's own commit (`/v1/version`) first.
