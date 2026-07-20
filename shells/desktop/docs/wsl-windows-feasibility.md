<!--
Copyright (c) 2026 CueCrux Ltd. All rights reserved.
Licensed under the CueCrux Community Licence (CCL v1.0).
-->

# M6a — Windows/WSL2 feasibility spike

ExecPlan `crux-desktop-mission-control-2026-07-19`, milestone **M6a**. Early spike:
does the desktop shell's **attach** mode (a Windows-side app reaching a WSL2-side
`corecruxd`) work over the WSL2 network boundary, and by which path? Go/no-go before
committing the M6b packaging program.

## Test environment (real box)

Measured on the developer workstation on 2026-07-20:

| Property | Value |
|---|---|
| Host | Win11 + WSL2 (`MYLES-PC`) |
| WSL kernel | `5.15.167.4-microsoft-standard-WSL2` |
| Networking mode | **NAT** (`.wslconfig` has no `networkingMode=mirrored`) |
| `localhostForwarding` | **on** (default; not disabled in `.wslconfig`) |
| WSL `eth0` | `172.30.129.210/20` (NAT-assigned, **changes across reboots**) |
| Tailnet | `tailscale0 = 100.92.27.92/32` (stable) |

Note: kernel 5.15 predates the mirrored-networking default; mirrored mode is **not
active** here and would require Win11 22H2+, a current WSL, and an explicit
`networkingMode=mirrored`.

## Reachability matrix — Windows app → WSL2 `corecruxd` (attach mode)

| # | Path | Works? | Notes / caveats |
|---|---|---|---|
| 1 | **`localhost` forwarding** (NAT default): Windows `http://127.0.0.1:<port>` → WSL daemon | **Primary** | localhostForwarding maps Windows loopback to WSL. Reliable for a daemon bound to `0.0.0.0:<port>` in WSL; **historically flaky for a `127.0.0.1`-bound service** in WSL. Attach mode requires auth (OD-42), so a `0.0.0.0` bind behind that auth is acceptable and the reliable choice. **Windows→WSL reach must be confirmed on the box** (cannot be tested from inside WSL). |
| 2 | WSL `eth0` IP (`172.30.x.x:<port>`) | Yes, but unstable | Direct, but the NAT IP changes across reboots → not a stable profile URL. |
| 3 | **Tailnet IP** (`100.92.27.92:<port>`) | **Robust fallback** | Stable, independent of WSL networking mode, and already authenticated at the tailnet layer. The M1 connection manager accepts any attach URL, so a tailnet-IP profile works today with no shell change. |
| 4 | Mirrored mode (`127.0.0.1` bidirectional) | N/A here | The clean future default (no per-service bind gymnastics), but needs the upgrades above. Document as the recommended target once the box is on a mirrored-capable WSL. |
| 5 | hvsock / named-pipe proxy (Docker Desktop pattern) | Fallback only | The documented fallback **iff** a Unix-socket surface is ever needed (microsoft/WSL#5961). `corecruxd` speaks HTTP/TCP, so this is **not required** for the primary path. |

Firewall: loopback-forwarded traffic (path 1) does not prompt Windows Defender; a
fresh `0.0.0.0` listen may prompt once on first bind (operator allows).

## Go / no-go

**GO.** The attach path is viable today with no shell change:
- **Primary:** `localhost` forwarding (NAT, default-on) with the WSL attach-daemon
  bound `0.0.0.0:<port>` **behind the M1 auth broker** (bundled mode keeps its
  loopback-only, auth-off sidecar unchanged).
- **Fallback:** a tailnet-IP attach profile — stable across reboots and networking
  modes.

The M1 connection manager (both-modes, credential broker, health/degraded rendering)
already supports both as ordinary attach profiles by URL.

## Deferred to the M6b operator packaging pass

These cannot be established from inside WSL and fold into M6b's real-hardware run:
- Windows `127.0.0.1:<port>` actually reaching a WSL-bound daemon (path 1), for both
  `0.0.0.0` and `127.0.0.1` WSL binds, with the Defender prompt behavior recorded.
- Persistence of `localhost` forwarding across reboot + WSL restart.
- Windows installer/autostart/tray-survives-close/reboot-reattach (M6b proper).
- The mirrored-mode retest once the box is on a mirrored-capable WSL.
