<!--
Copyright (c) 2026 CueCrux Ltd. All rights reserved.
Licensed under the CueCrux Community Licence (CCL v1.0).
-->

# M9 — RCX Registry + WikiCrux shell tabs (design + gate matrix)

ExecPlan `crux-desktop-mission-control-2026-07-19`, milestone **M9**. Registry
(`registry.rcxprotocol.org`) and WikiCrux open as tabs in the desktop shell and
web viewer behind one SSO session; a receipt's verification link resolves
in-console. This document records the design and marks which parts are
verifiable now vs. operator/hardware/SSO-gated — the milestone's acceptance gate
(one login across both surfaces on both webview engines) cannot be established
from a headless Linux/WSL host, so M9 ships as this spec plus the small
buildable pieces noted below.

## The one structural rule: tabs are zero-native-capability remote origins

Registry and WikiCrux are **external origins**. Per the M1 security boundary
(`shells/desktop/connection/src/navigation.rs`), the shell grants **zero Tauri
IPC / filesystem / keychain / updater capability** to any non-daemon origin, and
the credential broker's bearer never reaches page JS. M9 must not weaken this:

- A shell tab that loads `registry.rcxprotocol.org` or the WikiCrux origin runs
  in a webview with **no** registered Tauri command, an explicit CSP, and a
  navigation policy that permits only that origin's own navigations. It is a
  sandboxed viewport, not a trusted surface.
- The connection broker/proxy and its session cookie (`__crux_proxy`) are
  **per-daemon-origin** and are **never** exposed to a registry/wiki tab
  (different origin; SameSite=Strict + HttpOnly already prevent leakage).
- `is_public_http_link` already classifies external `http(s)` targets; M9 adds a
  small **tab allowlist** (exact registry + wiki origins) so those two — and only
  those two — may open as in-shell tabs rather than being handed to the system
  browser. Everything else keeps the M1 behaviour (tray-approved system-browser
  open).

## Identity: one SSO session (dependency, not built here)

"One login across console + registry + wiki" is the SSO leg owned by
`cross-site-auth-sso-cuecrux-2026-07-13`. M9 **consumes** that session; it does
not implement cross-origin auth. Until SSO is live, the tabs render the
surfaces' own unauthenticated/logged-out state (honest degraded, not an error).
Session propagation to a third-party origin inside a webview (cookie/partition
behaviour) differs between WebKitGTK (Linux) and WebView2 (Windows) — this is the
core of the operator test matrix below.

## Receipt → registry verification link (buildable)

A CROWN receipt already anchors to the RCX Registry for external verification.
The console can render a receipt's verification link as a normal external link
that resolves against `registry.rcxprotocol.org` — this is a pure URL
construction from the receipt id and needs no SSO. This is the one M9 piece that
is verifiable headless and should land as a small console change (a
`registryVerifyUrl(receiptId)` helper + the link on the session-detail receipt
chip from M4b), guarded so it is an external link (M1 policy), never an embed.

## Gate matrix

| Gate item | Verifiable now? | Owner |
|---|---|---|
| Tab allowlist restricts in-shell tabs to exactly the registry + wiki origins | Yes (unit-testable in the connection crate, like `is_public_http_link`) | build |
| Tabs receive zero native capability (no IPC command, explicit CSP, origin-locked navigation) | Partly (config asserted; runtime needs a real webview) | build + operator |
| `registryVerifyUrl(receiptId)` resolves to a registry verification URL and renders as an external link on the receipt chip | Yes (console smoke) | build |
| One login across console + registry + wiki | **No** — needs live SSO (`cross-site-auth-sso`) | operator |
| Works on both WebKitGTK (Linux) and WebView2 (Windows): login, logout, account-switch, token-expiry, offline, blocked-framing, deep-link | **No** — needs both real webview engines + packaged app | operator (folds with M6b) |
| Tabs degrade gracefully offline | Partly (logic testable; real offline needs a webview) | build + operator |

## Recommended M9 landing

1. **Build now** (this PR is design-only; the code is a small follow-up): the tab
   allowlist in `connection/navigation.rs` (unit-tested) + `registryVerifyUrl`
   console helper on the M4b receipt chip (smoke-tested) + the zero-capability
   CSP/navigation config for the two tab origins.
2. **Operator pass** (folds with M6b packaging on a real Win11+WSL2 box, once SSO
   is live): the two-engine login/session matrix above.

Rationale for shipping the design first: the acceptance gate is SSO- and
webview-engine-bound, so building the viewport code before the SSO session and
real engines exist would be unverifiable — the honest sequence is spec now, the
small allowlist/link code next, and the matrix at the operator packaging pass.
