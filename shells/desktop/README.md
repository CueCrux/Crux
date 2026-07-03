# Crux desktop shell

A native desktop wrapper around the Crux console. It is a **thin webview over a
bundled `corecruxd` sidecar** — the app spawns the daemon on a loopback port with
auth off, waits for it to become healthy, then loads
`http://127.0.0.1:<port>/console` in a native window. On quit it shuts the daemon
down; no orphan daemon survives the shell.

This is the **desktop shell (M6)** of ExecPlan
[`unified-shell-console-2026-07-03`](../../../PlanCrux/.agent/execplans/unified-shell-console-2026-07-03.md),
housed **in-tree, workspace-excluded** per decision **OD-31**.

## Architecture

```
┌─────────────────────── Crux.app (Tauri v2) ───────────────────────┐
│                                                                    │
│  src/main.rs                                                       │
│    ├─ resolve app-data dir + bundled corecruxd (externalBin)       │
│    ├─ crux-shell-lifecycle::spawn_sidecar()                        │
│    │      env: CORECRUXD_AUTH_MODE=off                             │
│    │           CORECRUXD_HTTP_PORT=<free loopback port>            │
│    │           CORECRUXD_DATA_DIR=<per-user app data>              │
│    │           CORECRUXD_CONSOLE_V2=1                              │
│    ├─ wait_for_health()  →  GET /healthz == 200                    │
│    └─ WebviewWindow → http://127.0.0.1:<port>/console             │
│                                   │                                │
│                                   ▼                                │
│                         ┌──────────────────┐                       │
│                         │  corecruxd        │  (child process,     │
│                         │  127.0.0.1:<port> │   loopback only)     │
│                         └──────────────────┘                       │
│  on close / exit → SidecarHandle::shutdown() (Drop = backstop)     │
└────────────────────────────────────────────────────────────────────┘
```

Two crates, **each its own Cargo workspace** (so the root daemon workspace stays
untouched and the app's webkit stack never blocks the daemon build):

| Crate | Path | Builds on the dev box? | Role |
|---|---|---|---|
| `crux-shell-lifecycle` | `lifecycle/` | **Yes** — std-only, no deps | Spawn / health-poll / shutdown the sidecar. Fully unit-tested. |
| `crux-desktop-shell` | `app/` | **No** — needs webkit2gtk | Tauri v2 window + sidecar wiring. CI-only build. |

### Auth posture

The sidecar binds `127.0.0.1` with `CORECRUXD_AUTH_MODE=off`. There is no
network-exposed, unauthenticated endpoint — the daemon is reachable only from
this machine, and the shell's webview **is** the trusted operator surface. This
matches the v2 console posture derivation in the ExecPlan.

## Build

### Lifecycle crate (any host, including the WSL dev box)

```bash
cargo test --manifest-path shells/desktop/lifecycle/Cargo.toml
```

Green here because it is `std`-only (fake daemon = a canned-`200` `TcpListener`;
`/bin/sleep` stands in for the child in the spawn/shutdown/Drop tests).

### Desktop app (CI or a VM with the webkit toolchain)

The app **cannot** compile on a host without `pkg-config` + webkit2gtk/GTK
(the CueCrux WSL dev box and self-hosted CI runners). Validate its manifests
structurally instead:

```bash
cargo metadata --no-deps --manifest-path shells/desktop/app/Cargo.toml   # parses
python3 -m json.tool shells/desktop/app/tauri.conf.json                  # valid
python3 -m json.tool shells/desktop/app/capabilities/default.json        # valid
```

Full build (GitHub-hosted `ubuntu-latest`, or a dev VM):

```bash
# 1. Linux prerequisites (Tauri v2)
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev libsoup-3.0-dev \
  libjavascriptcoregtk-4.1-dev build-essential curl wget file libxdo-dev libssl-dev pkg-config

# 2. Generate the icon set (not committed — source art in the console assets)
cargo install tauri-cli --version '^2.0'
cargo tauri icon crates/corecruxd/console/assets/CueCrux-Arc-Loop.png \
  --output shells/desktop/app/icons

# 3. Stage the sidecar into the externalBin slot
cargo build --release --bin corecruxd
triple="$(rustc -vV | sed -n 's/^host: //p')"
mkdir -p shells/desktop/app/binaries
cp target/release/corecruxd "shells/desktop/app/binaries/corecruxd-${triple}"

# 4a. Compile gate
cargo build --release --manifest-path shells/desktop/app/Cargo.toml
# 4b. Bundle installers (macOS .dmg/.app, Windows .msi, Linux .deb/.AppImage)
cd shells/desktop/app && cargo tauri build
```

CI does 1–4a on every `shells/desktop/**` PR (`.github/workflows/desktop-shell.yml`);
the bundle (4b) runs as a **non-blocking follow-up** job.

### Icons

Icons are **generated, not committed**. `cargo tauri icon <src.png>` fans a single
source PNG out into `32x32.png`, `128x128.png`, `128x128@2x.png`, `icon.icns`
(macOS) and `icon.ico` (Windows) — the set referenced in `tauri.conf.json`.
Source art: `crates/corecruxd/console/assets/CueCrux-Arc-Loop.png`.

### Per-platform notes

- **macOS**: universal `.app`/`.dmg`; sign + notarise for distribution.
- **Windows**: `.msi` (WiX) / `.exe` (NSIS); the release build hides the console
  window (`windows_subsystem = "windows"`).
- **Linux**: `.deb` + `.AppImage`; requires the webkit2gtk-4.1 runtime.
- The sidecar is delivered via Tauri `externalBin`, laid down next to the app
  executable; `resolve_sidecar_binary()` finds it there at runtime.

## Clean-VM validation checklist (operator gate)

The ExecPlan **M6 gate** is deferred to a manual pass on a **fresh VM** (no
prior CueCrux install). This checklist also folds in the deferred **M5** manual
items so a single operator pass covers both. Run it against the bundle from the
`app-bundle` CI job (or a local `cargo tauri build`).

### M6 — desktop shell

- [ ] **Fresh VM, no prior install.** Clean OS image; confirm no `corecruxd` on
      `PATH`, no `~/.local/share/Crux` (or platform app-data equivalent), no
      existing process: `pgrep -laf corecruxd` returns nothing.
- [ ] **Install the artifact.** Install the `.dmg`/`.msi`/`.AppImage`/`.deb`.
- [ ] **App boots the daemon + console with no prior setup.** Launch Crux; the
      window loads the console (Overwatch landing). Confirm the sidecar came up:
      `pgrep -laf corecruxd` shows exactly one, bound to a loopback port.
- [ ] **Sidecar sha matches its release tag.** Verify the bundled binary is the
      attested release build, not a local rebuild:
      ```bash
      sha256sum "<install-dir>/corecruxd"           # or corecruxctl --version / build sha
      # compare against the release artifact's published sha256 for the tag
      ```
- [ ] **Quit leaves no orphan daemon (the gate).** Close the window / Quit, then:
      ```bash
      sleep 2; pgrep -laf corecruxd     # must return NOTHING
      ```
      Repeat for force-quit of the app window to confirm Drop/exit handlers fire.
- [ ] **Failure dialog.** Simulate a daemon that never becomes healthy (e.g.
      point at a corrupt data dir); confirm the native error dialog appears **and
      names the log path**, and that quitting still leaves no orphan.

### M5 — PWA / phone tier (deferred manual items, same pass)

- [ ] **Offline reload serves the app shell.** In the console (any shell), go
      offline and reload — the service-worker app shell renders (no `/v1/*`
      served stale).
- [ ] **Installability audit passes** (manifest + service worker + icons).
- [ ] **Gate-approval flow at 390px.** The M3 work-gate approve/reject flow
      completes end-to-end at 390px viewport width; touch targets ≥44px.

Record the pass (approving passport + date) per the ExecPlan's medium-risk
human-gate requirement before the desktop artifact ships.
