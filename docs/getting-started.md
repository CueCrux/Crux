# Getting started with Crux

From zero to a **verifiable receipt** in about ten minutes: install (≈5
minutes), boot, connect your first agent harness, store a fact, and prove the
receipt catches tampering. Crux is a single local-first binary — no account,
no telemetry, no outbound connections (verify that yourself:
`scripts/assert-no-phone-home.sh`).

Pick one install path, then continue at [First boot](#2-first-boot).

## 1. Install (~5 minutes)

Release binaries are cosign-signed; native installer targets also carry SLSA
provenance. Whatever path you choose, verify the artifact **before** anything
runs — copy-paste commands and the cross-build provenance boundary live in
[verify-release.md](verify-release.md).

### Option A — installer script (macOS, Linux, WSL2)

Resolve the exact release, download the installer and its signature, verify it,
then read and run it. We never ask you to pipe a URL into a shell, and the
installer refuses to install binaries that fail signature verification (it
needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)).

```bash
REPO=CueCrux/Crux
TAG="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
  "https://github.com/${REPO}/releases/latest" | sed 's|.*/tag/||')"
BASE="https://github.com/${REPO}/releases/download/${TAG}"
curl -fsSLO "${BASE}/install.sh" \
  -O "${BASE}/install.sh.sig" \
  -O "${BASE}/install.sh.pem"
cosign verify-blob \
  --certificate install.sh.pem \
  --signature install.sh.sig \
  --certificate-identity \
    "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  install.sh
less install.sh
bash install.sh --version "${TAG}"  # add --with-service for a service unit
```

Installs `crux`, `corecruxd` (same binary, service-manager name),
`corecruxctl`, and `crux-hook` into `~/.local/bin`, and creates a private data
dir (`~/.local/share/crux`, mode 0700). Nothing is auto-started.

Re-run the verified installer to upgrade the complete set together. Packaged
installs refuse daemon-only `crux self update` so the CLI and hook cannot be
left on an older version.

### Option B — Docker / Podman

Pull-only compose stack with a pinned version, non-root runtime, and a
healthcheck: [examples/quickstart/](../examples/quickstart/). Or minimally:

```bash
docker run -d --name crux \
  -p 127.0.0.1:14800:14800 -p 127.0.0.1:14801:14801 \
  -v crux-data:/data \
  -e CORECRUXD_AUTH_MODE=dev_scopes \
  -e CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND=1 \
  -e CORECRUXD_HTTP_HOST=0.0.0.0 -e CORECRUXD_MCP_HOST=0.0.0.0 \
  ghcr.io/cuecrux/crux-daemon:latest
```

`:latest` tracks the newest **release tag**, not `main`. Verify the image
signature by digest first ([verify-release.md §4](verify-release.md)).

### Option C — Debian / Ubuntu (.deb)

```bash
TAG=v0.5.0   # pick the release you want
curl -fsSLO "https://github.com/CueCrux/Crux/releases/download/${TAG}/crux-daemon_${TAG#v}_amd64.deb"
# verify its cosign signature first — verify-release.md §1, same flags
sudo dpkg -i "crux-daemon_${TAG#v}_amd64.deb"
```

Ships a systemd unit that is installed but **not** enabled; start it when you
choose: `sudo systemctl enable --now crux` (data in `/var/lib/crux`).

### Option D — Homebrew

```bash
brew tap cuecrux/tap && brew install crux
```

(Available once the tap is published alongside the first public release.)

### Windows

Native Windows builds are post-v1. Use WSL2 with Option A — it is a
first-class, continuously-dogfooded path. WSL2 specifics are in
[Troubleshooting](#troubleshooting) below.

### Build from source

Rust 1.88+, `protobuf-compiler`, then `cargo build --locked --release`. See
the [README Quickstart](../README.md#quickstart).

#### Cargo feature flags

The default build is the Community Edition daemon. All optional surfaces are
off by default; enable them with `--features`:

| Feature | Default | What it adds |
|---|---|---|
| `hosted-surfaces` | off | Hosted-service HTTP surfaces: the Pro GPU-1 compute bridge (`/v1/gpu1/*`) and the Pro cloud access posture (`GET /v1/cloud/access-contract`). Compiled entirely out of the default Community Edition binary — the routes 404 and their handler code is absent — so a stock build advertises and serves neither. |
| `wasm-extensions` | off | wasmtime-backed host for `kind: wasm` community extensions. |
| `otel` | off | OpenTelemetry OTLP export. |

Runtime env flags (e.g. `CORECRUXD_CONTEXT_SURFACE`, `CORECRUXD_QUOTA`) gate
routes that are always *compiled in* but return 404 until enabled; the
`hosted-surfaces` cargo feature is different — it removes the routes and
handlers from the binary at build time.

## 2. First boot

If you installed a service unit, start it (`systemctl --user enable --now
crux` / `launchctl load ...` / `sudo systemctl enable --now crux`).
Otherwise, foreground:

```bash
CORECRUXD_AUTH_MODE=dev_scopes CORECRUXD_DATA_DIR=~/.local/share/crux crux
```

`CORECRUXD_AUTH_MODE` must be set explicitly — there is no default.
`dev_scopes` is right for a single-user loopback install; use `off` only for
throwaway local experiments, and `jwt_hs256`/`jwt_jwks` for anything shared
(see [config.example.env](../config.example.env)).

Now open **<http://127.0.0.1:14800>** — the embedded console (it ships inside
the binary; works fully offline) runs a one-time setup: auth posture, health
check. Or probe from the shell:

```bash
curl -sf http://127.0.0.1:14800/readyz          # {"ok":true}
curl -sf http://127.0.0.1:14800/v1/version | jq '.version, .product.tier'
```

Prefer a guided tour? `corecruxctl quickstart` walks config → health → first
fact → query → cleanup interactively.

## 3. Connect Claude Code

The daemon's MCP server listens on `http://127.0.0.1:14801/mcp`:

```bash
claude mcp add --transport http crux http://127.0.0.1:14801/mcp
```

Start a new Claude Code session and the `mcp__crux__*` tools (`store_fact`,
`query_facts`, `query`, `save_session`, …) are available. If the daemon runs
with agent tokens (`CRUX_AGENT_TOKEN`), pass the matching
`Authorization: Bearer` header — see
[examples/mcp-configs/](../examples/mcp-configs/) for header-carrying configs.

Optional but worth it: the [Claude Code observation hooks](../integrations/claude-code/)
capture every session lifecycle event as an Ed25519-signed observation —
verifiable evidence, not a self-reported log.

## 4. The first receipt (the point of all this)

Store a fact — from the Claude Code session you just connected ("store a fact
that the rollout completed"), or by hand:

```bash
curl -s -X PUT http://127.0.0.1:14800/v1/facts \
  -H "Content-Type: application/json" \
  -H "X-Corecrux-Scopes: facts:write,facts:read" \
  -d '{"entity":"getting-started","key":"first_fact","value":"stored at minute ten"}' | jq .
```

Every state mutation produces a signed CROWN receipt. See it in the console
(Facts → entity timeline), then prove the signature actually protects you —
this 60-second demo seeds a receipt, verifies the store, flips one byte on
disk, and watches verification fail:

```bash
bash scripts/demo-receipt-tamper.sh
```

That failure is the product: your agent's memory is evidence, not vibes.

## 5. Connect a second harness

The same daemon serves every harness on this machine — that's the
continuity story (one memory, many agents):

- **Codex CLI**: [integrations/codex-cli/](../integrations/codex-cli/) —
  stdio MCP shim + observation hooks.
- **Claude Desktop / Cursor**: ready-made configs in
  [examples/mcp-configs/](../examples/mcp-configs/).
- Anything that speaks MCP: point it at `http://127.0.0.1:14801/mcp`.

Facts stored from Claude Code are immediately queryable from the second
harness (`query_facts` on the same entity).

## Troubleshooting

**WSL2** (this is our daily test bed):

- Backgrounding the daemon from a script: a bare `&` is fragile under WSL
  tty-detach. Use `setsid nohup crux < /dev/null > crux.log 2>&1 &` then
  `disown` — or just use the systemd user unit (`install.sh --with-service`),
  WSL2 ships systemd by default these days.
- Windows-side browsers reach the console via `http://127.0.0.1:14800`
  (localhost forwarding is automatic; if you've disabled it, use the WSL
  interface IP from `ip addr show eth0`).
- Keep the data dir on the Linux filesystem (`~/.local/share/crux`), not
  under `/mnt/c` — 9p file locking will hurt you.

**Port already in use**: something else owns 14800/14801. Override with
`CORECRUXD_HTTP_PORT` / `CORECRUXD_MCP_PORT` (don't change them without
reason — 14800 is the documented Crux port).

**401/403 on `/v1/*`**: your auth mode wants scopes or a JWT. For
`dev_scopes`, send `X-Corecrux-Scopes` as in the examples; for JWT modes see
[session-handshake.md](session-handshake.md).

**"Pro required" / 501 on some routes**: the free local daemon is CPU-only
and some capabilities are hosted-only (GPU rerank/enrich, managed sync). The
boundary is machine-readable: `curl -s localhost:14800/v1/version | jq
'.product.capability_catalog'`. Free-tier routes never require an account.

**More**: [troubleshooting.md](troubleshooting.md), [ops-guide.md](ops-guide.md).

## Upgrade

Upgrades are always explicit — the daemon never updates automatically:

```bash
bash install.sh --version vX.Y.Z   # re-verifies signatures; data is kept
# or: brew upgrade crux / dpkg -i the new .deb / bump CRUX_VERSION in compose
```

Previous-version binaries stay downloadable forever (releases are superseded,
never deleted), so pinning back is the same command with an older tag.

## Uninstall

```bash
bash install.sh --uninstall        # removes binaries + service unit
```

Your data is **never** deleted by uninstall. Export it first if you're
leaving (console → Settings → Export, or `GET /v1/facts/export`), then remove
the data dir yourself: `rm -rf ~/.local/share/crux`. Docker: `docker compose
down -v` deletes the volume — same rule, your explicit `-v`.
