# Crux daemon — container quickstart

Pull-only compose stack for running the published Crux daemon image. No
source checkout, no local build. For the build-from-source stack, use the
`docker-compose.yml` at the repository root instead.

> [!WARNING]
> This is a loopback-only, single-user development stack. Its `dev_scopes`
> mode trusts caller-supplied scopes, so do not expose it through a reverse
> proxy, tunnel, or public interface. For shared use, deploy the standalone
> [`../remote/`](../remote/) stack behind TLS.

## 1. Verify the image (once per version)

Every published image is signed (cosign keyless) and carries a CycloneDX
SBOM attestation. Verify by digest before first use — copy-paste commands in
[`docs/verify-release.md`](../../docs/verify-release.md) §4.

## 2. Start

```bash
docker compose -f docker-compose.yml up -d
curl -sf http://127.0.0.1:14800/readyz
```

Then open <http://127.0.0.1:14800> — the embedded Crux Console walks you
through one-time setup (auth posture, health check).

Pin a version (recommended — `:latest` tracks the newest *release tag*, not
`main`):

```bash
CRUX_VERSION=0.5.0 docker compose -f docker-compose.yml up -d
```

## Conventions

| Thing | Convention |
|---|---|
| Image | `ghcr.io/cuecrux/crux-daemon:<X.Y.Z>` (also `:latest` = newest release, `:edge` = main) |
| User | non-root, uid/gid `65532:65532` |
| Data | single volume at `/data` (`CORECRUXD_DATA_DIR`) — this is *all* daemon state; back it up, you can move hosts with it |
| Ports | HTTP API + console `14800`, MCP `14801` — published on loopback only |
| Health | `GET /readyz` (wired as the container healthcheck) |
| Logs | JSON on stdout (`CORECRUX_LOG_FORMAT=json`) |
| Runtime | read-only root, all capabilities dropped, privilege escalation disabled, restricted `/tmp` tmpfs |

### Bind mounts

Named volumes inherit `/data` ownership from the image. If you bind-mount
instead, chown the host directory to the runtime uid first:

```bash
mkdir -p ./crux-data && sudo chown -R 65532:65532 ./crux-data
```

### No phone-home

The free-tier daemon makes no outbound connections — no telemetry, no
account, no update polling (`CORECRUXD_UPDATE_CHECK_ENABLED=0` here; the
git-drift probe only applies to repo-checkout deploys). Outbound features
(sync, remote embeddings) are opt-in env configuration.

## Smoke test (clean machine)

```bash
docker compose -f docker-compose.yml up -d
# wait for healthy
docker compose -f docker-compose.yml ps --format '{{.Name}} {{.Health}}'
curl -sf http://127.0.0.1:14800/readyz && echo OK
# MCP handshake (initialize over streamable HTTP)
curl -sf -X POST http://127.0.0.1:14801/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
```

## Stop / remove

```bash
docker compose -f docker-compose.yml down        # keeps the data volume
docker compose -f docker-compose.yml down -v     # deletes daemon state too
```
