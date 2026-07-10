# Operations Guide

## Networked Deployment Auth Preflight

Before exposing a Crux Daemon beyond the host, run the deploy audit in the
same environment that will launch `corecruxd`:

```bash
corecruxctl deploy-audit --network-exposed
```

The command resolves `CORECRUXD_AUTH_MODE`, `CORECRUXD_HTTP_HOST`, and
`CORECRUXD_GRPC_HOST` with the daemon's environment-over-YAML precedence. Use
`--config /path/to/config.yaml` when auditing a config outside
`CORECRUXD_CONFIG_PATH` / `$XDG_CONFIG_HOME/crux/config.yaml`. Explicit
`--auth-mode`, `--http-bind`, and `--grpc-bind` overrides are available for
rendered container or service-manager configuration. `--json` emits a report
suitable for deployment logs.

| Effective listeners / surface | `dev_scopes` (including the unset audit default) | `jwt_hs256` / `jwt_jwks` | `off` |
|---|---|---|---|
| Loopback (`127.0.0.0/8`, `::1`) or Unix socket | PASS (with proxy-exposure warning) | PASS | WARN (throwaway local development only) |
| Non-loopback, enterprise/hosted mode, or `--network-exposed` | **FAIL** | PASS | **FAIL** |
| Unclassifiable bind | WARN | PASS | WARN |

`dev_scopes` trusts caller-provided scope headers and therefore disables the
tenant guard at a network trust boundary. The audit exits non-zero for unsafe
or invalid configurations; warnings remain zero-exit so operators can handle
environment-specific uncertainty explicitly.
`CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND=1` is a daemon development escape hatch,
not a deploy-audit waiver: network-exposed `dev_scopes` still fails this check.
JWT secret/JWKS validity remains enforced by daemon startup; this assertion is
specifically the required bind-by-auth-mode deployment gate.

The daemon's public `/healthz`, `/readyz`, and redacted `/v1/version` responses
do not report auth mode, so the audit does not try to infer it over HTTP. A
loopback listener may still be exposed by a reverse proxy, container port
publication, SSH tunnel, or service mesh; pass `--network-exposed` in those
deployments. This operator preflight is intentionally not a CI gate because CI
cannot know a target host's network topology.

## Incident Communications

Paid-tenant incidents use the customer-facing template in
[incident-comms.md](incident-comms.md). Keep the technical incident record in
Crux facts or the owning ExecPlan, but publish customer updates from that
template so the external timeline, impact statement, mitigation, and next
update time stay consistent. The status-page provider and staffing owner are a
launch gate, not a daemon code default.

## Rate Limiting

Crux Daemon includes a transport-level global request cap and a coarse
client-IP rate limiter. Production deployments should still put a TLS
reverse proxy (nginx, Caddy, Envoy) in front and configure route-specific rate
limits there.

Daemon-side rate limiting keys by effective client IP. `X-Corecrux-Passport-Id`
is validated at ingress but is not trusted as a pre-auth rate-limit key.
Forwarded client IP headers are ignored unless the proxy peer is listed in
`CORECRUXD_TRUSTED_PROXY_CIDRS`.

For same-host proxies, either:

- keep proxy-side rate limits authoritative; or
- set `CORECRUXD_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128` and configure the
  proxy to strip inbound `Forwarded` / `X-Forwarded-For` before setting them
  from the real client address.

When forwarded headers arrive from an untrusted peer, the daemon ignores them
and suppresses loopback exemption for that request. This gives an unconfigured
same-host proxy one shared daemon bucket rather than an unlimited loopback
bypass.

### Recommended Limits

| Endpoint | Recommended limit | Rationale |
|----------|-------------------|-----------|
| POST /v1/admin/append (+ `/v1/append` alias) | 100 req/s | Write path; disk I/O bound |
| POST /v1/query/* | 200 req/s | Read path; CPU-bound BM25 |
| PUT /v1/facts | 50 req/s | In-memory + journal write |
| GET /v1/facts/export | 10 req/s | Full scan; expensive |
| GET /healthz | Unlimited | Health probes |
| GET /metrics | 10 req/s | Prometheus scrape |

### Example: Caddy rate limiting

Use the `rate_limit` directive from the
[caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) plugin:

```caddyfile
:14800 {
    reverse_proxy localhost:14800

    rate_limit {
        zone append {
            key    {remote_host}
            events 100
            window 1s
        }
        zone query {
            key    {remote_host}
            events 200
            window 1s
        }
        zone facts_export {
            key    {remote_host}
            events 10
            window 1s
        }
    }

    @append  path /v1/admin/append /v1/append
    @query   path /v1/query/*
    @export  path /v1/facts/export

    handle @append  { rate_limit append }
    handle @query   { rate_limit query }
    handle @export  { rate_limit facts_export }
}
```

### Example: nginx rate limiting

```nginx
http {
    # Define rate-limit zones (per client IP)
    limit_req_zone $binary_remote_addr zone=append:10m  rate=100r/s;
    limit_req_zone $binary_remote_addr zone=query:10m   rate=200r/s;
    limit_req_zone $binary_remote_addr zone=facts_w:10m rate=50r/s;
    limit_req_zone $binary_remote_addr zone=export:10m  rate=10r/s;
    limit_req_zone $binary_remote_addr zone=metrics:10m rate=10r/s;

    server {
        listen 14800;

        location = /v1/admin/append {
            limit_req zone=append burst=20 nodelay;
            proxy_pass http://127.0.0.1:14800;
        }

        location = /v1/append {
            limit_req zone=append burst=20 nodelay;
            proxy_pass http://127.0.0.1:14800;
        }

        location /v1/query/ {
            limit_req zone=query burst=40 nodelay;
            proxy_pass http://127.0.0.1:14800;
        }

        location = /v1/facts {
            limit_req zone=facts_w burst=10 nodelay;
            proxy_pass http://127.0.0.1:14800;
        }

        location = /v1/facts/export {
            limit_req zone=export burst=2 nodelay;
            proxy_pass http://127.0.0.1:14800;
        }

        location = /healthz {
            # No rate limit — health probes must always succeed.
            proxy_pass http://127.0.0.1:14800;
        }

        location = /metrics {
            limit_req zone=metrics burst=2 nodelay;
            proxy_pass http://127.0.0.1:14800;
        }

        location / {
            proxy_pass http://127.0.0.1:14800;
        }
    }
}
```

### What happens without rate limiting

Without rate limiting, a burst of append requests can:

- Exhaust disk I/O bandwidth (sealed segment writes)
- Cause backpressure on the JSONL journal
- Increase response latency for all endpoints

The daemon will not crash but will degrade gracefully.

## Segment Corruption Recovery

CoreCrux uses append-only sealed segments with BLAKE3 integrity hashes.

### Detection

```bash
corecruxctl verify-store --data-dir ./data --scope all --mode full --strict
```

Reports structural/CRC failures and, with `--strict`, sealed segments whose decoded BLAKE3 hash
does not match the manifest.

### Recovery

1. **Quarantine the corrupted segment**: Move it to a backup directory
   ```bash
   mv data/shards/0/segments/seg_corrupted.ccxseg data/quarantine/
   ```

2. **Restart the daemon**: It will replay from the last good commit marker
   ```bash
   CORECRUXD_DATA_DIR=./data ./corecruxd
   ```

3. **Verify integrity after restart**:
   ```bash
   corecruxctl verify-store --data-dir ./data --scope all --mode full --strict
   ```

### Prevention

- Use filesystem-level snapshots (ZFS, LVM) for point-in-time recovery
- Run `verify-store --scope recent` as a daily cron job and schedule `--scope all --mode full --strict` during maintenance windows
- Monitor the `corecrux_segment_corrupt_total` Prometheus metric
- Enable capacity guards (`CORECRUXD_CAPACITY_GUARD_ENABLED=1`) to prevent writes when disk is low

### Before upgrades

- Check `/v1/version` or the MCP `update_status` tool before changing a running node.
- If the update state is `behind`, take a snapshot of `CORECRUXD_DATA_DIR` or an equivalent volume backup before pulling and rebuilding.
- If the update state is `ahead` or `diverged`, do not blind-pull. Review local commits first and use a human-approved merge or rebase flow.
- After the upgrade, rerun `corecruxctl verify-store --data-dir ./data --scope recent`; run the strict full scan when the maintenance window allows, and confirm the update state has moved to `current` or the expected tracked position.

### What data is lost

Sealed segments are immutable — corruption in a sealed segment means those events are unrecoverable from this node. Use receipt export (`/v1/replay/exports/receipts/{id}`) to verify which events had receipts issued before the corruption window.

Facts stored via the fact store (`/v1/facts`) are journaled separately in `facts.jsonl` and are unaffected by segment corruption.
