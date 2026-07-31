# Crux daemon — shared deployment behind TLS

This standalone Compose file is the hardened shared-host posture. It does not
extend either development stack, so it cannot inherit `dev_scopes` or
`CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND`.

It intentionally publishes HTTP and MCP only on host loopback. Run a TLS reverse
proxy on the same host, listening on 443, and proxy to `127.0.0.1:14800` and
`127.0.0.1:14801`. Never expose either upstream as plaintext.

## 1. Verify and select an immutable image

Follow [`../../docs/verify-release.md`](../../docs/verify-release.md) to verify
the image signature and attestations. Export the verified digest, including the
`sha256:` prefix:

```bash
export CRUX_IMAGE_DIGEST='sha256:<64-hex-digest>'
```

The Compose file constructs a digest-qualified GHCR reference and has no tag
fallback.

## 2. Provide distinct credentials

Resolve these values from a host secret manager. Do not put literal values in
`.env`, shell history, Compose overrides, or this repository.
Compose passes them to the container environment, so anyone with Docker-daemon
access can inspect them; treat access to the Docker socket as root-equivalent.

```bash
export CORECRUXD_JWT_HS256_SECRET="$(openssl rand -hex 32)"
export CORECRUXD_JWT_ISS='https://issuer.example.com'
export CORECRUXD_JWT_AUD='crux-daemon'
export CRUX_AGENT_TOKEN="$(openssl rand -hex 32)"
```

The JWT secret signs HTTP/gRPC access tokens. `CRUX_AGENT_TOKEN` is the
independent MCP bearer credential; never reuse the JWT secret, a JWT access
token, or a passport seed. For managed key rotation, configure `jwt_jwks`
instead as documented in [`../../docs/api-reference.md`](../../docs/api-reference.md).

## 3. Render and audit before startup

```bash
docker compose -f docker-compose.yml config --quiet

CORECRUXD_AUTH_MODE=jwt_hs256 \
CORECRUXD_HTTP_HOST=0.0.0.0 \
CORECRUXD_GRPC_HOST=127.0.0.1 \
corecruxctl deploy-audit --network-exposed

docker compose -f docker-compose.yml up -d
curl --fail --silent --show-error http://127.0.0.1:14800/readyz
```

The audit must pass. The public readiness probe is not proof that authenticated
routes work; also exercise one scoped HTTP request and an MCP `initialize` with
the intended credentials before cutover.

## 4. Terminate TLS on port 443

For example, a Caddy process running directly on the host can use separate
names for the API/console and MCP:

```caddyfile
crux.example.com {
    reverse_proxy 127.0.0.1:14800
}

mcp.crux.example.com {
    reverse_proxy 127.0.0.1:14801
}
```

Caddy obtains and renews certificates for public DNS names. Apply firewall,
proxy request-size, trusted-forwarder, and rate-limit policy for your
environment. If the reverse proxy runs in a container instead of on the host,
use an isolated internal Compose network and remove host publication; do not
make the upstream ports public as a shortcut.

## Runtime boundary

The container runs as uid/gid `65532`, drops every Linux capability, forbids
privilege escalation, uses a read-only root filesystem, and permits writes only
to the named `/data` volume and a restricted tmpfs. gRPC is not published.
Back up the data volume and test restoration before relying on the service.
