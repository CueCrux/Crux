# corecrux Helm chart

This chart is **not launch-supported** for the public Crux Daemon release line.

It remains in-tree as historical packaging work, but it is pinned to the old
`0.1.0` surface and does not expose the current daemon's MCP/gRPC ports,
release verification flow, or launch-default configuration. Do not use it as a
fresh-install path for the production cutover. Its retained defaults still set
`CORECRUXD_ROUTE_AUTH=enforce` so an accidental evaluation install does not
silently use shadow route authorization.

Supported launch install paths are documented in:

- [`../../docs/getting-started.md`](../../docs/getting-started.md)
- [`../../packaging/README.md`](../../packaging/README.md)
