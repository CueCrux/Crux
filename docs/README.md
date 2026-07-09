# Crux Documentation

Start here if you want to install, verify, operate, or integrate the free
Crux daemon. Crux is local-first: the daemon, console, HTTP API, and MCP
server run on your machine without a hosted account.

## First Run

- [Getting started](getting-started.md) - install, boot, connect an agent,
  store the first fact, and verify a receipt.
- [Verify releases](verify-release.md) - check signatures, SBOMs, images, and
  SLSA provenance before installing.
- [Troubleshooting](troubleshooting.md) - common startup, auth, WSL2, and
  port issues.

## Operator Docs

- [Operations guide](ops-guide.md) - daemon operation, backups, upgrades, and
  production-minded checks.
- [Incident communications](incident-comms.md) - paid-tenant incident timeline
  and update templates.
- [Release packaging](release-packaging.md) - supported launch artifacts and
  installer posture.
- [Update channel](update-channel.md) - explicit upgrade behavior and version
  notifications.
- [Testing and coverage](testing-and-coverage.md) - how the release gates and
  coverage numbers are measured.

## Developer and Agent Integration

- [Developer portal](developer-portal.md) - OpenAPI, RFC 7807 errors,
  receipt verification, SDKs, and contracts.
- [API reference](api-reference.md) - HTTP, gRPC, and MCP surfaces.
- [Agent guide](agent-guide.md) - using Crux as an agent memory and retrieval
  backend.
- [Session handshake](session-handshake.md) - identity, install UUIDs, and
  session binding.
- [MCP system prompt](mcp-system-prompt.md) - recommended agent runtime
  protocol.
- [LLM shim](llm-shim.md) - local shim behavior for LLM-facing integrations.

## Trust Surface

- [Threat model](THREAT_MODEL.md) - security assumptions and boundaries.
- [Trust Contract](../TRUST-CONTRACT.md) - the promises the daemon makes,
  each verifiable from this repository's source.
- [Agent codebase docs](../AGENTS.md) - reading order, crate atlas, claims,
  and invariants for AI agents exploring or modifying this repo.
- [Usage receipts](usage-receipts.md) - consent-gated, signed usage pings.
- [Activity log](activity-log.md) - signed activity and receipt timelines.
- [Benchmarks](benchmarks.md) - reproducible performance baselines.
- [Security policy](../SECURITY.md) - private vulnerability reporting and
  supported versions.

## More

- [Architecture](architecture.md) - the daemon's major internal planes.
- [Lens cookbook](lens-cookbook.md) - linking capabilities, tasks, and plans.
- [Licence FAQ](LICENCE-FAQ.md) - practical notes on the CueCrux Community
  Licence.
