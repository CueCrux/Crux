# Security Policy

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email **security@cuecrux.com** with:

1. Description of the vulnerability
2. Steps to reproduce
3. Affected versions
4. Impact assessment (your best estimate)

## Response Timeline

| Stage | Target |
|---|---|
| Acknowledgment | 48 hours |
| Assessment | 7 days |
| Fix release | 30 days |

CROWN receipt integrity bugs are treated as **critical severity** regardless of exploitability.

## Scope

| In scope | Out of scope |
|---|---|
| `corecruxd` daemon | VaultCrux hosted platform |
| `corecruxctl` CLI | Third-party dependencies (report upstream) |
| All `corecrux-*` crates | Social engineering |
| CROWN receipt generation/verification | |
| BLAKE3 chain integrity | |
| Tenant isolation | |

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | Current release |
| < 0.1 | Best effort |

## Recognition

Accepted reports receive credit in CHANGELOG.md and any published security advisory.

## Encryption

For sensitive reports, request our PGP key via security@cuecrux.com.
