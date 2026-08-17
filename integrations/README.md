# Crux Integration Packs

This folder is the public, PR-reviewable home for community integration packs.

> **Looking for LangChain / LlamaIndex / CrewAI?** Those are *framework
> adapters*, not packs — thin bindings over `GET /v1/context` that inject Crux
> memory into an agent framework. They live in
> [`integrations/adapters/`](adapters/) and follow their own conformance suite.
> Packs, described below, are signed capability bundles the daemon installs and
> sandboxes; the two share nothing but this folder.

Community packs live under:

```text
integrations/community/<pack-id>/<version>/manifest.json
integrations/community/<pack-id>/<version>/README.md
```

Rules:

- Packs must use schema `crux.integration.v1`.
- Packs must be declarative by default; `external_helper` is rejected for community packs.
- Packs must include `hashes.manifest`.
- Packs must include an Ed25519 Passport signature with a public key or trusted keyring entry.
- `publisher_passport_fpr` must be the publisher's Passport fingerprint, not `cuecrux:first-party`.
- Entry paths must be relative and must not contain `..`.
- Packs are inert until a local Passport grant enables exact capabilities.
- Dangerous capabilities require explicit maintainer review in an adjacent `review.json`.

Dangerous capabilities are:

- `admin:read`
- `facts:private:read`
- `integrations:grant`
- `integrations:install`
- `sessions:write`
- `tenant:content:preview`

`review.json` shape:

```json
{
  "maintainer_approval": true,
  "rationale": "Why this dangerous capability is necessary and safe."
}
```

CI validates community packs with:

```bash
cargo test -p crux-integrations --test community_packs
```

