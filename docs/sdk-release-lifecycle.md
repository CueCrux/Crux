# SDK release lifecycle

Policy for every published CueCrux SDK package. In this repo:
`@cuecrux/client` (npm, `sdks/typescript/`), `cuecrux-client` (PyPI,
`sdks/python/`) and `cuecrux-adapters` (PyPI, `integrations/adapters/`,
depends on `cuecrux-client`). The same policy governs portfolio packages
published from other repos (`@cuecrux/engine-client`) — link here rather
than fork the rules.

This is a **policy document**: it changes how releases are made, but reading
it never publishes anything, and adopting it is gated (see "Adoption gates").

## Versioning

- **Semver, strictly.** Breaking change to a public type, function signature,
  default, or wire expectation → major. Additive → minor. Fix → patch.
- SDK versions are **decoupled from the daemon version**. Daemon `v*` tags
  build and package both SDKs but never receive registry-write permission.
  Publishing requires an explicit `sdk-python-vX.Y.Z`,
  `sdk-typescript-vX.Y.Z` or `adapters-vX.Y.Z` tag, and the tag must
  exactly match the package version in `pyproject.toml`/`package.json`.
  `adapters-v*` refuses to publish until its `cuecrux-client` requirement
  resolves from PyPI, so release the Python SDK first.
- Each SDK declares the **API version it was generated/tested against** in
  its README and in package metadata, pinned to the daemon's
  `/v1/openapi.json` at the release commit. Generated clients are regenerated
  per daemon release; if regeneration produces no diff, no SDK release
  happens.
- Pre-1.0 (current state: both SDKs are 0.x): minor = may break, patch =
  safe. Say so in the README until 1.0.

## Compatibility & deprecation

- **n−1 support**: the current and previous major (after 1.0; current and
  previous *minor* while 0.x) receive fixes. Older lines get security fixes
  only, for 6 months, then EOL.
- Deprecations ship as warnings one release before removal, with a
  `@deprecated`/`DeprecationWarning` pointing at the replacement, and are
  listed in the changelog under a dedicated heading.
- The daemon keeps wire compatibility for `n−1` SDKs: a route or field an SDK
  in support depends on is not removed without a daemon major/breaking-notes
  entry.

## Publish integrity (T.5)

Current state: all three publish jobs use OIDC (`sdk-python.yml` since
#180, `sdk-typescript.yml` since `0e1b4903`, `adapters.yml` publish job).
No registry token is read by any workflow. What remains is registry-side
(see "Adoption gates").

1. **npm: provenance attestation.** `npm publish --access public
   --provenance` with `permissions: id-token: write` on the publish job.
   Links the published tarball to the exact workflow run + commit (Sigstore),
   verifiable via `npm audit signatures`. Long-lived `NPM_TOKEN` is replaced
   by npm **Trusted Publishing (OIDC)** so no registry secret lives in CI.
2. **PyPI: Trusted Publishing.** Replace the `PYPI_TOKEN` + twine flow with
   the `pypa/gh-action-pypi-publish` OIDC flow. PyPI side: project →
   Publishing → add GitHub publisher (`CueCrux/Crux`,
   `sdk-python.yml`). Generates PEP 740 attestations automatically. The
   `PYPI_TOKEN`/`NPM_TOKEN` secrets are deleted after cutover.

Do not add token-secret publish jobs.

## Release procedure (per SDK)

1. Bump version + changelog entry in the SDK directory (PR, normal review).
2. Regenerate from `/v1/openapi.json` if the daemon API moved; commit the
   regenerated client in the same PR with the API version pin updated.
3. Tests and reproducible packaging green in PR CI. Daemon tags repeat the
   build/package job but skip the publish job.
4. Push `sdk-python-vX.Y.Z`, `sdk-typescript-vX.Y.Z` or `adapters-vX.Y.Z`.
   A manual dispatch is build-only and cannot publish.
5. Post-publish: `npm audit signatures` / check the PyPI attestation badge;
   yank only for malware/credential incidents — broken releases are
   superseded by a patch, never unpublished (matches the binary-release
   supersede-never-delete rule).

Registry immutability is fail-closed. Do not use `skip-existing`: a matching
filename/version does not prove artifact identity and could hide an SDK source
change that was not accompanied by a version bump.

## Adoption gates (operator actions — nothing here is done by docs alone)

- [x] PR #172 merged (workflow-change freeze lifts).
- [x] Workflows on OIDC: `sdk-typescript.yml`, `sdk-python.yml`,
      `adapters.yml` (no environment; PyPI/npm publisher environment blank).
- [ ] npm: Trusted Publisher on `@cuecrux/client` = `CueCrux/Crux`,
      workflow `sdk-typescript.yml`.
- [ ] PyPI: pending publisher for `cuecrux-client` = `CueCrux/Crux`,
      workflow `sdk-python.yml` (the existing publisher covers only the old
      `corecrux-client` name).
- [ ] PyPI: pending publisher for `cuecrux-adapters` = `CueCrux/Crux`,
      workflow `adapters.yml`.
- [ ] Delete the unused `NPM_TOKEN` repo secret after one successful
      OIDC publish.
- [ ] First provenance-attested releases verified (`npm audit signatures`,
      PyPI attestation present) and recorded in the release notes.
