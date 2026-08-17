# Crux Daemon Release Packaging

Release bundles are produced by `scripts/package-daemon-release.sh`.

Each target bundle includes:

- `corecruxd-<target>` as the canonical daemon binary.
- `crux-<target>` as the user-facing alias for the same daemon binary.
- `corecruxctl-<target>` for administrative checks and store verification.
- `crux-hook-<target>` for agent lifecycle hooks, including encrypted
  compaction snapshot sync.
- `LICENSE` (code licence), `NOTICE` (attribution), and `TRUST-CONTRACT.md`. The code licence is
  published to scanners as SPDX `Apache-2.0` (crate manifests + `.rs`
  headers); see [docs/LICENCE-FAQ.md](LICENCE-FAQ.md) → "machine-readable
  metadata".
- `README.md` and `config.example.yaml`.
- `content/MANIFEST.json`, `content/CONTENT-README.md`, and
  `content/LICENCE-CONTENT.md` (the content guide is renamed while staging so
  its basename remains distinct in GitHub's flat release-asset namespace; the
  content licence is shipped with the assets it governs).
- `RELEASE-MANIFEST-<target>.txt` with SHA-256 checksums keyed by the flat
  public release-asset basenames. Packaging and release creation both fail if
  two staged files would share a basename.

`scripts/assert-daemon-release-boundary.sh` verifies the required files, CUDA/GPU
exclusion boundary, package-script artifact markers, positive and negative
basename-guard fixtures, and a package smoke test whenever release binaries
already exist under `target/release`.

The boundary script proves only the local daemon distribution shape:

- required daemon, alias, CLI, hook, licence, trust-contract, README, config,
  content, and release-manifest files are present in the staged package
- hosted GPU/CUDA surfaces are excluded from the daemon package
- package-script smoke markers are produced for the staged binaries

It does not prove hosted backend behavior, GPU/CUDA acceleration, production
deployment safety, Trivy scan results, cosign signatures, SLSA provenance, or
runtime configuration on an operator host. Those are covered by the Docker and
release workflows, [docs/verify-release.md](verify-release.md), and any
deployment-specific ExecPlan gate.

Container release scans fail on actionable CRITICAL vulnerabilities by default.
If a Trivy outage or registry failure forces an emergency skip, the Docker
workflow requires a structured waiver with owner, expiry, reason, commit SHA,
run ID, and image reference, and uploads it as a 90-day artifact.

Enterprise customer-hosted installs can set the `enterprise` block in
`config.example.yaml` or the corresponding `CORECRUXD_ENTERPRISE_*` environment
variables. `corecruxd` validates the configured trust root on startup before any
customer-hosted backend can be used.
