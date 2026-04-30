# Crux Daemon Release Packaging

Release bundles are produced by `scripts/package-daemon-release.sh`.

Each target bundle includes:

- `corecruxd-<target>` as the canonical daemon binary.
- `crux-<target>` as the user-facing alias for the same daemon binary.
- `corecruxctl-<target>` for administrative checks and store verification.
- `LICENCE-CODE.md`, `LICENCE-CONTENT.md`, and `TRUST-CONTRACT.md`.
- `README.md` and `config.example.yaml`.
- `content/MANIFEST.json` and `content/README.md`.
- `RELEASE-MANIFEST-<target>.txt` with SHA-256 checksums for staged files.

`scripts/assert-daemon-release-boundary.sh` verifies the required files, CUDA/GPU
exclusion boundary, package-script artifact markers, and a package smoke test
whenever release binaries already exist under `target/release`.

Enterprise customer-hosted installs can set the `enterprise` block in
`config.example.yaml` or the corresponding `CORECRUXD_ENTERPRISE_*` environment
variables. `corecruxd` validates the configured trust root on startup before any
customer-hosted backend can be used.
