# Packaging

Installer + package-manager sources for the Crux daemon. Threat ref **T.5**
governs everything here: no pipe-to-shell, signed artifacts only, signature
verification *before* install, no phone-home, nothing auto-starts.

| Path | What |
|---|---|
| `install.sh` | Audited installer (download → read → verify → run). Attached to each release so it is covered by the signed manifest. Hard-requires `cosign`; refuses unverified binaries. `--uninstall` keeps data. |
| `systemd/crux.service` | System-wide unit (shipped in the .deb; `DynamicUser` + `StateDirectory=crux`). `install.sh --with-service` writes a per-user unit instead. |
| `homebrew/crux.rb` | Formula **template** for `CueCrux/homebrew-tap`; rendered per release by `scripts/generate-homebrew-formula.sh` from the *verified* signed manifests. |
| `deb/` | nfpm config + maintainer scripts + `build-deb.sh` for the `.deb` attached to releases (no apt repo in v1 — see header comment in `deb/nfpm.yaml`). |
| `tests/install-smoke.sh` | Clean-VM gate: install → ready → MCP handshake → uninstall (data preserved). Operator-run against a published release. |

Posture rules every installer here follows:

1. **Verify, then install.** cosign keyless verification against the release
   workflow identity ([docs/verify-release.md](../docs/verify-release.md)).
2. **Never auto-start.** Units/agents are written to disk; the
   enable/start command is printed for the user to run.
3. **No phone-home.** Installed services set
   `CORECRUXD_UPDATE_CHECK_ENABLED=0`; upgrades are explicit
   (`install.sh --version vX.Y.Z`, `brew upgrade crux`, `dpkg -i`).
4. **Uninstall never deletes data.** Export first (console → Settings →
   Export); deleting `CORECRUXD_DATA_DIR` is the user's explicit command.
