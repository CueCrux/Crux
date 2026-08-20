---
name: pre-deploy-gate
description: "Preflight checklist that must pass before anything changes on a CueCrux prod target — corecrux-gpu-1, cuecrux-data-1, container images, hosted daemons. Covers migration state, the target's env vars and disk/memory headroom, cargo-deploy --backup-binary versus bare cargo build, the post-deploy binary-sha audit and smoke probe, and how to handle a failed step. Invoke when the user says: 'deploy', 'deploy the daemon', 'ship it to prod', 'push to gpu-1', 'push to data-1', 'roll out', 'cut a release and deploy', 'build and push the image', 'repoint :edge', 'restart the hosted daemon', or before running cargo-deploy, crux-deploy.sh, or deploy-train.sh."
---

# Pre-Deploy Gate

Before deploying to a prod target (`corecrux-gpu-1`, `cuecrux-data-1`, container images, hosted
daemons), run this checklist. **Every item must pass before the deploy step.**

This is the Insights-report `Deployment Gate` snippet, which attributed ~978 wasted compute hours to
prerequisite mismatches. Check every item against the target itself, not against your assumptions
about the target.

## Migration state

- All DB migrations present in order. List them: `ls db/migrations/` (or equivalent) and confirm contiguous numbering.
- Recent migrations applied locally and idempotent on re-run.
- No pending migration referenced in code but missing from the migration directory.

## Environment

- Required env vars present in the target's env (`CRUX_AGENT_TOKEN`, `CORECRUXD_AUTH_MODE`, `DATABASE_URL`, etc.). Do not assume the prod env mirrors local.
- Secrets sourced from passport-derived envelopes or vault — never `cat`'d into a file you write.
- Disk + memory headroom checked: `df -h` shows >10% free on the data partition; `free -g` shows headroom for the build process.

## Process management

- Background workers have a documented stop command. Don't `kill -9` a partially-flushed writer.

The process-detachment triad for long-running jobs is not deploy-scoped, so it stays in `CLAUDE.md`
rather than being restated here — it has to be in context before this skill would ever load.

## Deploy command discipline

- Use `cargo-deploy` (with `--backup-binary`) — not bare `cargo build --release`. Bare-cargo on prod bypasses drift tracking.
- After deploy: run `corecruxd-deploy-audit` to confirm running binary sha matches the latest tag.
- Smoke probe immediately after: `curl /readyz`, then one substantive endpoint.

## When something fails

- Don't retry blindly. Check logs (`journalctl -u corecruxd` or container logs) before the next attempt.
- Capture the failure as a Crux fact: `store_fact(entity="incident:<YYYY-MM-DD>", value={symptom, cause, fix_sha, repro_steps})`.

A green `/readyz` is not proof the deploy worked: it stays green through several failure modes this
workspace has hit (a wedged manifest, a stale image tag). The binary-sha audit and one substantive
endpoint are the checks that actually discriminate.
