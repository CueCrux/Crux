+++
name = "pre-deploy-gate"
version = 1
description = "Preflight checklist before prod deploys. Codifies the Insights-report `Deployment Gate` snippet (~978 wasted compute hours from prerequisite mismatches)."
targets = ["claude_md", "agents_md"]
order = 50
risk_class = "medium"
+++

## Pre-Deploy Gate

Before deploying to a prod target (`corecrux-gpu-1`, `cuecrux-data-1`, container images, hosted daemons), run the preflight checklist. **Every item must pass before the deploy step.**

### Migration state

- All DB migrations present in order. List them: `ls db/migrations/` (or equivalent) and confirm contiguous numbering.
- Recent migrations applied locally and idempotent on re-run.
- No pending migration referenced in code but missing from the migration directory.

### Environment

- Required env vars present in the target's env (`CRUX_AGENT_TOKEN`, `CORECRUXD_AUTH_MODE`, `DATABASE_URL`, etc.). Do not assume the prod env mirrors local.
- Secrets sourced from passport-derived envelopes or vault — never `cat`'d into a file you write.
- Disk + memory headroom checked: `df -h` shows >10% free on the data partition; `free -g` shows headroom for the build process.

### Process management

- Long-running jobs use `setsid + nohup + < /dev/null + disown` (the WSL-tested triad). Bare `&` is fragile under tty-detach.
- Background workers have a documented stop command. Don't `kill -9` a partially-flushed writer.

### Deploy command discipline

- Use `cargo-deploy` (with `--backup-binary`) — not bare `cargo build --release`. Bare-cargo on prod bypasses drift tracking.
- After deploy: run `corecruxd-deploy-audit` to confirm running binary sha matches the latest tag.
- Smoke probe immediately after: `curl /readyz`, then one substantive endpoint.

### When something fails

- Don't retry blindly. Check logs (`journalctl -u corecruxd` or container logs) before the next attempt.
- Capture the failure as a Crux fact: `store_fact(entity="incident:<YYYY-MM-DD>", value={symptom, cause, fix_sha, repro_steps})`.

### Three-place wiring

When introducing a new on-disk artifact type (companion file, projection, lens kind), update all three wiring points: storage allowlist, projection registry, and load-at-startup. Missing any one creates a quarantine-on-restart class of bug.
