# Self-hosted CI runner operator guide

The Crux Daemon CI matrix (`.github/workflows/ci.yml` jobs `Lint`, `Test`, `MSRV`, `Coverage`, plus the rustdoc / licence / advisory checks) runs on **self-hosted GitHub Actions runners** labelled `[self-hosted, ci]`. That choice is deliberate: the workspace builds 26 Rust crates, the full test suite takes ~10 minutes on a warm runner, and caching is reliable when CARGO_HOME is on stable disk.

This guide documents how to provision a fresh runner and how to recover when an existing one breaks.

## When you'd reach for this guide

Any of these symptoms on a CI run:

- `error: linker 'cc' not found` (the runner is missing the C build toolchain).
- `sudo: a password is required` during `taiki-e/install-action` (the runner user lacks passwordless sudo, so the action can't install missing tools).
- `error: failed to run custom build command for proc-macro2` and similar build-script crashes that have nothing to do with the code.
- Every job in the matrix failing within 9–15 seconds of starting.

The fix is at the OS level, not in the workflow.

## One-shot provision

Get onto the runner host (SSH; the host is on Tailscale per `[[prod-ops-cheatsheet]]`). As a user with sudo:

```bash
cd /path/to/Crux               # any checkout of this repo
sudo bash scripts/provision-self-hosted-runner.sh
```

The script (also linked here for reference: `scripts/provision-self-hosted-runner.sh`):

1. Installs the build toolchain (`build-essential`, `pkg-config`, `libssl-dev`, `clang`, `lld`, `curl`, `jq`, `git`, `cmake`, `protobuf-compiler`). Picks `apt-get` or `dnf` based on what's available.
2. Writes `/etc/sudoers.d/gha-runner-nopasswd` with `gha-runner ALL=(ALL) NOPASSWD:ALL`. `taiki-e/install-action` needs this; without it the action retries `sudo` repeatedly and then bails after ~1 minute.
3. Verifies `cc --version` runs and that `gha-runner` can `sudo -n true` without prompting.

Override the runner user with `RUNNER_USER=alice sudo -E bash scripts/provision-self-hosted-runner.sh` if your installation uses a different account.

After the script succeeds, restart the runner service so it picks up the new sudoers file:

```bash
sudo systemctl restart actions-runner.gha-runner.service   # systemd
# or:
sudo /home/gha-runner/actions-runner/svc.sh stop && sudo /home/gha-runner/actions-runner/svc.sh start
```

## Detecting the broken state without an SSH

A new preflight step in every `ci.yml` job (`Preflight: verify build toolchain`) probes for `cc` + passwordless sudo before any expensive cargo work. When it fails, the log contains:

```
::error::Self-hosted runner is missing C build toolchain (cc not found).
::error::Run scripts/provision-self-hosted-runner.sh on the runner host.
```

That's the cue to come back here.

## Unblock without a runner fix: the fallback workflow

If you need to merge before the runner is fixed, every PR can opt into `ubuntu-latest` runners by adding the `ci:fallback` label. The workflow `.github/workflows/ci-fallback.yml` is identical to `ci.yml` except for the `runs-on` line.

The fallback path is slower (cold caches every run, no CARGO_HOME on stable disk) and shouldn't become the default — it exists so an operator can ship one urgent PR without rebuilding the self-hosted runner first.

## Historical incidents

| Date | Symptom | Root cause | Fix |
|---|---|---|---|
| 2026-05-19 | `cc not found` + `sudo password required` on Crux PR #84 | Runner image had no build-essential; gha-runner user lacked passwordless sudo. | Manual remediation (apt install + sudoers edit). Recorded as fact `incident:2026-05-19, key=crux-ci-runner-broken`. This script + runbook codify the durable fix. |

## See also

- Workflow: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
- Fallback workflow: [`.github/workflows/ci-fallback.yml`](../.github/workflows/ci-fallback.yml)
- Provision script: [`scripts/provision-self-hosted-runner.sh`](../scripts/provision-self-hosted-runner.sh)
- Ops cheatsheet (Tailscale SSH targets): `[[prod-ops-cheatsheet]]` in PlanCrux MEMORY.md
