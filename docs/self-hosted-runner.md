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

## The Windows GUI runner (`[self-hosted, windows-gui]`)

Everything above is about the Linux `[self-hosted, ci]` runners. There is one
other class: a **GUI-capable Windows runner** that exists solely so the desktop
shell's `desktop GUI smoke (windows, interactive session)` job in
[`.github/workflows/desktop-shell.yml`](../.github/workflows/desktop-shell.yml)
can launch the app and watch it.

It is a separate box, with labels that no other job requests, so ordinary CI
never lands on it. The host is on Tailscale per `[[prod-ops-cheatsheet]]`; the
runner itself is a Hyper-V guest on an internal NAT switch, reachable from the
host with PowerShell Direct (`Invoke-Command -VMName …`).

### Why it can't just be another Windows runner

Compiling and bundling prove nothing about whether the app *starts*. A
Tauri/WebView2 window cannot be created without a desktop, which disqualifies
two configurations that otherwise look perfectly healthy:

| Disqualifier | Symptom | Fix |
|---|---|---|
| **Server Core** | no `explorer.exe` anywhere; every GUI assertion fails | Reinstall. Core **cannot** be converted to Desktop Experience — that switch was removed after Server 2012 R2. Apply install image **index 2** (`… Desktop Experience`), not index 1. |
| **Runner in Session 0** | app launches, no window ever appears | The runner must **not** be a Windows service, and must **not** be a scheduled task registered via `Register-ScheduledTask -User/-Password` (that parameter set forces `LogonType=Password`, which is non-interactive). Use `New-ScheduledTaskPrincipal -LogonType Interactive` + `-AtLogOn` under an autologon user. |

The workflow's preflight step asserts both in about five seconds, so a
misconfigured box fails immediately instead of forty minutes later at launch.
Verify by hand with: the SessionId of `Runner.Listener` must match `explorer.exe`
and must not be `0`.

### Provisioning

In the guest, elevated:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\provision-windows-gui-runner.ps1 -RunnerToken <token> -AutologonPassword <password>
```

Mint the token with:

```bash
gh api -X POST orgs/CueCrux/actions/runners/registration-token -q .token
```

The script is idempotent and self-verifying: it refuses to run on Server Core,
installs the toolchain (VS Build Tools VCTools, Git, rustup, `tauri-cli ^2.0` —
the same constraint the Linux jobs use so the lanes cannot drift), upgrades the
WebView2 Evergreen runtime (server images ship an old inbox build), disables the
lock screen and sleep, pre-adds the 14800/14801 firewall rules, and finishes by
asserting that `Runner.Listener` really landed in the interactive session.

Two host-side notes that are easy to get wrong when building the guest:

- **Run the *host's* `bcdboot`**, not the applied image's copy. The image's
  `bcdboot.exe` resolves its DLLs out of the offline `System32` and fails,
  leaving no `bootmgfw.efi` and an unbootable disk — while returning an exit
  code that is easy to log and ignore. Assert `bootmgfw.efi` exists rather than
  trusting the exit code.
- **Nested virtualisation requires static memory.** Enabling
  `Set-VMProcessor -ExposeVirtualizationExtensions $true` (needed for WSL2
  inside the guest) is incompatible with dynamic memory, and needs the VM off.
  Decide before the box is in service.

### Watching it work

The runner shares console session 1 with the desktop, so the app appears on the
guest's console. Either RDP to the guest (via a host portproxy bound to the
tailnet address — **not** `0.0.0.0`; these hosts can have public IPs), or open
the VM console from the host's Hyper-V Manager.

Leave the host's **Enhanced Session Mode off**. Enhanced mode opens a *new* RDP
session rather than showing session 1, which hides the very desktop you are
trying to watch.

### What the smoke job does and does not cover

It asserts, on every desktop-touching PR: a window appears, an
`msedgewebview2` host actually starts (so something rendered), the bundled
`corecruxd` sidecar is spawned from the `externalBin` slot **with no console
window**, the MSI installs per-machine and ships `corecruxd.exe` beside the app,
and a graceful close reaps the sidecar. A desktop screenshot is uploaded as an
artifact on every run, including failures.

The console-window assertion is there because the lane found that defect on its
first green run: `corecruxd` is console-subsystem and the shell is
GUI-subsystem, so without `CREATE_NO_WINDOW` Windows gave the sidecar a visible
console — a stray black box beside the app for its whole lifetime, invisible to
every Linux job. If you ever need to check this by hand, do **not** test
`(Get-Process corecruxd).MainWindowHandle`: since Win11/Server 2025 the console
window belongs to the console *host* (WindowsTerminal/conhost), not the child,
so that property reads `0` while the window is plainly on screen. Enumerate
top-level windows instead.

It deliberately does **not** cover three things, so don't read a green run as
covering them:

- **Reboot re-attach.** A GitHub Actions job cannot survive its own runner
  rebooting. Because the runner is a VM, the *host* can drive the reboot and
  read the evidence out-of-band — but that is a separate two-phase harness, not
  this job.
- **The Windows Defender first-bind prompt.** The provisioning script pre-adds
  the firewall rules, which asserts *rule state*. An interactive prompt in an
  automated run is a hang, not a test result, so prompt behaviour on a clean box
  stays a one-off human observation.
- **WSL2 parity with a developer box.** WSL2 works in the guest under nested
  virt, but on a different kernel and networking mode than a real Win11 dev
  machine. A green result there says nothing about the M6a matrix on your box.

## Historical incidents

| Date | Symptom | Root cause | Fix |
|---|---|---|---|
| 2026-05-19 | `cc not found` + `sudo password required` on Crux PR #84 | Runner image had no build-essential; gha-runner user lacked passwordless sudo. | Manual remediation (apt install + sudoers edit). Recorded as fact `incident:2026-05-19, key=crux-ci-runner-broken`. This script + runbook codify the durable fix. |

## See also

- Workflow: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
- Fallback workflow: [`.github/workflows/ci-fallback.yml`](../.github/workflows/ci-fallback.yml)
- Provision script: [`scripts/provision-self-hosted-runner.sh`](../scripts/provision-self-hosted-runner.sh)
- Desktop shell workflow: [`.github/workflows/desktop-shell.yml`](../.github/workflows/desktop-shell.yml)
- Windows GUI provision script: [`scripts/provision-windows-gui-runner.ps1`](../scripts/provision-windows-gui-runner.ps1)
- Ops cheatsheet (Tailscale SSH targets): `[[prod-ops-cheatsheet]]` in PlanCrux MEMORY.md
