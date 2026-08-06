# Protected self-hosted runner operator guide

Pull-request and merge-queue code runs on disposable GitHub-hosted workers. The
persistent `[self-hosted, hel1]` pool is reserved for reviewed `main` state in:

- `.github/workflows/coverage-attestation.yml`
- `.github/workflows/egress-probe.yml`
- `.github/workflows/mutants.yml`

The repository policy check rejects PR-reachable self-hosted, custom, dynamic,
or unresolved runner selection. It also requires every PR/merge-reachable
workflow to declare top-level `contents: read` and rejects job-level write
permissions unless the job is an exact allowlisted publish/deploy job with its
exact protected-event guard and minimum permission set. Build/test jobs never
inherit Pages, package, Security-tab, or OIDC write authority from a mixed
workflow. That check is a merge guard; the runner-group restriction below is
the runtime security boundary.

## Mandatory legacy-host cutover

Do not convert an existing PR runner in place. PR-controlled code previously
ran on `hel1` with unrestricted passwordless root, so its OS, firmware-facing
state, runner credentials, workspaces, Cargo/Rustup homes, sccache data, and
other shared caches are not trustworthy after the policy change.

Before reusing persistent capacity:

1. Disable and remove every old listener in GitHub.
2. Reimage the host from trusted media; do not copy old runner homes, build
   caches, tool binaries, workspaces, or system configuration into the image.
3. Rotate any host, tailnet, deployment, or service credential that the old
   runner could read.
4. Configure the restricted runner group below.
5. Create the unprivileged service account and install a checksum-verified
   `rustup-init`/minimal Rust toolchain into its clean home.
6. Run the provisioner, then register a new listener directly into that group.

`scripts/provision-self-hosted-runner.sh` establishes the desired state on a
clean host. It cannot prove or restore the integrity of a previously
root-compromisable host.

## Required GitHub runner-group policy

Put every `hel1` listener in a non-default organization runner group. Configure
the group for selected-repository access to `CueCrux/Crux`, then select only
these workflow references:

```text
CueCrux/Crux/.github/workflows/coverage-attestation.yml@refs/heads/main
CueCrux/Crux/.github/workflows/egress-probe.yml@refs/heads/main
CueCrux/Crux/.github/workflows/mutants.yml@refs/heads/main
```

Keep `restricted_to_workflows=true`; do not grant the group to all workflows.
GitHub requires the full workflow path and supports pinning it to a branch,
tag, or full SHA. Only jobs directly defined in the selected workflow receive
access. See [Managing access to self-hosted runners using
groups](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access).

On `main`, apply `.github/merge-queue-ruleset.json` after the bootstrap run. It
requires the `Workflow runner policy` status, code-owner review, last-push
approval, and has an empty bypass list. Keep `.github/` and both
`scripts/check_workflow_runner_policy*.py` under required code-owner review.
The ruleset README records the non-deadlocking first-merge sequence.

If the repository is public and workflow-restricted groups are unavailable,
do not register a persistent runner to it. Use GitHub-hosted workers or
one-job ephemeral/JIT runners instead.

## Service-account boundary

The runner service account must have:

- no `NOPASSWD` entry and no other non-interactive sudo policy;
- no Docker socket or other root-equivalent host socket;
- no production credentials, deploy keys, or cloud metadata access;
- no production/Tailscale route unless the protected job explicitly requires
  it and the route is separately constrained;
- a dedicated work directory and externally retained job logs.

The old `/etc/sudoers.d/gha-runner-nopasswd` grant was unrestricted root and
must be disabled before the listener starts. The provision script moves that
exact legacy file to a recoverable `.disabled` path and then refuses to pass if
the account still has a non-interactive sudo policy.

`scripts/runner-hel1-per-runner-home.sh` no longer seeds a new runner home from
the shared legacy Cargo/Rustup caches by default. Its explicit
`CRUX_RUNNER_TRUSTED_SEED=1` escape hatch is only for a cache created after a
clean rebuild and verified as trusted.

## One-shot provision

From a trusted checkout on the runner host:

```bash
cd /path/to/Crux
sudo -E bash scripts/provision-self-hosted-runner.sh
```

The script installs the native build toolchain, disables the legacy sudoers
grant, verifies `cc`, verifies the account's trusted `rustup`/`cargo` bootstrap,
and verifies that `gha-runner` cannot use non-interactive sudo. It deliberately
does not download or execute a toolchain installer. Override the account when
needed:

```bash
RUNNER_USER=alice sudo -E bash scripts/provision-self-hosted-runner.sh
```

Restart the listener only after both the local privilege check and the GitHub
runner-group policy are in place:

```bash
sudo systemctl restart actions-runner.gha-runner.service
```

The protected coverage workflow also probes for `cc` before expensive work. It
does not probe for or require sudo.

## Pull-request CI and the legacy fallback

`.github/workflows/ci.yml` is now the full disposable PR/merge-queue gate. The
label-triggered `.github/workflows/ci-fallback.yml` is retained only as a
compatibility diagnostic; it is additive, lacks full gate parity, and is not a
security fallback.

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

| Date | Symptom | Root cause | Current corrective control |
|---|---|---|---|
| 2026-05-19 | `cc not found` and a sudo prompt on PR #84 | PR jobs ran on a persistent host and the proposed workaround granted the runner unrestricted root. | PR execution moved to disposable workers; protected runners are unprivileged and workflow/ref-restricted. |

## See also

- Runner policy: [`.github/workflows/runner-policy.yml`](../.github/workflows/runner-policy.yml)
- Primary CI: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
- Provision script: [`scripts/provision-self-hosted-runner.sh`](../scripts/provision-self-hosted-runner.sh)
- Desktop shell workflow: [`.github/workflows/desktop-shell.yml`](../.github/workflows/desktop-shell.yml)
- Windows GUI provision script: [`scripts/provision-windows-gui-runner.ps1`](../scripts/provision-windows-gui-runner.ps1)
- Ops cheatsheet (Tailscale SSH targets): `[[prod-ops-cheatsheet]]` in PlanCrux MEMORY.md
