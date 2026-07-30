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

## Historical incidents

| Date | Symptom | Root cause | Current corrective control |
|---|---|---|---|
| 2026-05-19 | `cc not found` and a sudo prompt on PR #84 | PR jobs ran on a persistent host and the proposed workaround granted the runner unrestricted root. | PR execution moved to disposable workers; protected runners are unprivileged and workflow/ref-restricted. |

## See also

- Runner policy: [`.github/workflows/runner-policy.yml`](../.github/workflows/runner-policy.yml)
- Primary CI: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
- Provision script: [`scripts/provision-self-hosted-runner.sh`](../scripts/provision-self-hosted-runner.sh)
