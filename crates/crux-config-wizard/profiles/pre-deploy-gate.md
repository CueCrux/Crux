+++
name = "pre-deploy-gate"
version = 2
description = "Preflight discipline before prod deploys. Codifies the Insights-report `Deployment Gate` snippet (~978 wasted compute hours from prerequisite mismatches). v2 moves the checklist itself into the bundled `pre-deploy-gate` skill, which loads on a deploy trigger, and keeps inline only the two rules that bite outside a deploy — where that skill never fires."
targets = ["claude_md", "agents_md"]
order = 50
risk_class = "medium"
+++

## Pre-Deploy Gate

Before deploying to a prod target (`corecrux-gpu-1`, `cuecrux-data-1`, container images, hosted
daemons), work the `pre-deploy-gate` skill's checklist: migration state, the target's env and
headroom, deploy-command discipline, the post-deploy binary-sha audit and smoke probe, and how to
handle a failed step. Every item passes before the deploy step.

Two of its rules are not deploy-scoped, so they stay here — a deploy-triggered skill has not loaded
at the moment either one bites:

- Long-running jobs use `setsid + nohup + < /dev/null + disown` (the WSL-tested triad). Bare `&` is
  fragile under tty-detach.
- When introducing a new on-disk artifact type (companion file, projection, lens kind), update all
  three wiring points: storage allowlist, projection registry, and load-at-startup. Missing any one
  creates a quarantine-on-restart class of bug.
