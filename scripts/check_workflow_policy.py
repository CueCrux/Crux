#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
"""Enforce the workflow supply-chain policy.

Five rules, each one a regression that has already cost something somewhere:

1.  Every workflow declares a top-level ``permissions:``. Without one the
    GITHUB_TOKEN inherits the repository default, which is invisible from
    the workflow file and has historically been ``write``.
2.  Nothing grants ``write-all``.
3.  Every action is pinned to a full-length commit SHA. A mutable tag is a
    standing write primitive for whoever controls the upstream repository.
4.  ``dtolnay/rust-toolchain`` call sites name their toolchain explicitly.
    That action reads the channel off the ref it was invoked by, so pinning
    the ref -- which rule 3 requires -- silently strips the channel unless a
    ``toolchain:`` input replaces it.
5.  No workflow runs untrusted code on the privileged self-hosted pool.
    ``pull_request`` is fine: fork runs are gated behind maintainer approval
    (``all_external_contributors``). ``pull_request_target`` and
    ``workflow_run`` are not -- they pair a privileged token with attacker
    -influenced refs and must stay on GitHub-hosted runners.

Exemptions, both narrow and deliberate:

*   Reusable workflows may be referenced by tag. GitHub's own SHA-pinning
    policy exempts them, and slsa-github-generator rejects SHA refs.
*   Local (``./``) and ``docker://`` references have no ref to pin.

Usage: ``python3 scripts/check_workflow_policy.py [--workflows DIR]``
Exit 0 clean, 1 on any violation.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from typing import Iterable, NamedTuple

import yaml

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)")
PRIVILEGED_TRIGGERS = ("pull_request_target", "workflow_run")
TOOLCHAIN_REF_ACTION = "dtolnay/rust-toolchain"


class Finding(NamedTuple):
    path: str
    line: int
    rule: str
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.message}"


def _triggers(doc: dict) -> list[str]:
    # PyYAML resolves the bare key `on` to the boolean True (YAML 1.1), so a
    # plain doc["on"] misses every workflow in this repository.
    raw = doc.get("on", doc.get(True))
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(t) for t in raw]
    if isinstance(raw, dict):
        return [str(t) for t in raw]
    return []


def _is_self_hosted(runs_on: object) -> bool:
    if isinstance(runs_on, str):
        return "self-hosted" in runs_on
    if isinstance(runs_on, list):
        return any("self-hosted" in str(x) for x in runs_on)
    if isinstance(runs_on, dict):  # `runs-on: {group: ..., labels: [...]}`
        return _is_self_hosted(runs_on.get("labels", []))
    return False


def _grants_write_all(node: object) -> bool:
    return isinstance(node, str) and node.strip() == "write-all"


def _check_pinning(path: str, lines: list[str]) -> Iterable[Finding]:
    for n, line in enumerate(lines, start=1):
        m = USES_RE.match(line)
        if not m:
            continue
        ref = m.group("ref").strip("'\"")
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        if "@" not in ref:
            yield Finding(path, n, "unpinned-action", f"`{ref}` has no ref at all")
            continue
        action, rev = ref.rsplit("@", 1)
        # A reusable workflow is `owner/repo/.github/workflows/x.yml@ref`.
        if ".github/workflows/" in action:
            continue
        if not SHA_RE.match(rev):
            yield Finding(
                path,
                n,
                "unpinned-action",
                f"`{action}` is pinned to the mutable ref `{rev}`; "
                "use a full-length commit SHA with the tag as a trailing comment",
            )


def _check_toolchain_inputs(path: str, lines: list[str]) -> Iterable[Finding]:
    for n, line in enumerate(lines, start=1):
        m = USES_RE.match(line)
        if not m or TOOLCHAIN_REF_ACTION not in m.group("ref"):
            continue
        # Only meaningful once the ref is a SHA. While it is still `@stable`
        # the ref carries the channel correctly and there is nothing to say;
        # rule 3 is what moves it into scope.
        rev = m.group("ref").strip("'\"").rsplit("@", 1)[-1]
        if not SHA_RE.match(rev):
            continue
        # The step's `with:` block, if any, is the indented run that follows.
        window = lines[n : n + 6]
        block: list[str] = []
        for follower in window:
            if follower.strip().startswith("- ") or (
                follower.strip() and not follower.startswith(" " * (len(line) - len(line.lstrip())))
            ):
                break
            block.append(follower)
        if not any(re.match(r"\s*toolchain:\s*\S", b) for b in block):
            yield Finding(
                path,
                n,
                "toolchain-ref-stripped",
                f"`{TOOLCHAIN_REF_ACTION}` is pinned to a SHA but names no `toolchain:` "
                "input; the action reads its channel from the ref, so the pin silently "
                "changes which Rust this job installs",
            )


def check_workflow(path: pathlib.Path) -> list[Finding]:
    text = path.read_text()
    lines = text.split("\n")
    rel = str(path)
    findings: list[Finding] = []

    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [Finding(rel, 1, "unparseable", f"YAML did not parse: {exc}")]
    if not isinstance(doc, dict):
        return [Finding(rel, 1, "unparseable", "workflow is not a mapping")]

    if "permissions" not in doc:
        findings.append(
            Finding(
                rel,
                1,
                "missing-permissions",
                "no top-level `permissions:`; the token silently inherits the "
                "repository default. Declare `contents: read` and widen per job.",
            )
        )
    if _grants_write_all(doc.get("permissions")):
        findings.append(Finding(rel, 1, "write-all", "top-level `permissions: write-all`"))

    triggers = _triggers(doc)
    privileged = [t for t in triggers if t in PRIVILEGED_TRIGGERS]

    jobs = doc.get("jobs") or {}
    for name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if _grants_write_all(job.get("permissions")):
            findings.append(Finding(rel, 1, "write-all", f"job `{name}` grants `write-all`"))
        if privileged and _is_self_hosted(job.get("runs-on")):
            findings.append(
                Finding(
                    rel,
                    1,
                    "untrusted-on-privileged-runner",
                    f"job `{name}` runs on the self-hosted pool under "
                    f"`{privileged[0]}`, which executes attacker-influenced refs "
                    "with a privileged token. Move it to a GitHub-hosted runner.",
                )
            )

    findings.extend(_check_pinning(rel, lines))
    findings.extend(_check_toolchain_inputs(rel, lines))
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workflows", default=".github/workflows", type=pathlib.Path)
    args = ap.parse_args(argv)

    paths = sorted(args.workflows.glob("*.yml")) + sorted(args.workflows.glob("*.yaml"))
    if not paths:
        print(f"no workflows found under {args.workflows}", file=sys.stderr)
        return 1

    findings: list[Finding] = []
    for path in paths:
        findings.extend(check_workflow(path))

    for f in findings:
        print(f.render(), file=sys.stderr)
        # Surface in the PR diff as well as the log.
        print(f"::error file={f.path},line={f.line}::[{f.rule}] {f.message}")

    if findings:
        print(
            f"\nFAIL: {len(findings)} workflow policy violation(s) across {len(paths)} workflows",
            file=sys.stderr,
        )
        return 1
    print(f"PASS: {len(paths)} workflows satisfy the supply-chain policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
