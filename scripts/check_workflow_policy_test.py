#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
"""Tests for scripts/check_workflow_policy.py."""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import textwrap
import unittest


SCRIPT = pathlib.Path(__file__).with_name("check_workflow_policy.py")
SPEC = importlib.util.spec_from_file_location("check_workflow_policy", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
TOOLCHAIN_SHA = "4360b52568e2003a75bf9bc1d59f33a8e3fc893c"


def findings_for(body: str) -> list[module.Finding]:
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "w.yml"
        p.write_text(textwrap.dedent(body).lstrip("\n"))
        return module.check_workflow(p)


def rules(body: str) -> set[str]:
    return {f.rule for f in findings_for(body)}


class PinningTest(unittest.TestCase):
    def test_mutable_tag_is_rejected(self) -> None:
        found = findings_for(
            f"""
            name: W
            on: [push]
            permissions:
              contents: read
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v7
            """
        )
        self.assertEqual([f.rule for f in found], ["unpinned-action"])
        self.assertEqual(found[0].line, 9)

    def test_full_sha_is_accepted(self) -> None:
        self.assertEqual(
            rules(
                f"""
                name: W
                on: [push]
                permissions:
                  contents: read
                jobs:
                  j:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/checkout@{SHA} # v7
                """
            ),
            set(),
        )

    def test_reusable_workflow_may_use_a_tag(self) -> None:
        # GitHub's SHA-pinning policy exempts reusable workflows, and
        # slsa-github-generator rejects SHA refs outright.
        self.assertEqual(
            rules(
                """
                name: W
                on: [push]
                permissions:
                  contents: read
                jobs:
                  j:
                    uses: slsa-framework/slsa-github-generator/.github/workflows/g.yml@v2.1.0
                """
            ),
            set(),
        )

    def test_local_and_docker_refs_are_exempt(self) -> None:
        self.assertEqual(
            rules(
                """
                name: W
                on: [push]
                permissions:
                  contents: read
                jobs:
                  j:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: ./.github/actions/local
                      - uses: docker://alpine:3.20
                """
            ),
            set(),
        )


class PermissionsTest(unittest.TestCase):
    def test_missing_top_level_permissions_is_rejected(self) -> None:
        self.assertIn(
            "missing-permissions",
            rules(
                """
                name: W
                on: [push]
                jobs:
                  j:
                    runs-on: ubuntu-latest
                    steps:
                      - run: true
                """
            ),
        )

    def test_write_all_is_rejected_at_both_levels(self) -> None:
        self.assertIn(
            "write-all",
            rules(
                """
                name: W
                on: [push]
                permissions: write-all
                jobs:
                  j:
                    runs-on: ubuntu-latest
                    steps:
                      - run: true
                """
            ),
        )
        self.assertIn(
            "write-all",
            rules(
                """
                name: W
                on: [push]
                permissions:
                  contents: read
                jobs:
                  j:
                    runs-on: ubuntu-latest
                    permissions: write-all
                    steps:
                      - run: true
                """
            ),
        )


class ToolchainRefTest(unittest.TestCase):
    def test_pinned_toolchain_without_an_explicit_channel_is_rejected(self) -> None:
        self.assertIn(
            "toolchain-ref-stripped",
            rules(
                f"""
                name: W
                on: [push]
                permissions:
                  contents: read
                jobs:
                  j:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: dtolnay/rust-toolchain@{TOOLCHAIN_SHA} # stable
                      - run: cargo build
                """
            ),
        )

    def test_pinned_toolchain_with_an_explicit_channel_is_accepted(self) -> None:
        self.assertEqual(
            rules(
                f"""
                name: W
                on: [push]
                permissions:
                  contents: read
                jobs:
                  j:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: dtolnay/rust-toolchain@{TOOLCHAIN_SHA} # stable
                        with:
                          toolchain: stable
                          components: clippy
                """
            ),
            set(),
        )

    def test_unpinned_toolchain_is_only_an_unpinned_action(self) -> None:
        # While the ref is still `@stable` it carries the channel correctly.
        # Claiming the channel was stripped would be false.
        self.assertEqual(
            rules(
                """
                name: W
                on: [push]
                permissions:
                  contents: read
                jobs:
                  j:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: dtolnay/rust-toolchain@stable
                """
            ),
            {"unpinned-action"},
        )


class UntrustedRunnerTest(unittest.TestCase):
    """The S2 decision, encoded.

    `pull_request` on the self-hosted pool is allowed: fork runs are gated
    behind maintainer approval. `pull_request_target` is not -- it pairs a
    privileged token with attacker-influenced refs.
    """

    # Indented to match the inline literals below: the two are concatenated
    # before `dedent`, which only strips the prefix they share.
    SELF_HOSTED_JOB = """
                jobs:
                  j:
                    runs-on: [self-hosted, ci, Linux]
                    steps:
                      - run: true
                """

    def test_pull_request_on_self_hosted_is_allowed(self) -> None:
        self.assertEqual(
            rules(
                """
                name: W
                on:
                  pull_request:
                    branches: [main]
                permissions:
                  contents: read
                """
                + self.SELF_HOSTED_JOB
            ),
            set(),
        )

    def test_pull_request_target_on_self_hosted_is_rejected(self) -> None:
        self.assertIn(
            "untrusted-on-privileged-runner",
            rules(
                """
                name: W
                on:
                  pull_request_target:
                    branches: [main]
                permissions:
                  contents: read
                """
                + self.SELF_HOSTED_JOB
            ),
        )

    def test_pull_request_target_on_github_hosted_is_allowed(self) -> None:
        self.assertEqual(
            rules(
                """
                name: W
                on:
                  pull_request_target:
                    branches: [main]
                permissions:
                  contents: read
                jobs:
                  j:
                    runs-on: ubuntu-latest
                    steps:
                      - run: true
                """
            ),
            set(),
        )

    def test_runner_group_label_form_is_recognised(self) -> None:
        self.assertIn(
            "untrusted-on-privileged-runner",
            rules(
                """
                name: W
                on:
                  workflow_run:
                    workflows: [CI]
                permissions:
                  contents: read
                jobs:
                  j:
                    runs-on:
                      group: pool
                      labels: [self-hosted, ci]
                    steps:
                      - run: true
                """
            ),
        )


class YamlQuirkTest(unittest.TestCase):
    def test_bare_on_key_is_read_despite_yaml_boolean_coercion(self) -> None:
        # PyYAML resolves the bare key `on` to True. A checker that reads
        # doc["on"] sees no triggers and silently passes every workflow.
        self.assertIn(
            "untrusted-on-privileged-runner",
            rules(
                """
                name: W
                on:
                  pull_request_target:
                jobs:
                  j:
                    runs-on: [self-hosted]
                    steps:
                      - run: true
                permissions:
                  contents: read
                """
            ),
        )


class RealWorkflowsTest(unittest.TestCase):
    def test_this_repository_satisfies_the_policy(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows"
        found: list[module.Finding] = []
        for p in sorted(root.glob("*.yml")):
            found.extend(module.check_workflow(p))
        self.assertEqual([f.render() for f in found], [])


if __name__ == "__main__":
    unittest.main()
