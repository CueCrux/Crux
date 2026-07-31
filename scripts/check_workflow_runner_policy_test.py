#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.

from __future__ import annotations

import os
import tempfile
import textwrap
import unittest
from pathlib import Path

import check_workflow_runner_policy as policy


class WorkflowRunnerPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / ".github/workflows").mkdir(parents=True)
        self.workflow(
            "runner-policy.yml",
            """
            name: Workflow runner policy
            on:
              pull_request_target:
              merge_group:
              push:
                branches: [main]
            permissions:
              contents: read
            concurrency:
              group: runner-policy-${{ github.event.pull_request.number || github.ref }}
              cancel-in-progress: true
            jobs:
              runner-policy:
                name: Workflow runner policy
                runs-on: ubuntu-latest
                timeout-minutes: 10
                steps:
                  - name: Trusted policy
                    uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
                    with:
                      ref: refs/heads/main
                      path: policy
                      persist-credentials: false
                  - name: PR candidate
                    if: github.event_name == 'pull_request_target'
                    uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
                    with:
                      repository: ${{ github.event.pull_request.head.repo.full_name }}
                      ref: ${{ github.event.pull_request.head.sha }}
                      path: candidate
                      persist-credentials: false
                      submodules: false
                  - name: Merge candidate
                    if: github.event_name != 'pull_request_target'
                    uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
                    with:
                      ref: ${{ github.sha }}
                      path: candidate
                      persist-credentials: false
                      submodules: false
                  - name: Test
                    run: python3 policy/scripts/check_workflow_runner_policy_test.py
                  - name: Scan
                    run: python3 policy/scripts/check_workflow_runner_policy.py --root candidate
            """,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def workflow(self, name: str, source: str) -> Path:
        path = self.root / ".github/workflows" / name
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        return path

    def errors(self) -> list[str]:
        return policy.audit(self.root)

    def assert_rejected(self, needle: str) -> None:
        errors = self.errors()
        self.assertTrue(errors, "expected policy rejection")
        self.assertTrue(
            any(needle in error for error in errors),
            f"{needle!r} absent from {errors!r}",
        )

    def test_accepts_literal_hosted_pull_request_and_merge_group_jobs(self) -> None:
        self.workflow(
            "ci.yml",
            """
            on:
              pull_request:
              merge_group:
            permissions:
              contents: read
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - run: |
                      echo "runs-on: [self-hosted, hel1] is inert script text"
            """,
        )
        self.assertEqual(self.errors(), [])

    def test_untrusted_workflow_requires_exact_read_only_top_level_permissions(self) -> None:
        self.workflow(
            "ci.yml",
            """
            on: pull_request
            jobs:
              test:
                runs-on: ubuntu-latest
            """,
        )
        self.assert_rejected(
            "top-level permissions exactly to contents: read"
        )

        self.workflow(
            "ci.yml",
            """
            on: pull_request
            permissions: write-all
            jobs:
              test:
                runs-on: ubuntu-latest
            """,
        )
        self.assert_rejected(
            "top-level permissions exactly to contents: read"
        )

        self.workflow(
            "ci.yml",
            """
            on: pull_request
            permissions:
              contents: read
              issues: write
            jobs:
              test:
                runs-on: ubuntu-latest
            """,
        )
        self.assert_rejected(
            "top-level permissions exactly to contents: read"
        )

    def test_untrusted_job_rejects_writes_and_unresolved_permission_forms(self) -> None:
        self.workflow(
            "ci.yml",
            """
            on: pull_request
            permissions:
              contents: read
            jobs:
              write:
                runs-on: ubuntu-latest
                permissions:
                  contents: read
                  issues: write
            """,
        )
        self.assert_rejected("untrusted workflow job grants write permissions")

        self.workflow(
            "ci.yml",
            """
            on: pull_request
            permissions:
              contents: read
            jobs:
              write:
                runs-on: ubuntu-latest
                permissions: write-all
            """,
        )
        self.assert_rejected("must be a literal block mapping")

        self.workflow(
            "ci.yml",
            """
            on: pull_request
            permissions:
              contents: read
            jobs:
              write:
                runs-on: ubuntu-latest
                permissions:
                  contents: ${{ matrix.permission }}
            """,
        )
        self.assert_rejected("unresolved/merged key or value")

    def test_untrusted_job_rejects_every_github_write_scope(self) -> None:
        write_scopes = (
            "actions",
            "attestations",
            "checks",
            "contents",
            "deployments",
            "discussions",
            "id-token",
            "issues",
            "models",
            "packages",
            "pages",
            "pull-requests",
            "security-events",
            "statuses",
        )
        for scope in write_scopes:
            with self.subTest(scope=scope):
                self.workflow(
                    "ci.yml",
                    f"""
                    on: pull_request
                    permissions:
                      contents: read
                    jobs:
                      write:
                        runs-on: ubuntu-latest
                        permissions:
                          {scope}: write
                    """,
                )
                self.assert_rejected(
                    "untrusted workflow job grants write permissions"
                )

    def test_untrusted_reusable_workflow_permissions_are_checked_recursively(self) -> None:
        self.workflow(
            "caller.yml",
            """
            on: pull_request
            permissions:
              contents: read
            jobs:
              call:
                uses: ./.github/workflows/callee.yml
            """,
        )
        self.workflow(
            "callee.yml",
            """
            on: workflow_call
            permissions:
              contents: read
            jobs:
              unsafe:
                runs-on: ubuntu-latest
                permissions:
                  packages: write
            """,
        )
        self.assert_rejected("untrusted workflow job grants write permissions")

        self.workflow(
            "callee.yml",
            """
            on: workflow_call
            jobs:
              safe:
                runs-on: ubuntu-latest
            """,
        )
        self.assert_rejected(
            "top-level permissions exactly to contents: read"
        )

    def test_rejects_permission_merge_keys_duplicates_and_guard_continuations(self) -> None:
        self.workflow(
            "ci.yml",
            """
            on: pull_request
            permissions:
              contents: read
            jobs:
              write:
                runs-on: ubuntu-latest
                permissions:
                  contents: read
                  contents: write
                  <<: *privileged
            """,
        )
        errors = self.errors()
        self.assertTrue(
            any("duplicate job permissions key" in error for error in errors)
        )
        self.assertTrue(
            any("unresolved/merged key or value" in error for error in errors)
        )

        self.workflow(
            "docs.yml",
            """
            on: [push, pull_request]
            permissions:
              contents: read
            jobs:
              deploy:
                if: github.ref == 'refs/heads/main' && github.event_name == 'push'
                  || true
                runs-on: ubuntu-latest
                permissions:
                  contents: read
                  pages: write
                  id-token: write
            """,
        )
        self.assert_rejected(
            "guard must exactly match its protected-event policy"
        )

    def test_untrusted_job_accepts_narrower_read_or_empty_permissions(self) -> None:
        self.workflow(
            "ci.yml",
            """
            on: pull_request
            permissions:
              contents: read
            jobs:
              read:
                runs-on: ubuntu-latest
                permissions:
                  contents: read
                  issues: none
              empty:
                runs-on: ubuntu-latest
                permissions: {}
            """,
        )
        self.assertEqual(self.errors(), [])

    def test_accepts_exact_protected_privileged_job_exception(self) -> None:
        self.workflow(
            "docs.yml",
            """
            on: [push, pull_request, merge_group]
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
              deploy:
                if: github.ref == 'refs/heads/main' && github.event_name == 'push'
                runs-on: ubuntu-latest
                permissions:
                  contents: read
                  pages: write
                  id-token: write
            """,
        )
        self.assertEqual(self.errors(), [])

    def test_rejects_weakened_privileged_job_guard_or_expanded_permissions(self) -> None:
        self.workflow(
            "docs.yml",
            """
            on: [push, pull_request, merge_group]
            permissions:
              contents: read
            jobs:
              deploy:
                if: github.event_name != 'pull_request'
                runs-on: ubuntu-latest
                permissions:
                  contents: read
                  pages: write
                  id-token: write
            """,
        )
        self.assert_rejected(
            "guard must exactly match its protected-event policy"
        )

        self.workflow(
            "docs.yml",
            """
            on: [push, pull_request, merge_group]
            permissions:
              contents: read
            jobs:
              deploy:
                if: github.ref == 'refs/heads/main' && github.event_name == 'push'
                runs-on: ubuntu-latest
                permissions:
                  contents: read
                  pages: write
                  id-token: write
                  issues: write
            """,
        )
        self.assert_rejected(
            "permission set must exactly match its allowlisted minimum"
        )

    def test_rejects_protected_scalar_and_list_labels_case_insensitively(self) -> None:
        self.workflow(
            "ci.yml",
            """
            on: [push, pull_request]
            jobs:
              scalar:
                runs-on: HEL1
              list:
                runs-on: [Self-Hosted, linux, x64]
            """,
        )
        self.assert_rejected("untrusted job runner")

    def test_rejects_dynamic_matrix_or_variable_runner(self) -> None:
        self.workflow(
            "ci.yml",
            """
            on: pull_request
            jobs:
              matrix:
                runs-on: ${{ matrix.os }}
              variable:
                runs-on: ${{ vars.RUNNER }}
            """,
        )
        self.assert_rejected("runner expressions")

    def test_rejects_runner_mapping_and_unknown_custom_label(self) -> None:
        self.workflow(
            "ci.yml",
            """
            on: pull_request_target
            jobs:
              group:
                runs-on:
                  group: protected
                  labels: [self-hosted, hel1]
              custom:
                runs-on: arc-runner-set
            """,
        )
        self.assert_rejected("runner mapping/complex block")

    def test_job_if_cannot_hide_protected_runner_in_mixed_workflow(self) -> None:
        self.workflow(
            "mixed.yml",
            """
            on: [push, pull_request]
            jobs:
              publish:
                if: github.event_name == 'push'
                runs-on: [self-hosted, hel1]
            """,
        )
        self.assert_rejected("untrusted job runner")

    def test_protected_workflow_requires_main_guard_and_no_untrusted_event(self) -> None:
        self.workflow(
            "coverage-attestation.yml",
            """
            on:
              pull_request:
              workflow_dispatch:
            jobs:
              attest:
                runs-on: [self-hosted, hel1]
            """,
        )
        self.assert_rejected("workflow events must be exactly")

    def test_accepts_allowlisted_protected_workflow_with_main_guard(self) -> None:
        self.workflow(
            "egress-probe.yml",
            """
            on:
              push:
                branches: [main]
              workflow_dispatch:
            jobs:
              probe:
                if: github.ref == 'refs/heads/main'
                runs-on: [self-hosted, hel1]
            """,
        )
        self.assertEqual(self.errors(), [])

    def test_rejects_main_ref_guard_hidden_in_an_always_true_expression(self) -> None:
        self.workflow(
            "egress-probe.yml",
            """
            on: workflow_dispatch
            jobs:
              probe:
                if: contains("github.ref == 'refs/heads/main'", "main") || true
                runs-on: [self-hosted, hel1]
            """,
        )
        self.assert_rejected("must use exact main-ref guard")

    def test_rejects_indirect_event_on_a_protected_workflow(self) -> None:
        self.workflow(
            "egress-probe.yml",
            """
            on:
              workflow_run:
                workflows: [CI]
                types: [completed]
              workflow_dispatch:
            jobs:
              probe:
                if: github.ref == 'refs/heads/main'
                runs-on: [self-hosted, hel1]
            """,
        )
        self.assert_rejected("workflow events must be exactly")

    def test_rejects_protected_runner_outside_allowlist(self) -> None:
        self.workflow(
            "surprise.yml",
            """
            on:
              push:
                branches: [main]
            jobs:
              surprise:
                if: github.ref == 'refs/heads/main'
                runs-on: [self-hosted, hel1]
            """,
        )
        self.assert_rejected("not allowed in this workflow")

    def test_recurses_into_local_reusable_workflow(self) -> None:
        self.workflow(
            "caller.yml",
            """
            on: [pull_request, workflow_call]
            jobs:
              call:
                uses: ./.github/workflows/callee.yml
            """,
        )
        self.workflow(
            "callee.yml",
            """
            on: workflow_call
            jobs:
              unsafe:
                runs-on: [self-hosted, hel1]
            """,
        )
        self.assert_rejected("untrusted job runner")

    def test_rejects_external_reusable_workflow_and_cycle(self) -> None:
        self.workflow(
            "caller.yml",
            """
            on: pull_request
            jobs:
              external:
                uses: owner/repository/.github/workflows/build.yml@main
            """,
        )
        self.assert_rejected("literal local workflow")

        self.workflow(
            "caller.yml",
            """
            on: [pull_request, workflow_call]
            jobs:
              call:
                uses: ./.github/workflows/callee.yml
            """,
        )
        self.workflow(
            "callee.yml",
            """
            on: workflow_call
            jobs:
              call:
                uses: ./.github/workflows/caller.yml
            """,
        )
        self.assert_rejected("reusable workflow cycle")

    def test_rejects_duplicate_keys_merge_alias_and_malformed_job(self) -> None:
        self.workflow(
            "ci.yml",
            """
            on: pull_request
            jobs:
              test:
                runs-on: ubuntu-latest
                runs-on: [self-hosted, hel1]
              merged:
                <<: *runner
            """,
        )
        errors = self.errors()
        self.assertTrue(any("duplicate job key 'runs-on'" in error for error in errors))
        self.assertTrue(any("job merge keys are unsupported" in error for error in errors))

    def test_rejects_yaml_escaped_trigger_runner_and_duplicate_property_keys(self) -> None:
        self.workflow(
            "ci.yml",
            r"""
            on:
              "pull\u005frequest":
            jobs:
              escaped-runner:
                runs-on: "self\u002dhosted"
              semantic-duplicate:
                runs-on: ubuntu-latest
                "runs-\u006fn": [self-hosted, hel1]
            """,
        )
        errors = self.errors()
        self.assertTrue(any("trigger entries must be literal" in error for error in errors))
        self.assertTrue(any("job properties must be literal" in error for error in errors))

    def test_rejects_block_scalar_trigger(self) -> None:
        self.workflow(
            "ci.yml",
            """
            on: >-
              pull_request
            jobs:
              test:
                runs-on: custom-persistent
            """,
        )
        self.assert_rejected("block scalars are unsupported")

    def test_rejects_block_scalar_runner_in_trusted_nonallowlisted_workflow(self) -> None:
        self.workflow(
            "trusted.yml",
            """
            on: push
            jobs:
              test:
                runs-on: >-
                  self-hosted
            """,
        )
        self.assert_rejected("block scalars are unsupported")

    def test_release_dynamic_runner_exception_validates_every_matrix_value(self) -> None:
        self.workflow(
            "release.yml",
            """
            on:
              push:
                tags: ["v*"]
            jobs:
              build:
                runs-on: ${{ matrix.os }}
                strategy:
                  matrix:
                    include:
                      - target: safe
                        os: ubuntu-latest
                      - target: unsafe
                        os: self-hosted
            """,
        )
        self.assert_rejected("must be one literal GitHub-hosted label")

    def test_release_dynamic_exception_is_disabled_for_untrusted_trigger(self) -> None:
        self.workflow(
            "release.yml",
            """
            on: [push, pull_request]
            jobs:
              build:
                runs-on: ${{ matrix.os }}
                strategy:
                  matrix:
                    include:
                      - target: unsafe
                        os: self-hosted
            """,
        )
        self.assert_rejected("runner expressions")

    def test_release_matrix_rejects_yaml_escaped_semantic_duplicate(self) -> None:
        self.workflow(
            "release.yml",
            r"""
            on: push
            jobs:
              build:
                runs-on: ${{ matrix.os }}
                strategy:
                  matrix:
                    include:
                      - target: safe
                        os: ubuntu-latest
                  "matr\u0069x":
                    include:
                      - target: unsafe
                        os: self-hosted
            """,
        )
        self.assert_rejected("must be the one literal matrix key")

    def test_release_matrix_rejects_bare_dash_hidden_entry(self) -> None:
        self.workflow(
            "release.yml",
            """
            on: push
            jobs:
              build:
                runs-on: ${{ matrix.os }}
                strategy:
                  matrix:
                    include:
                      -
                        target: unsafe
                        os: self-hosted
                      - target: safe
                        os: ubuntu-latest
            """,
        )
        self.assert_rejected("must use a literal inline sequence mapping")

    def test_runner_policy_cannot_filter_pull_request_target_base_branches(self) -> None:
        self.workflow(
            "runner-policy.yml",
            """
            on:
              pull_request_target:
                branches: [main]
              merge_group:
              push:
                branches: [main]
            jobs:
              policy:
                runs-on: ubuntu-latest
            """,
        )
        self.assert_rejected("must cover every base branch")

    def test_runner_policy_rejects_duplicate_or_escaped_event_filters(self) -> None:
        self.workflow(
            "runner-policy.yml",
            r"""
            on:
              pull_request_target:
              pull_request_target:
                branches: [main]
              merge_group:
              push:
                branches: [main]
            jobs:
              policy:
                runs-on: ubuntu-latest
            """,
        )
        self.assert_rejected("duplicate trigger")

        self.workflow(
            "runner-policy.yml",
            r"""
            on:
              pull_request_target:
                "branc\u0068es": [main]
              merge_group:
              push:
                branches: [main]
            jobs:
              policy:
                runs-on: ubuntu-latest
            """,
        )
        self.assert_rejected("unresolved child key")

    def test_runner_policy_rejects_event_merge_key(self) -> None:
        self.workflow(
            "runner-policy.yml",
            """
            on:
              push: &filters
                branches: [main]
              pull_request_target:
                <<: *filters
              merge_group:
            jobs:
              policy:
                runs-on: ubuntu-latest
            """,
        )
        self.assert_rejected("merge keys/indirection")

    def test_runner_policy_workflow_cannot_be_deleted_or_neutralized(self) -> None:
        (self.root / ".github/workflows/runner-policy.yml").unlink()
        self.workflow(
            "ci.yml",
            """
            on: pull_request
            jobs:
              test:
                runs-on: ubuntu-latest
            """,
        )
        self.assert_rejected("trusted runner policy workflow is required")

        self.workflow(
            "runner-policy.yml",
            """
            on:
              pull_request_target:
              merge_group:
              push:
                branches: [main]
            jobs:
              runner-policy:
                runs-on: ubuntu-latest
                steps:
                  - run: "true"
            """,
        )
        self.assert_rejected("job keys must be exactly")

    def test_runner_policy_job_cannot_be_skipped_or_mask_failures(self) -> None:
        path = self.root / ".github/workflows/runner-policy.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "    name: Workflow runner policy\n",
                "    name: Workflow runner policy\n    if: false\n",
                1,
            ),
            encoding="utf-8",
        )
        self.assert_rejected("job keys must be exactly")

    def test_runner_policy_workflow_cannot_inject_environment_or_expand_permissions(self) -> None:
        path = self.root / ".github/workflows/runner-policy.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "permissions:\n",
                "env:\n  PYTHONPATH: candidate\npermissions:\n",
                1,
            ),
            encoding="utf-8",
        )
        self.assert_rejected("top-level keys must be exactly")

        path.write_text(
            source.replace("  contents: read\n", "  contents: write\n", 1),
            encoding="utf-8",
        )
        self.assert_rejected("permissions must be exactly")

        path.write_text(
            source.replace(
                "group: runner-policy-${{ github.event.pull_request.number || github.ref }}",
                "group: runner-policy-global",
                1,
            ),
            encoding="utf-8",
        )
        self.assert_rejected("concurrency shape changed")

    def test_runner_policy_rejects_pr_target_action_filter(self) -> None:
        path = self.root / ".github/workflows/runner-policy.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "  pull_request_target:\n",
                "  pull_request_target:\n    types: [closed]\n",
                1,
            ),
            encoding="utf-8",
        )
        self.assert_rejected("must cover every base branch")

    def test_runner_policy_rejects_bare_dash_extra_step(self) -> None:
        path = self.root / ".github/workflows/runner-policy.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "    steps:\n",
                "    steps:\n      -\n        run: echo candidate-controlled-extra-step\n",
                1,
            ),
            encoding="utf-8",
        )
        self.assert_rejected("literal inline sequence mappings")

        path.write_text(
            source.replace(
                "    name: Workflow runner policy\n",
                "    name: Workflow runner policy\n    continue-on-error: true\n",
                1,
            ),
            encoding="utf-8",
        )
        self.assert_rejected("job keys must be exactly")

    def test_runner_policy_rejects_plain_scalar_command_continuation(self) -> None:
        path = self.root / ".github/workflows/runner-policy.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "        run: python3 policy/scripts/check_workflow_runner_policy.py "
                "--root candidate\n",
                "        run: python3 policy/scripts/check_workflow_runner_policy.py "
                "--root candidate\n"
                "          && python3 candidate/evil.py\n",
                1,
            ),
            encoding="utf-8",
        )
        self.assert_rejected("scalar continuation")

    def test_runner_policy_rejects_top_level_name_continuation(self) -> None:
        path = self.root / ".github/workflows/runner-policy.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "name: Workflow runner policy\n",
                "name: Workflow runner policy\n"
                "  attacker-controlled suffix\n",
                1,
            ),
            encoding="utf-8",
        )
        self.assert_rejected("workflow name changed")

    def test_untrusted_workflow_cannot_shadow_policy_status_name(self) -> None:
        self.workflow(
            "shadow.yml",
            """
            on: pull_request
            jobs:
              shadow:
                name: Workflow runner policy
                runs-on: ubuntu-latest
            """,
        )
        self.assert_rejected("cannot claim reserved status")

        self.workflow(
            "shadow.yml",
            """
            on: pull_request
            jobs:
              shadow:
                name: ${{ 'Workflow runner policy' }}
                runs-on: ubuntu-latest
            """,
        )
        self.assert_rejected("dynamic job display name")

        self.workflow(
            "shadow.yml",
            """
            on: push
            jobs:
              shadow:
                name: Workflow runner policy
                runs-on: ubuntu-latest
            """,
        )
        self.assert_rejected("cannot claim reserved status")

    def test_rejects_plain_scalar_runner_and_guard_continuations(self) -> None:
        self.workflow(
            "ci.yml",
            """
            on: pull_request
            jobs:
              test:
                runs-on: ubuntu-latest
                  self-hosted
            """,
        )
        self.assert_rejected("runner scalar has unsupported continuation")

        (self.root / ".github/workflows/ci.yml").unlink()
        self.workflow(
            "egress-probe.yml",
            """
            on: workflow_dispatch
            jobs:
              probe:
                if: github.ref == 'refs/heads/main'
                  || true
                runs-on: [self-hosted, hel1]
            """,
        )
        self.assert_rejected("must use exact main-ref guard")

    def test_rejects_dynamic_runner_and_reusable_uses_continuations(self) -> None:
        self.workflow(
            "release.yml",
            """
            on: push
            jobs:
              build:
                runs-on: ${{ matrix.os }}
                  -large
                strategy:
                  matrix:
                    include:
                      - target: linux
                        os: ubuntu-latest
            """,
        )
        self.assert_rejected("runner scalar has unsupported continuation")

        (self.root / ".github/workflows/release.yml").unlink()
        self.workflow(
            "caller.yml",
            """
            on: pull_request
            jobs:
              call:
                uses: ./.github/workflows/callee.yml
                  trailing
            """,
        )
        self.assert_rejected("uses must be one line")

    def test_rejects_noncanonical_job_and_policy_event_child_indentation(self) -> None:
        self.workflow(
            "trusted.yml",
            """
            on: push
            jobs:
              hidden:
                  runs-on: self-hosted
            """,
        )
        self.assert_rejected("canonical four-space indentation")

        (self.root / ".github/workflows/trusted.yml").unlink()
        path = self.root / ".github/workflows/runner-policy.yml"
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "  pull_request_target:\n",
                "  pull_request_target:\n"
                "      types: [closed]\n",
                1,
            ),
            encoding="utf-8",
        )
        self.assert_rejected("unresolved child indentation")

    def test_rejects_unknown_custom_runner_on_trusted_workflow(self) -> None:
        self.workflow(
            "trusted.yml",
            """
            on: workflow_dispatch
            jobs:
              custom:
                runs-on: production-runner
            """,
        )
        self.assert_rejected("unknown/custom runner selection")

    def test_protected_runner_rejects_extra_or_incomplete_labels(self) -> None:
        self.workflow(
            "egress-probe.yml",
            """
            on: workflow_dispatch
            jobs:
              flow:
                if: github.ref == 'refs/heads/main'
                runs-on: [self-hosted, hel1, production-runner]
            """,
        )
        errors = self.errors()
        self.assertTrue(
            any("unknown/custom runner selection" in error for error in errors)
        )
        self.assertTrue(
            any("must use only the approved labels" in error for error in errors)
        )

        self.workflow(
            "egress-probe.yml",
            """
            on: workflow_dispatch
            jobs:
              block:
                if: github.ref == 'refs/heads/main'
                runs-on:
                  - self-hosted
                  - ci
            """,
        )
        self.assert_rejected("must use only the approved labels")

    def test_rejects_trigger_alias_and_symlink_workflow(self) -> None:
        self.workflow(
            "ci.yml",
            """
            events: &events
              - pull_request
            on: *events
            jobs:
              test:
                runs-on: ubuntu-latest
            """,
        )
        target = self.root / "outside.yml"
        target.write_text("on: push\njobs: {}\n", encoding="utf-8")
        os.symlink(target, self.root / ".github/workflows/link.yml")
        errors = self.errors()
        self.assertTrue(any("trigger indirection" in error for error in errors))
        self.assertTrue(any("must not be a symlink" in error for error in errors))

    def test_privileged_action_requires_full_commit_sha(self) -> None:
        path = self.workflow(
            "publish.yml",
            """
            on: push
            permissions:
              contents: read
            jobs:
              publish:
                runs-on: ubuntu-latest
                permissions:
                  contents: write
                steps:
                  - uses: owner/publisher@v3
            """,
        )
        self.assert_rejected("privileged external actions must use a reviewed full commit SHA")

        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "owner/publisher@v3",
                "owner/publisher@0123456789abcdef0123456789abcdef01234567",
            ),
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

    def test_action_pin_policy_covers_read_only_and_publish_jobs(self) -> None:
        self.workflow(
            "publish.yml",
            """
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: owner/builder@main
              unrelated:
                runs-on: ubuntu-latest
                steps:
                  - uses: owner/read-only-check@main
              publish:
                needs: build
                runs-on: ubuntu-latest
                permissions:
                  id-token: write
                steps:
                  - run: publish
            """,
        )
        errors = self.errors()
        self.assertTrue(any("job=build" in error for error in errors))
        self.assertTrue(any("job=unrelated" in error for error in errors))

    def test_secret_bearing_job_is_privileged_without_write_permissions(self) -> None:
        self.workflow(
            "sign.yml",
            """
            on: push
            permissions:
              contents: read
            jobs:
              sign:
                runs-on: ubuntu-latest
                env:
                  SIGNING_KEY: ${{ secrets.SIGNING_KEY }}
                steps:
                  - uses: owner/signer@v1
            """,
        )
        self.assert_rejected("privileged external actions must use a reviewed full commit SHA")

    def test_only_exact_slsa_mutable_ref_exception_is_accepted(self) -> None:
        path = self.workflow(
            "release.yml",
            """
            on: push
            permissions: {}
            jobs:
              provenance:
                permissions:
                  id-token: write
                uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
            """,
        )
        self.assertEqual(self.errors(), [])

        path.write_text(
            path.read_text(encoding="utf-8").replace("@v2.1.0", "@v2.1.1"),
            encoding="utf-8",
        )
        self.assert_rejected("privileged external actions must use a reviewed full commit SHA")

        self.workflow(
            "sdk-python.yml",
            """
            on: push
            permissions:
              contents: read
            jobs:
              publish:
                runs-on: ubuntu-latest
                permissions:
                  id-token: write
                steps:
                  - uses: pypa/gh-action-pypi-publish@v1.14.1
            """,
        )
        self.assert_rejected("pypa/gh-action-pypi-publish@v1.14.1")

    def test_privileged_docker_action_requires_digest_and_local_action_is_rejected(self) -> None:
        path = self.workflow(
            "publish.yml",
            """
            on: push
            permissions:
              packages: write
            jobs:
              publish:
                runs-on: ubuntu-latest
                steps:
                  - uses: docker://ghcr.io/owner/publisher:v1
            """,
        )
        self.assert_rejected("docker://ghcr.io/owner/publisher:v1")
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "docker://ghcr.io/owner/publisher:v1",
                "docker://ghcr.io/owner/publisher@sha256:"
                + "a" * 64,
            ),
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "      - uses: docker://",
                "      - uses: ./actions/local-publisher\n"
                "      - uses: docker://",
            ),
            encoding="utf-8",
        )
        self.assert_rejected("privileged local actions are unsupported")

    def test_privileged_steps_and_needs_indirection_fail_closed(self) -> None:
        self.workflow(
            "publish.yml",
            """
            on: push
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - &shared
                    uses: owner/builder@0123456789abcdef0123456789abcdef01234567
              publish:
                needs: *dependency
                runs-on: ubuntu-latest
                permissions:
                  contents: write
                steps: *shared
            """,
        )
        errors = self.errors()
        self.assertTrue(
            any("alias, merge, or unresolved mapping" in error for error in errors)
        )
        self.assertTrue(
            any("privileged job steps must be a literal block sequence" in error for error in errors)
        )

    def test_runner_policy_checkout_must_itself_be_sha_pinned(self) -> None:
        path = self.root / ".github/workflows/runner-policy.yml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/checkout@v7",
            ),
            encoding="utf-8",
        )
        self.assert_rejected("runner policy trusted step 1 must use actions/checkout")

    def test_omitted_permissions_treats_repository_default_as_privileged(self) -> None:
        self.workflow(
            "push.yml",
            """
            on: push
            jobs:
              publish:
                runs-on: ubuntu-latest
                steps:
                  - uses: owner/publisher@main
            """,
        )
        self.assert_rejected("privileged external actions must use a reviewed full commit SHA")

    def test_secret_context_bracket_and_workflow_env_forms_are_privileged(self) -> None:
        self.workflow(
            "sign.yml",
            """
            on: push
            permissions:
              contents: read
            env:
              ALL_SECRETS: ${{ toJSON(secrets) }}
            jobs:
              sign:
                runs-on: ubuntu-latest
                env:
                  SIGNING_KEY: ${{ secrets['SIGNING_KEY'] }}
                  TOKEN: ${{ github['token'] }}
                steps:
                  - uses: owner/signer@main
            """,
        )
        self.assert_rejected("privileged external actions must use a reviewed full commit SHA")

    def test_secret_context_yaml_escapes_and_dynamic_token_index_are_privileged(self) -> None:
        self.workflow(
            "sign.yml",
            r"""
            on: push
            permissions:
              contents: read
            jobs:
              sign:
                runs-on: ubuntu-latest
                env:
                  SIGNING_KEY: "${{ secr\u0065ts.SIGNING_KEY }}"
                  TOKEN: ${{ github[format('to{0}', 'ken')] }}
                steps:
                  - uses: owner/signer@main
            """,
        )
        self.assert_rejected("privileged external actions must use a reviewed full commit SHA")

    def test_yaml_anchor_or_alias_consumer_is_treated_as_privileged(self) -> None:
        self.workflow(
            "sign.yml",
            """
            on: push
            permissions:
              contents: read
            jobs:
              define:
                runs-on: ubuntu-latest
                env: &publish-env
                  TOKEN: ${{ secrets.PUBLISH_TOKEN }}
                steps:
                  - run: prepare
              consume:
                runs-on: ubuntu-latest
                env: *publish-env
                steps:
                  - uses: owner/publisher@main
            """,
        )
        errors = self.errors()
        self.assertTrue(
            any(
                "job=consume" in error and "owner/publisher@main" in error
                for error in errors
            ),
            errors,
        )

    def test_yaml_escaped_line_folding_cannot_hide_secret_context(self) -> None:
        self.workflow(
            "sign.yml",
            r"""
            on: push
            permissions:
              contents: read
            jobs:
              sign:
                runs-on: ubuntu-latest
                env:
                  SIGNING_KEY: "${{ secr\
                    ets.SIGNING_KEY }}"
                steps:
                  - uses: owner/signer@main
            """,
        )
        self.assert_rejected("privileged external actions must use a reviewed full commit SHA")

    def test_github_wildcard_context_cannot_hide_implicit_token(self) -> None:
        self.workflow(
            "publish.yml",
            """
            on: push
            permissions:
              contents: read
            jobs:
              publish:
                runs-on: ubuntu-latest
                env:
                  GITHUB_CONTEXT_VALUES: ${{ toJSON(github.*) }}
                steps:
                  - uses: owner/publisher@main
            """,
        )
        self.assert_rejected("privileged external actions must use a reviewed full commit SHA")

    def test_privileged_action_scan_accepts_noncanonical_yaml_indentation_but_not_tag(self) -> None:
        self.workflow(
            "publish.yml",
            """
            on: push
            permissions:
              contents: write
            jobs:
              publish:
                runs-on: ubuntu-latest
                steps:
                    - uses: owner/publisher@main
                timeout-minutes: 10
            """,
        )
        self.assert_rejected("owner/publisher@main")

        path = self.root / ".github/workflows/publish.yml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "owner/publisher@main",
                "owner/publisher@0123456789abcdef0123456789abcdef01234567",
            ),
            encoding="utf-8",
        )
        self.assertEqual(self.errors(), [])

    def test_privileged_local_reusable_workflow_is_scanned_transitively(self) -> None:
        self.workflow(
            "caller.yml",
            """
            on: push
            permissions:
              contents: write
            jobs:
              publish:
                uses: ./.github/workflows/callee.yml
            """,
        )
        self.workflow(
            "callee.yml",
            """
            on: workflow_call
            permissions:
              contents: read
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: owner/builder@main
            """,
        )
        errors = self.errors()
        self.assertTrue(
            any(
                ".github/workflows/callee.yml" in error
                and "owner/builder@main" in error
                for error in errors
            ),
            errors,
        )

    def test_rejects_symlinked_github_directory(self) -> None:
        external = self.root / "external"
        (external / "workflows").mkdir(parents=True)
        (external / "workflows/ci.yml").write_text(
            "on: pull_request\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
            encoding="utf-8",
        )
        candidate = self.root / "candidate"
        candidate.mkdir()
        os.symlink(external, candidate / ".github")
        errors = policy.audit(candidate)
        self.assertTrue(any(".github must be a real directory" in error for error in errors))

    def test_rejects_nested_local_reusable_path_even_through_symlink(self) -> None:
        self.workflow(
            "caller.yml",
            """
            on: pull_request
            jobs:
              call:
                uses: ./.github/workflows/nested/callee.yml
            """,
        )
        external = self.root / "external"
        external.mkdir()
        (external / "callee.yml").write_text(
            "on: workflow_call\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
            encoding="utf-8",
        )
        os.symlink(external, self.root / ".github/workflows/nested")
        self.assert_rejected("literal local workflow")


if __name__ == "__main__":
    unittest.main()
