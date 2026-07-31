#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
"""Fail closed on unsafe GitHub workflow runners and mutable action references.

This intentionally parses only the security-relevant GitHub Actions YAML
surface. Unsupported indirection is rejected in untrusted workflows rather
than evaluated as a GitHub expression, and every external action is required
to use an immutable commit or image digest. The checker has no third-party
runtime dependencies so the trusted default-branch copy can inspect a PR tree
as inert data from ``pull_request_target``.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


UNTRUSTED_EVENTS = frozenset({"pull_request", "pull_request_target", "merge_group"})
PROTECTED_LABELS = frozenset({"self-hosted", "hel1", "ci"})
REQUIRED_PROTECTED_LABELS = frozenset({"self-hosted", "hel1"})
PROTECTED_WORKFLOW_EVENTS = {
    ".github/workflows/coverage-attestation.yml": frozenset(
        {"push", "schedule", "workflow_dispatch"}
    ),
    ".github/workflows/egress-probe.yml": frozenset({"push", "workflow_dispatch"}),
    ".github/workflows/mutants.yml": frozenset({"schedule", "workflow_dispatch"}),
}
PROTECTED_WORKFLOWS = frozenset(PROTECTED_WORKFLOW_EVENTS)
TRUSTED_DYNAMIC_RUNNER_EXCEPTIONS = {
    (".github/workflows/release.yml", "build"): ("${{ matrix.os }}", "os"),
}
POLICY_WORKFLOW = ".github/workflows/runner-policy.yml"
POLICY_WORKFLOW_EVENTS = frozenset({"pull_request_target", "merge_group", "push"})
POLICY_STATUS_NAME = "Workflow runner policy"
ACTION_SHA = re.compile(r"^[0-9a-f]{40}$")
DOCKER_DIGEST = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
MUTABLE_ACTION_EXCEPTIONS = {
    (
        ".github/workflows/release.yml",
        "provenance",
        "slsa-framework/slsa-github-generator/.github/workflows/"
        "generator_generic_slsa3.yml@v2.1.0",
    ): (
        "slsa-github-generator requires an exact vX.Y.Z reusable-workflow ref "
        "so its verifier can authenticate the builder identity; commit refs are unsupported"
    ),
}
TRUSTED_DYNAMIC_JOB_NAME_EXCEPTIONS = {
    (".github/workflows/fuzz.yml", "fuzz"): "Fuzz (${{ matrix.target }})",
    (".github/workflows/mutants.yml", "mutants"): "shard ${{ matrix.shard }}",
    (".github/workflows/release.yml", "build"): "Build (${{ matrix.target }})",
}
MAIN_REF_GUARD = "github.ref == 'refs/heads/main'"
MAX_WORKFLOW_BYTES = 2 * 1024 * 1024
PRIVILEGED_JOB_EXCEPTIONS = {
    (".github/workflows/docker.yml", "build-and-push"): (
        "(github.event_name == 'push' && (github.ref == 'refs/heads/main' || "
        "startsWith(github.ref, 'refs/tags/v'))) || "
        "(github.event_name == 'workflow_dispatch' && "
        "github.ref == 'refs/heads/main')",
        {
            "contents": "read",
            "packages": "write",
            "security-events": "write",
            "id-token": "write",
        },
    ),
    (".github/workflows/docker.yml", "promote-release-aliases"): (
        "github.event_name == 'workflow_run' && "
        "github.event.workflow_run.conclusion == 'success' && "
        "github.event.workflow_run.event == 'push' && "
        "github.event.workflow_run.path == '.github/workflows/release.yml' && "
        "github.event.workflow_run.head_repository.full_name == github.repository && "
        "startsWith(github.event.workflow_run.head_branch, 'v')",
        {"contents": "read", "packages": "write"},
    ),
    (".github/workflows/docs.yml", "deploy"): (
        "github.ref == 'refs/heads/main' && github.event_name == 'push'",
        {"contents": "read", "pages": "write", "id-token": "write"},
    ),
    (".github/workflows/sdk-python.yml", "publish"): (
        "github.event_name == 'push' && "
        "startsWith(github.ref, 'refs/tags/sdk-python-v')",
        {"contents": "read", "id-token": "write"},
    ),
    (".github/workflows/sdk-typescript.yml", "publish"): (
        "github.event_name == 'push' && "
        "startsWith(github.ref, 'refs/tags/sdk-typescript-v')",
        {"contents": "read", "id-token": "write"},
    ),
}

HOSTED_RUNNER = re.compile(
    r"^(?:"
    r"ubuntu-(?:latest|\d{2}\.\d{2})(?:-arm)?|"
    r"windows-(?:latest|\d{4})|"
    r"macos-(?:latest|\d+)(?:-(?:large|xlarge|intel))?"
    r")$"
)
MAPPING_ENTRY = re.compile(
    r"""^(?:"(?P<double>[^"]+)"|'(?P<single>[^']+)'|"""
    r"(?P<bare>[A-Za-z0-9_.-]+|<<))\s*:\s*(?P<value>.*)$"
)


@dataclass(frozen=True)
class Line:
    number: int
    raw: str
    indent: int
    content: str


@dataclass(frozen=True)
class Section:
    key: str
    line: Line
    value: str
    start: int
    end: int


@dataclass(frozen=True)
class Job:
    name: str
    line: Line
    start: int
    end: int
    properties: dict[str, tuple[Line, str]]


class WorkflowDocument:
    def __init__(self, root: Path, path: Path) -> None:
        self.root = root
        self.path = path
        self.relative = path.relative_to(root).as_posix()
        self.errors: list[str] = []
        self.lines = self._read_lines()
        self.sections = self._parse_sections()

    def error(self, line: int, reason: str, job: str | None = None) -> None:
        context = f" job={job}" if job is not None else ""
        self.errors.append(f"{self.relative}:{line}:{context} {reason}".replace(": ", ": ", 1))

    def scalar_continuation(self, line: Line, end: int) -> Line | None:
        """Return the first indented continuation of a security-relevant scalar."""
        for candidate in self.lines[line.number : end]:
            if not candidate.content:
                continue
            if candidate.indent <= line.indent:
                return None
            return candidate
        return None

    def _read_lines(self) -> list[Line]:
        try:
            metadata = self.path.lstat()
        except OSError as exc:
            self.errors.append(f"{self.relative}:1: cannot inspect workflow: {exc}")
            return []
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            self.errors.append(f"{self.relative}:1: workflow must be a regular non-symlink file")
            return []
        if metadata.st_size > MAX_WORKFLOW_BYTES:
            self.errors.append(
                f"{self.relative}:1: workflow exceeds {MAX_WORKFLOW_BYTES} byte policy limit"
            )
            return []
        try:
            raw_lines = self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            self.errors.append(f"{self.relative}:1: cannot read UTF-8 workflow: {exc}")
            return []

        parsed: list[Line] = []
        for number, raw in enumerate(raw_lines, 1):
            prefix = raw[: len(raw) - len(raw.lstrip(" \t"))]
            if "\t" in prefix:
                self.errors.append(
                    f"{self.relative}:{number}: tab indentation is unsupported"
                )
            content = _strip_comment(raw.lstrip(" \t")).rstrip()
            parsed.append(Line(number, raw, len(prefix.expandtabs(8)), content))
        return parsed

    def _parse_sections(self) -> dict[str, Section]:
        starts: list[tuple[str, Line, str, int]] = []
        seen: dict[str, Line] = {}
        for index, line in enumerate(self.lines):
            if not line.content or line.indent != 0:
                continue
            if line.content in {"---", "..."}:
                continue
            entry = _mapping_entry(line.content)
            if entry is None:
                self.error(line.number, "unsupported top-level YAML construct")
                continue
            key, value = entry
            if key in seen:
                self.error(
                    line.number,
                    f"duplicate top-level key {key!r} (first at line {seen[key].number})",
                )
                continue
            seen[key] = line
            starts.append((key, line, value, index))

        sections: dict[str, Section] = {}
        for position, (key, line, value, start) in enumerate(starts):
            end = starts[position + 1][3] if position + 1 < len(starts) else len(self.lines)
            sections[key] = Section(key, line, value, start, end)
        return sections

    def events(self) -> set[str]:
        section = self.sections.get("on")
        if section is None:
            self.error(1, "workflow has no literal top-level 'on' key")
            return set()
        if _has_indirection(section.value):
            self.error(section.line.number, "trigger indirection/tags are unsupported")
            return set()
        if section.value:
            try:
                values = set(_literal_values(section.value))
            except ValueError as exc:
                self.error(section.line.number, f"unsupported inline trigger form: {exc}")
                return set()
            continuation = self.scalar_continuation(section.line, section.end)
            if continuation is not None:
                self.error(
                    continuation.number,
                    "multiline trigger scalars are unsupported",
                )
                return set()
            return values

        events: set[str] = set()
        event_lines: dict[str, Line] = {}
        for line in self.lines[section.start + 1 : section.end]:
            if not line.content:
                continue
            if line.indent == 2:
                entry = _mapping_entry(line.content)
                if entry is not None:
                    key, value = entry
                    if key == "<<":
                        self.error(line.number, "trigger merge keys are unsupported")
                    elif _has_indirection(key) or _has_indirection(value):
                        self.error(line.number, "trigger indirection/tags are unsupported")
                    elif value and self.scalar_continuation(line, section.end) is not None:
                        self.error(
                            line.number,
                            f"trigger {key!r} uses an unsupported multiline scalar",
                        )
                    elif key in event_lines:
                        self.error(
                            line.number,
                            f"duplicate trigger {key!r} "
                            f"(first at line {event_lines[key].number})",
                        )
                    else:
                        event_lines[key] = line
                        events.add(key)
                    continue
                if line.content.startswith("- "):
                    try:
                        events.update(_literal_values(line.content[2:].strip()))
                    except ValueError as exc:
                        self.error(line.number, f"unsupported trigger list item: {exc}")
                    continue
                self.error(line.number, "trigger entries must be literal event names")
            elif line.indent < 2:
                self.error(line.number, "invalid trigger indentation")
        if not events:
            self.error(section.line.number, "workflow trigger set is empty or unresolved")
        return events

    def event_child_keys(self, event: str) -> tuple[Line, str, dict[str, str]] | None:
        section = self.sections.get("on")
        if section is None or section.value:
            return None
        event_index: int | None = None
        event_line: Line | None = None
        event_value = ""
        for index in range(section.start + 1, section.end):
            line = self.lines[index]
            if not line.content or line.indent != 2:
                continue
            entry = _mapping_entry(line.content)
            if entry is not None and entry[0] == event:
                event_index = index
                event_line = line
                event_value = entry[1]
                break
        if event_index is None or event_line is None:
            return None
        children: dict[str, str] = {}
        child_lines: dict[str, Line] = {}
        for line in self.lines[event_index + 1 : section.end]:
            if not line.content:
                continue
            if line.indent <= 2:
                break
            if line.indent == 4:
                entry = _mapping_entry(line.content)
                if entry is None:
                    self.error(line.number, f"{event} contains an unresolved child key")
                    continue
                key, value = entry
                if key == "<<" or _has_indirection(value):
                    self.error(
                        line.number,
                        f"{event} child merge keys/indirection are unsupported",
                    )
                    continue
                continuation = (
                    self.scalar_continuation(line, section.end) if value else None
                )
                if continuation is not None:
                    self.error(
                        continuation.number,
                        f"{event} child {key!r} uses an unsupported multiline scalar",
                    )
                    continue
                if key in child_lines:
                    self.error(
                        line.number,
                        f"duplicate {event} child {key!r} "
                        f"(first at line {child_lines[key].number})",
                    )
                    continue
                child_lines[key] = line
                children[key] = value
            else:
                self.error(
                    line.number,
                    f"{event} contains unresolved child indentation",
                )
        return event_line, event_value, children

    def section_child_values(self, section_name: str) -> dict[str, str] | None:
        section = self.sections.get(section_name)
        if section is None or section.value:
            return None
        values: dict[str, str] = {}
        lines: dict[str, Line] = {}
        for line in self.lines[section.start + 1 : section.end]:
            if not line.content:
                continue
            if line.indent != 2:
                self.error(
                    line.number,
                    f"{section_name} contains unresolved nested configuration",
                )
                continue
            entry = _mapping_entry(line.content)
            if entry is None or entry[0] == "<<":
                self.error(
                    line.number,
                    f"{section_name} contains an unresolved/merged key",
                )
                continue
            key, value = entry
            if key in values:
                self.error(
                    line.number,
                    f"duplicate {section_name} key {key!r} "
                    f"(first at line {lines[key].number})",
                )
                continue
            lines[key] = line
            values[key] = value
        return values

    def job_child_values(self, job: Job, property_name: str) -> dict[str, str] | None:
        """Parse one literal job-level mapping without YAML indirection."""
        property_value = job.properties.get(property_name)
        if property_value is None:
            return None
        property_line, inline_value = property_value
        continuation = (
            self.scalar_continuation(property_line, job.end)
            if inline_value
            else None
        )
        if inline_value:
            if inline_value == "{}" and continuation is None:
                return {}
            self.error(
                property_line.number,
                f"job {property_name} must be a literal block mapping or {{}}",
                job.name,
            )
            return None

        values: dict[str, str] = {}
        lines: dict[str, Line] = {}
        for line in self.lines[property_line.number : job.end]:
            if not line.content:
                continue
            if line.indent <= property_line.indent:
                break
            if line.indent != property_line.indent + 2:
                self.error(
                    line.number,
                    f"job {property_name} contains unresolved nested configuration",
                    job.name,
                )
                continue
            entry = _mapping_entry(line.content)
            if (
                entry is None
                or entry[0] == "<<"
                or _has_indirection(entry[0])
                or _has_indirection(entry[1])
                or not entry[1]
            ):
                self.error(
                    line.number,
                    f"job {property_name} contains an unresolved/merged key or value",
                    job.name,
                )
                continue
            key, value = entry
            if key in values:
                self.error(
                    line.number,
                    f"duplicate job {property_name} key {key!r} "
                    f"(first at line {lines[key].number})",
                    job.name,
                )
                continue
            lines[key] = line
            values[key] = value
        if not values:
            self.error(
                property_line.number,
                f"job {property_name} mapping is empty; use literal {{}}",
                job.name,
            )
            return None
        return values

    def jobs(self) -> list[Job]:
        section = self.sections.get("jobs")
        if section is None:
            self.error(1, "workflow has no literal top-level 'jobs' key")
            return []
        if section.value:
            self.error(section.line.number, "inline or aliased jobs mappings are unsupported")
            return []

        starts: list[tuple[str, Line, int]] = []
        seen: dict[str, Line] = {}
        for index in range(section.start + 1, section.end):
            line = self.lines[index]
            if not line.content:
                continue
            if line.indent == 2:
                entry = _mapping_entry(line.content)
                if entry is None:
                    self.error(line.number, "job declarations must be literal mappings")
                    continue
                key, value = entry
                if key == "<<":
                    self.error(line.number, "job merge keys are unsupported")
                    continue
                if value:
                    self.error(line.number, f"inline job {key!r} is unsupported", key)
                    continue
                if key in seen:
                    self.error(
                        line.number,
                        f"duplicate job {key!r} (first at line {seen[key].number})",
                        key,
                    )
                    continue
                seen[key] = line
                starts.append((key, line, index))
            elif line.indent < 2:
                self.error(line.number, "invalid jobs indentation")

        jobs: list[Job] = []
        for position, (name, line, start) in enumerate(starts):
            end = starts[position + 1][2] if position + 1 < len(starts) else section.end
            properties: dict[str, tuple[Line, str]] = {}
            first_child = next(
                (
                    candidate
                    for candidate in self.lines[start + 1 : end]
                    if candidate.content
                ),
                None,
            )
            if first_child is None or first_child.indent != 4:
                self.error(
                    line.number if first_child is None else first_child.number,
                    "job properties must begin at the canonical four-space indentation",
                    name,
                )
            for candidate in self.lines[start + 1 : end]:
                if not candidate.content or candidate.indent != 4:
                    continue
                entry = _mapping_entry(candidate.content)
                if entry is None:
                    self.error(candidate.number, "job properties must be literal mappings", name)
                    continue
                key, value = entry
                if key == "<<":
                    self.error(candidate.number, "job merge keys are unsupported", name)
                    continue
                if key in properties:
                    first = properties[key][0]
                    self.error(
                        candidate.number,
                        f"duplicate job key {key!r} (first at line {first.number})",
                        name,
                    )
                    continue
                properties[key] = (candidate, value)
            jobs.append(Job(name, line, start, end, properties))
        if not jobs:
            self.error(section.line.number, "workflow contains no parseable jobs")
        return jobs

    def runner_values(self, job: Job) -> tuple[Line, list[str]] | None:
        runner = job.properties.get("runs-on")
        if runner is None:
            return None
        line, value = runner
        if value.strip().startswith(("|", ">")):
            return line, _literal_values(value)
        if value:
            continuation = self.scalar_continuation(line, job.end)
            if continuation is not None:
                raise ValueError(
                    f"runner scalar has unsupported continuation at line "
                    f"{continuation.number}"
                )
        if _has_indirection(value):
            raise ValueError("runner expressions, aliases, and tags are unsupported")
        if value:
            return line, _literal_values(value)

        values: list[str] = []
        for candidate in self.lines:
            if candidate.number <= line.number:
                continue
            if candidate.number >= self.lines[job.end - 1].number + 1:
                break
            if not candidate.content:
                continue
            if candidate.indent <= line.indent:
                break
            if candidate.indent != line.indent + 2 or not candidate.content.startswith("- "):
                raise ValueError("runner mapping/complex block selection is unsupported")
            values.extend(_literal_values(candidate.content[2:].strip()))
        if not values:
            raise ValueError("runner selection is empty")
        return line, values

    def job_action_uses(self, job: Job) -> list[tuple[Line, str]]:
        """Return literal job- and step-level ``uses`` references.

        This parser is deliberately strict for privileged jobs: aliases, merge
        keys, block scalars, expressions, duplicate properties, and scalar
        continuations fail closed instead of being interpreted.
        """
        references: list[tuple[Line, str]] = []

        reusable = job.properties.get("uses")
        if reusable is not None:
            line, value = reusable
            continuation = self.scalar_continuation(line, job.end)
            if continuation is not None:
                self.error(
                    continuation.number,
                    "privileged reusable-workflow uses must be one line",
                    job.name,
                )
            else:
                parsed = self._literal_action_reference(line, value, job)
                if parsed is not None:
                    references.append((line, parsed))

        steps = job.properties.get("steps")
        if steps is None:
            return references
        steps_line, steps_value = steps
        if steps_value:
            self.error(
                steps_line.number,
                "privileged job steps must be a literal block sequence",
                job.name,
            )
            return references

        steps_end = job.end
        for index in range(steps_line.number, job.end):
            candidate = self.lines[index]
            if candidate.content and candidate.indent <= steps_line.indent:
                steps_end = index
                break
        body = [
            candidate
            for candidate in self.lines[steps_line.number : steps_end]
            if candidate.content
        ]
        if not body:
            self.error(
                steps_line.number,
                "privileged job steps block is empty",
                job.name,
            )
            return references
        step_indent = body[0].indent
        if step_indent <= steps_line.indent:
            self.error(
                body[0].number,
                "privileged job steps must be indented below the steps key",
                job.name,
            )
            return references
        starts: list[int] = []
        for index in range(steps_line.number, steps_end):
            candidate = self.lines[index]
            if not candidate.content:
                continue
            if candidate.indent < step_indent:
                self.error(
                    candidate.number,
                    "privileged job steps use inconsistent indentation",
                    job.name,
                )
                continue
            if candidate.indent != step_indent:
                continue
            if not candidate.content.startswith("- "):
                self.error(
                    candidate.number,
                    "privileged job steps must use literal sequence mappings",
                    job.name,
                )
                continue
            starts.append(index)
        if not starts:
            self.error(
                steps_line.number,
                "privileged job steps contain no literal sequence mappings",
                job.name,
            )
            return references

        for position, start in enumerate(starts):
            end = starts[position + 1] if position + 1 < len(starts) else steps_end
            first = self.lines[start]
            first_entry = _mapping_entry(first.content[2:].strip())
            if first_entry is None or first_entry[0] == "<<":
                self.error(
                    first.number,
                    "privileged job step contains an alias, merge, or unresolved mapping",
                    job.name,
                )
                continue

            properties: dict[str, tuple[Line, str]] = {
                first_entry[0]: (first, first_entry[1])
            }
            for candidate in self.lines[start + 1 : end]:
                if not candidate.content or candidate.indent != step_indent + 2:
                    continue
                entry = _mapping_entry(candidate.content)
                if entry is None or entry[0] == "<<":
                    self.error(
                        candidate.number,
                        "privileged job step contains an alias, merge, or unresolved property",
                        job.name,
                    )
                    continue
                key, value = entry
                if key in properties:
                    self.error(
                        candidate.number,
                        f"privileged job step duplicates {key!r}",
                        job.name,
                    )
                    continue
                properties[key] = (candidate, value)

            action = properties.get("uses")
            if action is None:
                continue
            line, value = action
            parsed = self._literal_action_reference(line, value, job)
            if parsed is not None:
                references.append((line, parsed))
        return references

    def _literal_action_reference(
        self, line: Line, value: str, job: Job
    ) -> str | None:
        try:
            parsed = _literal_values(value)
        except ValueError as exc:
            self.error(
                line.number,
                f"privileged action uses is unresolved: {exc}",
                job.name,
            )
            return None
        if len(parsed) != 1:
            self.error(
                line.number,
                "privileged action uses must contain exactly one literal reference",
                job.name,
            )
            return None
        return parsed[0]

    def validate_hosted_include_matrix(self, job: Job, variable: str) -> None:
        strategy = job.properties.get("strategy")
        if strategy is None or strategy[1]:
            raise ValueError("dynamic runner exception requires a literal strategy block")
        strategy_index = strategy[0].number - 1
        matrix_index: int | None = None
        for index in range(strategy_index + 1, job.end):
            candidate = self.lines[index]
            if not candidate.content:
                continue
            if candidate.indent <= strategy[0].indent:
                break
            if candidate.indent == strategy[0].indent + 2:
                entry = _mapping_entry(candidate.content)
                if entry is None or entry[0] != "matrix":
                    raise ValueError(
                        f"dynamic runner strategy key at line {candidate.number} "
                        "must be the one literal matrix key"
                    )
                if matrix_index is not None or entry[1]:
                    raise ValueError(
                        "dynamic runner exception requires one literal matrix block"
                    )
                matrix_index = index
        if matrix_index is None:
            raise ValueError("dynamic runner exception has no literal matrix block")

        matrix_line = self.lines[matrix_index]
        matrix_end = job.end
        for index in range(matrix_index + 1, job.end):
            candidate = self.lines[index]
            if candidate.content and candidate.indent <= matrix_line.indent:
                matrix_end = index
                break

        include_index: int | None = None
        for index in range(matrix_index + 1, matrix_end):
            candidate = self.lines[index]
            if not candidate.content:
                continue
            if candidate.indent == matrix_line.indent + 2:
                entry = _mapping_entry(candidate.content)
                if entry is None or entry[0] != "include" or entry[1]:
                    raise ValueError(
                        "dynamic runner exception permits only a literal matrix.include list"
                    )
                if include_index is not None:
                    raise ValueError("dynamic runner matrix has duplicate include keys")
                include_index = index
            elif candidate.indent < matrix_line.indent + 2:
                raise ValueError("dynamic runner matrix indentation is unresolved")
        if include_index is None:
            raise ValueError("dynamic runner matrix has no literal include list")

        entry_indent = matrix_line.indent + 4
        starts: list[int] = []
        for index in range(include_index + 1, matrix_end):
            candidate = self.lines[index]
            if not candidate.content or candidate.indent != entry_indent:
                continue
            if not candidate.content.startswith("- "):
                raise ValueError(
                    f"dynamic runner matrix entry at line {candidate.number} "
                    "must use a literal inline sequence mapping"
                )
            starts.append(index)
        if not starts:
            raise ValueError("dynamic runner matrix.include contains no literal entries")

        for position, start in enumerate(starts):
            end = starts[position + 1] if position + 1 < len(starts) else matrix_end
            first = self.lines[start]
            if _mapping_entry(first.content[2:].strip()) is None:
                raise ValueError(
                    f"dynamic runner matrix entry at line {first.number} is unresolved"
                )
            values: list[tuple[Line, str]] = []
            for candidate in self.lines[start + 1 : end]:
                if not candidate.content:
                    continue
                if candidate.indent == entry_indent + 2:
                    entry = _mapping_entry(candidate.content)
                    if entry is None:
                        raise ValueError(
                            f"dynamic runner matrix key at line {candidate.number} is unresolved"
                        )
                    key, value = entry
                    if key == "<<" or _has_indirection(value):
                        raise ValueError(
                            f"dynamic runner matrix key at line {candidate.number} is indirect"
                        )
                    if key == variable:
                        values.append((candidate, value))
                else:
                    raise ValueError(
                        f"dynamic runner matrix entry at line {candidate.number} "
                        "contains unresolved nesting or scalar continuation"
                    )
            if len(values) != 1:
                raise ValueError(
                    f"dynamic runner matrix entry at line {first.number} must define "
                    f"exactly one {variable!r}"
                )
            runner_line, raw_value = values[0]
            try:
                runners = _literal_values(raw_value)
            except ValueError as exc:
                raise ValueError(
                    f"dynamic runner matrix value at line {runner_line.number}: {exc}"
                ) from exc
            if not _is_hosted_runner(runners):
                raise ValueError(
                    f"dynamic runner matrix value at line {runner_line.number} "
                    f"must be one literal GitHub-hosted label, got {runners!r}"
                )

    def validate_policy_steps(self, job: Job) -> None:
        steps_property = job.properties.get("steps")
        if steps_property is None or steps_property[1]:
            self.error(
                job.line.number,
                "runner policy job must contain one literal steps block",
                job.name,
            )
            return
        step_indent = steps_property[0].indent + 2
        starts: list[int] = []
        for index in range(steps_property[0].number, job.end):
            candidate = self.lines[index]
            if not candidate.content or candidate.indent != step_indent:
                continue
            if not candidate.content.startswith("- "):
                self.error(
                    candidate.number,
                    "runner policy steps must use literal inline sequence mappings",
                    job.name,
                )
                return
            starts.append(index)
        if len(starts) != 5:
            self.error(
                steps_property[0].number,
                f"runner policy job must contain exactly five trusted steps, got {len(starts)}",
                job.name,
            )
            return

        parsed_steps: list[tuple[Line, dict[str, str], dict[str, str]]] = []
        for position, start in enumerate(starts):
            end = starts[position + 1] if position + 1 < len(starts) else job.end
            first = self.lines[start]
            first_entry = _mapping_entry(first.content[2:].strip())
            if first_entry is None:
                self.error(first.number, "runner policy step is unresolved", job.name)
                return
            properties: dict[str, tuple[Line, str]] = {
                first_entry[0]: (first, first_entry[1])
            }
            active_property = first_entry[0]
            for candidate in self.lines[start + 1 : end]:
                if not candidate.content:
                    continue
                if candidate.indent == step_indent + 2:
                    entry = _mapping_entry(candidate.content)
                    if entry is None or entry[0] == "<<":
                        self.error(
                            candidate.number,
                            "runner policy step contains an unresolved/merged property",
                            job.name,
                        )
                        return
                    key, value = entry
                    if key in properties:
                        self.error(
                            candidate.number,
                            f"runner policy step duplicates {key!r}",
                            job.name,
                        )
                        return
                    properties[key] = (candidate, value)
                    active_property = key
                    continue
                if candidate.indent == step_indent + 4 and active_property == "with":
                    entry = _mapping_entry(candidate.content)
                    if entry is not None and entry[0] != "<<":
                        continue
                self.error(
                    candidate.number,
                    "runner policy step contains unresolved nesting or scalar continuation",
                    job.name,
                )
                return

            with_values: dict[str, str] = {}
            with_property = properties.get("with")
            if with_property is not None:
                if with_property[1]:
                    self.error(
                        with_property[0].number,
                        "runner policy checkout with-map must be a literal block",
                        job.name,
                    )
                    return
                for candidate in self.lines[
                    with_property[0].number : end
                ]:
                    if not candidate.content:
                        continue
                    if candidate.indent <= with_property[0].indent:
                        break
                    if candidate.indent != with_property[0].indent + 2:
                        self.error(
                            candidate.number,
                            "runner policy checkout with-map is unresolved",
                            job.name,
                        )
                        return
                    entry = _mapping_entry(candidate.content)
                    if entry is None or entry[0] == "<<":
                        self.error(
                            candidate.number,
                            "runner policy checkout input is unresolved/indirect",
                            job.name,
                        )
                        return
                    key, value = entry
                    if key in with_values:
                        self.error(
                            candidate.number,
                            f"runner policy checkout input duplicates {key!r}",
                            job.name,
                        )
                        return
                    with_values[key] = value

            flattened = {
                key: value
                for key, (_, value) in properties.items()
                if key not in {"name", "with"}
            }
            parsed_steps.append((first, flattened, with_values))

        checkout = re.compile(r"^actions/checkout@[0-9a-f]{40}$")
        expected = [
            (
                {"uses"},
                {
                    "ref": "refs/heads/main",
                    "path": "policy",
                    "persist-credentials": "false",
                },
            ),
            (
                {"if", "uses"},
                {
                    "repository": "${{ github.event.pull_request.head.repo.full_name }}",
                    "ref": "${{ github.event.pull_request.head.sha }}",
                    "path": "candidate",
                    "persist-credentials": "false",
                    "submodules": "false",
                },
            ),
            (
                {"if", "uses"},
                {
                    "ref": "${{ github.sha }}",
                    "path": "candidate",
                    "persist-credentials": "false",
                    "submodules": "false",
                },
            ),
            ({"run"}, {}),
            ({"run"}, {}),
        ]
        for index, ((line, properties, with_values), (keys, expected_with)) in enumerate(
            zip(parsed_steps, expected, strict=True)
        ):
            if set(properties) != keys or with_values != expected_with:
                self.error(
                    line.number,
                    f"runner policy trusted step {index + 1} shape changed",
                    job.name,
                )
                return
            if "uses" in properties and checkout.fullmatch(properties["uses"]) is None:
                self.error(
                    line.number,
                    f"runner policy trusted step {index + 1} must use actions/checkout",
                    job.name,
                )
                return

        if parsed_steps[1][1]["if"] != "github.event_name == 'pull_request_target'":
            self.error(
                parsed_steps[1][0].number,
                "runner policy PR checkout guard changed",
                job.name,
            )
        if parsed_steps[2][1]["if"] != "github.event_name != 'pull_request_target'":
            self.error(
                parsed_steps[2][0].number,
                "runner policy merge/main checkout guard changed",
                job.name,
            )
        if (
            parsed_steps[3][1]["run"]
            != "python3 policy/scripts/check_workflow_runner_policy_test.py"
        ):
            self.error(
                parsed_steps[3][0].number,
                "runner policy parser-test command changed",
                job.name,
            )
        if (
            parsed_steps[4][1]["run"]
            != "python3 policy/scripts/check_workflow_runner_policy.py --root candidate"
        ):
            self.error(
                parsed_steps[4][0].number,
                "runner policy candidate-scan command changed",
                job.name,
            )

    def validate_policy_job_shape(self, job: Job) -> None:
        expected_keys = {"name", "runs-on", "timeout-minutes", "steps"}
        if set(job.properties) != expected_keys:
            self.error(
                job.line.number,
                f"runner policy job keys must be exactly {sorted(expected_keys)!r}, "
                f"got {sorted(job.properties)!r}",
                job.name,
            )
            return
        for key, (line, value) in job.properties.items():
            continuation = (
                self.scalar_continuation(line, job.end) if value else None
            )
            if continuation is not None:
                self.error(
                    continuation.number,
                    f"runner policy job property {key!r} must be one line",
                    job.name,
                )
                return
        expected_values = {
            "name": "Workflow runner policy",
            "runs-on": "ubuntu-latest",
            "timeout-minutes": "10",
            "steps": "",
        }
        actual_values = {
            key: line_and_value[1] for key, line_and_value in job.properties.items()
        }
        if actual_values != expected_values:
            self.error(
                job.line.number,
                "runner policy job security-critical values changed",
                job.name,
            )
            return
        self.validate_policy_steps(job)


def _strip_comment(value: str) -> str:
    single = False
    double = False
    escaped = False
    index = 0
    while index < len(value):
        char = value[index]
        if double:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                double = False
        elif single:
            if char == "'" and index + 1 < len(value) and value[index + 1] == "'":
                index += 1
            elif char == "'":
                single = False
        elif char == '"':
            double = True
        elif char == "'":
            single = True
        elif char == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index]
        index += 1
    return value


def _mapping_entry(content: str) -> tuple[str, str] | None:
    match = MAPPING_ENTRY.match(content)
    if match is None:
        return None
    key = match.group("double") or match.group("single") or match.group("bare")
    # GitHub/YAML decodes escapes before interpreting keys. Treating the raw
    # spelling as a different key would allow semantic duplicates such as
    # "runs-\u006fn". Fail closed instead of implementing YAML escape rules.
    if match.group("double") is not None and "\\" in key:
        return None
    return key, match.group("value").strip()


def _has_indirection(value: str) -> bool:
    stripped = value.strip()
    return (
        "${{" in stripped
        or stripped.startswith(("*", "&", "!"))
        or "<<:" in stripped
    )


def _split_flow_list(value: str) -> list[str]:
    inner = value[1:-1]
    values: list[str] = []
    current: list[str] = []
    single = False
    double = False
    escaped = False
    for char in inner:
        if double:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                double = False
        elif single:
            current.append(char)
            if char == "'":
                single = False
        elif char == '"':
            double = True
            current.append(char)
        elif char == "'":
            single = True
            current.append(char)
        elif char == ",":
            values.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if single or double:
        raise ValueError("unterminated quote")
    values.append("".join(current).strip())
    return values


def _literal_values(value: str) -> list[str]:
    stripped = value.strip()
    if not stripped:
        raise ValueError("empty literal")
    if _has_indirection(stripped) or stripped.startswith(("{", "|", ">")):
        raise ValueError(
            "expressions, mappings, aliases, tags, and block scalars are unsupported"
        )
    if stripped.startswith("["):
        if not stripped.endswith("]"):
            raise ValueError("multiline flow lists are unsupported")
        raw_values = _split_flow_list(stripped)
    else:
        if any(token in stripped for token in ("[", "]", "{", "}")):
            raise ValueError("unsupported scalar syntax")
        raw_values = [stripped]

    parsed: list[str] = []
    for raw in raw_values:
        if not raw:
            raise ValueError("empty list item")
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
            if raw[0] == '"' and "\\" in raw:
                raise ValueError("escapes in double-quoted security literals are unsupported")
            raw = raw[1:-1]
        elif raw.startswith(("'", '"')) or raw.endswith(("'", '"')):
            raise ValueError("unterminated quote")
        if _has_indirection(raw) or not raw:
            raise ValueError("non-literal value")
        parsed.append(raw)
    return parsed


def _is_hosted_runner(values: list[str]) -> bool:
    return len(values) == 1 and HOSTED_RUNNER.fullmatch(values[0].casefold()) is not None


def _contains_protected_label(values: list[str]) -> bool:
    return any(value.strip().casefold() in PROTECTED_LABELS for value in values)

def _is_protected_runner(values: list[str]) -> bool:
    labels = [value.strip().casefold() for value in values]
    unique = set(labels)
    return (
        len(labels) == len(unique)
        and REQUIRED_PROTECTED_LABELS <= unique
        and unique <= PROTECTED_LABELS
    )


def _is_exact_main_ref_guard(value: str) -> bool:
    expression = value.strip()
    if expression.startswith("${{") and expression.endswith("}}"):
        expression = expression[3:-2].strip()
    return expression in {
        MAIN_REF_GUARD,
        f"always() && {MAIN_REF_GUARD}",
    }


def _local_workflow_target(value: str) -> PurePosixPath | None:
    try:
        values = _literal_values(value)
    except ValueError:
        return None
    if len(values) != 1 or not values[0].startswith("./"):
        return None
    target = PurePosixPath(values[0][2:])
    if (
        target.is_absolute()
        or ".." in target.parts
        or target.parts[:2] != (".github", "workflows")
        or len(target.parts) != 3
        or target.suffix not in {".yml", ".yaml"}
    ):
        return None
    return target


class RunnerPolicy:
    def __init__(self, root: Path) -> None:
        self.input_root = root
        self.root = root.resolve()
        self.errors: list[str] = []
        self._documents: dict[Path, WorkflowDocument] = {}
        self._visited: set[tuple[Path, bool]] = set()
        self._active: list[Path] = []

    def audit(self) -> list[str]:
        if self.input_root.is_symlink():
            return [".:1: candidate repository root must not be a symlink"]
        github_dir = self.root / ".github"
        workflow_dir = github_dir / "workflows"
        if github_dir.is_symlink() or not github_dir.is_dir():
            return [".github:1: .github must be a real directory"]
        if workflow_dir.is_symlink() or not workflow_dir.is_dir():
            return [".github/workflows:1: workflow directory must be a real directory"]
        try:
            entries = sorted(workflow_dir.iterdir(), key=lambda path: path.name)
        except OSError as exc:
            return [f".github/workflows:1: cannot list workflow directory: {exc}"]

        candidates: list[Path] = []
        for path in entries:
            if path.suffix not in {".yml", ".yaml"}:
                continue
            if path.is_symlink():
                self.errors.append(
                    f".github/workflows/{path.name}:1: workflow must not be a symlink"
                )
                continue
            candidates.append(path)
        if not candidates:
            self.errors.append(".github/workflows:1: no workflow files found")
        policy_path = workflow_dir / Path(POLICY_WORKFLOW).name
        if policy_path not in candidates:
            self.errors.append(
                f"{POLICY_WORKFLOW}:1: trusted runner policy workflow is required"
            )
        for path in candidates:
            self._audit_path(
                path,
                force_untrusted=False,
            )
        return sorted(set(self.errors))

    def _document(self, path: Path) -> WorkflowDocument:
        document = self._documents.get(path)
        if document is None:
            document = WorkflowDocument(self.root, path)
            self._documents[path] = document
        return document

    def _audit_untrusted_job_permissions(
        self, document: WorkflowDocument, job: Job
    ) -> None:
        if "permissions" not in job.properties:
            return
        permissions = document.job_child_values(job, "permissions")
        if permissions is None:
            return
        invalid = {
            scope: value
            for scope, value in permissions.items()
            if value not in {"read", "write", "none"}
        }
        if invalid:
            document.error(
                job.properties["permissions"][0].number,
                "untrusted job permissions must use only literal read, write, "
                f"or none values, got {invalid!r}",
                job.name,
            )
            return
        writes = {scope for scope, value in permissions.items() if value == "write"}
        if not writes:
            return

        exception = PRIVILEGED_JOB_EXCEPTIONS.get((document.relative, job.name))
        if exception is None:
            document.error(
                job.properties["permissions"][0].number,
                f"untrusted workflow job grants write permissions {sorted(writes)!r}",
                job.name,
            )
            return
        expected_guard, expected_permissions = exception
        guard = job.properties.get("if")
        guard_continuation = (
            document.scalar_continuation(guard[0], job.end)
            if guard is not None
            else None
        )
        if (
            guard is None
            or guard_continuation is not None
            or guard[1] != expected_guard
        ):
            document.error(
                (
                    guard_continuation.number
                    if guard_continuation is not None
                    else job.line.number
                ),
                "privileged job guard must exactly match its protected-event policy",
                job.name,
            )
        if permissions != expected_permissions:
            document.error(
                job.properties["permissions"][0].number,
                "privileged job permission set must exactly match its allowlisted "
                f"minimum {expected_permissions!r}, got {permissions!r}",
                job.name,
            )

    def _audit_privileged_action_pins(
        self,
        document: WorkflowDocument,
        jobs: list[Job],
    ) -> None:
        # Privilege classification itself is a mutable, expression-rich YAML
        # surface. Enforce immutable external references repository-wide so a
        # new secret spelling, token default, artifact edge, or YAML feature
        # cannot move an action outside the protected set.
        for job in jobs:
            for line, reference in document.job_action_uses(job):
                exception = MUTABLE_ACTION_EXCEPTIONS.get(
                    (document.relative, job.name, reference)
                )
                if exception is not None:
                    continue
                if reference.startswith("./"):
                    local = PurePosixPath(reference[2:])
                    if local.is_absolute() or ".." in local.parts:
                        document.error(
                            line.number,
                            f"privileged local action path is unsafe: {reference!r}",
                            job.name,
                        )
                        continue
                    workflow_target = _local_workflow_target(reference)
                    if reference.startswith("./.github/workflows/"):
                        if workflow_target is None:
                            document.error(
                                line.number,
                                f"privileged local reusable workflow path is unsafe: "
                                f"{reference!r}",
                                job.name,
                            )
                            continue
                        callee = self.root / workflow_target
                        if (
                            not callee.exists()
                            or callee.is_symlink()
                            or not callee.is_file()
                        ):
                            document.error(
                                line.number,
                                f"privileged local reusable workflow "
                                f"{workflow_target.as_posix()!r} is missing or unsafe",
                                job.name,
                            )
                            continue
                        callee_document = self._document(callee)
                        if "workflow_call" not in callee_document.events():
                            document.error(
                                line.number,
                                f"privileged local reusable workflow "
                                f"{workflow_target.as_posix()!r} lacks workflow_call",
                                job.name,
                            )
                            continue
                        self._audit_path(
                            callee,
                            force_untrusted=False,
                        )
                        continue
                    document.error(
                        line.number,
                        "privileged local actions are unsupported because nested "
                        f"external uses cannot be proven pinned: {reference!r}",
                        job.name,
                    )
                    continue
                if DOCKER_DIGEST.fullmatch(reference) is not None:
                    continue
                action, separator, revision = reference.rpartition("@")
                action_parts = action.split("/")
                literal_action = (
                    separator == "@"
                    and len(action_parts) >= 2
                    and all(
                        re.fullmatch(r"[A-Za-z0-9_.-]+", part) is not None
                        for part in action_parts
                    )
                )
                if not literal_action or ACTION_SHA.fullmatch(revision) is None:
                    document.error(
                        line.number,
                        "privileged external actions must use a reviewed full "
                        f"commit SHA (or Docker sha256 digest), got {reference!r}",
                        job.name,
                    )

    def _audit_path(
        self,
        path: Path,
        *,
        force_untrusted: bool,
    ) -> None:
        key = (path, force_untrusted)
        if key in self._visited:
            return
        if path in self._active:
            cycle = " -> ".join(
                item.relative_to(self.root).as_posix() for item in [*self._active, path]
            )
            self.errors.append(
                f"{path.relative_to(self.root).as_posix()}:1: reusable workflow cycle: {cycle}"
            )
            return
        self._active.append(path)
        document = self._document(path)
        events = document.events()
        jobs = document.jobs()
        untrusted = force_untrusted or bool(events & UNTRUSTED_EVENTS)
        protected_workflow = document.relative in PROTECTED_WORKFLOWS

        if document.relative == POLICY_WORKFLOW:
            expected_sections = {"name", "on", "permissions", "concurrency", "jobs"}
            if set(document.sections) != expected_sections:
                document.error(
                    1,
                    f"runner policy top-level keys must be exactly "
                    f"{sorted(expected_sections)!r}, got {sorted(document.sections)!r}",
                )
            name_section = document.sections.get("name")
            name_continuation = (
                document.scalar_continuation(name_section.line, name_section.end)
                if name_section is not None
                else None
            )
            if (
                name_section is None
                or name_section.value != POLICY_STATUS_NAME
                or name_continuation is not None
            ):
                document.error(1, "runner policy workflow name changed")
            permissions = document.section_child_values("permissions")
            if permissions != {"contents": "read"}:
                document.error(
                    document.sections.get(
                        "permissions", Section("", Line(1, "", 0, ""), "", 0, 0)
                    ).line.number,
                    "runner policy permissions must be exactly contents: read",
                )
            concurrency = document.section_child_values("concurrency")
            if concurrency != {
                "group": "runner-policy-${{ github.event.pull_request.number || github.ref }}",
                "cancel-in-progress": "true",
            }:
                document.error(
                    document.sections.get(
                        "concurrency", Section("", Line(1, "", 0, ""), "", 0, 0)
                    ).line.number,
                    "runner policy concurrency shape changed",
                )
            if events != POLICY_WORKFLOW_EVENTS:
                document.error(
                    document.sections.get(
                        "on", Section("", Line(1, "", 0, ""), "", 0, 0)
                    ).line.number,
                    f"runner policy workflow events must be exactly "
                    f"{sorted(POLICY_WORKFLOW_EVENTS)!r}, got {sorted(events)!r}",
                )
            pull_request_target = document.event_child_keys("pull_request_target")
            if pull_request_target is None:
                document.error(
                    document.sections.get(
                        "on", Section("", Line(1, "", 0, ""), "", 0, 0)
                    ).line.number,
                    "runner policy workflow must define pull_request_target as a block event",
                )
            else:
                event_line, event_value, event_children = pull_request_target
                if event_value or event_children:
                    document.error(
                        event_line.number,
                        "runner policy pull_request_target must cover every base branch",
                    )
            merge_group = document.event_child_keys("merge_group")
            if merge_group is None or merge_group[1] or merge_group[2]:
                document.error(
                    document.sections.get(
                        "on", Section("", Line(1, "", 0, ""), "", 0, 0)
                    ).line.number,
                    "runner policy merge_group trigger shape changed",
                )
            push = document.event_child_keys("push")
            if push is None or push[1] or push[2] != {"branches": "[main]"}:
                document.error(
                    document.sections.get(
                        "on", Section("", Line(1, "", 0, ""), "", 0, 0)
                    ).line.number,
                    "runner policy push trigger must be exactly branches: [main]",
                )
            if len(jobs) != 1 or jobs[0].name != "runner-policy":
                document.error(
                    document.sections.get(
                        "jobs", Section("", Line(1, "", 0, ""), "", 0, 0)
                    ).line.number,
                    "runner policy workflow must contain only the runner-policy job",
                )
            else:
                document.validate_policy_job_shape(jobs[0])

        expected_events = PROTECTED_WORKFLOW_EVENTS.get(document.relative)
        if protected_workflow and events != expected_events:
            document.error(
                document.sections.get("on", Section("", Line(1, "", 0, ""), "", 0, 0)).line.number,
                f"protected persistent-runner workflow events must be exactly "
                f"{sorted(expected_events or ())!r}, got {sorted(events)!r}",
            )

        if untrusted:
            permissions = document.section_child_values("permissions")
            if permissions != {"contents": "read"}:
                document.error(
                    document.sections.get(
                        "permissions", Section("", Line(1, "", 0, ""), "", 0, 0)
                    ).line.number,
                    "untrusted workflows must set top-level permissions exactly "
                    "to contents: read",
                )

        self._audit_privileged_action_pins(
            document,
            jobs,
        )

        for job in jobs:
            runner = job.properties.get("runs-on")
            reusable = job.properties.get("uses")
            if untrusted:
                self._audit_untrusted_job_permissions(document, job)
            job_display_name = job.properties.get("name")
            if job_display_name is not None:
                name_line, name_value = job_display_name
                name_continuation = document.scalar_continuation(
                    name_line, job.end
                )
                dynamic_exception = TRUSTED_DYNAMIC_JOB_NAME_EXCEPTIONS.get(
                    (document.relative, job.name)
                )
                if name_continuation is not None:
                    document.error(
                        name_continuation.number,
                        "job display names must be one line",
                        job.name,
                    )
                elif _has_indirection(name_value):
                    if name_value.strip() != dynamic_exception:
                        document.error(
                            name_line.number,
                            "dynamic job display name is unsupported",
                            job.name,
                        )
                else:
                    try:
                        display_names = _literal_values(name_value)
                    except ValueError as exc:
                        document.error(
                            name_line.number,
                            f"job display name is unresolved: {exc}",
                            job.name,
                        )
                    else:
                        if (
                            len(display_names) != 1
                            or display_names[0].casefold()
                            == POLICY_STATUS_NAME.casefold()
                        ) and not (
                            document.relative == POLICY_WORKFLOW
                            and job.name == "runner-policy"
                            and display_names == [POLICY_STATUS_NAME]
                        ):
                            document.error(
                                name_line.number,
                                f"jobs cannot claim reserved status "
                                f"{POLICY_STATUS_NAME!r}",
                                job.name,
                            )
            if (
                job.name.casefold() == POLICY_STATUS_NAME.casefold()
                and document.relative != POLICY_WORKFLOW
            ):
                document.error(
                    job.line.number,
                    f"job id cannot claim reserved status "
                    f"{POLICY_STATUS_NAME!r}",
                    job.name,
                )
            if protected_workflow and (runner is None or reusable is not None):
                document.error(
                    job.line.number,
                    "protected workflow jobs must select a protected runner directly",
                    job.name,
                )
                continue
            if untrusted and (runner is None) == (reusable is None):
                document.error(
                    job.line.number,
                    "untrusted job must define exactly one of runs-on or reusable-workflow uses",
                    job.name,
                )
                continue

            if reusable is not None:
                line, value = reusable
                if not untrusted:
                    continue
                continuation = document.scalar_continuation(line, job.end)
                if continuation is not None:
                    document.error(
                        continuation.number,
                        "untrusted reusable-workflow uses must be one line",
                        job.name,
                    )
                    continue
                target = _local_workflow_target(value)
                if target is None:
                    document.error(
                        line.number,
                        "untrusted reusable job must call a literal local workflow",
                        job.name,
                    )
                    continue
                callee = self.root / target
                if not callee.exists() or callee.is_symlink() or not callee.is_file():
                    document.error(
                        line.number,
                        f"local reusable workflow {target.as_posix()!r} is missing or unsafe",
                        job.name,
                    )
                    continue
                callee_document = self._document(callee)
                if "workflow_call" not in callee_document.events():
                    document.error(
                        line.number,
                        f"local reusable workflow {target.as_posix()!r} lacks workflow_call",
                        job.name,
                    )
                    continue
                self._audit_path(
                    callee,
                    force_untrusted=True,
                )
                continue

            if runner is None:
                continue
            try:
                parsed_runner = document.runner_values(job)
            except ValueError as exc:
                exception = TRUSTED_DYNAMIC_RUNNER_EXCEPTIONS.get(
                    (document.relative, job.name)
                )
                runner_continuation = document.scalar_continuation(
                    runner[0], job.end
                )
                if (
                    untrusted
                    or exception is None
                    or runner[1].strip() != exception[0]
                    or runner_continuation is not None
                ):
                    document.error(runner[0].number, str(exc), job.name)
                else:
                    try:
                        document.validate_hosted_include_matrix(job, exception[1])
                    except ValueError as matrix_error:
                        document.error(
                            runner[0].number,
                            str(matrix_error),
                            job.name,
                        )
                continue
            assert parsed_runner is not None
            runner_line, values = parsed_runner
            protected = _contains_protected_label(values)
            protected_selection = _is_protected_runner(values)
            hosted = _is_hosted_runner(values)

            if untrusted and not hosted:
                document.error(
                    runner_line.number,
                    f"untrusted job runner must be one literal GitHub-hosted label, got {values!r}",
                    job.name,
                )
            if not hosted and any(
                value.strip().casefold() not in PROTECTED_LABELS
                for value in values
            ):
                document.error(
                    runner_line.number,
                    f"unknown/custom runner selection is unsupported, got {values!r}",
                    job.name,
                )
            if protected and not protected_workflow:
                document.error(
                    runner_line.number,
                    "persistent/protected runner is not allowed in this workflow",
                    job.name,
                )
            if protected_workflow:
                if not protected_selection:
                    document.error(
                        runner_line.number,
                        "protected workflow runner must use only the approved labels "
                        f"{sorted(PROTECTED_LABELS)!r} and include "
                        f"{sorted(REQUIRED_PROTECTED_LABELS)!r}",
                        job.name,
                    )
                guard = job.properties.get("if")
                guard_continuation = (
                    document.scalar_continuation(guard[0], job.end)
                    if guard is not None
                    else None
                )
                if (
                    guard is None
                    or guard_continuation is not None
                    or not _is_exact_main_ref_guard(guard[1])
                ):
                    document.error(
                        (
                            guard_continuation.number
                            if guard_continuation is not None
                            else job.line.number
                        ),
                        f"protected runner job must use exact main-ref guard {MAIN_REF_GUARD!r}",
                        job.name,
                    )

        self.errors.extend(document.errors)
        self._active.pop()
        self._visited.add(key)


def audit(root: Path) -> list[str]:
    return RunnerPolicy(root).audit()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="candidate repository tree to inspect as inert data",
    )
    args = parser.parse_args()
    errors = audit(args.root)
    if errors:
        print("Workflow runner policy violations:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Workflow runner policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
