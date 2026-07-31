#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
"""Fail closed on Docker build-context and Compose posture regressions."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DUMMY_DIGEST = "sha256:" + ("0" * 64)
DUMMY_REMOTE_ENV = {
    "CRUX_IMAGE_DIGEST": DUMMY_DIGEST,
    "CORECRUXD_JWT_HS256_SECRET": "a" * 32,
    "CORECRUXD_JWT_ISS": "https://issuer.example.invalid",
    "CORECRUXD_JWT_AUD": "crux-daemon",
    "CRUX_AGENT_TOKEN": "b" * 32,
}
ALTERNATE_REMOTE_ENV = {
    "CRUX_IMAGE_DIGEST": "sha256:" + ("1" * 64),
    "CORECRUXD_JWT_HS256_SECRET": "c" * 32,
    "CORECRUXD_JWT_ISS": "https://alternate-issuer.example.invalid",
    "CORECRUXD_JWT_AUD": "alternate-crux-daemon",
    "CRUX_AGENT_TOKEN": "d" * 32,
}
LOCAL_POSTURE = "local-development-only"
REMOTE_POSTURE = "shared-behind-tls"
COMPOSE_PROJECT_NAME = "crux-policy"
COMPOSE_ALLOWED_ENV = {
    "docker-compose.yml": {
        "CORECRUXD_EMBEDDING_MODEL",
        "CORECRUXD_EMBEDDING_URL",
        "CORECRUXD_OBS_RETENTION_DAYS",
    },
    "docker-compose.dev.yml": set(),
    "examples/quickstart/docker-compose.yml": {"CRUX_VERSION"},
    "examples/remote/docker-compose.yml": set(DUMMY_REMOTE_ENV),
}
COMPOSE_EXPECTED_EXPRESSIONS = {
    "docker-compose.yml": [
        "CORECRUXD_EMBEDDING_MODEL:-nomic-embed-text",
        "CORECRUXD_EMBEDDING_MODEL:-nomic-embed-text",
        "CORECRUXD_EMBEDDING_URL:-",
        "CORECRUXD_OBS_RETENTION_DAYS:-",
    ],
    "docker-compose.dev.yml": [],
    "examples/quickstart/docker-compose.yml": ["CRUX_VERSION:-latest"],
    "examples/remote/docker-compose.yml": [
        "CORECRUXD_JWT_AUD:?Set the exact JWT audience",
        "CORECRUXD_JWT_HS256_SECRET:?Set a secret of at least 32 bytes",
        "CORECRUXD_JWT_ISS:?Set the exact JWT issuer",
        "CRUX_AGENT_TOKEN:?Set a distinct 32-to-256-character MCP bearer token",
        "CRUX_IMAGE_DIGEST:?Set CRUX_IMAGE_DIGEST to sha256 followed by the verified 64-hex digest",
    ],
}
COMPOSE_NATIVE_PROJECT = {
    ("docker-compose.yml",): "crux",
    ("docker-compose.yml", "docker-compose.dev.yml"): "crux",
    ("examples/quickstart/docker-compose.yml",): "quickstart",
    ("examples/remote/docker-compose.yml",): "remote",
}
ROOT_CRUX_KEYS = {
    "build",
    "cap_drop",
    "command",
    "deploy",
    "entrypoint",
    "environment",
    "healthcheck",
    "image",
    "init",
    "labels",
    "networks",
    "pids_limit",
    "ports",
    "pull_policy",
    "read_only",
    "restart",
    "security_opt",
    "tmpfs",
    "user",
    "volumes",
}
QUICKSTART_CRUX_KEYS = ROOT_CRUX_KEYS - {"build", "pull_policy"}
REMOTE_CRUX_KEYS = (QUICKSTART_CRUX_KEYS - {"deploy"}) | {"mem_limit", "stop_grace_period"}
OLLAMA_KEYS = {
    "cap_drop",
    "command",
    "entrypoint",
    "environment",
    "image",
    "init",
    "labels",
    "networks",
    "pids_limit",
    "ports",
    "profiles",
    "security_opt",
    "volumes",
}
WORKFLOW_JOB_HASHES = {
    "build-and-scan-pr": "5dbd551ecfedceedbb6ff173bd4f3721079eb8f8d95503c3f2045f032a72df0a",
    "build-and-push": "aa5ad4a694fe43e9b94e98a04ce08b2a954109da13c34529cda93024debaf3a5",
}
WORKFLOW_FILE_HASH = "1e3c4767998ff76ee4375110690047537e600f594ac1f31697c8479478bd9822"


class PolicyFailure(RuntimeError):
    """A repository container policy invariant failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyFailure(message)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def workflow_pull_request_paths(workflow: str) -> set[str]:
    """Parse the simple, literal PR path list used by docker.yml."""
    lines = workflow.splitlines()
    starts = [index for index, line in enumerate(lines) if line == "  pull_request:"]
    require(len(starts) == 1, "Docker workflow must have exactly one literal pull_request block")
    start = starts[0]
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].strip()
            and lines[index].startswith("  ")
            and not lines[index].startswith("    ")
        ),
        len(lines),
    )
    path_markers = [index for index in range(start + 1, end) if lines[index] == "    paths:"]
    require(len(path_markers) == 1, "Docker pull_request trigger must have exactly one literal paths list")
    paths_start = path_markers[0]
    paths: set[str] = set()
    for line in lines[paths_start + 1 : end]:
        if line and not line.startswith("      "):
            break
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        require(stripped.startswith("- "), f"unsupported Docker PR paths syntax: {stripped!r}")
        raw = stripped[2:].strip()
        require(raw.startswith('"') and raw.endswith('"'), f"Docker PR path must be double-quoted: {raw!r}")
        value = json.loads(raw)
        require(isinstance(value, str), f"Docker PR path must be a string: {raw!r}")
        require(value not in paths, f"duplicate Docker PR path: {value}")
        paths.add(value)
    return paths


def workflow_job_block(workflow: str, job_id: str) -> list[str]:
    lines = workflow.splitlines()
    marker = f"  {job_id}:"
    starts = [index for index, line in enumerate(lines) if line == marker]
    require(len(starts) == 1, f"Docker workflow must have exactly one {job_id!r} job")
    start = starts[0]
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[index])
        ),
        len(lines),
    )
    return lines[start:end]


def require_exact_workflow_job_hash(job: list[str], job_id: str) -> None:
    require(job_id in WORKFLOW_JOB_HASHES, f"{job_id}: no audited workflow hash")
    normalized = "\n".join(line.rstrip() for line in job).strip() + "\n"
    actual = sha256(normalized.encode("utf-8")).hexdigest()
    require(
        actual == WORKFLOW_JOB_HASHES[job_id],
        f"{job_id}: protected workflow contract changed (got sha256:{actual})",
    )


def workflow_named_steps(job: list[str], job_id: str) -> tuple[list[str], dict[str, list[str]]]:
    starts: list[tuple[int, str]] = []
    for index, line in enumerate(job):
        match = re.match(r"^      - name: (.+?)\s*$", line)
        if match:
            starts.append((index, match.group(1)))
    names = [name for _, name in starts]
    require(len(names) == len(set(names)), f"{job_id}: named workflow steps must be unique")
    blocks: dict[str, list[str]] = {}
    for position, (start, name) in enumerate(starts):
        end = len(job)
        for index in range(start + 1, len(job)):
            if re.match(r"^      - ", job[index]):
                end = index
                break
        blocks[name] = job[start:end]
    return names, blocks


def workflow_step_field(block: list[str], field: str) -> list[str]:
    pattern = re.compile(rf"^        {re.escape(field)}:\s*(.*?)\s*$")
    return [match.group(1) for line in block if (match := pattern.match(line))]


def workflow_step_mapping(block: list[str], field: str, step_name: str) -> dict[str, str]:
    markers = [index for index, line in enumerate(block) if line == f"        {field}:"]
    require(len(markers) == 1, f"{step_name}: must contain one canonical {field} mapping")
    start = markers[0]
    values: dict[str, str] = {}
    for line in block[start + 1 :]:
        if line.strip() and len(line) - len(line.lstrip(" ")) <= 8:
            break
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith("          ") or line.startswith("            "):
            continue
        match = re.fullmatch(r"          ([A-Za-z0-9_-]+):\s*(.*?)\s*", line)
        require(match is not None, f"{step_name}: {field} keys must use canonical YAML syntax")
        key, value = match.groups()
        require(key not in values, f"{step_name}: duplicate {field} key {key!r}")
        values[key] = value
    return values


def require_canonical_workflow_job(job: list[str], job_id: str) -> None:
    for line in job:
        require("\t" not in line, f"{job_id}: tab indentation is forbidden")
        indent = len(line) - len(line.lstrip(" "))
        if indent not in {4, 8}:
            continue
        content = line[indent:]
        if not content or content.startswith("#"):
            continue
        require(
            re.match(r"^[A-Za-z0-9_-]+:(?:\s|$)", content) is not None,
            f"{job_id}: mapping keys must use canonical YAML syntax: {content!r}",
        )


def require_exact_workflow_steps(
    job: list[str],
    job_id: str,
    expected_names: list[str],
) -> dict[str, list[str]]:
    names, blocks = workflow_named_steps(job, job_id)
    require(names == expected_names, f"{job_id}: named step sequence changed")
    starts = [line for line in job if re.match(r"^      - ", line)]
    require(
        len(starts) == len(expected_names) + 1
        and starts[0].startswith("      - uses: actions/checkout@"),
        f"{job_id}: only the one checkout and audited named steps are allowed",
    )
    return blocks


def dockerfile_instructions(dockerfile: str) -> list[tuple[str, str]]:
    """Return logical Dockerfile instructions with case-normalized keywords."""
    logical_lines: list[str] = []
    pending = ""
    for raw_line in dockerfile.splitlines():
        stripped = raw_line.strip()
        require(
            re.match(r"^#\s*(?:syntax|escape|check)\s*=", stripped, flags=re.IGNORECASE) is None,
            "Dockerfile parser directives are forbidden by the audited grammar",
        )
        if not stripped or (stripped.startswith("#") and not pending):
            continue
        pending = f"{pending} {stripped}".strip() if pending else stripped
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        logical_lines.append(pending)
        pending = ""
    require(not pending, "Dockerfile must not end with an unterminated continuation")
    instructions: list[tuple[str, str]] = []
    for line in logical_lines:
        parts = line.split(maxsplit=1)
        require(len(parts) == 2, f"unsupported Dockerfile instruction: {line!r}")
        instructions.append((parts[0].upper(), parts[1].strip()))
    return instructions


def compose_source_policy(files: list[str]) -> set[str]:
    allowed: set[str] = set()
    for path in files:
        require(path in COMPOSE_ALLOWED_ENV, f"{path}: no audited Compose environment policy")
        source = read(path)
        expressions: list[str] = []
        index = 0
        while index < len(source):
            if source[index] != "$":
                index += 1
                continue
            require(index + 1 < len(source), f"{path}: dangling dollar sign")
            if source[index + 1] == "$":
                index += 2
                continue
            require(source[index + 1] == "{", f"{path}: unbraced Compose interpolation is forbidden")
            end = source.find("}", index + 2)
            require(end != -1, f"{path}: unterminated Compose interpolation")
            expression = source[index + 2 : end]
            match = re.fullmatch(
                r"([A-Za-z_][A-Za-z0-9_]*)(?:(?::?[-+?])([^$}\r\n]*))?",
                expression,
            )
            require(match is not None, f"{path}: unsupported Compose interpolation {expression!r}")
            expressions.append(expression)
            index = end + 1
        expected = COMPOSE_ALLOWED_ENV[path]
        variables = {expression.split(":", 1)[0].split("-", 1)[0].split("+", 1)[0].split("?", 1)[0] for expression in expressions}
        require(
            variables == expected,
            f"{path}: Compose interpolation variables changed: expected {sorted(expected)}, got {sorted(variables)}",
        )
        require(
            sorted(expressions) == sorted(COMPOSE_EXPECTED_EXPRESSIONS[path]),
            f"{path}: Compose interpolation expressions/counts changed",
        )
        allowed.update(expected)
    return allowed


def compose_config(
    files: list[str],
    *,
    extra_env: dict[str, str] | None = None,
    profiles: list[str] | None = None,
    project_name: str | None = COMPOSE_PROJECT_NAME,
) -> dict[str, Any]:
    command = ["docker", "compose"]
    for file in files:
        command.extend(["-f", str(ROOT / file)])
    for profile in profiles or []:
        command.extend(["--profile", profile])
    command.extend(["config", "--format", "json"])

    allowed_env = compose_source_policy(files)
    environment = compose_environment(
        extra_env,
        allowed_env=allowed_env,
        project_name=project_name,
    )
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    require(
        result.returncode == 0,
        f"{' + '.join(files)} did not render with Docker Compose: {result.stderr.strip()}",
    )
    try:
        rendered = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise PolicyFailure(f"{' + '.join(files)} emitted invalid JSON: {error}") from error
    require(isinstance(rendered, dict), f"{' + '.join(files)} must render a JSON object")
    return rendered


def compose_environment(
    extra_env: dict[str, str] | None = None,
    *,
    allowed_env: set[str],
    project_name: str | None = COMPOSE_PROJECT_NAME,
) -> dict[str, str]:
    supplied = extra_env or {}
    require(
        set(supplied) <= allowed_env,
        f"policy render supplied unaudited Compose variables: {sorted(set(supplied) - allowed_env)}",
    )
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "COMPOSE_DISABLE_ENV_FILE": "1",
    }
    if project_name is not None:
        environment["COMPOSE_PROJECT_NAME"] = project_name
    environment.update(supplied)
    return environment


def require_compose_failure(files: list[str], *, missing_env: str, other_env: dict[str, str]) -> None:
    command = ["docker", "compose"]
    for file in files:
        command.extend(["-f", str(ROOT / file)])
    command.extend(["config", "--quiet"])
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=compose_environment(
            other_env,
            allowed_env=compose_source_policy(files),
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    require(
        result.returncode != 0 and missing_env in result.stderr,
        f"{' + '.join(files)} must reject missing required variable {missing_env}",
    )


def service(rendered: dict[str, Any], name: str, source: str) -> dict[str, Any]:
    services = rendered.get("services")
    require(isinstance(services, dict), f"{source}: rendered services must be a mapping")
    value = services.get(name)
    require(isinstance(value, dict), f"{source}: missing rendered service {name!r}")
    return value


def environment_of(value: dict[str, Any], source: str) -> dict[str, str]:
    environment = value.get("environment")
    require(isinstance(environment, dict), f"{source}: environment must render as a mapping")
    return environment


def assert_loopback_ports(value: dict[str, Any], source: str) -> None:
    require(
        value.get("ports")
        == [
            {
                "mode": "ingress",
                "host_ip": "127.0.0.1",
                "target": 14800,
                "published": "14800",
                "protocol": "tcp",
            },
            {
                "mode": "ingress",
                "host_ip": "127.0.0.1",
                "target": 14801,
                "published": "14801",
                "protocol": "tcp",
            },
        ],
        f"{source}: publish only HTTP 14800 and MCP 14801 on IPv4 loopback",
    )


def assert_hardened_runtime(
    value: dict[str, Any],
    source: str,
    *,
    expected_keys: set[str],
    check_data_volume: bool = True,
) -> None:
    require(set(value) == expected_keys, f"{source}: rendered service keys changed: {sorted(set(value))}")
    require(value.get("init") is True, f"{source}: init must be enabled")
    require(value.get("user") == "65532:65532", f"{source}: must run as uid/gid 65532")
    require(value.get("read_only") is True, f"{source}: root filesystem must be read-only")
    require(value.get("cap_drop") == ["ALL"], f"{source}: all Linux capabilities must be dropped")
    require(
        value.get("security_opt") == ["no-new-privileges:true"],
        f"{source}: no-new-privileges must be the only security override",
    )
    require(value.get("privileged") is not True, f"{source}: privileged mode is forbidden")
    for forbidden in (
        "cap_add",
        "cgroup",
        "configs",
        "develop",
        "device_cgroup_rules",
        "devices",
        "external_links",
        "gpus",
        "group_add",
        "ipc",
        "label_file",
        "links",
        "network_mode",
        "pid",
        "post_start",
        "pre_stop",
        "runtime",
        "secrets",
        "sysctls",
        "use_api_socket",
        "userns_mode",
        "uts",
        "volumes_from",
    ):
        require(not value.get(forbidden), f"{source}: {forbidden} is forbidden")
    require(value.get("command") is None, f"{source}: image command must not be overridden")
    require(value.get("entrypoint") is None, f"{source}: image entrypoint must not be overridden")
    require(value.get("networks") == {"default": None}, f"{source}: only the isolated project network is allowed")
    pids_limit = value.get("pids_limit")
    require(isinstance(pids_limit, int) and 0 < pids_limit <= 512, f"{source}: pids_limit must be 1..512")
    require(
        value.get("tmpfs") == ["/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"],
        f"{source}: tmpfs must be the one canonical restricted /tmp mount",
    )
    if check_data_volume:
        require(
            value.get("volumes")
            == [
                {
                    "type": "volume",
                    "source": "crux-data",
                    "target": "/data",
                    "volume": {},
                }
            ],
            f"{source}: the writable mount must be exactly the named crux-data volume at /data",
        )


def assert_healthcheck(value: dict[str, Any], source: str) -> None:
    require(
        value.get("healthcheck")
        == {
            "test": [
                "CMD",
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "4",
                "http://127.0.0.1:14800/readyz",
            ],
            "timeout": "5s",
            "interval": "10s",
            "retries": 3,
            "start_period": "10s",
        },
        f"{source}: healthcheck must be the canonical bounded exec-form readiness probe",
    )


def assert_project_resources(
    rendered: dict[str, Any],
    source: str,
    *,
    expected_volumes: set[str] | None = None,
    project_name: str = COMPOSE_PROJECT_NAME,
) -> None:
    expected_volumes = expected_volumes or {"crux-data"}
    require(
        set(rendered) == {"name", "networks", "services", "volumes"}
        and rendered.get("name") == project_name,
        f"{source}: rendered project keys/name changed",
    )
    networks = rendered.get("networks")
    require(
        isinstance(networks, dict) and set(networks) == {"default"},
        f"{source}: exactly one project-local default network is allowed",
    )
    default_network = networks["default"]
    require(
        isinstance(default_network, dict)
        and default_network
        == {
            "name": f"{project_name}_default",
            "ipam": {},
        },
        f"{source}: default network may not be external, attachable, or driver-configured",
    )
    volumes = rendered.get("volumes")
    require(
        isinstance(volumes, dict) and set(volumes) == expected_volumes,
        f"{source}: project volume allowlist changed",
    )
    for volume_name, volume in volumes.items():
        require(
            volume == {"name": f"{project_name}_{volume_name}"},
            f"{source}: {volume_name} may not be external or backed by host driver options",
        )


def assert_native_project_resources(
    files: list[str],
    *,
    extra_env: dict[str, str] | None = None,
    profiles: list[str] | None = None,
    expected_volumes: set[str] | None = None,
) -> None:
    key = tuple(files)
    require(key in COMPOSE_NATIVE_PROJECT, f"{' + '.join(files)}: no native project-name policy")
    rendered = compose_config(
        files,
        extra_env=extra_env,
        profiles=profiles,
        project_name=None,
    )
    assert_project_resources(
        rendered,
        f"{' + '.join(files)}:native-project",
        expected_volumes=expected_volumes,
        project_name=COMPOSE_NATIVE_PROJECT[key],
    )


def check_dockerignore() -> None:
    dockerignore = ROOT / ".dockerignore"
    require(dockerignore.is_file() and not dockerignore.is_symlink(), ".dockerignore must be a regular file")
    overrides = sorted(
        path.name
        for path in ROOT.iterdir()
        if path.name.endswith(".dockerignore") and path.name != ".dockerignore"
    )
    require(
        not overrides,
        f"Dockerfile-specific ignore files override the audited .dockerignore: {overrides}",
    )
    patterns = [
        line.strip()
        for line in read(".dockerignore").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    require(patterns and patterns[0] == "**", ".dockerignore must begin by excluding the entire context")
    require(len(patterns) == len(set(patterns)), ".dockerignore must not contain duplicate patterns")
    broad_includes = {
        "!Dockerfile",
        "!.dockerignore",
        "!Cargo.toml",
        "!Cargo.lock",
        "!rust-toolchain.toml",
        "!LICENSE",
        "!NOTICE",
        "!crates/",
        "!crates/**",
        "!proto/",
        "!proto/**",
        "!integrations/",
        "!integrations/**",
    }
    safe_jsonl_includes = {
        "!crates/corecrux-receipts/vectors/audit-bundle-v1/invalid-events-hash/events.jsonl",
        "!crates/corecrux-receipts/vectors/audit-bundle-v1/valid-minimal/events.jsonl",
        "!crates/corecrux-receipts/vectors/audit-bundle-v1/valid-minimal-v2/events.jsonl",
        "!crates/corecrux-receipts/vectors/audit-bundle-v1/valid-minimal-v3/events.jsonl",
        "!crates/corecruxctl/tests/fixtures_code_health/cargo_check.jsonl",
        "!integrations/claude-code/compaction-survival/fixtures/transcript.jsonl",
    }
    required_includes = broad_includes | safe_jsonl_includes
    actual_includes = {pattern for pattern in patterns if pattern.startswith("!")}
    require(
        actual_includes == required_includes,
        f".dockerignore allowlist changed: expected {sorted(required_includes)}, got {sorted(actual_includes)}",
    )
    sensitive_excludes = {
        "**/.git",
        "**/.git/**",
        "**/.env*",
        "**/.mcp.json",
        "**/*.jsonl",
        "**/*.key",
        "**/passport.key",
        "**/credentials.json",
        "**/data",
        "**/data/**",
        "**/crux-data",
        "**/crux-data/**",
        "**/passports",
        "**/passports/**",
        "**/selected_repos.json",
        "**/sync_cursor.json",
        "**/console/settings.json",
        "**/LOCK",
        "**/.install-uuid",
        "**/target",
        "**/target/**",
        "**/node_modules",
        "**/node_modules/**",
        "**/__pycache__",
        "**/__pycache__/**",
        "**/*.pyc",
    }
    require(sensitive_excludes <= set(patterns), ".dockerignore is missing explicit sensitive/cache exclusions")
    last_broad_include = max(patterns.index(pattern) for pattern in broad_includes)
    require(
        all(patterns.index(pattern) > last_broad_include for pattern in sensitive_excludes),
        ".dockerignore sensitive exclusions must follow all source negations",
    )
    jsonl_exclude = patterns.index("**/*.jsonl")
    require(
        all(patterns.index(pattern) > jsonl_exclude for pattern in safe_jsonl_includes),
        ".dockerignore safe JSONL fixtures must be re-included only after the blanket exclusion",
    )


def check_compose_discovery_files() -> None:
    compose_name = re.compile(r"^(?:compose|docker-compose)(?:\.[A-Za-z0-9_-]+)?\.ya?ml$")
    expectations = {
        ROOT: {"docker-compose.yml", "docker-compose.dev.yml"},
        ROOT / "examples/quickstart": {"docker-compose.yml"},
        ROOT / "examples/remote": {"docker-compose.yml"},
    }
    for directory, expected in expectations.items():
        actual = {path.name for path in directory.iterdir() if compose_name.fullmatch(path.name)}
        require(actual == expected, f"{directory.relative_to(ROOT) or Path('.')}: ambiguous Compose discovery files: {sorted(actual)}")
        for name in expected:
            path = directory / name
            require(path.is_file() and not path.is_symlink(), f"{path.relative_to(ROOT)} must be a regular file")


def check_dockerfile_and_workflow() -> None:
    dockerfile = read("Dockerfile")
    instructions = dockerfile_instructions(dockerfile)
    require(
        instructions
        == [
            ("FROM", "rust:1.88.0-bookworm AS builder"),
            ("WORKDIR", "/build"),
            ("COPY", "Cargo.toml Cargo.lock rust-toolchain.toml ./"),
            ("COPY", "crates/ crates/"),
            ("COPY", "proto/ proto/"),
            ("COPY", "integrations/ integrations/"),
            ("ARG", "GIT_SHA=unknown"),
            ("ENV", "CORECRUX_GIT_SHA=${GIT_SHA}"),
            ("ARG", "RELEASE_VERSION="),
            ("RUN", "cargo build --locked --release --bin corecruxd --bin corecruxctl"),
            ("FROM", "cgr.dev/chainguard/wolfi-base:latest"),
            ("RUN", "apk add --no-cache ca-certificates curl git"),
            ("COPY", "--from=builder /build/target/release/corecruxd /usr/local/bin/corecruxd"),
            ("COPY", "--from=builder /build/target/release/corecruxctl /usr/local/bin/corecruxctl"),
            ("COPY", "LICENSE NOTICE /usr/share/doc/crux-daemon/"),
            ("RUN", "mkdir -p /data && chown -R 65532:65532 /data"),
            ("ENV", "CORECRUXD_DATA_DIR=/data"),
            ("ENV", "CORECRUXD_BUILD_CCXI=1"),
            ("ENV", "CORECRUX_LOG_FORMAT=json"),
            ("EXPOSE", "14800"),
            (
                "HEALTHCHECK",
                "--interval=10s --timeout=5s --start-period=10s --retries=3 "
                "CMD curl --fail --silent --show-error --max-time 4 "
                "http://127.0.0.1:14800/readyz || exit 1",
            ),
            ("VOLUME", '["/data"]'),
            ("USER", "65532:65532"),
            ("CMD", '["corecruxd"]'),
        ],
        "Dockerfile instructions must match the audited two-stage build exactly",
    )
    from_lines = [arguments for keyword, arguments in instructions if keyword == "FROM"]
    require(
        from_lines == [
            "rust:1.88.0-bookworm AS builder",
            "cgr.dev/chainguard/wolfi-base:latest",
        ],
        f"Dockerfile base policy changed: {from_lines!r}",
    )
    require("apt-get" not in dockerfile, "Dockerfile must rely on vendored protoc, not distro build packages")
    require("protobuf-compiler" not in dockerfile, "Dockerfile must not install redundant system protoc")
    require("hadolint ignore=DL3007" in dockerfile, "floating Wolfi base must have a scoped lint exception")
    require("hadolint ignore=DL3018" in dockerfile, "floating Wolfi packages must have a scoped lint exception")
    runtime_start = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction == ("FROM", "cgr.dev/chainguard/wolfi-base:latest")
    )
    runtime_instructions = instructions[runtime_start + 1 :]
    require(
        [arguments for keyword, arguments in runtime_instructions if keyword == "USER"] == ["65532:65532"],
        "Dockerfile runtime must have exactly one effective non-root USER",
    )
    require(
        [arguments for keyword, arguments in runtime_instructions if keyword == "CMD"] == ['["corecruxd"]'],
        "Dockerfile runtime must have exactly one corecruxd CMD",
    )
    require(
        not any(keyword == "ENTRYPOINT" for keyword, _ in runtime_instructions),
        "Dockerfile runtime must not override corecruxd through ENTRYPOINT",
    )
    require(
        [arguments for keyword, arguments in runtime_instructions if keyword == "VOLUME"] == ['["/data"]'],
        "Dockerfile runtime may declare only the /data volume",
    )
    require(
        [arguments for keyword, arguments in runtime_instructions if keyword == "HEALTHCHECK"]
        == [
            "--interval=10s --timeout=5s --start-period=10s --retries=3 "
            "CMD curl --fail --silent --show-error --max-time 4 "
            "http://127.0.0.1:14800/readyz || exit 1"
        ],
        "Dockerfile runtime must retain the one bounded readiness healthcheck",
    )

    workflow = read(".github/workflows/docker.yml")
    normalized_workflow = "\n".join(
        line.rstrip() for line in workflow.splitlines()
    ).strip() + "\n"
    require(
        sha256(normalized_workflow.encode("utf-8")).hexdigest() == WORKFLOW_FILE_HASH,
        "Docker workflow contract changed; review the complete file and update its audited hash",
    )
    require("provenance: mode=max" in workflow, "published image must capture max-mode provenance")
    require(
        "python3 scripts/check-container-hardening.py" in workflow,
        "Docker workflow must run this policy guard",
    )
    pr_paths = workflow_pull_request_paths(workflow)
    for image_input in (
        "*.dockerignore",
        "**/*.dockerignore",
        "compose*.yml",
        "compose*.yaml",
        "docker-compose*.yml",
        "docker-compose*.yaml",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "LICENSE",
        "NOTICE",
        "crates/**",
        "proto/**",
        "integrations/**",
    ):
        require(image_input in pr_paths, f"Docker PR trigger must cover {image_input}")
    digest_ref = "${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.push.outputs.digest }}"
    require(
        workflow.count(f"image-ref: {digest_ref}") == 2,
        "protected Trivy report and gate must both scan the one pushed candidate digest",
    )
    require(
        "docker buildx imagetools create --tag \"$tag\" \"$SOURCE_IMAGE\"" in workflow,
        "accepted build tags must alias the scanned digest without rebuilding",
    )
    require(
        workflow.count("uses: docker/build-push-action@") == 2
        and workflow.count("          context: .") == 2,
        "Docker workflow must have exactly the audited PR and candidate builds at context '.'",
    )
    require(
        re.search(r"(?m)^\s+file:", workflow) is None and "build-contexts:" not in workflow,
        "Docker workflow must not select an unaudited Dockerfile or additional build context",
    )

    pr_job = workflow_job_block(workflow, "build-and-scan-pr")
    require_exact_workflow_job_hash(pr_job, "build-and-scan-pr")
    require_canonical_workflow_job(pr_job, "build-and-scan-pr")
    pr_names = [
        "Verify immutable release tag policy",
        "Validate container and Compose security postures",
        "Build image for scan (no push)",
        "Trivy scan (SARIF report, CRITICAL+HIGH)",
        "Upload PR Trivy report",
        "Trivy gate (fail on fixable CRITICAL)",
    ]
    pr_steps = require_exact_workflow_steps(pr_job, "build-and-scan-pr", pr_names)
    pr_guard = pr_steps["Validate container and Compose security postures"]
    require(
        workflow_step_field(pr_guard, "if") == []
        and workflow_step_field(pr_guard, "continue-on-error") == []
        and workflow_step_field(pr_guard, "run") == ["python3 scripts/check-container-hardening.py"],
        "PR container policy guard must run unconditionally and fail the job",
    )
    pr_build = pr_steps["Build image for scan (no push)"]
    require(
        workflow_step_field(pr_build, "if") == []
        and workflow_step_field(pr_build, "continue-on-error") == []
        and workflow_step_field(pr_build, "uses")
        == ["docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a # v7.3.0"]
        and workflow_step_mapping(pr_build, "with", "PR image build")
        == {
            "context": ".",
            "push": "false",
            "load": "true",
            "tags": "local/crux-daemon:scan",
            "build-args": "|",
        },
        "PR image must be built once from the audited local context without pushing",
    )
    pr_report = pr_steps["Trivy scan (SARIF report, CRITICAL+HIGH)"]
    require(
        workflow_step_field(pr_report, "if") == []
        and workflow_step_field(pr_report, "continue-on-error") == []
        and workflow_step_mapping(pr_report, "with", "PR Trivy report").get("image-ref")
        == "local/crux-daemon:scan"
        and workflow_step_mapping(pr_report, "with", "PR Trivy report").get("exit-code")
        == '"0"',
        "PR Trivy report must inspect the one locally built image",
    )
    pr_gate = pr_steps["Trivy gate (fail on fixable CRITICAL)"]
    require(
        workflow_step_field(pr_gate, "if") == []
        and workflow_step_field(pr_gate, "continue-on-error") == []
        and workflow_step_mapping(pr_gate, "with", "PR Trivy gate").get("image-ref")
        == "local/crux-daemon:scan"
        and workflow_step_mapping(pr_gate, "with", "PR Trivy gate").get("exit-code")
        == '"1"',
        "PR Trivy gate must fail on the one locally built image",
    )

    protected_job = workflow_job_block(workflow, "build-and-push")
    require_exact_workflow_job_hash(protected_job, "build-and-push")
    require_canonical_workflow_job(protected_job, "build-and-push")
    require(
        not any(re.match(r"^\s+continue-on-error:", line) for line in protected_job),
        "protected Docker publication steps must never continue on error",
    )
    protected_names = [
        "Verify immutable release tag policy",
        "Validate container and Compose security postures",
        "Log in to GHCR",
        "Extract metadata",
        "Build and push uniquely named scan candidate",
        "Trivy scan (SARIF report, CRITICAL+HIGH)",
        "Upload Trivy SARIF to Security tab",
        "Trivy gate (fail on CRITICAL)",
        "Validate Trivy gate waiver",
        "Log Trivy gate skip",
        "Upload Trivy waiver",
        "Generate image SBOM (syft)",
        "Install cosign",
        "Sign image + attest SBOM (cosign keyless)",
        "Promote scanned digest to build tags",
    ]
    protected_steps = require_exact_workflow_steps(
        protected_job,
        "build-and-push",
        protected_names,
    )

    guard_step = protected_steps["Validate container and Compose security postures"]
    require(
        workflow_step_field(guard_step, "if") == []
        and workflow_step_field(guard_step, "continue-on-error") == []
        and workflow_step_field(guard_step, "run") == ["python3 scripts/check-container-hardening.py"],
        "container policy guard must run unconditionally and fail the protected job",
    )
    candidate_step = protected_steps["Build and push uniquely named scan candidate"]
    require(
        workflow_step_field(candidate_step, "if") == []
        and workflow_step_field(candidate_step, "continue-on-error") == []
        and workflow_step_field(candidate_step, "id") == ["push"],
        "candidate build must run once under the default success condition",
    )
    require(
        workflow_step_field(candidate_step, "uses")
        == ["docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a # v7.3.0"]
        and workflow_step_mapping(candidate_step, "with", "candidate image build")
        == {
            "context": ".",
            "push": "true",
            "tags": "${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:candidate-${{ github.run_id }}-${{ github.run_attempt }}",
            "labels": "${{ steps.meta.outputs.labels }}",
            "provenance": "mode=max",
            "build-args": "|",
        },
        "candidate build must bind the push digest to the audited repository/context",
    )
    report_step = protected_steps["Trivy scan (SARIF report, CRITICAL+HIGH)"]
    require(
        workflow_step_field(report_step, "if") == []
        and workflow_step_field(report_step, "continue-on-error") == []
        and any(f"image-ref: {digest_ref}" in line for line in report_step),
        "protected Trivy report must scan the candidate digest and fail on tool errors",
    )
    gate_step = protected_steps["Trivy gate (fail on CRITICAL)"]
    require(
        workflow_step_field(gate_step, "if") == ["${{ inputs.skip_trivy_gate != true }}"]
        and workflow_step_field(gate_step, "continue-on-error") == []
        and any(f"image-ref: {digest_ref}" in line for line in gate_step)
        and any('exit-code: "1"' in line for line in gate_step),
        "protected Trivy gate must fail closed unless the explicit waiver path is selected",
    )
    for waiver_step_name in ("Validate Trivy gate waiver", "Upload Trivy waiver"):
        waiver_step = protected_steps[waiver_step_name]
        require(
            workflow_step_field(waiver_step, "if") == ["${{ inputs.skip_trivy_gate == true }}"]
            and workflow_step_field(waiver_step, "continue-on-error") == [],
            f"{waiver_step_name} must be mandatory on the explicit waiver path",
        )
    promotion_step = protected_steps["Promote scanned digest to build tags"]
    require(
        workflow_step_field(promotion_step, "if") == []
        and workflow_step_field(promotion_step, "continue-on-error") == [],
        "digest promotion must use GitHub's default success() condition and fail hard",
    )
    require(
        workflow_step_mapping(promotion_step, "env", "digest promotion")
        == {
            "EXPECTED_DIGEST": "${{ steps.push.outputs.digest }}",
            "FINAL_TAGS": "${{ steps.meta.outputs.tags }}",
            "SOURCE_IMAGE": "${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.push.outputs.digest }}",
        },
        "digest promotion must consume only the scanned candidate digest and metadata tags",
    )


def check_local_stack(path: str, *, build_expected: bool) -> None:
    source = read(path)
    require("SECURITY POSTURE: LOCAL DEVELOPMENT ONLY" in source, f"{path}: missing local-only banner")
    render_env = {"CRUX_VERSION": "policy-version"} if path == "examples/quickstart/docker-compose.yml" else None
    rendered = compose_config([path], extra_env=render_env)
    expected_services = {"crux"}
    require(set(rendered.get("services", {})) == expected_services, f"{path}: unexpected service set")
    all_profiles = compose_config([path], extra_env=render_env, profiles=["*"])
    expected_all_services = {"crux", "ollama"} if path == "docker-compose.yml" else {"crux"}
    require(
        set(all_profiles.get("services", {})) == expected_all_services,
        f"{path}: unexpected service hidden behind a profile",
    )
    crux = service(rendered, "crux", path)
    expected_keys = ROOT_CRUX_KEYS if build_expected else QUICKSTART_CRUX_KEYS
    expected_image = (
        "cuecrux/crux-daemon:latest"
        if build_expected
        else "ghcr.io/cuecrux/crux-daemon:policy-version"
    )
    require(crux.get("image") == expected_image, f"{path}: unexpected Crux image origin")
    if build_expected:
        require(crux.get("pull_policy") == "build", f"{path}: root stack must use its local build output")
    require(
        crux.get("labels") == {"io.cuecrux.security.posture": LOCAL_POSTURE},
        f"{path}: missing machine-readable local-only posture",
    )
    environment = environment_of(crux, path)
    expected_environment = {
        "CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND": "1",
        "CORECRUXD_AUTH_MODE": "dev_scopes",
        "CORECRUXD_BUILD_CCXI": "1",
        "CORECRUXD_DATA_DIR": "/data",
        "CORECRUXD_GRPC_HOST": "127.0.0.1",
        "CORECRUXD_HTTP_HOST": "0.0.0.0",
        "CORECRUXD_MCP_HOST": "0.0.0.0",
        "CORECRUXD_MCP_PORT": "14801",
        "CORECRUXD_ROUTE_AUTH": "enforce",
        "CORECRUX_LOG_FORMAT": "json",
    }
    if build_expected:
        expected_environment.update(
            {
                "CORECRUXD_EMBEDDING_MODEL": "nomic-embed-text",
                "CORECRUXD_EMBEDDING_URL": "",
                "CORECRUXD_OBS_RETENTION_DAYS": "",
            }
        )
    else:
        expected_environment["CORECRUXD_UPDATE_CHECK_ENABLED"] = "0"
    require(environment == expected_environment, f"{path}: local environment policy changed")
    expected_build = {"context": str(ROOT), "dockerfile": "Dockerfile"} if build_expected else None
    require(crux.get("build") == expected_build, f"{path}: unexpected source-build posture")
    assert_loopback_ports(crux, path)
    assert_hardened_runtime(crux, path, expected_keys=expected_keys)
    require(crux.get("restart") == "unless-stopped", f"{path}: restart policy changed")
    require(
        crux.get("deploy")
        == {
            "resources": {
                "limits": {
                    "memory": "4294967296",
                    "pids": 512,
                }
            },
            "placement": {},
        },
        f"{path}: resource limits changed",
    )
    assert_healthcheck(crux, path)
    assert_project_resources(rendered, path)
    assert_native_project_resources(
        [path],
        extra_env=render_env,
    )
    if build_expected:
        alternate_inputs = {
            "CORECRUXD_EMBEDDING_MODEL": "policy-model;not-shell",
            "CORECRUXD_EMBEDDING_URL": "https://embedding.example.invalid/v1",
            "CORECRUXD_OBS_RETENTION_DAYS": "37",
        }
        alternate = compose_config([path], extra_env=alternate_inputs, profiles=["*"])
        alternate_crux = service(alternate, "crux", f"{path}:alternate-inputs")
        alternate_environment = expected_environment | {
            "CORECRUXD_EMBEDDING_MODEL": alternate_inputs["CORECRUXD_EMBEDDING_MODEL"],
            "CORECRUXD_EMBEDDING_URL": alternate_inputs["CORECRUXD_EMBEDDING_URL"],
            "CORECRUXD_OBS_RETENTION_DAYS": alternate_inputs["CORECRUXD_OBS_RETENTION_DAYS"],
        }
        require(
            environment_of(alternate_crux, f"{path}:alternate-inputs") == alternate_environment,
            f"{path}: data-only interpolation moved outside the approved environment fields",
        )
        default_all_crux = service(all_profiles, "crux", f"{path}:default-all-profiles")
        default_non_environment = {key: value for key, value in default_all_crux.items() if key != "environment"}
        alternate_non_environment = {key: value for key, value in alternate_crux.items() if key != "environment"}
        require(
            alternate_non_environment == default_non_environment,
            f"{path}: data-only interpolation changed a non-environment security field",
        )
        assert_ollama_service(
            service(alternate, "ollama", f"{path}:alternate-ollama"),
            f"{path}:alternate-ollama",
            alternate_inputs["CORECRUXD_EMBEDDING_MODEL"],
        )
    else:
        default_rendered = compose_config([path])
        default_crux = service(default_rendered, "crux", f"{path}:default-version")
        require(
            default_crux.get("image") == "ghcr.io/cuecrux/crux-daemon:latest",
            f"{path}: default image tag changed",
        )
        default_non_image = {key: value for key, value in default_crux.items() if key != "image"}
        selected_non_image = {key: value for key, value in crux.items() if key != "image"}
        require(
            default_non_image == selected_non_image,
            f"{path}: CRUX_VERSION interpolation changed a non-image security field",
        )


def check_dev_overlay() -> None:
    overlay = "docker-compose.dev.yml"
    require(
        "SECURITY POSTURE: LOCAL DEVELOPMENT ONLY" in read(overlay),
        f"{overlay}: missing local-only source-mount warning",
    )
    rendered = compose_config(["docker-compose.yml", overlay])
    source = "docker-compose.yml + docker-compose.dev.yml"
    require(set(rendered.get("services", {})) == {"crux"}, f"{source}: unexpected merged service set")
    hostile = "safe-model;printf PWNED"
    all_profiles = compose_config(
        ["docker-compose.yml", overlay],
        extra_env={"CORECRUXD_EMBEDDING_MODEL": hostile},
        profiles=["*"],
    )
    require(
        set(all_profiles.get("services", {})) == {"crux", "ollama"},
        f"{source}: unexpected merged service hidden behind a profile",
    )
    crux = service(rendered, "crux", source)
    require(
        crux.get("labels") == {"io.cuecrux.security.posture": LOCAL_POSTURE},
        f"{source}: merged service must remain labelled local-only",
    )
    expected_environment = {
        "CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND": "1",
        "CORECRUXD_AUTH_MODE": "dev_scopes",
        "CORECRUXD_BUILD_CCXI": "1",
        "CORECRUXD_CONSOLE_DEV_PATH": "/console-dev",
        "CORECRUXD_DATA_DIR": "/data",
        "CORECRUXD_EMBEDDING_MODEL": "nomic-embed-text",
        "CORECRUXD_EMBEDDING_URL": "",
        "CORECRUXD_GRPC_HOST": "127.0.0.1",
        "CORECRUXD_HTTP_HOST": "0.0.0.0",
        "CORECRUXD_MCP_HOST": "0.0.0.0",
        "CORECRUXD_MCP_PORT": "14801",
        "CORECRUXD_OBS_RETENTION_DAYS": "",
        "CORECRUXD_ROUTE_AUTH": "enforce",
        "CORECRUXD_SOURCE_ROOTS": "/sources,/src",
        "CORECRUXD_WORKSPACE_PATH": "/src",
        "CORECRUX_LOG_FORMAT": "json",
    }
    require(environment_of(crux, source) == expected_environment, f"{source}: merged environment policy changed")
    require(
        crux.get("build") == {"context": str(ROOT), "dockerfile": "Dockerfile"},
        f"{source}: overlay must retain the audited root build context",
    )
    assert_loopback_ports(crux, source)
    assert_hardened_runtime(
        crux,
        source,
        expected_keys=ROOT_CRUX_KEYS,
        check_data_volume=False,
    )
    require(crux.get("restart") == "unless-stopped", f"{source}: restart policy changed")
    assert_healthcheck(crux, source)
    assert_project_resources(rendered, source)
    assert_project_resources(
        all_profiles,
        f"{source}:all-profiles",
        expected_volumes={"crux-data", "ollama-models"},
    )
    assert_native_project_resources(
        ["docker-compose.yml", overlay],
        profiles=["*"],
        expected_volumes={"crux-data", "ollama-models"},
    )
    assert_ollama_service(
        service(all_profiles, "ollama", f"{source}:ollama"),
        f"{source}:ollama",
        hostile,
    )

    volumes = crux.get("volumes")
    require(isinstance(volumes, list), f"{source}: merged mounts must be a list")
    data_volumes = [volume for volume in volumes if isinstance(volume, dict) and volume.get("target") == "/data"]
    require(
        data_volumes
        == [{"type": "volume", "source": "crux-data", "target": "/data", "volume": {}}],
        f"{source}: /data must remain the one project-managed writable volume",
    )
    expected_binds = {
        "/console-dev": ROOT / "crates/corecruxd/console",
        "/src/crates": ROOT / "crates",
        "/src/Cargo.toml": ROOT / "Cargo.toml",
        "/src/Cargo.lock": ROOT / "Cargo.lock",
        "/sources/plancrux": ROOT.parent / "PlanCrux",
    }
    binds = [volume for volume in volumes if isinstance(volume, dict) and volume.get("type") == "bind"]
    require(len(binds) == len(expected_binds), f"{source}: unexpected bind-mount count")
    require(
        len(volumes) == 1 + len(expected_binds),
        f"{source}: every merged mount must be the data volume or an approved read-only bind",
    )
    for bind in binds:
        target = bind.get("target")
        require(target in expected_binds, f"{source}: unapproved bind target {target!r}")
        require(bind.get("source") == str(expected_binds[target]), f"{source}: unapproved source for {target}")
        require(bind.get("read_only") is True, f"{source}: bind {target} must be read-only")
        require(bind.get("bind") == {}, f"{source}: bind {target} may not set propagation/options")


def assert_ollama_service(ollama: dict[str, Any], source: str, expected_model: str) -> None:
    require(set(ollama) == OLLAMA_KEYS, f"{source}: rendered service keys changed: {sorted(set(ollama))}")
    require(ollama.get("image") == "ollama/ollama:latest", f"{source}: unexpected Ollama image origin")
    require(
        ollama.get("labels") == {"io.cuecrux.security.posture": LOCAL_POSTURE},
        f"{source}: Ollama must be labelled local-only",
    )
    require(
        environment_of(ollama, source) == {"OLLAMA_MODEL": expected_model},
        f"{source}: Ollama model must be the only environment input",
    )
    require(ollama.get("init") is True, f"{source}: Ollama must use an init process")
    require(ollama.get("cap_drop") == ["ALL"], f"{source}: Ollama must drop all Linux capabilities")
    require(
        ollama.get("security_opt") == ["no-new-privileges:true"],
        f"{source}: Ollama must disable privilege escalation",
    )
    require(ollama.get("pids_limit") == 512, f"{source}: Ollama must retain its PID limit")
    require(ollama.get("command") is None, f"{source}: Ollama command override is forbidden")
    require(ollama.get("profiles") == ["embeddings"], f"{source}: Ollama profile changed")
    for forbidden in (
        "cap_add",
        "cgroup",
        "configs",
        "develop",
        "device_cgroup_rules",
        "devices",
        "external_links",
        "gpus",
        "group_add",
        "ipc",
        "label_file",
        "links",
        "network_mode",
        "pid",
        "post_start",
        "pre_stop",
        "privileged",
        "runtime",
        "secrets",
        "sysctls",
        "use_api_socket",
        "userns_mode",
        "uts",
        "volumes_from",
    ):
        require(not ollama.get(forbidden), f"{source}: Ollama setting {forbidden} is forbidden")
    require(ollama.get("networks") == {"default": None}, f"{source}: Ollama may use only the project network")
    require(
        ollama.get("ports")
        == [
            {
                "mode": "ingress",
                "host_ip": "127.0.0.1",
                "target": 11434,
                "published": "11434",
                "protocol": "tcp",
            }
        ],
        f"{source}: Ollama must publish only port 11434 on loopback",
    )
    require(
        ollama.get("volumes")
        == [
            {
                "type": "volume",
                "source": "ollama-models",
                "target": "/root/.ollama",
                "volume": {},
            }
        ],
        f"{source}: Ollama may mount only its project-managed model volume",
    )
    require(
        ollama.get("entrypoint")
        == [
            "/bin/sh",
            "-ec",
            'ollama serve & pid=$$!; sleep 3; ollama pull "$$OLLAMA_MODEL"; wait "$$pid"',
        ],
        f"{source}: Ollama entrypoint must match the audited model-pull program exactly",
    )


def check_ollama_injection_boundary() -> None:
    hostile = "safe-model;printf PWNED"
    rendered = compose_config(
        ["docker-compose.yml"],
        extra_env={"CORECRUXD_EMBEDDING_MODEL": hostile},
        profiles=["embeddings"],
    )
    require(
        set(rendered.get("services", {})) == {"crux", "ollama"},
        "docker-compose.yml: embeddings profile may contain only crux and ollama",
    )
    crux = service(rendered, "crux", "docker-compose.yml:embeddings:crux")
    assert_loopback_ports(crux, "docker-compose.yml:embeddings:crux")
    assert_hardened_runtime(
        crux,
        "docker-compose.yml:embeddings:crux",
        expected_keys=ROOT_CRUX_KEYS,
    )
    assert_healthcheck(crux, "docker-compose.yml:embeddings:crux")
    assert_project_resources(
        rendered,
        "docker-compose.yml:embeddings",
        expected_volumes={"crux-data", "ollama-models"},
    )
    assert_ollama_service(service(rendered, "ollama", "docker-compose.yml:ollama"), "docker-compose.yml:ollama", hostile)


def expected_remote_environment(supplied: dict[str, str]) -> dict[str, str]:
    return {
        "CORECRUXD_AUTH_MODE": "jwt_hs256",
        "CORECRUXD_BUILD_CCXI": "1",
        "CORECRUXD_DATA_DIR": "/data",
        "CORECRUXD_GRPC_HOST": "127.0.0.1",
        "CORECRUXD_HTTP_HOST": "0.0.0.0",
        "CORECRUXD_JWT_AUD": supplied["CORECRUXD_JWT_AUD"],
        "CORECRUXD_JWT_HS256_SECRET": supplied["CORECRUXD_JWT_HS256_SECRET"],
        "CORECRUXD_JWT_ISS": supplied["CORECRUXD_JWT_ISS"],
        "CORECRUXD_MCP_HOST": "0.0.0.0",
        "CORECRUXD_MCP_PORT": "14801",
        "CORECRUXD_ROUTE_AUTH": "enforce",
        "CORECRUXD_TENANT_WRITE_STAMP": "on",
        "CORECRUXD_UPDATE_CHECK_ENABLED": "0",
        "CORECRUX_LOG_FORMAT": "json",
        "CRUX_AGENT_TOKEN": supplied["CRUX_AGENT_TOKEN"],
    }


def check_remote_stack() -> None:
    path = "examples/remote/docker-compose.yml"
    source = read(path)
    require("@${CRUX_IMAGE_DIGEST:?" in source, f"{path}: image must require a digest")
    for forbidden in (":latest", "dev_scopes", "CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND"):
        require(forbidden not in source, f"{path}: forbidden remote posture token {forbidden!r}")
    for required in (
        "${CORECRUXD_JWT_HS256_SECRET:?",
        "${CORECRUXD_JWT_ISS:?",
        "${CORECRUXD_JWT_AUD:?",
        "${CRUX_AGENT_TOKEN:?",
    ):
        require(required in source, f"{path}: credential must be required: {required}")
    for missing in DUMMY_REMOTE_ENV:
        other_env = DUMMY_REMOTE_ENV.copy()
        other_env.pop(missing)
        require_compose_failure([path], missing_env=missing, other_env=other_env)

    rendered = compose_config([path], extra_env=DUMMY_REMOTE_ENV)
    require(set(rendered.get("services", {})) == {"crux"}, f"{path}: remote example may contain only crux")
    all_profiles = compose_config([path], extra_env=DUMMY_REMOTE_ENV, profiles=["*"])
    require(
        set(all_profiles.get("services", {})) == {"crux"},
        f"{path}: remote example may not hide services behind profiles",
    )
    alternate = compose_config([path], extra_env=ALTERNATE_REMOTE_ENV)
    alternate_crux = service(alternate, "crux", f"{path}:alternate-inputs")
    require(
        alternate_crux.get("image")
        == f"ghcr.io/cuecrux/crux-daemon@{ALTERNATE_REMOTE_ENV['CRUX_IMAGE_DIGEST']}",
        f"{path}: image digest must come from the required operator input",
    )
    require(
        environment_of(alternate_crux, f"{path}:alternate-inputs")
        == expected_remote_environment(ALTERNATE_REMOTE_ENV),
        f"{path}: remote credentials must come from the required operator inputs",
    )
    crux = service(rendered, "crux", path)
    require(set(crux) == REMOTE_CRUX_KEYS, f"{path}: rendered service keys changed: {sorted(set(crux))}")
    require(
        crux.get("image") == f"ghcr.io/cuecrux/crux-daemon@{DUMMY_DIGEST}",
        f"{path}: image must render by digest only",
    )
    require("build" not in crux, f"{path}: remote example must never build operator-controlled source")
    require(
        crux.get("labels") == {"io.cuecrux.security.posture": REMOTE_POSTURE},
        f"{path}: missing machine-readable shared posture",
    )
    environment = environment_of(crux, path)
    require(
        environment == expected_remote_environment(DUMMY_REMOTE_ENV),
        f"{path}: remote environment values must match the exact secure posture",
    )
    require(
        "CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND" not in environment,
        f"{path}: insecure development bind override must be absent",
    )
    assert_loopback_ports(crux, path)
    assert_hardened_runtime(crux, path, expected_keys=REMOTE_CRUX_KEYS)
    require(crux.get("restart") == "unless-stopped", f"{path}: restart policy changed")
    require(crux.get("mem_limit") == "4294967296", f"{path}: memory limit changed")
    require(crux.get("stop_grace_period") == "30s", f"{path}: stop grace period changed")
    assert_healthcheck(crux, path)
    assert_project_resources(rendered, path)
    assert_native_project_resources(
        [path],
        extra_env=DUMMY_REMOTE_ENV,
    )
    normalized = {
        key: value
        for key, value in crux.items()
        if key not in {"image", "environment"}
    }
    alternate_normalized = {
        key: value
        for key, value in alternate_crux.items()
        if key not in {"image", "environment"}
    }
    require(
        alternate_normalized == normalized,
        f"{path}: credential/digest interpolation changed a security field",
    )


def main() -> int:
    checks = (
        check_dockerignore,
        check_compose_discovery_files,
        check_dockerfile_and_workflow,
        lambda: check_local_stack("docker-compose.yml", build_expected=True),
        lambda: check_local_stack("examples/quickstart/docker-compose.yml", build_expected=False),
        check_dev_overlay,
        check_ollama_injection_boundary,
        check_remote_stack,
    )
    failures: list[str] = []
    for check in checks:
        try:
            check()
        except (OSError, PolicyFailure) as error:
            failures.append(str(error))
    if failures:
        for failure in failures:
            print(f"container policy failure: {failure}", file=sys.stderr)
        return 1
    print("container policy guard passed: build context and Compose postures are hardened")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
