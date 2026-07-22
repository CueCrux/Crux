#!/usr/bin/env python3
"""Fail closed if Docker metadata can move a floating release alias."""

from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/docker.yml"


def indented_block(lines: list[str], marker: str) -> list[str]:
    matches = [index for index, line in enumerate(lines) if line.strip() == marker]
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one {marker!r} block, found {len(matches)}")
    start = matches[0]
    indent = len(lines[start]) - len(lines[start].lstrip())
    block: list[str] = []
    for line in lines[start + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        if line.strip() and not line.lstrip().startswith("#"):
            block.append(line.strip())
    return block


lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
metadata_actions = [line for line in lines if "uses: docker/metadata-action@" in line]
if len(metadata_actions) != 1:
    raise SystemExit(f"expected one docker/metadata-action step, found {len(metadata_actions)}")

flavor = indented_block(lines, "flavor: |")
if flavor != ["latest=false"]:
    raise SystemExit(f"metadata flavor must be exactly latest=false, got {flavor!r}")

tags = indented_block(lines, "tags: |")
expected = {
    "type=semver,pattern={{version}}",
    "type=raw,value=edge,enable=${{ github.ref == 'refs/heads/main' }}",
}
if set(tags) != expected or len(tags) != len(expected):
    raise SystemExit(f"metadata tags must be immutable semver plus main-only edge, got {tags!r}")

print("Docker tag policy guard passed: release builds cannot move latest or minor aliases")
