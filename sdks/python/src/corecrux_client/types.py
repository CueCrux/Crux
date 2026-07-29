# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""CoreCrux API data types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Fact:
    """A stored fact returned by the CoreCrux API."""

    fact_id: str
    entity: str
    key: str
    value: str
    confidence: float
    stored_at: str
    tokens: int
    deleted: bool
    version: int
    source_receipt: str | None = None
    supersedes: str | None = None
    private: bool = False


@dataclass
class StoreFact:
    """Payload for creating a new fact via the CoreCrux API."""

    entity: str
    key: str
    value: str
    confidence: float = 1.0
    private: bool = False
    source_receipt: str | None = None


@dataclass
class TextSearchHit:
    """A single hit from a text-search query."""

    segment_index: int
    doc_id: int
    score: float
    frame_offset: int
    token_count: int


@dataclass
class TextSearchCoverage:
    """Coverage metadata for a text-search query."""

    score: float
    gaps: list[dict[str, Any]] = field(default_factory=list)
    below_floor: int = 0


@dataclass
class TextSearchMeta:
    """Execution metadata for a text-search query."""

    backend: str
    took_ms: int
    segments_searched: int
    total_docs: int
    total_candidates: int = 0


@dataclass
class TextSearchResult:
    """Full response from a text-search query."""

    results: list[TextSearchHit]
    coverage: TextSearchCoverage
    meta: TextSearchMeta
    tokens_used: int | None = None
    tokens_available: int | None = None
    results_omitted: int | None = None
    scan_mode: bool = False


@dataclass
class FactQueryResult:
    """Response from the query-facts endpoint."""

    facts: list[Fact]
    total_tokens: int


@dataclass
class SessionState:
    """Stored session state returned by the CoreCrux API."""

    session_id: str
    state: dict[str, Any]
    updated_at: str
    total_tokens: int
    expires_at: str | None = None
