# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
# See LICENCE.md in the repository root.

"""Crux Daemon Python client."""

from .client import AsyncCoreCruxClient, CoreCruxClient
from .errors import CoreCruxError
from .types import (
    Fact,
    FactQueryResult,
    SessionState,
    StoreFact,
    TextSearchCoverage,
    TextSearchHit,
    TextSearchMeta,
    TextSearchResult,
)

__all__ = [
    "AsyncCoreCruxClient",
    "CoreCruxClient",
    "CoreCruxError",
    "Fact",
    "FactQueryResult",
    "SessionState",
    "StoreFact",
    "TextSearchCoverage",
    "TextSearchHit",
    "TextSearchMeta",
    "TextSearchResult",
]
