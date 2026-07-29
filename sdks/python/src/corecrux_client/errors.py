# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""CoreCrux error types."""


class CoreCruxError(Exception):
    """Raised when the CoreCrux API returns a non-2xx response.

    Attributes:
        status_code: HTTP status code from the server.
        detail: Human-readable error detail string.
        type: Optional problem type URI (RFC 7807).
    """

    def __init__(self, status_code: int, detail: str, type: str = ""):
        self.status_code = status_code
        self.detail = detail
        self.type = type
        super().__init__(f"CoreCrux error {status_code}: {detail}")
