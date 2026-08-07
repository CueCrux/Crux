# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Start a throwaway corecruxd for the live conformance layer.

In Python rather than a shell wrapper because the suite needs *two* daemons --
one with the context surface on, one with it off -- and driving that from the
same process that asserts on it keeps the whole gate a single entry point.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

__all__ = ["Daemon", "repo_root", "find_binary"]


def repo_root() -> Path:
    """The Crux checkout this package lives in."""
    return Path(__file__).resolve().parents[3]


def find_binary() -> Path | None:
    """Locate a corecruxd binary: ``CORECRUXD_BIN``, then the debug build."""
    env = os.environ.get("CORECRUXD_BIN")
    if env and Path(env).is_file() and os.access(env, os.X_OK):
        return Path(env)
    for candidate in ("target/debug/corecruxd", "target/release/corecruxd"):
        path = repo_root() / candidate
        if path.is_file() and os.access(path, os.X_OK):
            return path
    found = shutil.which("corecruxd")
    return Path(found) if found else None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Daemon:
    """A corecruxd child process on a scratch data dir. Use as a context manager."""

    def __init__(self, binary: Path, *, context_surface: bool = True) -> None:
        self.binary = binary
        self.context_surface = context_surface
        self.port = _free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.data_dir = Path(tempfile.mkdtemp(prefix="crux-conformance-"))
        self._proc: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> Daemon:
        env = {
            **os.environ,
            "CORECRUXD_AUTH_MODE": "off",
            "CORECRUXD_DATA_DIR": str(self.data_dir),
            "CORECRUXD_HTTP_PORT": str(self.port),
            "CORECRUXD_GRPC_PORT": str(_free_port()),
            "CORECRUXD_MCP_PORT": str(_free_port()),
            # The case that matters: with this unset the routes 404, and the
            # adapter must surface that rather than return an empty bundle.
            "CORECRUXD_CONTEXT_SURFACE": "1" if self.context_surface else "0",
        }
        self.log_path = self.data_dir / "daemon.log"
        with self.log_path.open("wb") as log:
            self._proc = subprocess.Popen(
                [str(self.binary)], env=env, stdout=log, stderr=subprocess.STDOUT
            )
        self._wait_ready()
        return self

    def _wait_ready(self, timeout_s: int = 60) -> None:
        import httpx

        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                raise RuntimeError(
                    f"daemon exited during startup:\n{self.log_path.read_text()[-2000:]}"
                )
            try:
                if httpx.get(f"{self.base_url}/readyz", timeout=2.0).status_code == 200:
                    return
            except Exception:  # noqa: BLE001 - not up yet
                pass
            time.sleep(0.5)
        raise RuntimeError(f"daemon never became ready:\n{self.log_path.read_text()[-2000:]}")

    def __exit__(self, *exc: object) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=15)
        shutil.rmtree(self.data_dir, ignore_errors=True)
