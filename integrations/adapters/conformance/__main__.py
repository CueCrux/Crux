# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Run the conformance suite. The M6.2 gate.

    python -m conformance              # mapping + live (boots two daemons)
    python -m conformance --mapping    # mapping only; no daemon needed

Every discovered adapter runs every case. Exit code is non-zero on any failure.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "sdks" / "python" / "src"))

from conformance.daemon import Daemon, find_binary  # noqa: E402
from conformance.suite import discover_adapters, run_live_cases, run_mapping_cases  # noqa: E402


def main(argv: list[str]) -> int:
    mapping_only = "--mapping" in argv
    adapters = discover_adapters()
    print(f"adapters: {', '.join(a.name for a in adapters)}")

    failures = []

    print("\n── mapping ────────────────────────────────────────────")
    for adapter in adapters:
        found = run_mapping_cases(adapter)
        failures.extend(found)
        print(f"  {'FAIL' if found else 'ok  '} {adapter.name} ({len(found)} failures)")

    if mapping_only:
        print("\nlive layer skipped (--mapping)")
    else:
        binary = find_binary()
        if binary is None:
            print(
                "\nlive layer SKIPPED: no corecruxd binary "
                "(build one, or set CORECRUXD_BIN)",
                file=sys.stderr,
            )
            # A skipped live layer is not a pass. The gate needs both.
            return 2 if not failures else 1
        print(f"\n── live ───────────────────────────────────────────────\n  daemon: {binary}")
        from corecrux_client import CoreCruxClient

        with Daemon(binary) as on, Daemon(binary, context_surface=False) as off:
            with (
                CoreCruxClient(on.base_url) as client,
                CoreCruxClient(off.base_url) as gated_off,
            ):
                for adapter in adapters:
                    found = run_live_cases(adapter, client, gated_off_client=gated_off)
                    failures.extend(found)
                    print(f"  {'FAIL' if found else 'ok  '} {adapter.name} ({len(found)} failures)")

    print()
    if failures:
        print(f"conformance: {len(failures)} FAILURE(S)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("conformance: all cases pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
