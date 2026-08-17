# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Give a CrewAI agent access to Crux memory.

    python examples/crewai_example.py --boot        # start a daemon, run, tear down
    python examples/crewai_example.py http://127.0.0.1:14800

No model call and no API key: the point is the memory half. The tool is what
an agent would call; running a real crew would need an LLM provider, which is
the caller's business, not the adapter's.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "sdks" / "python" / "src"))

from cuecrux_client import CueCruxClient  # noqa: E402
from cuecrux_client.types import StoreFact  # noqa: E402

from crux_adapters.core import fetch_bundle  # noqa: E402
from crux_adapters.crewai import CruxMemoryTool, to_context_string  # noqa: E402


def run(base_url: str) -> int:
    with CueCruxClient(base_url) as client:
        client.store_fact(
            StoreFact(entity="project:atlas", key="database", value="Postgres 16, not MySQL")
        )
        client.store_fact(
            StoreFact(entity="project:atlas", key="deploy", value="Fridays are frozen")
        )

        # 1. As a tool the agent calls when it needs to remember something.
        #    Crux does the recall; CrewAI does not re-embed or re-rank.
        tool = CruxMemoryTool(client=client, entity="project:atlas", token_budget=2000)
        print(f"tool: {tool.name}")

        # No query: `entity=` is the only true scope, so this returns exactly
        # the atlas facts.
        for line in tool.run().splitlines():
            print(f"  {line}")

        # With a query the daemon UNIONS keyword recall on top of the addressed
        # entity -- it does not filter to it. On a fresh daemon the seeded
        # `__bootstrap__::` docs dominate that keyword pass, so this returns
        # far more. Worth seeing rather than hiding: it is the daemon's recall
        # behaviour, and an adapter that trimmed it would be re-deciding.
        widened = tool.run(query="what database does atlas use")
        print(f"\n  with a query: {len(widened.splitlines()) - 1} lines "
              f"(addressed entity UNION keyword recall)")

        # Attach it to an agent exactly as you would any CrewAI tool:
        #
        #     from crewai import Agent
        #     Agent(role="...", goal="...", backstory="...", tools=[tool])

        # 2. As a static context block for a Task description or backstory,
        #    when you want the memory present rather than fetched on demand.
        bundle = fetch_bundle(client, entity="project:atlas", token_budget=2000)
        print("\nstatic context block:")
        for line in to_context_string(bundle).splitlines():
            print(f"  {line}")

        print(f"\nstable_hash: {bundle.stable_hash}")
        print(f"truncated:   {bundle.truncated}")

        # A truncated bundle says so in the header rather than passing a
        # partial memory off as a whole one.
        tiny = fetch_bundle(client, token_budget=1)
        assert tiny.truncated, "expected a 1-token budget to truncate"
        print(f"\nat token_budget=1: {to_context_string(tiny).splitlines()[0]}")

    print("\ncrewai example: ok")
    return 0


def main(argv: list[str]) -> int:
    if "--boot" in argv:
        from conformance.daemon import Daemon, find_binary

        binary = find_binary()
        if binary is None:
            print("no corecruxd binary; build one or set CORECRUXD_BIN", file=sys.stderr)
            return 2
        with Daemon(binary) as daemon:
            return run(daemon.base_url)

    base_url = next((a for a in argv if a.startswith("http")), "http://127.0.0.1:14800")
    return run(base_url)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
