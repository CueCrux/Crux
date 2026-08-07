# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Inject Crux memory into LangChain.

    python examples/langchain_example.py --boot        # start a daemon, run, tear down
    python examples/langchain_example.py http://127.0.0.1:14800

No model call and no API key: the point is the retrieval half. Pass the
documents to whatever chain you already have.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "sdks" / "python" / "src"))

from corecrux_client import CoreCruxClient  # noqa: E402
from corecrux_client.types import StoreFact  # noqa: E402

from crux_adapters.langchain import (  # noqa: E402
    CruxContextRetriever,
    to_documents,
    to_system_message,
)
from crux_adapters.core import fetch_bundle  # noqa: E402


def run(base_url: str) -> int:
    with CoreCruxClient(base_url) as client:
        # Seed something worth recalling.
        client.store_fact(
            StoreFact(entity="project:atlas", key="database", value="Postgres 16, not MySQL")
        )
        client.store_fact(
            StoreFact(entity="project:atlas", key="deploy", value="Fridays are frozen")
        )

        # 1. As a retriever, scoped to an entity -- drop it into any chain
        #    that takes one.
        retriever = CruxContextRetriever(
            client=client, entity="project:atlas", token_budget=2000
        )
        # No query text: scoped strictly to the entity.
        docs = retriever.invoke("")
        print(f"scoped retriever returned {len(docs)} documents")
        for doc in docs:
            freshness = doc.metadata.get("freshness", "?")
            print(f"  [{doc.metadata['crux_kind']}/{freshness}] {doc.page_content}")

        # Worth knowing: `entity=` is the only true scope. A `query` UNIONS
        # keyword recall on top rather than filtering, and on a fresh daemon
        # the seeded `__bootstrap__::` documentation facts dominate that pass.
        # See the README table for the measured numbers.
        unscoped = CruxContextRetriever(client=client, token_budget=2000).invoke("")
        bootstrap = sum(1 for d in unscoped if d.metadata.get("entity", "").startswith("__"))
        print(f"\nunscoped: {len(unscoped)} documents, {bootstrap} of them daemon bootstrap docs")

        # 2. As a system-message prefix -- the injection shape.
        bundle = fetch_bundle(client, entity="project:atlas", token_budget=2000)
        message = to_system_message(bundle)
        print(f"\nsystem message ({len(message.content)} chars):")
        for line in message.content.splitlines():
            print(f"  {line}")

        # The stable region is byte-stable while the fact chain is unchanged,
        # so a provider-side prompt cache hits on this prefix.
        print(f"\nstable_hash: {bundle.stable_hash}")
        print(f"truncated:   {bundle.truncated}")

        # Documents and the message are two views of the same bundle.
        assert len(to_documents(bundle)) == len(bundle.items)

    print("\nlangchain example: ok")
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
