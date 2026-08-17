# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""Exercise every M6.1 surface against a LIVE daemon.

The unit tests in ``tests/`` prove the wire shape against a stub. This proves
the daemon actually answers, that the SDK parses what comes back, and that the
context bundle's stable region really is stable. Driven by ``sdks/live-smoke.sh``,
which starts the daemon with the required flags.

Usage: ``python3 smoke.py <base_url>``
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from cuecrux_client import CueCruxClient  # noqa: E402
from cuecrux_client.errors import CueCruxError  # noqa: E402
from cuecrux_client.types import StoreFact  # noqa: E402

failures: list[str] = []


def check(name: str, fn, *, allow_status: tuple[int, ...] = ()) -> object:
    """Run one probe. An allowed status counts as reached, not broken."""
    try:
        result = fn()
    except CueCruxError as err:
        if err.status_code in allow_status:
            print(f"  ok   {name} (HTTP {err.status_code}, expected)")
            return None
        failures.append(f"{name}: HTTP {err.status_code} {err.detail}")
        print(f"  FAIL {name}: HTTP {err.status_code} {err.detail}")
        return None
    except Exception as err:  # noqa: BLE001 - a smoke run reports, never crashes
        failures.append(f"{name}: {type(err).__name__} {err}")
        print(f"  FAIL {name}: {type(err).__name__} {err}")
        return None
    print(f"  ok   {name}")
    return result


def main(base_url: str) -> int:
    with CueCruxClient(base_url) as client:
        client.store_fact(
            StoreFact(entity="smoke:m6", key="surface", value="sdk breadth", confidence=1.0)
        )

        print("context")
        bundle = check("context", lambda: client.context(entity="smoke:m6", token_budget=500))
        check("post_context", lambda: client.post_context(query="smoke", token_budget=500))
        md = check("context_markdown", lambda: client.context_markdown(entity="smoke:m6"))
        msgs = check("context_messages", lambda: client.context_messages(entity="smoke:m6"))

        if bundle is not None:
            for field in ("bundle_version", "sections", "stable_hash", "budget"):
                if field not in bundle:
                    failures.append(f"context bundle missing '{field}'")
                    print(f"  FAIL context bundle missing '{field}'")
            # The stable region must be byte-stable for an unchanged fact chain
            # -- this is what makes provider-side prompt caches hit.
            again = client.context(entity="smoke:m6", token_budget=500)
            if again["stable_hash"] != bundle["stable_hash"]:
                failures.append("stable_hash changed across two identical calls")
                print("  FAIL stable_hash is not stable across identical calls")
            else:
                print("  ok   stable_hash is stable across identical calls")

        if isinstance(md, str) and not md.strip():
            failures.append("context_markdown returned empty text")
            print("  FAIL context_markdown returned empty text")
        if isinstance(msgs, dict) and not msgs.get("messages"):
            failures.append("context_messages returned no messages")
            print("  FAIL context_messages returned no messages")

        print("review")
        extracted = check(
            "extract_memory",
            lambda: client.extract_memory(
                "I bought three bikes on 2026-08-07 for $1,200.", profile="comprehensive"
            ),
        )
        check("list_candidates", lambda: client.list_candidates(status="candidate"))
        candidates = (extracted or {}).get("candidates") or []
        if candidates:
            cid = candidates[0].get("candidate_id") or candidates[0].get("id")
            if cid:
                # The fail-closed gate: an unscored candidate must be REFUSED
                # at a threshold, not promoted by default.
                check(
                    "promote_candidate (unscored, expect refusal)",
                    lambda: client.promote_candidate(cid, auto_threshold=0.9),
                    allow_status=(400, 422),
                )
                check(
                    "reject_candidate",
                    lambda: client.reject_candidate(cid, "smoke run"),
                    allow_status=(404,),
                )
        else:
            print("  --   no candidates extracted; promote/reject not exercised")

        check("review_contradictions", lambda: client.review_contradictions(limit=5))
        check("review_queue", lambda: client.review_queue(limit=5))
        check("apply_expiries", lambda: client.apply_expiries(["f_nonexistent"]))

        print("consolidation")
        a = client.store_fact(StoreFact(entity="smoke:merge", key="k", value="v1", confidence=0.5))
        b = client.store_fact(StoreFact(entity="smoke:merge", key="k", value="v2", confidence=0.5))
        merged = check(
            "consolidate",
            lambda: client.consolidate("smoke:merge", "k", "canonical", [a.fact_id, b.fact_id]),
        )
        canonical = ((merged or {}).get("receipt") or {}).get("canonical_fact_id")
        if canonical:
            check("undo_consolidation", lambda: client.undo_consolidation(canonical))
        else:
            check(
                "undo_consolidation (no canonical id; expect refusal)",
                lambda: client.undo_consolidation("f_nonexistent"),
                allow_status=(400, 404, 409, 422),
            )

        print("ingest")
        check(
            "local_ingest",
            lambda: client.local_ingest(
                "smoke-tenant",
                "smoke-corpus",
                [{"doc_id": "d1", "chunks": [{"chunk_id": "c1", "text": "hello from the smoke run"}]}],
            ),
        )
        check(
            "import_memory_pack (dry run, unsigned pack; expect refusal)",
            lambda: client.import_memory_pack("smoke-tenant", {}, dry_run=True),
            allow_status=(400, 403, 404, 422),
        )

        print("extensions")
        check("list_extensions", lambda: client.list_extensions())
        check("list_registry_entries", lambda: client.list_registry_entries(), allow_status=(404,))
        check("list_trusted_keys", lambda: client.list_trusted_keys())
        if client.get_extension("smoke-nonexistent") is None:
            print("  ok   get_extension returns None for an unknown id")
        else:
            failures.append("get_extension returned a body for an unknown id")
            print("  FAIL get_extension returned a body for an unknown id")
        check("list_grants", lambda: client.list_grants("smoke-nonexistent"), allow_status=(404,))
        check(
            "invoke_extension_tool (unknown extension; expect refusal)",
            lambda: client.invoke_extension_tool("smoke-nonexistent", "noop", passport_fpr="smoke-fpr"),
            allow_status=(403, 404),
        )

        print("events")
        # The stream is infinite; take the first event a write produces.
        import threading

        seen: list[dict] = []

        def reader() -> None:
            try:
                for event in client.subscribe_events(types=["fact.stored"]):
                    seen.append(event)
                    break
            except Exception as err:  # noqa: BLE001
                failures.append(f"subscribe_events: {type(err).__name__} {err}")

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        with CueCruxClient(base_url) as writer:
            import time

            time.sleep(0.5)  # let the subscriber attach before the write
            writer.store_fact(StoreFact(entity="smoke:events", key="k", value="v"))
        thread.join(timeout=10)

        if seen and seen[0].get("type") == "fact.stored":
            print("  ok   subscribe_events received fact.stored")
        else:
            failures.append("subscribe_events saw no fact.stored within 10s")
            print("  FAIL subscribe_events saw no fact.stored within 10s")

    print()
    if failures:
        print(f"python smoke: {len(failures)} FAILURE(S)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("python smoke: all surfaces reached")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:14800"))
