# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.

"""The mapping layer of the conformance suite, plus negative controls.

CI-able: no daemon, no network, stdlib ``unittest``. The live layer needs a
built corecruxd and runs via ``python -m conformance``.

The negative controls matter as much as the positive ones. A conformance suite
that passes everything it is shown is not a gate, and this suite passed every
adapter on its first run -- so each property is also asserted to FAIL against a
deliberately non-conforming adapter. If someone later loosens a case, one of
these breaks.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from conformance.suite import (  # noqa: E402
    FIXTURES,
    Adapter,
    discover_adapters,
    run_mapping_cases,
)
from crux_adapters.core import bundle_from_json  # noqa: E402


def _cases(failures) -> set[str]:
    return {f.case for f in failures}


class MappingConformance(unittest.TestCase):
    def test_every_discovered_adapter_conforms(self) -> None:
        adapters = discover_adapters()
        self.assertTrue(adapters, "no adapters discovered, not even the neutral core")
        for adapter in adapters:
            with self.subTest(adapter=adapter.name):
                failures = run_mapping_cases(adapter)
                self.assertEqual(failures, [], f"{adapter.name}: {[str(f) for f in failures]}")

    def test_the_core_adapter_is_always_available(self) -> None:
        # The suite must be runnable on a machine with no frameworks installed,
        # otherwise CI silently checks nothing.
        self.assertIn("core", {a.name for a in discover_adapters()})

    def test_every_registered_binding_exposes_both_conformance_hooks(self) -> None:
        # A binding registered without its hooks would be skipped silently by
        # discover_adapters() and never conform to anything.
        import importlib

        from conformance.suite import _BINDINGS

        self.assertEqual(
            [name for name, _, _ in _BINDINGS],
            ["langchain", "llamaindex", "crewai"],
            "the three shipped bindings must all be registered",
        )
        for name, module_name, guard in _BINDINGS:
            with self.subTest(binding=name):
                module = importlib.import_module(module_name)
                # Importing must never require the framework -- the guard is
                # what raises, and only when the adapter is actually used.
                self.assertTrue(callable(getattr(module, guard)))
                self.assertTrue(callable(getattr(module, "adapter_entrypoint", None)))
                self.assertTrue(callable(getattr(module, "adapter_items", None)))

    def test_every_binding_module_imports_without_its_framework(self) -> None:
        # `import crux_adapters.crewai` on a machine with no CrewAI must work;
        # only calling into it may fail. Otherwise discover_adapters() would
        # blow up instead of skipping.
        import importlib

        from conformance.suite import _BINDINGS

        for _, module_name, _ in _BINDINGS:
            with self.subTest(module=module_name):
                self.assertIsNotNone(importlib.import_module(module_name))


class NegativeControls(unittest.TestCase):
    """Each case must reject an adapter that violates exactly that property."""

    def test_reordering_is_caught(self) -> None:
        # The daemon's presentation order is what stable_hash covers; an
        # adapter that "helpfully" sorts breaks prompt-cache hits.
        reorderer = Adapter(
            name="reorders",
            fetch=lambda *a, **k: None,
            items=lambda b: sorted(b.items, key=lambda i: i.id, reverse=True),
        )
        self.assertIn("order-preserved", _cases(run_mapping_cases(reorderer)))

    def test_dropping_stale_facts_is_caught(self) -> None:
        # Staleness is an annotation, not a filter. Hiding stale facts changes
        # what the daemon decided to inject.
        hider = Adapter(
            name="hides-stale",
            fetch=lambda *a, **k: None,
            items=lambda b: [i for i in b.items if i.metadata.get("freshness") != "stale"],
        )
        self.assertIn("stale-present", _cases(run_mapping_cases(hider)))

    def test_losing_metadata_is_caught(self) -> None:
        import dataclasses

        stripper = Adapter(
            name="strips-metadata",
            fetch=lambda *a, **k: None,
            items=lambda b: [dataclasses.replace(i, metadata={}) for i in b.items],
        )
        caught = _cases(run_mapping_cases(stripper))
        self.assertIn("fact-metadata", caught)
        self.assertIn("stale-annotated", caught)

    def test_reformatting_fact_text_is_caught(self) -> None:
        # All three adapters must inject byte-identical text, or cross-adapter
        # comparisons mean nothing.
        import dataclasses

        reformatter = Adapter(
            name="reformats",
            fetch=lambda *a, **k: None,
            items=lambda b: [dataclasses.replace(i, text=i.text.upper()) for i in b.items],
        )
        self.assertIn("fact-text-format", _cases(run_mapping_cases(reformatter)))

    def test_dropping_a_section_kind_is_caught(self) -> None:
        facts_only = Adapter(
            name="facts-only",
            fetch=lambda *a, **k: None,
            items=lambda b: [i for i in b.items if i.kind == "facts"],
        )
        caught = _cases(run_mapping_cases(facts_only))
        self.assertIn("section-kinds", caught)
        self.assertIn("aux-item", caught)

    def test_inventing_items_is_caught(self) -> None:
        from crux_adapters.core import ContextItem

        padder = Adapter(
            name="invents",
            fetch=lambda *a, **k: None,
            items=lambda b: [*b.items, ContextItem(id="made-up", text="x", kind="facts")],
        )
        self.assertIn("item-count", _cases(run_mapping_cases(padder)))


class BundleMapping(unittest.TestCase):
    """Properties of the neutral mapping itself, independent of any adapter."""

    def test_truncated_reflects_dropped(self) -> None:
        self.assertTrue(bundle_from_json(FIXTURES["truncated"]).truncated)
        self.assertFalse(bundle_from_json(FIXTURES["ordered"]).truncated)

    def test_raw_payload_is_preserved(self) -> None:
        # Going through an adapter must never lose access to the real response.
        bundle = bundle_from_json(FIXTURES["ordered"])
        self.assertEqual(bundle.raw, FIXTURES["ordered"])

    def test_as_text_joins_in_bundle_order(self) -> None:
        bundle = bundle_from_json(FIXTURES["ordered"])
        self.assertEqual(
            bundle.as_text().splitlines(),
            ["alpha · k1: v1", "alpha · k2: v2", "beta · k1: v3", "resume here"],
        )

    def test_missing_optional_fields_do_not_crash(self) -> None:
        # Sections carry `facts` or `items`, never both; neither key is
        # guaranteed present (the daemon skips empty vectors).
        bundle = bundle_from_json({"sections": [{"kind": "facts"}], "budget": {}})
        self.assertEqual(bundle.items, ())
        self.assertEqual(bundle.dropped, ())


if __name__ == "__main__":
    unittest.main()
