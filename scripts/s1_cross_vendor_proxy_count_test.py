#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("s1_cross_vendor_proxy_count.py")
SPEC = importlib.util.spec_from_file_location("s1_cross_vendor_proxy_count", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class S1CrossVendorProxyCountTest(unittest.TestCase):
    def test_summarize_counts_providers_actors_and_truncation_warning(self) -> None:
        aggregate = {
            "matched": 4,
            "returned": 3,
            "observations": [
                {"ts": "2026-07-01T00:00:00Z", "provider": "claude-code"},
                {"ts": "2026-07-01T01:00:00Z", "provider": "anthropic"},
                {"ts": "2026-07-01T02:00:00Z", "provider": "openai"},
                {"ts": "2026-06-01T00:00:00Z", "provider": "openai"},
            ],
        }
        facts = [
            {"stored_at": "2026-07-01T00:00:00Z", "actor": "claude-work"},
            {"stored_at": "2026-07-01T01:00:00Z", "actor": "codex-work"},
            {"stored_at": "2026-07-01T02:00:00Z"},
            {"stored_at": "2026-06-01T00:00:00Z", "actor": "codex-work"},
        ]

        summary = module.summarize(
            aggregate,
            facts,
            since="2026-07-01T00:00:00Z",
            until="2026-07-02T00:00:00Z",
        )

        self.assertEqual(summary["observations"]["provider_counts"]["claude-code"], 1)
        self.assertEqual(summary["observations"]["provider_vendor_family_counts"]["anthropic"], 2)
        self.assertEqual(summary["observations"]["provider_vendor_family_counts"]["openai"], 1)
        self.assertEqual(summary["facts"]["actor_counts"]["claude-work"], 1)
        self.assertEqual(summary["facts"]["actor_counts"]["codex-work"], 1)
        self.assertEqual(summary["facts"]["missing_actor"], 1)
        self.assertTrue(summary["proxy_cross_vendor_activity"])
        self.assertEqual(summary["known_vendor_families"], ["anthropic", "openai"])
        self.assertIn("truncated", summary["warnings"][0])

    def test_anthropic_only_is_not_cross_vendor_activity(self) -> None:
        summary = module.summarize(
            {
                "matched": 2,
                "returned": 2,
                "observations": [
                    {"ts": "2026-07-01T00:00:00Z", "provider": "claude-code"},
                    {"ts": "2026-07-01T01:00:00Z", "provider": "anthropic"},
                ],
            },
            [{"stored_at": "2026-07-01T00:00:00Z", "actor": "claude-work"}],
            since="2026-07-01T00:00:00Z",
            until="2026-07-02T00:00:00Z",
        )

        self.assertFalse(summary["proxy_cross_vendor_activity"])
        self.assertEqual(summary["known_vendor_families"], ["anthropic"])

    def test_data_dir_scan_counts_exact_providers_without_payload_leak(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            observations = pathlib.Path(tmp) / "observations"
            observations.mkdir()
            records = [
                {
                    "ts": "2026-07-01T00:00:00Z",
                    "provider": "claude-code",
                    "principal": "claude-work",
                    "payload": "SECRET_DO_NOT_PRINT",
                },
                {
                    "ts": "2026-07-01T01:00:00Z",
                    "provider": "openai",
                    "principal": "codex-work",
                    "payload": "SECRET_DO_NOT_PRINT",
                },
                {
                    "ts": "2026-06-01T01:00:00Z",
                    "provider": "openai",
                    "principal": "codex-work",
                },
            ]
            with (observations / "session.jsonl").open("w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record) + "\n")
                handle.write("{not-json\n")

            aggregate, provider_counts, principal_counts = module.count_observation_jsonl(
                tmp,
                "2026-07-01T00:00:00Z",
                "2026-07-02T00:00:00Z",
            )

        self.assertEqual(aggregate["matched"], 2)
        self.assertEqual(aggregate["malformed_lines"], 1)
        self.assertEqual(provider_counts, {"claude-code": 1, "openai": 1})
        self.assertEqual(principal_counts, {"claude-work": 1, "codex-work": 1})
        rendered = json.dumps({"aggregate": aggregate, "providers": provider_counts, "principals": principal_counts})
        self.assertNotIn("SECRET_DO_NOT_PRINT", rendered)


if __name__ == "__main__":
    unittest.main()
