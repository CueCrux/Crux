#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
"""Read-only S1 proxy count over observations providers and fact actors."""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any


SCHEMA = "crux.s1_cross_vendor_proxy_count.v1"
CORPUS = "CueCrux internal daemon observations and fact export"
CAVEAT = (
    "Proxy over provider-tagged observations and fact actor passports; "
    "it measures cross-vendor activity, not faithful handoff edges."
)
DEFAULT_PROVIDERS = ",".join(
    [
        "claude-code",
        "anthropic",
        "openai",
        "openclaw",
        "codex-cli",
        "crux-mcp",
        "crux-usage-receipts",
        "crux-gateway",
        "crux-context-surface",
        "corecruxd",
        "openai-shim",
        "llm_shim",
        "llm-shim",
    ]
)


def rfc3339_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_since(days: int) -> str:
    value = datetime.now(timezone.utc) - timedelta(days=days)
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_rfc3339(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def in_window(record: dict[str, Any], field: str, since: str, until: str) -> bool:
    raw = record.get(field)
    if not raw:
        return False
    try:
        ts = parse_rfc3339(str(raw))
    except ValueError:
        return False
    return parse_rfc3339(since) <= ts <= parse_rfc3339(until)


def vendor_family(label: str | None) -> str:
    normalized = (label or "").strip().lower()
    if not normalized:
        return "unknown"
    if "claude" in normalized or "anthropic" in normalized:
        return "anthropic"
    if "codex" in normalized or "openai" in normalized:
        return "openai"
    if "openclaw" in normalized:
        return "openclaw"
    return "unknown"


def count_field(records: list[dict[str, Any]], field: str, missing_label: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for record in records:
        value = record.get(field)
        label = str(value).strip() if value is not None else ""
        counts[label or missing_label] += 1
    return counts


def count_observation_jsonl(data_dir: str, since: str, until: str) -> tuple[dict[str, Any], dict[str, int], dict[str, int]]:
    root = os.path.join(data_dir, "observations") if os.path.isdir(os.path.join(data_dir, "observations")) else data_dir
    paths = sorted(glob.glob(os.path.join(root, "**", "*.jsonl"), recursive=True))
    provider_counts: Counter[str] = Counter()
    principal_counts: Counter[str] = Counter()
    malformed_lines = 0
    counted = 0
    for path in paths:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    malformed_lines += 1
                    continue
                if not isinstance(record, dict) or not in_window(record, "ts", since, until):
                    continue
                counted += 1
                provider = str(record.get("provider") or "").strip() or "(missing)"
                principal = str(record.get("principal") or "").strip() or "(missing)"
                provider_counts[provider] += 1
                principal_counts[principal] += 1
    aggregate = {
        "matched": counted,
        "returned": counted,
        "observations": [],
        "data_dir_files": len(paths),
        "malformed_lines": malformed_lines,
    }
    return aggregate, sorted_counts(provider_counts), sorted_counts(principal_counts)


def family_counts(counts: Counter[str]) -> Counter[str]:
    families: Counter[str] = Counter()
    for label, count in counts.items():
        families[vendor_family(label)] += count
    return families


def sorted_counts(counts: Counter[str]) -> dict[str, int]:
    return {key: counts[key] for key in sorted(counts)}


def response_count_map(payload: dict[str, Any], key: str) -> dict[str, int] | None:
    raw = payload.get(key)
    if not isinstance(raw, dict):
        return None
    counts: dict[str, int] = {}
    for label, value in raw.items():
        try:
            count = int(value)
        except (TypeError, ValueError):
            continue
        if count > 0:
            counts[str(label)] = count
    return {label: counts[label] for label in sorted(counts)}


def proxy_conclusion(
    provider_family_counts: Counter[str],
    actor_family_counts: Counter[str],
    known_families: list[str],
) -> str:
    if len(known_families) > 1:
        if len([family for family in provider_family_counts if family != "unknown"]) > 1:
            return "non_claude_provider_observed"
        if len([family for family in actor_family_counts if family != "unknown"]) > 1:
            return "non_claude_fact_actor_observed"
        return "mixed_proxy_sources_observed"
    if known_families == ["anthropic"]:
        return "no_non_claude_provider_or_actor_observed"
    if not known_families:
        return "no_known_vendor_activity_observed"
    return "single_vendor_activity_observed"


def summarize(
    aggregate: dict[str, Any],
    facts: list[dict[str, Any]],
    *,
    since: str,
    until: str,
    provider_breakdown: dict[str, int] | None = None,
    principal_breakdown: dict[str, int] | None = None,
    provider_probe_warnings: list[str] | None = None,
    observation_mode: str = "http",
) -> dict[str, Any]:
    observations = [
        record
        for record in aggregate.get("observations", [])
        if isinstance(record, dict) and in_window(record, "ts", since, until)
    ]
    facts_in_window = [record for record in facts if in_window(record, "stored_at", since, until)]

    provider_counts = Counter(provider_breakdown) if provider_breakdown is not None else count_field(observations, "provider", "(missing)")
    actor_counts = count_field(
        [record for record in facts_in_window if record.get("actor")],
        "actor",
        "(missing)",
    )
    actor_missing = sum(1 for record in facts_in_window if not record.get("actor"))

    provider_family_counts = family_counts(provider_counts)
    actor_family_counts = family_counts(actor_counts)
    known_families = sorted(
        family
        for family in set(provider_family_counts) | set(actor_family_counts)
        if family != "unknown"
    )

    warnings: list[str] = list(provider_probe_warnings or [])
    matched = int(aggregate.get("matched", len(observations)) or 0)
    returned = int(aggregate.get("returned", len(observations)) or 0)
    if matched > returned:
        warnings.append(
            "observations aggregate was truncated "
            f"(matched={matched}, returned={returned}); use a narrower window if full coverage is required"
        )

    source = {
        "mode": observation_mode,
        "fact_actor_endpoint": "/v1/facts/export",
    }
    if observation_mode == "data_dir":
        source["observation_files"] = "observations/*.jsonl"
    else:
        source["observation_endpoint"] = "/v1/observations/aggregate"

    return {
        "schema": SCHEMA,
        "corpus": CORPUS,
        "source": source,
        "window": {"since": since, "until": until},
        "observations": {
            "matched": matched,
            "returned": returned,
            "sample_counted_in_window": len(observations),
            "provider_counts": sorted_counts(provider_counts),
            "provider_vendor_family_counts": sorted_counts(provider_family_counts),
            "principal_counts": principal_breakdown or {},
        },
        "facts": {
            "counted_in_window": len(facts_in_window),
            "actor_counts": sorted_counts(actor_counts),
            "actor_vendor_family_counts": sorted_counts(actor_family_counts),
            "missing_actor": actor_missing,
        },
        "known_vendor_families": known_families,
        "proxy_cross_vendor_activity": len(known_families) > 1,
        "proxy_conclusion": proxy_conclusion(provider_family_counts, actor_family_counts, known_families),
        "warnings": warnings,
        "caveat": CAVEAT,
    }


def api_get_json(base_url: str, path: str, params: dict[str, Any], headers: dict[str, str], timeout: float) -> dict[str, Any]:
    query = urllib.parse.urlencode({key: value for key, value in params.items() if value is not None})
    url = f"{base_url.rstrip('/')}{path}"
    if query:
        url = f"{url}?{query}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"GET {path} failed with HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GET {path} failed: {exc.reason}") from exc


def auth_headers(args: argparse.Namespace) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "X-Corecrux-Scopes": "query:read,admin:read",
    }
    token = os.environ.get("CRUX_AGENT_TOKEN") or os.environ.get("CORECRUXD_ADMIN_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    passport = args.passport
    if passport:
        headers["X-Corecrux-Passport-Id"] = passport
    return headers


def fetch_fact_export(args: argparse.Namespace, headers: dict[str, str]) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        payload = api_get_json(
            args.base_url,
            "/v1/facts/export",
            {"since": args.since, "cursor": cursor, "limit": args.fact_page_limit},
            headers,
            args.timeout,
        )
        page = payload.get("facts", [])
        facts.extend(record for record in page if isinstance(record, dict))
        if not payload.get("has_more"):
            return facts
        cursor = payload.get("next_cursor")
        if not cursor:
            raise RuntimeError("facts export reported has_more=true without next_cursor")


def provider_probe_list(args: argparse.Namespace, aggregate: dict[str, Any]) -> list[str]:
    providers = {value.strip() for value in args.providers.split(",") if value.strip()}
    for record in aggregate.get("observations", []):
        if isinstance(record, dict) and record.get("provider"):
            providers.add(str(record["provider"]))
    return sorted(providers)


def fetch_provider_breakdown(
    args: argparse.Namespace,
    headers: dict[str, str],
    aggregate: dict[str, Any],
) -> tuple[dict[str, int], list[str]]:
    warnings: list[str] = []
    counts: dict[str, int] = {}
    total = int(aggregate.get("matched", 0) or 0)
    if args.until_was_explicit:
        warnings.append(
            "HTTP provider probes are exact for the since lower bound only; /v1/observations/aggregate has no until filter"
        )
    for provider in provider_probe_list(args, aggregate):
        payload = api_get_json(
            args.base_url,
            "/v1/observations/aggregate",
            {"since": args.since, "provider": provider, "limit": 1},
            headers,
            args.timeout,
        )
        matched = int(payload.get("matched", 0) or 0)
        if matched > 0:
            counts[provider] = matched
    probed_total = sum(counts.values())
    if total > probed_total:
        counts["(unlisted providers)"] = total - probed_total
        warnings.append(
            "provider breakdown has unlisted providers; add them with --providers after inspecting the sample feed"
        )
    elif probed_total > total:
        warnings.append(
            "provider probes exceeded the aggregate total, likely because observations changed during the run"
        )
    return counts, warnings


def fetch_inputs(args: argparse.Namespace) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int], dict[str, int], list[str], str]:
    headers = auth_headers(args)
    if args.data_dir:
        aggregate, provider_breakdown, principal_breakdown = count_observation_jsonl(args.data_dir, args.since, args.until)
        provider_warnings = []
        observation_mode = "data_dir"
    else:
        aggregate = api_get_json(
            args.base_url,
            "/v1/observations/aggregate",
            {"since": args.since, "limit": args.observation_limit},
            headers,
            args.timeout,
        )
        provider_breakdown = response_count_map(aggregate, "provider_counts")
        principal_breakdown = response_count_map(aggregate, "principal_counts") or {}
        provider_warnings = []
        if provider_breakdown is None:
            provider_breakdown, provider_warnings = fetch_provider_breakdown(args, headers, aggregate)
        elif args.until_was_explicit:
            provider_warnings.append(
                "HTTP provider counts are exact for the since lower bound only; /v1/observations/aggregate has no until filter"
            )
        observation_mode = "http"
    facts = fetch_fact_export(args, headers)
    return aggregate, facts, provider_breakdown, principal_breakdown, provider_warnings, observation_mode


def render_human(summary: dict[str, Any]) -> str:
    lines = [
        "S1 cross-vendor proxy count",
        f"window: {summary['window']['since']} .. {summary['window']['until']}",
        (
            "observations: "
            f"matched={summary['observations']['matched']} "
            f"returned={summary['observations']['returned']} "
            f"sample_counted_in_window={summary['observations']['sample_counted_in_window']}"
        ),
        "provider_counts:",
    ]
    provider_counts = summary["observations"]["provider_counts"]
    lines.extend(f"  {key}: {value}" for key, value in provider_counts.items())
    if not provider_counts:
        lines.append("  (none)")
    lines.append("fact_actor_counts:")
    actor_counts = summary["facts"]["actor_counts"]
    lines.extend(f"  {key}: {value}" for key, value in actor_counts.items())
    if not actor_counts:
        lines.append("  (none)")
    lines.append(f"fact_missing_actor: {summary['facts']['missing_actor']}")
    lines.append(
        "provider_vendor_families: "
        + json.dumps(summary["observations"]["provider_vendor_family_counts"], sort_keys=True)
    )
    if summary["observations"]["principal_counts"]:
        lines.append("observation_principals: " + json.dumps(summary["observations"]["principal_counts"], sort_keys=True))
    lines.append(
        "actor_vendor_families: "
        + json.dumps(summary["facts"]["actor_vendor_family_counts"], sort_keys=True)
    )
    known_families = ", ".join(summary["known_vendor_families"]) or "(none)"
    lines.append("known_vendor_families: " + known_families)
    lines.append(f"proxy_cross_vendor_activity: {str(summary['proxy_cross_vendor_activity']).lower()}")
    lines.append(f"proxy_conclusion: {summary['proxy_conclusion']}")
    if summary["warnings"]:
        lines.append("warnings:")
        lines.extend(f"  {warning}" for warning in summary["warnings"])
    lines.append(f"caveat: {summary['caveat']}")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.environ.get("CRUX_HTTP_URL", "http://127.0.0.1:14800"))
    parser.add_argument(
        "--data-dir",
        default="",
        help="optional daemon data dir or observations dir for exact read-only JSONL provider counts",
    )
    parser.add_argument("--window-days", type=int, default=14, help="default lookback window when --since is omitted")
    parser.add_argument("--since", default="", help="inclusive RFC3339 lower bound; default is now minus --window-days")
    parser.add_argument("--until", default="", help="inclusive RFC3339 upper bound for local counting; default is now")
    parser.add_argument("--observation-limit", type=int, default=10000)
    parser.add_argument("--fact-page-limit", type=int, default=10000)
    parser.add_argument(
        "--providers",
        default=os.environ.get("CRUX_S1_PROVIDERS", DEFAULT_PROVIDERS),
        help="comma-separated provider names to probe for full matched counts",
    )
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--passport", default="", help="Optional X-Corecrux-Passport-Id header")
    parser.add_argument("--json", action="store_true", help="emit JSON; this is the default")
    parser.add_argument("--human", action="store_true", help="emit a one-screen human summary")
    parser.add_argument("--self-test", action="store_true", help="run fixture tests without contacting a daemon")
    args = parser.parse_args(argv)
    args.until_was_explicit = bool(args.until)
    if not args.until:
        args.until = rfc3339_now()
    if not args.since:
        args.since = default_since(args.window_days)
    return args


def run_self_test() -> None:
    aggregate = {
        "matched": 4,
        "returned": 3,
        "observations": [
            {"ts": "2026-07-01T00:00:00Z", "provider": "claude-code", "value": "SECRET_DO_NOT_PRINT"},
            {"ts": "2026-07-01T01:00:00Z", "provider": "anthropic"},
            {"ts": "2026-07-01T02:00:00Z", "provider": "openai"},
            {"ts": "2026-06-01T00:00:00Z", "provider": "openai"},
        ],
    }
    facts = [
        {"stored_at": "2026-07-01T00:00:00Z", "actor": "claude-work", "value": "SECRET_DO_NOT_PRINT"},
        {"stored_at": "2026-07-01T01:00:00Z", "actor": "codex-work"},
        {"stored_at": "2026-07-01T02:00:00Z"},
    ]
    summary = summarize(
        aggregate,
        facts,
        since="2026-07-01T00:00:00Z",
        until="2026-07-02T00:00:00Z",
    )
    assert summary["schema"] == SCHEMA
    assert summary["observations"]["provider_vendor_family_counts"] == {"anthropic": 2, "openai": 1}
    assert summary["facts"]["actor_vendor_family_counts"] == {"anthropic": 1, "openai": 1}
    assert summary["proxy_cross_vendor_activity"] is True
    assert summary["proxy_conclusion"] == "non_claude_provider_observed"
    rendered = json.dumps(summary, sort_keys=True) + "\n" + render_human(summary)
    assert "SECRET_DO_NOT_PRINT" not in rendered


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            run_self_test()
            print("self-test OK")
            return 0
        parse_rfc3339(args.since)
        parse_rfc3339(args.until)
        aggregate, facts, provider_breakdown, principal_breakdown, provider_warnings, observation_mode = fetch_inputs(args)
        summary = summarize(
            aggregate,
            facts,
            since=args.since,
            until=args.until,
            provider_breakdown=provider_breakdown,
            principal_breakdown=principal_breakdown,
            provider_probe_warnings=provider_warnings,
            observation_mode=observation_mode,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.human:
        print(render_human(summary))
    else:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
