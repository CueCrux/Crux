#!/usr/bin/env python3
"""CRC-v1 conformance validator — the portable conformance oracle.

Validates response fixtures (or real captured responses) against
`crc-v1.schema.json` PLUS the contract invariants that JSON Schema can't fully
express. Repos that emit CRC-v1 (CoreCrux, VaultCrux, the daemon) vendor this
file + the schema and run it in CI against representative responses.

Usage:
  python3 validate_crc_v1.py crc-v1.schema.json fixtures/crc-v1-*.json
  cat response.json | python3 validate_crc_v1.py crc-v1.schema.json -

Exit 0 = all valid; non-zero = at least one failure (prints each).
Uses `jsonschema` if installed; otherwise falls back to a structural subset
check so CI works without the dependency.
"""
import json
import sys


def _schema_validate(schema, doc):
    """Prefer jsonschema; fall back to a minimal structural check."""
    try:
        import jsonschema  # type: ignore
        jsonschema.validate(doc, schema)
        return []
    except ImportError:
        return _fallback_validate(doc)
    except Exception as e:  # jsonschema.ValidationError
        return [f"schema: {getattr(e, 'message', str(e))}"]


def _fallback_validate(d):
    errs = []
    if not isinstance(d, dict):
        return ["root is not an object"]
    if d.get("contract") != "crc-v1":
        errs.append("contract must be 'crc-v1'")
    if d.get("kind") not in ("search", "addressed", "fact", "session"):
        errs.append(f"kind invalid: {d.get('kind')!r}")
    if d.get("hydrate_tier") not in ("pointer", "summary", "full"):
        errs.append(f"hydrate_tier invalid: {d.get('hydrate_tier')!r}")
    return errs


def _invariants(d):
    """Contract invariants beyond raw schema (the load-bearing rules)."""
    errs = []
    kind = d.get("kind")
    tier = d.get("hydrate_tier")

    # INV-1: pointer tier returns no hydrated bodies.
    if tier == "pointer" and d.get("content"):
        errs.append("INV-1: hydrate_tier=pointer must NOT include non-empty 'content'")

    # INV-2: search must carry pointers + cost_estimate.
    if kind == "search":
        if not d.get("pointers"):
            errs.append("INV-2: kind=search requires non-empty 'pointers'")
        if not isinstance(d.get("cost_estimate"), dict):
            errs.append("INV-2: kind=search requires 'cost_estimate'")

    # INV-3: agent_decision is non-null ONLY for search.
    ad = d.get("agent_decision")
    if kind == "search" and ad is None:
        errs.append("INV-3: kind=search requires non-null 'agent_decision'")
    if kind != "search" and ad not in (None,):
        errs.append(f"INV-3: kind={kind} must have null 'agent_decision'")

    # INV-4: memory resolves (fact/session) carry freshness + a canonical slug so
    # the next turn re-addresses by key. `fact` strictly requires freshness (decay/
    # supersession is the whole point); `session` echoes the slug. `addressed`
    # (content-pointer hydration, e.g. fetch-content/query_expand) has both
    # optional — chunk bodies don't decay like facts.
    if kind == "fact":
        env = d.get("envelope") or {}
        if "freshness" not in env or env.get("freshness") is None:
            errs.append("INV-4: kind=fact requires envelope.freshness")
    if kind in ("fact", "session"):
        if not (d.get("next") or {}).get("canonical_slug"):
            errs.append(f"INV-4: kind={kind} should echo next.canonical_slug")

    # INV-5: cost_estimate, when present, has all three tiers as ints.
    ce = d.get("cost_estimate")
    if isinstance(ce, dict):
        for t in ("pointer", "summary", "full"):
            if not isinstance(ce.get(t), int):
                errs.append(f"INV-5: cost_estimate.{t} must be an integer")
    return errs


def main(argv):
    if len(argv) < 3:
        print("usage: validate_crc_v1.py <schema.json> <fixture.json|-> ...", file=sys.stderr)
        return 2
    schema = json.load(open(argv[1]))
    targets = argv[2:]
    failures = 0
    for t in targets:
        doc = json.load(sys.stdin) if t == "-" else json.load(open(t))
        errs = _schema_validate(schema, doc) + _invariants(doc)
        label = "<stdin>" if t == "-" else t
        if errs:
            failures += 1
            print(f"FAIL {label}")
            for e in errs:
                print(f"   - {e}")
        else:
            print(f"ok   {label}  (kind={doc.get('kind')} tier={doc.get('hydrate_tier')})")
    print(f"\n{len(targets) - failures}/{len(targets)} valid")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
