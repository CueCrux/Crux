#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
"""M0 buyer-fit baseline harness.

Loads the labeled baseline corpus into a running Crux daemon, runs the labeled
queries, and records latency / recall@5 / recall-per-token / stale-contradiction
handling. These numbers are the regression gate for M1-M6.

Corpus identity is fixed (buyer-fit-m0-baseline-v1). The retrieval lane exercised
is the daemon's existing keyword fact lane (GET /v1/facts with token_budget) --
NOT dense semantic (which table-stake #2 / M3 adds). Named honestly so M3's lift
is attributable.

Usage:
  CRUX_URL=http://127.0.0.1:24800 python3 run-baseline.py \
      --corpus baseline-corpus.v1.json --out baseline-metrics.v1.json
Auth: if CRUX_TOKEN is set it is sent as a bearer; against an auth=off local
daemon no token is needed.
"""
import argparse, json, os, statistics, time, urllib.request, urllib.error

def _req(method, url, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            payload = r.read()
            dt = (time.perf_counter() - t0) * 1000.0
            return r.status, json.loads(payload) if payload else {}, dt
    except urllib.error.HTTPError as e:
        dt = (time.perf_counter() - t0) * 1000.0
        return e.code, {"error": e.read().decode(errors="replace")}, dt

def put_fact(base, token, entity, key, value):
    return _req("PUT", f"{base}/v1/facts", token,
                {"entity": entity, "key": key, "value": value})

def query(base, token, q, top_k=5, token_budget=500):
    from urllib.parse import quote
    url = f"{base}/v1/facts?query={quote(q)}&top_k={top_k}&token_budget={token_budget}"
    return _req("GET", url, token)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument("--token-budget", type=int, default=500)
    args = ap.parse_args()
    base = os.environ.get("CRUX_URL", "http://127.0.0.1:24800").rstrip("/")
    token = os.environ.get("CRUX_TOKEN", "")

    corpus = json.load(open(args.corpus))
    # id -> (entity, key) for relevance resolution
    id_ek = {f["id"]: (f["entity"], f["key"]) for f in corpus["facts"]}
    pair_ek = {f"stale_contradiction:{p['entity']}": (p["entity"], p["key"], p["fresh_value"], p["stale_value"])
               for p in corpus["stale_contradiction_pairs"]}

    # --- load corpus ---
    loaded, load_fail = 0, []
    for f in corpus["facts"]:
        st, _, _ = put_fact(base, token, f["entity"], f["key"], f["value"])
        if st == 201: loaded += 1
        else: load_fail.append((f["id"], st))
    # stale/contradiction: store stale first, then fresh (same entity+key -> supersede)
    for p in corpus["stale_contradiction_pairs"]:
        put_fact(base, token, p["entity"], p["key"], p["stale_value"])
        put_fact(base, token, p["entity"], p["key"], p["fresh_value"])

    # --- run queries ---
    latencies, per_query, hits, tokens_per_q = [], [], 0, []
    sc_total, sc_pass = 0, 0
    for item in corpus["queries"]:
        st, resp, dt = query(base, token, item["q"], args.top_k, args.token_budget)
        latencies.append(dt)
        facts = resp.get("facts", []) if isinstance(resp, dict) else []
        got_ek = {(f.get("entity"), f.get("key")) for f in facts}
        got_vals = [f.get("value", "") for f in facts]
        tokens_per_q.append(resp.get("total_tokens", sum(f.get("tokens", 0) for f in facts)))
        rel = item["relevant"]
        if any(r.startswith("stale_contradiction:") for r in rel):
            sc_total += 1
            ent, key, fresh_v, stale_v = pair_ek[rel[0]]
            fresh_rank = next((i for i, v in enumerate(got_vals) if fresh_v[:40] in v), -1)
            stale_rank = next((i for i, v in enumerate(got_vals) if stale_v[:40] in v), -1)
            fresh_returned = fresh_rank >= 0
            stale_suppressed = stale_rank < 0
            # Pass criterion: fresh is present AND ranked strictly above stale
            # (or stale absent entirely). This is the achievable freshness signal
            # on the raw keyword lane, which does not suppress superseded rows.
            fresh_above_stale = fresh_returned and (stale_suppressed or fresh_rank < stale_rank)
            sc_pass += 1 if fresh_above_stale else 0
            per_query.append({"q": item["q"], "type": "stale_contradiction",
                              "fresh_returned": fresh_returned, "fresh_rank": fresh_rank,
                              "stale_rank": stale_rank, "stale_suppressed": stale_suppressed,
                              "fresh_ranked_above_stale": fresh_above_stale,
                              "latency_ms": round(dt, 1), "tokens": tokens_per_q[-1]})
        else:
            want = {id_ek[r] for r in rel}
            all_present = want.issubset(got_ek)
            hits += 1 if all_present else 0
            per_query.append({"q": item["q"], "type": "recall",
                              "want": [f"{e}/{k}" for e, k in want],
                              "recall_at_5": all_present, "latency_ms": round(dt, 1),
                              "tokens": tokens_per_q[-1]})

    recall_queries = [q for q in corpus["queries"]
                      if not any(r.startswith("stale_contradiction:") for r in q["relevant"])]
    n_recall = len(recall_queries)
    recall_at_5 = hits / n_recall if n_recall else 0.0
    mean_tokens = statistics.mean(tokens_per_q) if tokens_per_q else 0.0
    lat_sorted = sorted(latencies)
    def pct(p):
        if not lat_sorted: return 0.0
        i = min(len(lat_sorted) - 1, int(round((p / 100) * (len(lat_sorted) - 1))))
        return round(lat_sorted[i], 1)

    metrics = {
        "corpus": corpus["corpus"],
        "retrieval_lane": "keyword fact lane (GET /v1/facts, token_budget) — pre-M3, NOT dense semantic",
        "token_budget": args.token_budget,
        "top_k": args.top_k,
        "facts_loaded": loaded,
        "load_failures": load_fail,
        "latency_ms": {"p50": pct(50), "p95": pct(95), "mean": round(statistics.mean(latencies), 1) if latencies else 0.0},
        "recall_at_5": round(recall_at_5, 3),
        "recall_queries": n_recall,
        "mean_returned_tokens": round(mean_tokens, 1),
        "recall_per_1k_tokens": round((recall_at_5 / mean_tokens * 1000) if mean_tokens else 0.0, 3),
        "fresh_ranked_above_stale": round(sc_pass / sc_total, 3) if sc_total else None,
        "fresh_ranked_above_stale_cases": f"{sc_pass}/{sc_total}",
        "note_superseded_suppression": "the raw keyword GET /v1/facts lane returns superseded rows alongside fresh ones (fresh ranks first but stale is not suppressed). The MCP query_facts tool hides superseded by default; this HTTP lane does not. Baseline signal for M1/M2/M3.",
        "capture_reliability": "N/A at M0 — auto-extraction does not exist yet (M1 build); this is the zero point",
        "per_query": per_query,
    }
    json.dump(metrics, open(args.out, "w"), indent=2)
    print(json.dumps({k: v for k, v in metrics.items() if k != "per_query"}, indent=2))

if __name__ == "__main__":
    main()
