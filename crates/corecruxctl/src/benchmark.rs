// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! CruxScore Lite benchmark harness.
//!
//! Ingests a labelled corpus, runs queries, measures 7 metrics, and optionally
//! uploads results to scorecrux.com.

use std::time::Instant;

use serde::{Deserialize, Serialize};

// ── Corpus types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Document {
    doc_id: String,
    #[allow(dead_code)]
    domain: String,
    title: String,
    content: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code, clippy::struct_field_names)] // Fields deserialized from benchmark JSON; names match the schema.
struct Query {
    query_id: String,
    query: String,
    expected_doc_ids: Vec<String>,
    domain: String,
    difficulty: String,
}

// ── Score types ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CruxScoreLite {
    pub version: String,
    pub coverage_score: f32,
    pub recall_at_5: f32,
    pub mrr: f32,
    pub fact_recall: f32,
    pub version_chain_depth: f32,
    pub query_latency_p50_ms: f64,
    pub query_latency_p95_ms: f64,
    pub corpus_size: usize,
    pub query_count: usize,
    pub config_hash: String,
    pub crux_version: String,
    pub timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BenchmarkReport {
    suite: String,
    scores: CruxScoreLite,
    config: BenchmarkConfig,
    system: SystemInfo,
}

#[derive(Debug, Serialize, Deserialize)]
struct BenchmarkConfig {
    bm25_k1: f32,
    bm25_b: f32,
    graph_weight: f32,
    build_ccxi: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SystemInfo {
    crux_version: String,
    os: String,
    arch: String,
}

// ── Entry point ──────────────────────────────────────────────────

pub fn run(
    http_base: &str,
    suite: &str,
    upload: bool,
    output: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match suite {
        "quick" => run_quick(http_base, upload, output),
        "standard" => {
            eprintln!("Standard benchmark suite: download from scorecrux.com on first run.");
            eprintln!("Not yet available — use --suite quick for now.");
            Ok(())
        }
        other => {
            eprintln!("Unknown suite: {other}. Available: quick, standard");
            std::process::exit(1);
        }
    }
}

fn run_quick(
    http_base: &str,
    upload: bool,
    output: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check daemon is reachable
    eprintln!("\n  CruxScore Lite Benchmark (quick suite)\n");
    eprint!("  Connecting to {http_base}... ");
    match ureq::get(&format!("{http_base}/readyz")).call() {
        Ok(_) => eprintln!("connected"),
        Err(e) => {
            eprintln!("failed: {e}");
            eprintln!("  Is corecruxd running? Start it with: source config.example.env && corecruxd");
            return Err("daemon not reachable".into());
        }
    }

    // Load embedded corpus
    let docs: Vec<Document> = serde_json::from_str(include_str!("../benchmark/corpus/quick/documents.json"))?;
    let queries: Vec<Query> = serde_json::from_str(include_str!("../benchmark/corpus/quick/queries.json"))?;

    eprintln!("  Corpus: {} documents, {} queries\n", docs.len(), queries.len());

    // Step 1: Ingest documents as facts
    eprint!("  Ingesting documents... ");
    let ingest_start = Instant::now();
    for doc in &docs {
        let body = serde_json::json!({
            "entity": format!("__benchmark__::{}", doc.doc_id),
            "key": "content",
            "value": format!("{}\n\n{}", doc.title, doc.content),
            "confidence": 1.0
        });
        ureq::put(&format!("{http_base}/v1/facts"))
            .header("Content-Type", "application/json")
            .send_json(body)?;
    }
    let ingest_ms = ingest_start.elapsed().as_millis();
    eprintln!("{} docs in {}ms", docs.len(), ingest_ms);

    // Step 2: Run queries and measure
    eprint!("  Running queries... ");
    let mut latencies: Vec<f64> = Vec::new();
    let mut recall_hits = 0usize;
    let mut recall_total = 0usize;
    let mut mrr_sum = 0.0f64;
    let mut coverage_sum = 0.0f32;

    for q in &queries {
        let start = Instant::now();
        let mut resp = ureq::get(&format!(
            "{http_base}/v1/facts?query={}&top_k=5",
            urlencoding::encode(&q.query)
        ))
        .call()?;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        latencies.push(latency_ms);

        let body: serde_json::Value = resp.body_mut().read_json()?;
        let facts = body["facts"].as_array().cloned().unwrap_or_default();

        // Extract doc_ids from returned facts (entity = __benchmark__::{doc_id})
        let returned_ids: Vec<String> = facts
            .iter()
            .filter_map(|f| {
                f["entity"]
                    .as_str()
                    .and_then(|e| e.strip_prefix("__benchmark__::"))
                    .map(String::from)
            })
            .collect();

        // Recall@5: fraction of expected docs found in top-5
        let hits: usize = q.expected_doc_ids.iter().filter(|id| returned_ids.contains(id)).count();
        recall_hits += hits;
        recall_total += q.expected_doc_ids.len();

        // MRR: reciprocal rank of first expected doc
        let first_rank = returned_ids
            .iter()
            .position(|id| q.expected_doc_ids.contains(id))
            .map_or(0.0, |pos| 1.0 / (pos as f64 + 1.0));
        mrr_sum += first_rank;

        // Coverage: simple term coverage
        let query_terms: Vec<&str> = q.query.split_whitespace().collect();
        let matched = query_terms
            .iter()
            .filter(|t| {
                facts.iter().any(|f| {
                    f["value"]
                        .as_str()
                        .is_some_and(|v| v.to_lowercase().contains(&t.to_lowercase()))
                })
            })
            .count();
        coverage_sum += matched as f32 / query_terms.len().max(1) as f32;
    }

    eprintln!("{} queries completed", queries.len());

    // Step 3: Fact store benchmark (store + version + recall)
    eprint!("  Fact store benchmark... ");
    let fact_test_count = 10;
    let mut fact_ids = Vec::new();
    for i in 0..fact_test_count {
        let body = serde_json::json!({
            "entity": "__benchmark__::fact_test",
            "key": format!("key_{i}"),
            "value": format!("test value {i}"),
            "confidence": 0.9
        });
        let resp: serde_json::Value = ureq::put(&format!("{http_base}/v1/facts"))
            .header("Content-Type", "application/json")
            .send_json(body)?
            .into_body()
            .read_json()?;
        if let Some(id) = resp["fact_id"].as_str() {
            fact_ids.push(id.to_string());
        }
    }
    // Update one fact to test versioning
    let body = serde_json::json!({
        "entity": "__benchmark__::fact_test",
        "key": "key_0",
        "value": "updated value 0",
        "confidence": 0.95
    });
    ureq::put(&format!("{http_base}/v1/facts"))
        .header("Content-Type", "application/json")
        .send_json(body)?;

    // Query back
    let resp: serde_json::Value = ureq::get(&format!(
        "{http_base}/v1/facts?query=test+value&entity=__benchmark__::fact_test&top_k=20"
    ))
    .call()?
    .into_body()
    .read_json()?;
    let found = resp["facts"].as_array().map_or(0, |a| a.len());
    let fact_recall = found as f32 / (fact_test_count + 1) as f32; // +1 for the update

    // Check version chain
    let history_resp: serde_json::Value = ureq::get(&format!(
        "{http_base}/v1/facts/entity/__benchmark__::fact_test/key/key_0/history"
    ))
    .call()?
    .into_body()
    .read_json()?;
    let chain_depth = history_resp["versions"].as_array().map_or(1, |a| a.len());

    eprintln!("{} facts, chain depth {}", fact_test_count, chain_depth);

    // Step 4: Compute scores
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p50 = percentile(&latencies, 0.50);
    let p95 = percentile(&latencies, 0.95);

    let scores = CruxScoreLite {
        version: "lite-1.0".to_string(),
        coverage_score: coverage_sum / queries.len().max(1) as f32,
        recall_at_5: recall_hits as f32 / recall_total.max(1) as f32,
        mrr: mrr_sum as f32 / queries.len().max(1) as f32,
        fact_recall: fact_recall.min(1.0),
        version_chain_depth: chain_depth as f32,
        query_latency_p50_ms: p50,
        query_latency_p95_ms: p95,
        corpus_size: docs.len(),
        query_count: queries.len(),
        config_hash: "default".to_string(),
        crux_version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    // Step 5: Display results
    eprintln!("\n  CruxScore Lite Results:");
    eprintln!("  ────────────────────────────────");
    eprintln!("    coverage_score:     {:.3}", scores.coverage_score);
    eprintln!("    recall@5:           {:.3}", scores.recall_at_5);
    eprintln!("    mrr:                {:.3}", scores.mrr);
    eprintln!("    fact_recall:        {:.3}", scores.fact_recall);
    eprintln!("    version_chain:      {:.1}", scores.version_chain_depth);
    eprintln!("    query_latency_p50:  {:.1}ms", scores.query_latency_p50_ms);
    eprintln!("    query_latency_p95:  {:.1}ms", scores.query_latency_p95_ms);

    // Step 6: Build report
    let report = BenchmarkReport {
        suite: "quick".to_string(),
        scores: scores.clone(),
        config: BenchmarkConfig {
            bm25_k1: 1.2,
            bm25_b: 0.75,
            graph_weight: 0.3,
            build_ccxi: true,
        },
        system: SystemInfo {
            crux_version: env!("CARGO_PKG_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        },
    };

    let json = serde_json::to_string_pretty(&report)?;

    // Save to file
    let out_path = output.unwrap_or("cruxscore-report.json");
    std::fs::write(out_path, &json)?;
    eprintln!("\n  Report saved to: {out_path}");

    // Step 7: Cleanup benchmark data
    eprint!("  Cleaning up benchmark data... ");
    let cleanup_resp: serde_json::Value = ureq::get(&format!(
        "{http_base}/v1/facts?entity=__benchmark__::fact_test&top_k=100"
    ))
    .call()?
    .into_body()
    .read_json()?;
    if let Some(facts) = cleanup_resp["facts"].as_array() {
        for f in facts {
            if let Some(id) = f["fact_id"].as_str() {
                let _ = ureq::delete(&format!("{http_base}/v1/facts/{id}")).call();
            }
        }
    }
    // Also clean up benchmark docs
    for doc in &docs {
        let entity = format!("__benchmark__::{}", doc.doc_id);
        let resp: serde_json::Value = ureq::get(&format!(
            "{http_base}/v1/facts?entity={}&top_k=10",
            urlencoding::encode(&entity)
        ))
        .call()?
        .into_body()
        .read_json()?;
        if let Some(facts) = resp["facts"].as_array() {
            for f in facts {
                if let Some(id) = f["fact_id"].as_str() {
                    let _ = ureq::delete(&format!("{http_base}/v1/facts/{id}")).call();
                }
            }
        }
    }
    eprintln!("done");

    // Step 8: Upload (optional)
    if upload {
        eprint!("\n  Uploading to scorecrux.com... ");
        match ureq::post("https://scorecrux.com/api/v1/submit")
            .header("Content-Type", "application/json")
            .send_json(serde_json::json!(report))
        {
            Ok(mut resp) => {
                let body: serde_json::Value = resp.body_mut().read_json().unwrap_or_default();
                if let Some(url) = body["url"].as_str() {
                    eprintln!("uploaded!");
                    eprintln!("  View at: {url}");
                } else {
                    eprintln!("uploaded (no URL in response)");
                }
            }
            Err(e) => {
                eprintln!("failed: {e}");
                eprintln!("  Report saved locally — upload manually later.");
            }
        }
    }

    eprintln!();
    Ok(())
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

pub fn compare(file1: &str, file2: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let r1: BenchmarkReport = serde_json::from_str(&std::fs::read_to_string(file1)?)?;
    let r2: BenchmarkReport = serde_json::from_str(&std::fs::read_to_string(file2)?)?;

    eprintln!("\n  CruxScore Lite Comparison");
    eprintln!("  ──────────────────────────────────────────────");
    eprintln!("  {:25} {:>10} {:>10} {:>10}", "Metric", "Run 1", "Run 2", "Delta");
    eprintln!("  {:25} {:>10} {:>10} {:>10}", "─────", "─────", "─────", "─────");

    let metrics = [
        ("coverage_score", r1.scores.coverage_score, r2.scores.coverage_score),
        ("recall@5", r1.scores.recall_at_5, r2.scores.recall_at_5),
        ("mrr", r1.scores.mrr, r2.scores.mrr),
        ("fact_recall", r1.scores.fact_recall, r2.scores.fact_recall),
        (
            "version_chain",
            r1.scores.version_chain_depth,
            r2.scores.version_chain_depth,
        ),
    ];

    for (name, v1, v2) in &metrics {
        let delta = v2 - v1;
        let arrow = if delta > 0.001 {
            "+"
        } else if delta < -0.001 {
            ""
        } else {
            " "
        };
        eprintln!("  {:25} {:>10.3} {:>10.3} {:>9}{:.3}", name, v1, v2, arrow, delta);
    }

    let lat_metrics = [
        (
            "query_latency_p50_ms",
            r1.scores.query_latency_p50_ms,
            r2.scores.query_latency_p50_ms,
        ),
        (
            "query_latency_p95_ms",
            r1.scores.query_latency_p95_ms,
            r2.scores.query_latency_p95_ms,
        ),
    ];

    for (name, v1, v2) in &lat_metrics {
        let delta = v2 - v1;
        let arrow = if delta > 0.1 {
            "+"
        } else if delta < -0.1 {
            ""
        } else {
            " "
        };
        eprintln!("  {:25} {:>9.1}ms {:>9.1}ms {:>8}{:.1}ms", name, v1, v2, arrow, delta);
    }

    eprintln!();
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;

    #[test]
    fn percentile_basic() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((percentile(&data, 0.5) - 3.0).abs() < 0.01);
        assert!((percentile(&data, 0.0) - 1.0).abs() < 0.01);
        assert!((percentile(&data, 1.0) - 5.0).abs() < 0.01);
    }

    #[test]
    fn percentile_empty() {
        assert!((percentile(&[], 0.5) - 0.0).abs() < 0.01);
    }

    #[test]
    fn corpus_deserializes() {
        let docs: Vec<Document> = serde_json::from_str(include_str!("../benchmark/corpus/quick/documents.json"))
            .expect("documents.json must parse");
        assert_eq!(docs.len(), 50);

        let queries: Vec<Query> = serde_json::from_str(include_str!("../benchmark/corpus/quick/queries.json"))
            .expect("queries.json must parse");
        assert_eq!(queries.len(), 20);
    }

    #[test]
    fn all_query_doc_ids_exist_in_corpus() {
        let docs: Vec<Document> =
            serde_json::from_str(include_str!("../benchmark/corpus/quick/documents.json")).unwrap();
        let queries: Vec<Query> = serde_json::from_str(include_str!("../benchmark/corpus/quick/queries.json")).unwrap();

        let doc_ids: std::collections::HashSet<&str> = docs.iter().map(|d| d.doc_id.as_str()).collect();

        for q in &queries {
            for id in &q.expected_doc_ids {
                assert!(
                    doc_ids.contains(id.as_str()),
                    "query {} references doc_id {} which doesn't exist",
                    q.query_id,
                    id
                );
            }
        }
    }

    fn serve_mock_daemon() -> (String, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock daemon");
        listener.set_nonblocking(true).expect("set mock daemon nonblocking");
        let base = format!("http://{}", listener.local_addr().expect("mock addr"));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let fact_counter = Arc::new(AtomicUsize::new(0));
        let counter_thread = Arc::clone(&fact_counter);

        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };

                let req = crate::test_support::read_full_request(&mut stream);
                let mut parts = req.lines().next().unwrap_or_default().split_whitespace();
                let method = parts.next().unwrap_or_default();
                let path = parts.next().unwrap_or_default();

                let body = match (method, path) {
                    ("GET", "/readyz") => "{}".to_string(),
                    ("PUT", "/v1/facts") => {
                        let n = counter_thread.fetch_add(1, Ordering::Relaxed);
                        format!(r#"{{"fact_id":"f_mock_{n}"}}"#)
                    }
                    ("GET", p) if p.starts_with("/v1/facts/entity/") && p.ends_with("/history") => {
                        r#"{"versions":[{"fact_id":"f_mock_0"},{"fact_id":"f_mock_1"}]}"#.to_string()
                    }
                    ("GET", p) if p.starts_with("/v1/facts?query=") => {
                        r#"{"facts":[{"fact_id":"f_doc_1","entity":"__benchmark__::doc_001","value":"rust benchmark latency policy test value"},{"fact_id":"f_doc_2","entity":"__benchmark__::doc_002","value":"storage graph session coverage"}]}"#
                            .to_string()
                    }
                    ("GET", p) if p.starts_with("/v1/facts?entity=") => r#"{"facts":[]}"#.to_string(),
                    ("DELETE", _) => "{}".to_string(),
                    _ => r#"{"facts":[]}"#.to_string(),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (base, stop, handle)
    }

    #[test]
    fn quick_benchmark_runs_against_mock_daemon_and_writes_report() {
        let (base, stop, handle) = serve_mock_daemon();
        let dir = tempfile::tempdir().expect("tempdir");
        let output = dir.path().join("cruxscore-report.json");

        run(&base, "quick", false, output.to_str()).expect("quick benchmark");

        stop.store(true, Ordering::Relaxed);
        let _ = std::net::TcpStream::connect(base.trim_start_matches("http://"));
        handle.join().expect("mock daemon thread");

        let report: BenchmarkReport =
            serde_json::from_slice(&std::fs::read(&output).expect("read benchmark report")).expect("parse report");
        assert_eq!(report.suite, "quick");
        assert_eq!(report.scores.corpus_size, 50);
        assert_eq!(report.scores.query_count, 20);
        assert!(report.scores.query_latency_p50_ms >= 0.0);
        assert_eq!(report.scores.config_hash, "default");
    }

    #[test]
    fn compare_accepts_two_report_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mk_report = |name: &str, coverage_score: f32, latency: f64| {
            let report = BenchmarkReport {
                suite: "quick".to_string(),
                scores: CruxScoreLite {
                    version: "lite-1.0".to_string(),
                    coverage_score,
                    recall_at_5: 0.5,
                    mrr: 0.25,
                    fact_recall: 1.0,
                    version_chain_depth: 2.0,
                    query_latency_p50_ms: latency,
                    query_latency_p95_ms: latency + 1.0,
                    corpus_size: 2,
                    query_count: 1,
                    config_hash: "default".to_string(),
                    crux_version: "test".to_string(),
                    timestamp: "2026-05-15T00:00:00Z".to_string(),
                },
                config: BenchmarkConfig {
                    bm25_k1: 1.2,
                    bm25_b: 0.75,
                    graph_weight: 0.3,
                    build_ccxi: true,
                },
                system: SystemInfo {
                    crux_version: "test".to_string(),
                    os: "test".to_string(),
                    arch: "test".to_string(),
                },
            };
            let path = dir.path().join(name);
            std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
            path
        };

        let one = mk_report("one.json", 0.4, 10.0);
        let two = mk_report("two.json", 0.7, 7.5);
        compare(one.to_str().unwrap(), two.to_str().unwrap()).expect("compare");
    }
}
