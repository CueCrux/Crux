// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Feature Registry analytics — port of PlanCrux's `/capabilities/analysis/*`
//! handlers (`gaps`, `promises`, `coverage`) onto the substrate.
//!
//! Pure functions over a slice of capability payloads (`serde_json::Value`).
//! Reading from the substrate is the caller's job — these fns are
//! storage-agnostic so they can be tested without spinning up a daemon.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

const MANIFESTO_PROMISES: &[(u64, &str)] = &[
    (1, "Every answer traceable to sources"),
    (2, "Memory cannot rot"),
    (3, "Enterprise retrieval unsolved — we solve it"),
    (4, "Execution accuracy compounds"),
    (5, "Intelligence × Context is multiplicative"),
    (6, "Agents deserve better tools"),
    (7, "Provenance is non-negotiable"),
    (8, "Economy rewards contribution"),
    (9, "Security by design, not afterthought"),
    (10, "Open audit, closed attack surface"),
];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Gap {
    pub id: String,
    pub system: String,
    pub r#type: String,
    pub severity: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GapsSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct GapsReport {
    pub gaps: Vec<Gap>,
    pub count: usize,
    pub summary: GapsSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromiseEntry {
    pub promise: u64,
    pub label: String,
    pub total: usize,
    pub shipped: usize,
    pub built: usize,
    pub building: usize,
    pub planned: usize,
    pub tested: usize,
    pub audited: usize,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PromiseCoverage {
    pub coverage: Vec<PromiseEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageReport {
    pub total_capabilities: usize,
    pub total_tested: usize,
    pub total_audited: usize,
    pub maturity: BTreeMap<String, usize>,
    pub systems: BTreeMap<String, SystemCoverage>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SystemCoverage {
    pub total: usize,
    pub tested: usize,
    pub audited: usize,
    pub shipped: usize,
}

fn payload_str<'a>(p: &'a Value, key: &str) -> Option<&'a str> {
    p.get(key).and_then(|v| v.as_str())
}

fn tests_count(p: &Value, kind: &str) -> usize {
    p.get("tests")
        .and_then(|t| t.get(kind))
        .and_then(|v| v.as_array())
        .map_or(0, std::vec::Vec::len)
}

fn has_any_tests(p: &Value) -> bool {
    tests_count(p, "unit") + tests_count(p, "integration") + tests_count(p, "e2e") > 0
}

fn dod_len(p: &Value) -> usize {
    p.get("dod").and_then(|v| v.as_array()).map_or(0, std::vec::Vec::len)
}

fn audit_status(p: &Value) -> &str {
    p.get("audit")
        .and_then(|a| a.get("status"))
        .and_then(|s| s.as_str())
        .unwrap_or("gap")
}

fn promise_alignment(p: &Value) -> Vec<u64> {
    p.get("promise_alignment")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
        .unwrap_or_default()
}

/// Mirror of the PlanCrux `/capabilities/analysis/gaps` handler.
pub fn compute_gaps(capabilities: &[Value]) -> GapsReport {
    let mut gaps = Vec::new();
    for cap in capabilities {
        let id = payload_str(cap, "id").unwrap_or("").to_string();
        let system = payload_str(cap, "system").unwrap_or("").to_string();
        let maturity = payload_str(cap, "maturity").unwrap_or("planned");
        let has_unit = tests_count(cap, "unit") > 0;
        let has_integration = tests_count(cap, "integration") > 0;
        let has_any = has_any_tests(cap);
        let audit = audit_status(cap);

        if !has_any {
            gaps.push(Gap {
                id: id.clone(),
                system: system.clone(),
                r#type: "no_tests".into(),
                severity: if maturity == "shipped" { "critical" } else { "high" }.into(),
                detail: format!("No tests for {maturity} capability"),
            });
        } else if !has_unit {
            gaps.push(Gap {
                id: id.clone(),
                system: system.clone(),
                r#type: "no_unit_tests".into(),
                severity: "medium".into(),
                detail: "Missing unit tests".into(),
            });
        } else if !has_integration && maturity == "shipped" {
            gaps.push(Gap {
                id: id.clone(),
                system: system.clone(),
                r#type: "no_integration_tests".into(),
                severity: "high".into(),
                detail: "Shipped capability missing integration tests".into(),
            });
        }

        if audit == "gap" {
            let detail = cap
                .get("audit")
                .and_then(|a| a.get("notes"))
                .and_then(|n| n.as_str())
                .unwrap_or("Not yet audited")
                .to_string();
            gaps.push(Gap {
                id: id.clone(),
                system: system.clone(),
                r#type: "audit_gap".into(),
                severity: if maturity == "shipped" { "critical" } else { "high" }.into(),
                detail,
            });
        }

        if dod_len(cap) == 0 {
            gaps.push(Gap {
                id,
                system,
                r#type: "no_dod".into(),
                severity: "high".into(),
                detail: "No Definition of Done assertions".into(),
            });
        }
    }

    let sev_rank = |s: &str| match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 9,
    };
    gaps.sort_by_key(|g| sev_rank(&g.severity));

    let mut summary = GapsSummary {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };
    for g in &gaps {
        match g.severity.as_str() {
            "critical" => summary.critical += 1,
            "high" => summary.high += 1,
            "medium" => summary.medium += 1,
            "low" => summary.low += 1,
            _ => {}
        }
    }
    let count = gaps.len();
    GapsReport { gaps, count, summary }
}

/// Mirror of the PlanCrux `/capabilities/analysis/promises` handler.
pub fn compute_promise_coverage(capabilities: &[Value]) -> PromiseCoverage {
    let mut coverage = Vec::new();
    for (p, label) in MANIFESTO_PROMISES {
        let p = *p;
        let aligned: Vec<&Value> = capabilities
            .iter()
            .filter(|c| promise_alignment(c).contains(&p))
            .collect();
        let tested = aligned.iter().filter(|c| has_any_tests(c)).count();
        let audited = aligned.iter().filter(|c| audit_status(c) == "audited").count();
        let mut shipped = 0;
        let mut built = 0;
        let mut building = 0;
        let mut planned = 0;
        for c in &aligned {
            match payload_str(c, "maturity").unwrap_or("planned") {
                "shipped" => shipped += 1,
                "built" => built += 1,
                "building" => building += 1,
                "planned" => planned += 1,
                _ => {}
            }
        }
        coverage.push(PromiseEntry {
            promise: p,
            label: (*label).into(),
            total: aligned.len(),
            shipped,
            built,
            building,
            planned,
            tested,
            audited,
            capabilities: aligned
                .iter()
                .filter_map(|c| payload_str(c, "id").map(String::from))
                .collect(),
        });
    }
    PromiseCoverage { coverage }
}

/// Mirror of the PlanCrux `/capabilities/analysis/coverage` handler.
pub fn compute_coverage_report(capabilities: &[Value]) -> CoverageReport {
    let mut systems: BTreeMap<String, SystemCoverage> = BTreeMap::new();
    let mut maturity: BTreeMap<String, usize> = BTreeMap::new();
    for c in capabilities {
        let sys = payload_str(c, "system").unwrap_or("").to_string();
        let s = systems.entry(sys).or_default();
        s.total += 1;
        if has_any_tests(c) {
            s.tested += 1;
        }
        if audit_status(c) == "audited" {
            s.audited += 1;
        }
        let m = payload_str(c, "maturity").unwrap_or("planned").to_string();
        if m == "shipped" {
            s.shipped += 1;
        }
        *maturity.entry(m).or_insert(0) += 1;
    }
    CoverageReport {
        total_capabilities: capabilities.len(),
        total_tested: capabilities.iter().filter(|c| has_any_tests(c)).count(),
        total_audited: capabilities.iter().filter(|c| audit_status(c) == "audited").count(),
        maturity,
        systems,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Vec<Value> {
        vec![
            json!({
                "id":"A","name":"Alpha","system":"Crux","maturity":"shipped",
                "tests":{"unit":["a.rs"],"integration":[]},
                "audit":{"status":"audited"},
                "dod":["compiles"],
                "promise_alignment":[1,2]
            }),
            json!({
                "id":"B","name":"Beta","system":"Crux","maturity":"shipped",
                "tests":{},
                "audit":{"status":"gap"},
                "dod":[],
                "promise_alignment":[1]
            }),
            json!({
                "id":"C","name":"Gamma","system":"Engine","maturity":"built",
                "tests":{"unit":["c.rs"],"integration":["ci.rs"]},
                "audit":{"status":"audited"},
                "dod":["compiles","linted"],
                "promise_alignment":[2]
            }),
        ]
    }

    #[test]
    fn gaps_identifies_critical_no_tests_for_shipped() {
        let r = compute_gaps(&sample());
        let crit: Vec<_> = r.gaps.iter().filter(|g| g.severity == "critical").collect();
        assert!(crit.iter().any(|g| g.id == "B" && g.r#type == "no_tests"));
        // B has no_dod (high) and no_tests (critical) and audit_gap (critical) — three gaps for B alone.
        assert!(r.count >= 4);
        // A is shipped with no integration tests → high.
        assert!(r
            .gaps
            .iter()
            .any(|g| g.id == "A" && g.r#type == "no_integration_tests" && g.severity == "high"));
    }

    #[test]
    fn promise_coverage_buckets_capabilities() {
        let c = compute_promise_coverage(&sample());
        let p1 = c.coverage.iter().find(|p| p.promise == 1).unwrap();
        assert_eq!(p1.total, 2); // A + B aligned to promise 1
        assert_eq!(p1.shipped, 2);
        assert_eq!(p1.tested, 1); // only A has tests
        let p2 = c.coverage.iter().find(|p| p.promise == 2).unwrap();
        assert_eq!(p2.total, 2); // A + C
                                 // No-one aligns to 3..=10.
        for p in &c.coverage {
            if p.promise >= 3 {
                assert_eq!(p.total, 0);
            }
        }
    }

    #[test]
    fn coverage_report_tallies_per_system() {
        let r = compute_coverage_report(&sample());
        assert_eq!(r.total_capabilities, 3);
        assert_eq!(r.total_tested, 2); // A, C
        assert_eq!(r.total_audited, 2);
        let crux = r.systems.get("Crux").unwrap();
        assert_eq!(crux.total, 2);
        assert_eq!(crux.shipped, 2);
        let engine = r.systems.get("Engine").unwrap();
        assert_eq!(engine.total, 1);
        assert_eq!(engine.shipped, 0);
    }
}
