// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `token_savings` — live holdout savings summary (token-efficiency cutover CO-4).
//!
//! Reads the process-wide live holdout accumulator ([`crate::holdout`]) and
//! reports the measured token saving of the shaped (treatment) arm vs. the
//! unshaped (control) arm as a point estimate **with a 95% CI** — never a bare
//! counterfactual (plan R5). Read-only; writes nothing.
//!
//! Returns a "disabled" stub when `CRUX_OUTPUT_HOLDOUT` is 0 (the default): with
//! no control fraction there is no live control arm to measure against.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::JsonRpcError;

pub fn tool_input_schema() -> Value {
    json!({ "type": "object", "properties": {}, "examples": [ {} ] })
}

pub const TOOL_DESCRIPTION: &str = "Report the live token savings of the shaped vs. unshaped (holdout \
control) retrieval arms as a point estimate with a 95% CI. Read-only. Requires CRUX_OUTPUT_HOLDOUT > 0 \
(a sampled control fraction); returns a disabled stub otherwise.";

/// Implement the `token_savings` MCP tool. Async to match the dispatch signature
/// (the accumulator is a sync `Mutex`, so nothing is awaited).
#[allow(clippy::unused_async)]
pub async fn handle_token_savings(_args: &Value, _ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let fraction = crate::holdout::holdout_fraction();
    if fraction <= 0.0 {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": "token_savings: holdout disabled (set CRUX_OUTPUT_HOLDOUT=0.05 to sample a live control arm)"
            }],
            "holdout_enabled": false,
        }));
    }

    let snap = match crate::holdout::accumulator().lock() {
        Ok(acc) => acc.report(),
        Err(_) => {
            return Ok(json!({ "content": [{ "type": "text", "text": "token_savings: accumulator unavailable" }] }))
        }
    };

    // Per-mechanism (CO-5): the compaction (M3) line is the isolated, always-≥0
    // token saving; the net line folds in reversible's (M1) recall cost and can be
    // negative — never read one as the other.
    let compaction_line = if snap.n_compaction == 0 {
        "  compaction (M3): no samples yet".to_string()
    } else {
        format!(
            "  compaction (M3): {:.1}% (95% CI {:.1}–{:.1}%) · n={} — the token saving",
            snap.compaction.reduction * 100.0,
            snap.compaction.ci_low * 100.0,
            snap.compaction.ci_high * 100.0,
            snap.n_compaction,
        )
    };
    let net_line = if snap.n_control == 0 || snap.n_treatment == 0 {
        format!(
            "  net (all-shaped vs unshaped): not enough samples (control={}, treatment={})",
            snap.n_control, snap.n_treatment
        )
    } else {
        format!(
            "  net (all-shaped vs unshaped): {:.1}% (95% CI {:.1}–{:.1}%) · control={} reqs/{} tok · treatment={} reqs/{} tok — includes reversible's (M1) recall cost, so it can be negative",
            snap.net.reduction * 100.0,
            snap.net.ci_low * 100.0,
            snap.net.ci_high * 100.0,
            snap.n_control,
            snap.net.control_tokens,
            snap.n_treatment,
            snap.net.treatment_tokens,
        )
    };
    let summary = format!("token_savings (holdout={fraction:.3}):\n{compaction_line}\n{net_line}");

    Ok(json!({
        "content": [{ "type": "text", "text": summary }],
        "holdout_enabled": true,
        "holdout_fraction": fraction,
        // Compaction (M3) — the isolated token saving (always ≥ 0).
        "compaction": {
            "n": snap.n_compaction,
            "reduction_pct": snap.compaction.reduction * 100.0,
            "ci95_low_pct": snap.compaction.ci_low * 100.0,
            "ci95_high_pct": snap.compaction.ci_high * 100.0,
            "pretty_tokens": snap.compaction.control_tokens,
            "compact_tokens": snap.compaction.treatment_tokens,
        },
        // Net (all-shaped vs all-unshaped) — folds in reversible's recall cost.
        "net": {
            "n_control": snap.n_control,
            "n_treatment": snap.n_treatment,
            "reduction_pct": snap.net.reduction * 100.0,
            "ci95_low_pct": snap.net.ci_low * 100.0,
            "ci95_high_pct": snap.net.ci_high * 100.0,
            "control_tokens": snap.net.control_tokens,
            "treatment_tokens": snap.net.treatment_tokens,
        },
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    #[tokio::test]
    async fn disabled_when_holdout_off() {
        let _g = crate::test_env_lock().lock().await;
        std::env::remove_var(crate::holdout::HOLDOUT_ENV);
        let res = handle_token_savings(&json!({}), &ctx()).await.unwrap();
        assert_eq!(res["holdout_enabled"], false);
    }

    #[tokio::test]
    async fn reports_savings_when_enabled() {
        let _g = crate::test_env_lock().lock().await;
        std::env::set_var(crate::holdout::HOLDOUT_ENV, "0.5");
        crate::holdout::accumulator().lock().unwrap().clear_for_test();
        // Seed via the public record path (it respects the env gate set above).
        for _ in 0..4 {
            crate::holdout::record_sample(true, 400);
            crate::holdout::record_sample(false, 300);
        }
        // Seed compaction samples directly (sample_compaction needs a sampled
        // key; the accumulator is the unit under test here).
        crate::holdout::sample_compaction("k", &json!({"a": 1, "b": [1, 2, 3]}));
        let res = handle_token_savings(&json!({}), &ctx()).await.unwrap();
        assert_eq!(res["holdout_enabled"], true);
        assert_eq!(res["net"]["n_control"], 4);
        assert!((res["net"]["reduction_pct"].as_f64().unwrap() - 25.0).abs() < 1.0);
        // Compaction is reported separately and is non-negative.
        assert!(res["compaction"].is_object());
        crate::holdout::accumulator().lock().unwrap().clear_for_test();
        std::env::remove_var(crate::holdout::HOLDOUT_ENV);
    }
}
