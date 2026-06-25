// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
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

    let (n_control, n_treatment, report) = match crate::holdout::accumulator().lock() {
        Ok(acc) => acc.report(),
        Err(_) => {
            return Ok(json!({ "content": [{ "type": "text", "text": "token_savings: accumulator unavailable" }] }))
        }
    };

    let summary = if n_control == 0 || n_treatment == 0 {
        format!(
            "token_savings: holdout fraction {:.3}, but not enough samples yet (control={n_control}, treatment={n_treatment})",
            fraction
        )
    } else {
        format!(
            "token_savings: {:.1}% (95% CI {:.1}–{:.1}%) · control={n_control} reqs/{} tok · treatment={n_treatment} reqs/{} tok · holdout={:.3}",
            report.reduction * 100.0,
            report.ci_low * 100.0,
            report.ci_high * 100.0,
            report.control_tokens,
            report.treatment_tokens,
            fraction,
        )
    };

    Ok(json!({
        "content": [{ "type": "text", "text": summary }],
        "holdout_enabled": true,
        "holdout_fraction": fraction,
        "n_control": n_control,
        "n_treatment": n_treatment,
        "reduction_pct": report.reduction * 100.0,
        "ci95_low_pct": report.ci_low * 100.0,
        "ci95_high_pct": report.ci_high * 100.0,
        "control_tokens": report.control_tokens,
        "treatment_tokens": report.treatment_tokens,
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
        let res = handle_token_savings(&json!({}), &ctx()).await.unwrap();
        assert_eq!(res["holdout_enabled"], true);
        assert_eq!(res["n_control"], 4);
        assert!((res["reduction_pct"].as_f64().unwrap() - 25.0).abs() < 1.0);
        crate::holdout::accumulator().lock().unwrap().clear_for_test();
        std::env::remove_var(crate::holdout::HOLDOUT_ENV);
    }
}
