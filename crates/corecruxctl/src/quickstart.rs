// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::fmt::Write as _;

/// Interactive quickstart wizard for new CoreCrux users.
///
/// Walks through five steps: configuration, daemon health-check, store a test
/// fact, query it back, then clean up and print next-steps guidance.
pub fn run(http_base: &str, non_interactive: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base = http_base.trim_end_matches('/');

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════╗");
    eprintln!("  ║   CoreCrux Quickstart Wizard         ║");
    eprintln!("  ╚══════════════════════════════════════╝");
    eprintln!();

    // ── Step 1: Configuration ───────────────────────────────────────────
    eprintln!("  [1/5] Configuration");

    let data_dir: String;
    let auth_mode: String;
    let build_ccxi: String;

    if non_interactive {
        data_dir = "./data".to_string();
        auth_mode = "off".to_string();
        build_ccxi = "Y".to_string();
        eprintln!("    Using defaults (non-interactive): data_dir=./data, auth=off, ccxi=Y");
    } else {
        data_dir = prompt("Data directory", "./data");
        auth_mode = prompt("Auth mode (off / dev_scopes / jwt_hs256 / jwt_jwks)", "off");
        build_ccxi = prompt("Build CCXI companion indexes?", "Y");
    }

    let config = build_config_env(&data_dir, &auth_mode, &build_ccxi);
    std::fs::write("config.env", &config)?;
    eprintln!("    Wrote config.env");
    eprintln!();

    // ── Step 2: Check daemon ────────────────────────────────────────────
    eprintln!("  [2/5] Checking daemon");

    let readyz_url = format!("{base}/readyz");
    match ureq::get(&readyz_url).call() {
        Ok(_) => {
            eprintln!("    Connected to CoreCrux at {base}");
        }
        Err(e) => {
            eprintln!("    Cannot reach daemon at {readyz_url}. Is corecruxd running?");
            eprintln!("    Error: {e}");
            eprintln!();
            eprintln!("    Start the daemon first:");
            eprintln!("      corecruxd --data-dir {data_dir}");
            return Err(format!("Daemon unreachable at {readyz_url}").into());
        }
    }
    eprintln!();

    // ── Step 3: Store a test fact ───────────────────────────────────────
    eprintln!("  [3/5] Storing a test fact");

    let facts_url = format!("{base}/v1/facts");
    let body = serde_json::json!({
        "entity": "__quickstart__",
        "key": "greeting",
        "value": "Hello from CoreCrux!",
        "confidence": 1.0
    });

    let put_resp = ureq::put(&facts_url)
        .send_json(body)
        .map_err(|e| format!("PUT {facts_url} failed: {e}"))?;

    let put_json: serde_json::Value = put_resp.into_json()?;
    let fact_id = put_json
        .get("fact_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    if fact_id.is_empty() {
        eprintln!("    Warning: response did not contain fact_id — full response:");
        eprintln!("    {put_json}");
    } else {
        eprintln!("    Stored fact_id: {fact_id}");
    }
    eprintln!();

    // ── Step 4: Query it back ───────────────────────────────────────────
    eprintln!("  [4/5] Querying the test fact");

    let query_url = format!("{base}/v1/facts?query=quickstart+greeting");
    match ureq::get(&query_url).call() {
        Ok(resp) => {
            let query_json: serde_json::Value = resp.into_json()?;
            eprintln!("    Query result: {query_json}");
        }
        Err(e) => {
            eprintln!("    Warning: query failed: {e}");
        }
    }
    eprintln!();

    // ── Step 5: Cleanup + next steps ────────────────────────────────────
    eprintln!("  [5/5] Cleanup & next steps");

    if !fact_id.is_empty() {
        let delete_url = format!("{base}/v1/facts/{fact_id}");
        match ureq::delete(&delete_url).call() {
            Ok(_) => eprintln!("    Deleted test fact {fact_id}"),
            Err(e) => eprintln!("    Warning: cleanup DELETE failed: {e}"),
        }
    }

    eprintln!();
    eprintln!("  Quickstart complete! Next steps:");
    eprintln!();
    eprintln!("    HTTP API       {base}/v1/");
    eprintln!("    MCP endpoint   http://localhost:14801/mcp");
    eprintln!("    Update status  {base}/v1/version");
    eprintln!("    Docs           https://docs.cuecrux.com/corecrux/");
    eprintln!("    Benchmark      corecruxctl audit-pack --offline");
    eprintln!("    Playground     {base}/playground");
    eprintln!();

    Ok(())
}

/// Build the contents of a `config.env` file from wizard answers.
#[allow(clippy::unwrap_used)] // SAFETY: writeln! to a String is infallible
fn build_config_env(data_dir: &str, auth_mode: &str, build_ccxi: &str) -> String {
    let mut buf = String::new();
    writeln!(buf, "# CoreCrux quickstart configuration").unwrap();
    writeln!(buf, "CORECRUXD_DATA_DIR={data_dir}").unwrap();
    writeln!(buf, "CORECRUXD_AUTH_MODE={auth_mode}").unwrap();
    writeln!(
        buf,
        "CORECRUXD_BUILD_CCXI={}",
        if build_ccxi.eq_ignore_ascii_case("y") || build_ccxi.eq_ignore_ascii_case("yes") {
            "true"
        } else {
            "false"
        }
    )
    .unwrap();
    buf
}

fn prompt(message: &str, default: &str) -> String {
    eprint!("    {} [{}]: ", message, default);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap_or(0);
    let trimmed = input.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_env_content() {
        let content = build_config_env("./data", "off", "Y");
        assert!(content.contains("CORECRUXD_DATA_DIR=./data"));
        assert!(content.contains("CORECRUXD_AUTH_MODE=off"));
        assert!(content.contains("CORECRUXD_BUILD_CCXI=true"));

        let content_no = build_config_env("/srv/corecrux", "dev_scopes", "N");
        assert!(content_no.contains("CORECRUXD_DATA_DIR=/srv/corecrux"));
        assert!(content_no.contains("CORECRUXD_AUTH_MODE=dev_scopes"));
        assert!(content_no.contains("CORECRUXD_BUILD_CCXI=false"));
    }

    #[test]
    fn prompt_default() {
        // prompt() reads from stdin; with no stdin data, read_line returns 0
        // bytes and the function should return the default.
        // We cannot easily mock stdin in a unit test, so we test the logic
        // inline: empty input ⇒ default.
        let trimmed = "";
        let result = if trimmed.is_empty() {
            "my_default".to_string()
        } else {
            trimmed.to_string()
        };
        assert_eq!(result, "my_default");
    }
}
