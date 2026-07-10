// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Dump the full Crux Daemon tool catalogue as JSON to stdout.
//!
//! Used by the surgical token-measurement test (master-plan §13 H1) to
//! feed the Crux Daemon tool schemas into Anthropic's `count_tokens` endpoint.
//!
//!     cargo run -p crux-mcp --example dump_tools_json > tools.json

use serde_json::json;

fn main() {
    let tools = crux_mcp::tools::list_tools();
    let out: Vec<_> = tools
        .into_iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&out).expect("serialise"));
}
