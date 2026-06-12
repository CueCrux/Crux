// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

// CLI binary — operator-facing stderr output is the UX.
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! `crux-llm-shim` — opt-in local-LLM context-injection proxy (G17).
//!
//! EXPERIMENTAL (v1). Default-OFF: requires `CRUX_LLM_SHIM=1`.
//!
//! ```text
//! CRUX_LLM_SHIM=1 crux-llm-shim \
//!     --upstream http://localhost:11434 \
//!     --listen 127.0.0.1:11435 \
//!     --bundle-file ~/.local/state/crux/context-bundle.md
//! ```
//!
//! Point an OpenAI-compatible client at `http://127.0.0.1:11435/v1` and every
//! `chat/completions` request gets the Crux context bundle prepended as the
//! first system message; mediation receipt records are minted per request and
//! per stream end-state. Everything else passes through unmodified.

use std::path::PathBuf;

use clap::Parser;
use crux_claude_hooks::llm_shim;

#[derive(Debug, Parser)]
#[command(
    name = "crux-llm-shim",
    about = "Local-LLM context-injection shim for the Crux Daemon (experimental, default-OFF).",
    version
)]
struct Cli {
    /// Upstream model server base URL. Allowlist: localhost / loopback /
    /// RFC1918 literal IPs only, plain http. Cloud upstreams are refused.
    #[arg(long)]
    upstream: String,

    /// Loopback address to listen on.
    #[arg(long, default_value = "127.0.0.1:11435")]
    listen: String,

    /// Rendered context-bundle markdown to inject (read once at startup).
    /// Mutually exclusive with --context-endpoint.
    #[arg(long, conflicts_with = "context_endpoint")]
    bundle_file: Option<PathBuf>,

    /// Local daemon context endpoint to fetch the bundle from at startup
    /// (plan A transport, e.g. http://127.0.0.1:14800/v1/context).
    #[arg(long)]
    context_endpoint: Option<String>,

    /// Session id stamped on receipt records. Default: shim-<pid>-<epoch>.
    #[arg(long)]
    session_id: Option<String>,

    /// JSONL spool for receipt records when the daemon is unreachable (or
    /// --no-daemon-receipts is set).
    #[arg(long)]
    receipts_spool: Option<PathBuf>,

    /// Disable best-effort POSTs to the daemon's /v1/mediation/receipts
    /// (records then go to the local spool only).
    #[arg(long)]
    no_daemon_receipts: bool,
}

fn default_spool() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("crux/llm-shim/receipts.jsonl")
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("crux-llm-shim: {err:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    llm_shim::ensure_enabled()?;
    let upstream = llm_shim::allowlist::validate_upstream(&cli.upstream)?;

    let bundle = match (&cli.bundle_file, &cli.context_endpoint) {
        (Some(path), _) => Some(llm_shim::bundle_from_file(path)?),
        (None, Some(url)) => Some(llm_shim::bundle_from_endpoint(url)?),
        (None, None) => {
            eprintln!(
                "crux-llm-shim: no --bundle-file / --context-endpoint — running in passthrough \
                 mode (no context injection; stream receipts still minted)"
            );
            None
        }
    };

    let session_id = cli.session_id.unwrap_or_else(|| {
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("shim-{}-{epoch}", std::process::id())
    });

    let config = llm_shim::ShimConfig {
        upstream,
        listen: cli.listen,
        bundle,
        session_id,
        receipts_spool: cli.receipts_spool.unwrap_or_else(default_spool),
        daemon_receipts: !cli.no_daemon_receipts,
    };

    eprintln!(
        "crux-llm-shim (EXPERIMENTAL): {} -> {} | bundle: {} | receipts: {}{}",
        config.listen,
        config.upstream,
        config.bundle.as_ref().map_or("none (passthrough)", |b| b.origin.as_str()),
        if config.daemon_receipts { "daemon+spool " } else { "spool-only " },
        config.receipts_spool.display()
    );

    let handle = llm_shim::serve(config)?;
    eprintln!("crux-llm-shim: listening on {}", handle.addr);
    // Run until killed; the accept loop owns the listener thread.
    loop {
        std::thread::park();
    }
}
