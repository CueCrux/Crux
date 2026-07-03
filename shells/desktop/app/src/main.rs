// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

// Hide the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Crux desktop shell — a Tauri v2 wrapper.
//!
//! Boot sequence:
//!   1. Resolve the per-user app-data dir and the bundled `corecruxd` sidecar.
//!   2. Spawn the sidecar (loopback, auth **off**, `CONSOLE_V2=1`) via the
//!      std-only `crux-shell-lifecycle` crate.
//!   3. Poll `/healthz` until the daemon is ready.
//!   4. Open the main window on `http://127.0.0.1:<port>/console`.
//!   5. On window close / app exit, shut the sidecar down (Drop is the backstop)
//!      so no orphan daemon survives the shell — the ExecPlan M6 gate.
//!
//! ## Auth posture
//!
//! The sidecar binds `127.0.0.1` with auth off, so the shell's webview *is* the
//! operator surface. The daemon is never reachable off this machine; there is no
//! network-exposed, unauthenticated endpoint. This matches the v2 console
//! posture derivation in ExecPlan `unified-shell-console-2026-07-03`.
//!
//! This binary compiles in CI only (webkit2gtk toolchain); see the crate README.

use std::path::PathBuf;
use std::sync::Mutex;

use tauri::{Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

use crux_shell_lifecycle::{spawn_sidecar, SidecarConfig, SidecarHandle};

/// The live sidecar, held in Tauri managed state so the window/exit handlers can
/// shut it down deterministically.
struct SidecarState(Mutex<Option<SidecarHandle>>);

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            match boot_sidecar(app) {
                Ok(sidecar) => {
                    let url = sidecar.console_url();
                    // Create the main window on the sidecar's console origin. The
                    // URL is only known at runtime (ephemeral port), so the window
                    // is built here rather than declared in tauri.conf.json.
                    WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url.parse()?))
                        .title("Crux")
                        .inner_size(1280.0, 860.0)
                        .min_inner_size(900.0, 600.0)
                        .build()?;
                    app.manage(SidecarState(Mutex::new(Some(sidecar))));
                    Ok(())
                }
                Err(message) => {
                    // Surface a native error dialog (with the log path baked into
                    // `message`) then quit cleanly. The sidecar has already been
                    // shut down inside boot_sidecar's failure path.
                    app.handle()
                        .dialog()
                        .message(message)
                        .title("Crux failed to start")
                        .kind(MessageDialogKind::Error)
                        .blocking_show();
                    app.handle().exit(1);
                    Ok(())
                }
            }
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { .. } = event {
                shutdown_sidecar(window.app_handle());
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to build the Crux desktop shell")
        .run(|app_handle, event| {
            if let RunEvent::ExitRequested { .. } = event {
                shutdown_sidecar(app_handle);
            }
        });
}

/// Resolve paths, spawn the sidecar, and block until it is healthy.
///
/// On any failure returns a human-readable message (including the daemon log
/// path where relevant) for the boot-failure dialog, having first ensured no
/// orphan daemon is left running.
fn boot_sidecar(app: &tauri::App) -> Result<SidecarHandle, String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve the application data directory: {e}"))?;

    let binary = resolve_sidecar_binary()
        .map_err(|e| format!("could not locate the bundled corecruxd sidecar: {e}"))?;

    // Defaults set auth=off, loopback bind, CONSOLE_V2=1 — see SidecarConfig.
    let config = SidecarConfig::new(&data_dir);

    let mut sidecar = spawn_sidecar(&binary, config)
        .map_err(|e| format!("failed to launch the corecruxd sidecar: {e}"))?;

    if let Err(e) = sidecar.wait_for_health() {
        // The error already carries the log path. Guarantee no orphan before we
        // surface the failure to the operator.
        let _ = sidecar.shutdown();
        return Err(format!(
            "The Crux local daemon did not become healthy.\n\n{e}\n\nThe shell will now exit."
        ));
    }

    Ok(sidecar)
}

/// Locate the bundled sidecar binary.
///
/// Tauri's `externalBin` copies the sidecar next to the main executable at
/// bundle time (stripping the target-triple suffix on install), so we resolve it
/// relative to the running binary.
fn resolve_sidecar_binary() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "current executable has no parent directory",
        )
    })?;
    let name = if cfg!(windows) {
        "corecruxd.exe"
    } else {
        "corecruxd"
    };
    Ok(dir.join(name))
}

/// Shut the sidecar down if it is still managed. Idempotent: the first caller
/// (window close or exit request) takes the handle; later calls no-op. Drop on
/// the handle is the final backstop.
fn shutdown_sidecar(app: &tauri::AppHandle) {
    if let Some(state) = app.try_state::<SidecarState>() {
        if let Ok(mut guard) = state.0.lock() {
            if let Some(mut sidecar) = guard.take() {
                let _ = sidecar.shutdown();
            }
        }
    }
}
