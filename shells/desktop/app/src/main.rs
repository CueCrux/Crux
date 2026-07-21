// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

// Hide the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]
#![deny(clippy::expect_used, clippy::unwrap_used)]

//! Native connection manager for the Crux console.
//!
//! Bundled profiles preserve the existing lifecycle supervisor: an auth-off
//! loopback sidecar is owned by the shell and stopped on switch, close, or
//! exit. Attach profiles never own the daemon. Their static agent token is
//! loaded from the OS credential store and held behind a fresh loopback proxy,
//! so configurable console content receives neither the bearer nor Tauri IPC.

mod upstream;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use crux_shell_connection::{
    authorize_local_plan_path, compute_local_plan_hashes, generation_is_current as generation_matches,
    is_public_http_link, local_plan_hashes_initialization_script, next_generation, origin_is_allowed, probe_health,
    shell_tab_for_url, shell_tab_for_window_label, Backoff, HealthReport, HealthState, NativeCredentialBroker,
    OriginKey, OriginPolicy, Profile, ProfileMode, ProfileSet, ProfileStore, ProxyControl, ProxyHandle, ProxyServer,
    RuntimeCapabilitiesSummary, ShellTab, StatusPage, Upstream,
};
use crux_shell_lifecycle::{spawn_sidecar, SidecarConfig, SidecarHandle};
use tauri::menu::{CheckMenuItem, Menu, MenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::webview::NewWindowResponse;
use tauri::{
    App, AppHandle, Manager, RunEvent, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent, Wry,
};

use upstream::UreqUpstream;

const MAIN_WINDOW: &str = "main";
const PROFILE_STORE_FILENAME: &str = "connection-profiles-v1.json";
const PROFILE_MENU_PREFIX: &str = "profile:";
const OPEN_EXTERNAL_MENU_ID: &str = "open-external-link";
const RETRY_MENU_ID: &str = "retry-active-profile";
const QUIT_MENU_ID: &str = "quit-crux";

type SharedSidecar = Arc<Mutex<SidecarHandle>>;

#[derive(Debug, Clone)]
struct StatusRecord {
    state: HealthState,
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PendingOpen {
    PublicHttp(String),
    LocalPlan(PathBuf),
}

struct WindowReplacement {
    window_label: String,
    initial_url: Url,
    origins: Arc<RwLock<OriginPolicy>>,
    local_plan_script: String,
}

struct ActivationTransition {
    old_proxy: Option<ProxyHandle>,
    old_sidecar: Option<SharedSidecar>,
    window_replacement: Option<WindowReplacement>,
}

struct ProfileMenuEntry {
    name: String,
    item: CheckMenuItem<Wry>,
}

struct TrayUpdate {
    item: CheckMenuItem<Wry>,
    text: String,
    checked: bool,
}

struct TrayParts {
    profile_menu: Vec<ProfileMenuEntry>,
    open_external_item: MenuItem<Wry>,
    tray: TrayIcon<Wry>,
}

struct RuntimeState {
    profiles: ProfileSet,
    store: ProfileStore,
    app_data_dir: PathBuf,
    generation: u64,
    statuses: BTreeMap<String, StatusRecord>,
    runtime_capabilities: BTreeMap<String, Option<RuntimeCapabilitiesSummary>>,
    profile_menu: Vec<ProfileMenuEntry>,
    open_external_item: MenuItem<Wry>,
    pending_open: Option<PendingOpen>,
    window_label: String,
    proxy: Option<ProxyHandle>,
    sidecar: Option<SharedSidecar>,
    origins: Arc<RwLock<OriginPolicy>>,
    configuration_error: Option<String>,
    _tray: TrayIcon<Wry>,
}

#[derive(Clone)]
struct ManagedState(Arc<Mutex<RuntimeState>>);

fn main() {
    let built = tauri::Builder::default()
        .setup(|app| {
            if setup_shell(app).is_err() {
                app.handle().exit(1);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { .. } = event {
                // Isolated public shell tabs are disposable child windows.
                // Closing one must not stop the daemon or exit the application.
                if shell_tab_for_window_label(window.label()).is_some() {
                    return;
                }
                shutdown_owned_resources(window.app_handle());
                window.app_handle().exit(0);
            }
        })
        .build(tauri::generate_context!());

    let Ok(application) = built else {
        std::process::exit(1);
    };
    application.run(|app, event| {
        if let RunEvent::ExitRequested { .. } = event {
            shutdown_owned_resources(app);
        }
    });
}

fn setup_shell(app: &mut App) -> Result<(), String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "could not resolve the application data directory".to_string())?;
    let store = ProfileStore::new(app_data_dir.join(PROFILE_STORE_FILENAME));
    let (profiles, configuration_error) = match load_or_create_profiles(&store) {
        Ok(profiles) => (profiles, None),
        Err(reason) => {
            let fallback = ProfileSet::new("Configuration", vec![Profile::bundled("Configuration")])
                .map_err(|_| "could not create the configuration error state".to_string())?;
            (fallback, Some(reason))
        }
    };

    let local_plan_script = active_local_plan_initialization_script(&profiles)?;
    let active_name = profiles.active_profile.clone();
    let mut statuses = BTreeMap::new();
    for profile in &profiles.profiles {
        let (state, reason) = if profile.name == active_name {
            match &configuration_error {
                Some(reason) => (HealthState::Unreachable, reason.clone()),
                None => (HealthState::Degraded, "connection check in progress".to_string()),
            }
        } else {
            (HealthState::Unreachable, "not checked in this app session".to_string())
        };
        statuses.insert(
            profile.name.clone(),
            StatusRecord {
                state,
                reason: Some(reason),
            },
        );
    }

    let server = ProxyServer::bind().map_err(|_| "could not bind the native connection status origin".to_string())?;
    let control = server.control();
    let initial_page = match &configuration_error {
        Some(reason) => StatusPage {
            status: 503,
            title: "Connection profiles are unavailable".to_string(),
            profile: active_name.clone(),
            message: format!("{reason}. Correct the profile file and restart Crux."),
            retry: None,
        },
        None => connecting_page(&active_name),
    };
    control
        .show_status(initial_page)
        .map_err(|_| "could not initialize the native connection status".to_string())?;
    let proxy = server
        .start()
        .map_err(|_| "could not start the native connection status origin".to_string())?;
    let initial_origin = proxy.origin();
    let origin_key =
        OriginKey::parse(&initial_origin).ok_or_else(|| "the native connection origin was invalid".to_string())?;
    let origins = Arc::new(RwLock::new(OriginPolicy {
        active_proxy: Some(origin_key),
        bundled_sidecar: None,
    }));

    let TrayParts {
        profile_menu,
        open_external_item,
        tray,
    } = build_tray(app, &profiles, &statuses, configuration_error.is_none())?;
    let runtime = Arc::new(Mutex::new(RuntimeState {
        profiles,
        store,
        app_data_dir,
        generation: 1,
        statuses,
        runtime_capabilities: BTreeMap::new(),
        profile_menu,
        open_external_item,
        pending_open: None,
        window_label: MAIN_WINDOW.to_string(),
        proxy: Some(proxy),
        sidecar: None,
        origins: Arc::clone(&origins),
        configuration_error,
        _tray: tray,
    }));
    if !app.manage(ManagedState(Arc::clone(&runtime))) {
        return Err("could not install the native connection state".to_string());
    }

    let initial_url = Url::parse(&format!("{initial_origin}/?generation=1"))
        .map_err(|_| "the native connection status URL was invalid".to_string())?;
    build_main_window(
        app,
        MAIN_WINDOW,
        1,
        initial_url,
        Arc::clone(&origins),
        local_plan_script,
        true,
    )?;

    let profile = {
        let guard = runtime
            .lock()
            .map_err(|_| "the native connection state is unavailable".to_string())?;
        guard
            .profiles
            .active_profile()
            .map_err(|error| error.reason().to_string())?
            .clone()
    };
    if runtime
        .lock()
        .ok()
        .is_some_and(|guard| guard.configuration_error.is_none())
    {
        launch_activation(
            app.handle().clone(),
            runtime,
            1,
            profile,
            control,
            ActivationTransition {
                old_proxy: None,
                old_sidecar: None,
                window_replacement: None,
            },
        );
    }
    Ok(())
}

fn load_or_create_profiles(store: &ProfileStore) -> Result<ProfileSet, String> {
    match store.path().try_exists() {
        Ok(true) => store.load().map_err(|error| error.reason().to_string()),
        Ok(false) => {
            let profiles = ProfileSet::new("Local", vec![Profile::bundled("Local")])
                .map_err(|error| error.reason().to_string())?;
            store.save(&profiles).map_err(|error| error.reason().to_string())?;
            Ok(profiles)
        }
        Err(_) => Err("could not inspect the connection profile store".to_string()),
    }
}

fn active_local_plan_initialization_script(profiles: &ProfileSet) -> Result<String, String> {
    let profile = profiles.active_profile().map_err(|error| error.reason().to_string())?;
    let hashes = local_plan_hashes_for_profile(profile)?;
    Ok(local_plan_hashes_initialization_script(hashes.as_ref()))
}

fn local_plan_hashes_for_profile(profile: &Profile) -> Result<Option<BTreeMap<String, String>>, String> {
    profile
        .local_plan_root
        .as_deref()
        .map(compute_local_plan_hashes)
        .transpose()
        .map_err(|_| "could not read the profile's local ExecPlan root".to_string())
}

fn build_main_window<M: Manager<Wry>>(
    app: &M,
    window_label: &str,
    window_generation: u64,
    initial_url: Url,
    origins: Arc<RwLock<OriginPolicy>>,
    local_plan_script: String,
    visible: bool,
) -> Result<WebviewWindow<Wry>, String> {
    let navigation_origins = Arc::clone(&origins);
    let new_window_origins = origins;
    let navigation_app = app.app_handle().clone();
    let new_window_app = app.app_handle().clone();
    let navigation_window_label = window_label.to_string();
    let new_window_label = navigation_window_label.clone();
    WebviewWindowBuilder::new(app, window_label, WebviewUrl::External(initial_url))
        .title("Crux")
        // Rule 0: the console uses an in-memory browser profile so a reused
        // loopback port cannot recover storage from an earlier app session.
        .incognito(true)
        .visible(visible)
        .inner_size(1280.0, 860.0)
        .min_inner_size(900.0, 600.0)
        .initialization_script(local_plan_script)
        // Rule 1: in-webview navigation is limited to the current proxy and,
        // while bundled mode is live, that one shell-owned sidecar origin.
        // An allowlisted public product origin opens in a separate zero-IPC
        // webview; a local plan or any other public target can only queue a
        // native tray approval. Page script never launches a handler.
        .on_navigation(move |url| {
            if handle_local_plan_navigation(
                &navigation_app,
                &navigation_window_label,
                window_generation,
                url,
            ) {
                false
            } else if shared_origin_is_allowed(&navigation_origins, url) {
                true
            } else if shell_tab_for_url(url.as_str()).is_some() {
                open_shell_tab(&navigation_app, window_generation, url);
                false
            } else {
                if is_public_http_link(url.as_str()) {
                    queue_external_link(&navigation_app, window_generation, url);
                }
                false
            }
        })
        // Rule 2: page-requested webviews are never accepted. Exact product-tab
        // origins are opened through the native isolated-window builder;
        // allowlisted local plans and all other public HTTP(S) targets enter the
        // one-item approval queue. Loopback and all other schemes are denied.
        .on_new_window(move |url, _features| {
            if !handle_local_plan_navigation(&new_window_app, &new_window_label, window_generation, &url)
                && !shared_origin_is_allowed(&new_window_origins, &url)
            {
                if shell_tab_for_url(url.as_str()).is_some() {
                    open_shell_tab(&new_window_app, window_generation, &url);
                } else if is_public_http_link(url.as_str()) {
                    queue_external_link(&new_window_app, window_generation, &url);
                }
            }
            NewWindowResponse::Deny
        })
        // Rule 3: downloads are denied regardless of daemon response headers.
        .on_download(|_webview, _event| false)
        .build()
        .map_err(|_| "could not build the Crux console window".to_string())
}

/// Open or focus one of the two public product tabs after re-checking the
/// active profile generation on the UI thread.
fn open_shell_tab(app: &AppHandle, window_generation: u64, target: &Url) {
    let Some(tab) = shell_tab_for_url(target.as_str()) else {
        return;
    };
    let Some(managed) = app.try_state::<ManagedState>() else {
        return;
    };
    let runtime = Arc::clone(&managed.0);
    if !runtime_generation_is_current(&runtime, window_generation) {
        return;
    }
    let target = target.clone();
    let scheduler = app.clone();
    let ui = app.clone();
    let _ = scheduler.run_on_main_thread(move || {
        if !runtime_generation_is_current(&runtime, window_generation) || !tab.allows(target.as_str()) {
            return;
        }
        if let Some(window) = ui.get_webview_window(tab.window_label()) {
            let _ = window.navigate(target);
            let _ = window.show();
            let _ = window.set_focus();
            return;
        }
        let _ = build_shell_tab_window(&ui, tab, target);
    });
}

/// Build a remote product viewport with no initialization script, no accepted
/// popups/downloads, and an exact-origin top-level navigation policy.
///
/// The app registers no invoke handler, and `capabilities/default.json` has no
/// remote URL grant or command permissions. Consequently remote page script
/// has no Tauri IPC, filesystem, keychain, updater, or lifecycle capability.
fn build_shell_tab_window(app: &AppHandle, tab: ShellTab, initial_url: Url) -> Result<WebviewWindow<Wry>, String> {
    if !tab.allows(initial_url.as_str()) {
        return Err("the public shell-tab URL was outside its allow-list".to_string());
    }
    let navigation_tab = tab;
    WebviewWindowBuilder::new(app, tab.window_label(), WebviewUrl::External(initial_url))
        .title(tab.title())
        // Product tabs share the platform webview's external-origin cookie
        // store so the eventual SSO flow can span Registry and WikiCrux. They
        // receive no daemon bearer or proxy cookie: those remain bound to the
        // main webview's distinct loopback origin and HttpOnly session.
        .incognito(false)
        .inner_size(1180.0, 820.0)
        .min_inner_size(760.0, 520.0)
        .on_navigation(move |url| navigation_tab.allows(url.as_str()))
        .on_new_window(|_url, _features| NewWindowResponse::Deny)
        .on_download(|_webview, _event| false)
        .build()
        .map_err(|_| "could not build the isolated public shell tab".to_string())
}

fn close_shell_tabs(app: &AppHandle) {
    for tab in [ShellTab::RcxRegistry, ShellTab::WikiCrux] {
        if let Some(window) = app.get_webview_window(tab.window_label()) {
            let _ = window.destroy();
        }
    }
}

fn replace_main_window(
    app: &AppHandle,
    runtime: &Arc<Mutex<RuntimeState>>,
    generation: u64,
    replacement: WindowReplacement,
) -> Result<(), String> {
    let new_label = replacement.window_label;
    let new_window = build_main_window(
        app,
        &new_label,
        generation,
        replacement.initial_url,
        replacement.origins,
        replacement.local_plan_script,
        false,
    )?;
    if !runtime_generation_is_current(runtime, generation) {
        let _ = new_window.destroy();
        return Ok(());
    }
    if new_window.show().is_err() {
        let _ = new_window.destroy();
        return Err("could not show the replacement Crux console window".to_string());
    }
    let old_label = match runtime.lock() {
        Ok(mut guard) if generation_matches(guard.generation, generation) => {
            std::mem::replace(&mut guard.window_label, new_label)
        }
        Ok(_) => {
            let _ = new_window.destroy();
            return Ok(());
        }
        Err(_) => {
            let _ = new_window.destroy();
            return Err("the native connection state is unavailable".to_string());
        }
    };
    if let Some(old_window) = app.get_webview_window(&old_label) {
        if old_window.destroy().is_err() {
            let _ = old_window.hide();
        }
    }
    Ok(())
}

fn build_tray(
    app: &App,
    profiles: &ProfileSet,
    statuses: &BTreeMap<String, StatusRecord>,
    profiles_usable: bool,
) -> Result<TrayParts, String> {
    let menu = Menu::new(app).map_err(|_| "could not create the connection tray menu".to_string())?;
    let mut entries = Vec::with_capacity(profiles.profiles.len());
    for (index, profile) in profiles.profiles.iter().enumerate() {
        let status = statuses.get(&profile.name).cloned().unwrap_or(StatusRecord {
            state: HealthState::Unreachable,
            reason: None,
        });
        let item = CheckMenuItem::with_id(
            app,
            format!("{PROFILE_MENU_PREFIX}{index}"),
            menu_label(&profile.name, &status),
            profiles_usable,
            profile.name == profiles.active_profile,
            None::<&str>,
        )
        .map_err(|_| "could not create a profile tray item".to_string())?;
        menu.append(&item)
            .map_err(|_| "could not add a profile tray item".to_string())?;
        entries.push(ProfileMenuEntry {
            name: profile.name.clone(),
            item,
        });
    }
    let open_external = MenuItem::with_id(
        app,
        OPEN_EXTERNAL_MENU_ID,
        "Open approved target — none pending",
        false,
        None::<&str>,
    )
    .map_err(|_| "could not create the external-link approval item".to_string())?;
    let retry = MenuItem::with_id(
        app,
        RETRY_MENU_ID,
        "Retry active profile",
        profiles_usable,
        None::<&str>,
    )
    .map_err(|_| "could not create the retry tray item".to_string())?;
    let quit = MenuItem::with_id(app, QUIT_MENU_ID, "Quit Crux", true, None::<&str>)
        .map_err(|_| "could not create the quit tray item".to_string())?;
    menu.append(&open_external)
        .and_then(|()| menu.append(&retry))
        .and_then(|()| menu.append(&quit))
        .map_err(|_| "could not complete the connection tray menu".to_string())?;

    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("Crux connection manager")
        .on_menu_event(|app, event| handle_tray_event(app, event.id().as_ref()));
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    let tray = builder
        .build(app)
        .map_err(|_| "could not create the Crux tray icon".to_string())?;
    Ok(TrayParts {
        profile_menu: entries,
        open_external_item: open_external,
        tray,
    })
}

fn handle_tray_event(app: &AppHandle, id: &str) {
    if id == QUIT_MENU_ID {
        shutdown_owned_resources(app);
        app.exit(0);
        return;
    }
    let Some(managed) = app.try_state::<ManagedState>() else {
        return;
    };
    let runtime = Arc::clone(&managed.0);
    if id == OPEN_EXTERNAL_MENU_ID {
        let selected = runtime.lock().ok().map(|mut guard| {
            let pending = guard.pending_open.take();
            let local_root = guard
                .profiles
                .active_profile()
                .ok()
                .and_then(|profile| profile.local_plan_root.clone());
            (pending, local_root, guard.open_external_item.clone())
        });
        if let Some((pending, local_root, item)) = selected {
            let _ = item.set_text("Open approved target — none pending");
            let _ = item.set_enabled(false);
            match pending {
                Some(PendingOpen::PublicHttp(value)) => {
                    if let Ok(target) = Url::parse(&value) {
                        open_in_system_browser(&target);
                    }
                }
                Some(PendingOpen::LocalPlan(path)) => {
                    if let Some(authorized) = local_root.and_then(|root| authorize_local_plan_path(root, path).ok()) {
                        open_local_plan_in_system_handler(&authorized);
                    }
                }
                None => {}
            }
        }
        return;
    }
    if id == RETRY_MENU_ID {
        let active = runtime
            .lock()
            .ok()
            .and_then(|guard| guard.profiles.active_profile().ok().map(|profile| profile.name.clone()));
        if let Some(active) = active {
            request_switch(app, runtime, &active);
        }
        return;
    }
    let Some(index) = id
        .strip_prefix(PROFILE_MENU_PREFIX)
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return;
    };
    let target = runtime
        .lock()
        .ok()
        .and_then(|guard| guard.profiles.profiles.get(index).map(|profile| profile.name.clone()));
    if let Some(target) = target {
        request_switch(app, runtime, &target);
    }
}

fn request_switch(app: &AppHandle, runtime: Arc<Mutex<RuntimeState>>, target: &str) {
    let snapshot = {
        let Ok(mut guard) = runtime.lock() else {
            return;
        };
        if let Some(reason) = guard.configuration_error.clone() {
            drop(guard);
            show_current_error(
                app,
                &runtime,
                "Connection profiles are unavailable",
                &format!("{reason}. Correct the profile file and restart Crux."),
            );
            return;
        }
        let Some(profile) = guard.profiles.profiles.iter().find(|profile| profile.name == target) else {
            return;
        };
        let profile = profile.clone();
        let profiles = guard.profiles.clone();
        let store = guard.store.clone();
        // Reserve the next generation before clearing browser state. Any
        // already-running worker or queued UI callback becomes stale before
        // it could repopulate host-scoped cookies during the switch.
        guard.generation = next_generation(guard.generation);
        // Quiesce the previous credential boundary in the same app-state
        // critical section as the generation change. New browser requests can
        // never observe a reserved switch with forwarding still enabled.
        if let Some(control) = guard.proxy.as_ref().map(ProxyHandle::control) {
            let switching = StatusPage {
                status: 503,
                title: "Switching Crux profile".to_string(),
                profile: profile.name.clone(),
                message: "The previous credential boundary is closed while the new profile is prepared.".to_string(),
                retry: Some("Connection work is bounded and remains visible in the tray.".to_string()),
            };
            if control.show_status(switching).is_err() {
                control.stop();
            }
        }
        guard.pending_open = None;
        (
            guard.generation,
            profiles,
            store,
            profile,
            guard.open_external_item.clone(),
        )
    };

    let (snapshot_generation, mut profiles, store, profile, external_item) = snapshot;
    // A profile boundary must not leave remote content visible under stale
    // account/tenant context. The external cookie-engine matrix remains an M9
    // operator gate, but the native lifecycle closes every product tab now.
    close_shell_tabs(app);
    let local_plan_script = match local_plan_hashes_for_profile(&profile) {
        Ok(hashes) => local_plan_hashes_initialization_script(hashes.as_ref()),
        Err(reason) => {
            show_current_error(
                app,
                &runtime,
                "Local ExecPlan root is unavailable",
                &format!("{reason}. Correct the selected profile and retry."),
            );
            return;
        }
    };
    let _ = external_item.set_text("Open approved target — none pending");
    let _ = external_item.set_enabled(false);
    if profiles.set_active(target).is_err() {
        show_current_error(
            app,
            &runtime,
            "Profile switch was rejected",
            "The selected profile is no longer present. Check the profile file and retry.",
        );
        return;
    }
    if clear_profile_storage(app, &runtime, snapshot_generation).is_err() {
        show_current_error(
            app,
            &runtime,
            "Profile isolation could not be established",
            "Crux could not clear the current in-memory webview state, so the profile switch was blocked.",
        );
        return;
    }

    let server = match ProxyServer::bind() {
        Ok(server) => server,
        Err(_) => {
            show_current_error(
                app,
                &runtime,
                "Profile switch could not start",
                "Crux could not bind a fresh loopback proxy origin. Retry from the tray.",
            );
            return;
        }
    };
    let control = server.control();
    if control.show_status(connecting_page(&profile.name)).is_err() {
        show_current_error(
            app,
            &runtime,
            "Profile switch could not start",
            "Crux could not initialize the fresh proxy state. Retry from the tray.",
        );
        return;
    }
    let proxy = match server.start() {
        Ok(proxy) => proxy,
        Err(_) => {
            show_current_error(
                app,
                &runtime,
                "Profile switch could not start",
                "Crux could not start the fresh loopback proxy. Retry from the tray.",
            );
            return;
        }
    };
    let proxy_origin = proxy.origin();
    let Some(proxy_key) = OriginKey::parse(&proxy_origin) else {
        return;
    };

    let installed = {
        let Ok(mut guard) = runtime.lock() else {
            return;
        };
        if !generation_matches(guard.generation, snapshot_generation) {
            Ok(None)
        } else {
            let origins = Arc::clone(&guard.origins);
            let Ok(mut policy) = origins.write() else {
                return;
            };
            if store.save(&profiles).is_err() {
                Err(())
            } else {
                let previous_active = guard.profiles.active_profile.clone();
                if guard
                    .profiles
                    .profiles
                    .iter()
                    .find(|candidate| candidate.name == previous_active)
                    .is_some_and(|candidate| candidate.mode == ProfileMode::Bundled)
                {
                    guard.statuses.insert(
                        previous_active,
                        StatusRecord {
                            state: HealthState::Unreachable,
                            reason: Some("shell-owned daemon stopping after profile switch".to_string()),
                        },
                    );
                }
                policy.active_proxy = Some(proxy_key);
                policy.bundled_sidecar = None;
                guard.profiles = profiles;
                guard.statuses.insert(
                    profile.name.clone(),
                    StatusRecord {
                        state: HealthState::Degraded,
                        reason: Some("connection check in progress".to_string()),
                    },
                );
                guard.runtime_capabilities.remove(&profile.name);
                let old_proxy = guard.proxy.replace(proxy);
                // Keep the app-owned Arc in RuntimeState until shutdown finishes.
                // A concurrent quit can therefore always find and stop it.
                let old_sidecar = guard.sidecar.clone();
                let tray_updates = tray_updates(&guard);
                Ok(Some((
                    guard.generation,
                    old_proxy,
                    old_sidecar,
                    tray_updates,
                    Arc::clone(&guard.origins),
                )))
            }
        }
    };
    let (generation, old_proxy, old_sidecar, tray_updates, origins) = match installed {
        Ok(Some(installed)) => installed,
        Ok(None) => return,
        Err(()) => {
            show_current_error(
                app,
                &runtime,
                "Profile switch was not saved",
                "Crux kept the current native boundary. Check the app-data directory and retry.",
            );
            return;
        }
    };
    apply_tray_updates(app, Arc::clone(&runtime), generation, tray_updates);
    let Ok(initial_url) = Url::parse(&format!("{proxy_origin}/?generation={generation}")) else {
        navigation_failed(app, Arc::clone(&runtime), generation);
        return;
    };
    launch_activation(
        app.clone(),
        runtime,
        generation,
        profile,
        control,
        ActivationTransition {
            old_proxy,
            old_sidecar,
            window_replacement: Some(WindowReplacement {
                window_label: format!("{MAIN_WINDOW}-{generation}-{}", initial_url.port().unwrap_or_default()),
                initial_url,
                origins,
                local_plan_script,
            }),
        },
    );
}

fn launch_activation(
    app: AppHandle,
    runtime: Arc<Mutex<RuntimeState>>,
    generation: u64,
    profile: Profile,
    control: ProxyControl,
    transition: ActivationTransition,
) {
    let failure_sidecar = transition.old_sidecar.clone();
    let failure_app = app.clone();
    let failure_runtime = Arc::clone(&runtime);
    let failure_control = control.clone();
    let failure_profile = profile.name.clone();
    let spawn = thread::Builder::new()
        .name(format!("crux-profile-{generation}"))
        .spawn(move || {
            stop_previous(&runtime, transition.old_proxy, transition.old_sidecar);
            if !runtime_generation_is_current(&runtime, generation) {
                return;
            }
            if let Some(replacement) = transition.window_replacement {
                if replace_main_window(&app, &runtime, generation, replacement).is_err() {
                    let page = StatusPage {
                        status: 503,
                        title: "Profile window unavailable".to_string(),
                        profile: profile.name.clone(),
                        message: "Crux could not establish a fresh isolated webview for the selected profile."
                            .to_string(),
                        retry: Some("Choose Retry in the tray.".to_string()),
                    };
                    publish_page(&app, &runtime, generation, &control, page, HealthState::Unreachable);
                    return;
                }
                if !runtime_generation_is_current(&runtime, generation) {
                    return;
                }
            }
            match profile.mode {
                ProfileMode::Bundled => activate_bundled(&app, &runtime, generation, &profile, &control),
                ProfileMode::Attach => activate_attach(&app, &runtime, generation, &profile, &control),
            }
        });
    if spawn.is_err() {
        if let Some(sidecar) = failure_sidecar {
            shutdown_shared_sidecar(&sidecar);
            clear_shared_sidecar(&failure_runtime, &sidecar);
        }
        let page = StatusPage {
            status: 503,
            title: "Connection worker unavailable".to_string(),
            profile: failure_profile,
            message: "Crux could not start the bounded native connection check.".to_string(),
            retry: Some("Choose Retry in the tray.".to_string()),
        };
        publish_page(
            &failure_app,
            &failure_runtime,
            generation,
            &failure_control,
            page,
            HealthState::Unreachable,
        );
    }
}

fn activate_attach(
    app: &AppHandle,
    runtime: &Arc<Mutex<RuntimeState>>,
    generation: u64,
    profile: &Profile,
    control: &ProxyControl,
) {
    let Some(token_ref) = profile.token_ref.as_deref() else {
        publish_native_error(
            app,
            runtime,
            generation,
            control,
            profile,
            "Attach credential is unavailable",
            "The profile has no credential reference.",
        );
        return;
    };
    let token = match NativeCredentialBroker::default().load(token_ref) {
        Ok(token) => token,
        Err(error) => {
            publish_native_error(
                app,
                runtime,
                generation,
                control,
                profile,
                "Attach credential is unavailable",
                error.reason(),
            );
            return;
        }
    };
    let probe_upstream = match UreqUpstream::for_probe(&profile.url) {
        Ok(upstream) => upstream,
        Err(error) => {
            publish_native_error(
                app,
                runtime,
                generation,
                control,
                profile,
                "Attach transport was rejected",
                error.reason(),
            );
            return;
        }
    };

    let mut backoff = Backoff::default();
    loop {
        if !runtime_generation_is_current(runtime, generation) {
            return;
        }
        let report = probe_health(&probe_upstream, Some(&token));
        if report.state != HealthState::Unreachable {
            if !report.forwarding_allowed() {
                publish_native_error(
                    app,
                    runtime,
                    generation,
                    control,
                    profile,
                    "Attach credential was reflected",
                    report
                        .reason
                        .as_deref()
                        .unwrap_or("the daemon returned credential material in a probe response"),
                );
                return;
            }
            if !runtime_generation_is_current(runtime, generation) {
                return;
            }
            let upstream: Arc<dyn Upstream> = match UreqUpstream::for_proxy(&profile.url) {
                Ok(upstream) => Arc::new(upstream),
                Err(error) => {
                    publish_native_error(
                        app,
                        runtime,
                        generation,
                        control,
                        profile,
                        "Attach proxy transport was rejected",
                        error.reason(),
                    );
                    return;
                }
            };
            let handshake_url = match control.set_forward(&profile.url, Arc::clone(&upstream), token) {
                Ok(handshake_url) => handshake_url,
                Err(_) => {
                    publish_native_error(
                        app,
                        runtime,
                        generation,
                        control,
                        profile,
                        "Attach proxy could not start",
                        "The native proxy rejected its upstream state.",
                    );
                    return;
                }
            };
            publish_ready(app, runtime, generation, profile, report, &handshake_url);
            return;
        }

        let reason = report
            .reason
            .as_deref()
            .unwrap_or("the selected daemon could not be reached");
        let Some(delay) = backoff.next_delay() else {
            let page = StatusPage {
                status: 503,
                title: "Crux daemon is unreachable".to_string(),
                profile: profile.name.clone(),
                message: reason.to_string(),
                retry: Some("The retry budget is exhausted. Choose Retry in the tray.".to_string()),
            };
            publish_page(app, runtime, generation, control, page, HealthState::Unreachable);
            return;
        };
        let page = StatusPage {
            status: 503,
            title: "Crux daemon is unreachable".to_string(),
            profile: profile.name.clone(),
            message: reason.to_string(),
            retry: Some(format!(
                "Visible retry {}/{} in {} ms.",
                backoff.attempts(),
                backoff.maximum_attempts(),
                delay.as_millis()
            )),
        };
        publish_page(app, runtime, generation, control, page, HealthState::Unreachable);
        thread::sleep(delay);
    }
}

fn activate_bundled(
    app: &AppHandle,
    runtime: &Arc<Mutex<RuntimeState>>,
    generation: u64,
    profile: &Profile,
    control: &ProxyControl,
) {
    let app_data_dir = runtime.lock().ok().map(|guard| guard.app_data_dir.clone());
    let Some(app_data_dir) = app_data_dir else {
        return;
    };
    let binary = match resolve_sidecar_binary() {
        Ok(binary) => binary,
        Err(_) => {
            publish_native_error(
                app,
                runtime,
                generation,
                control,
                profile,
                "Bundled daemon is unavailable",
                "The packaged corecruxd sidecar could not be located.",
            );
            return;
        }
    };
    // Spawn and publish ownership while the runtime lock is held. Exit can
    // therefore observe either no new child or a registered SharedSidecar,
    // never an untracked process between those two states.
    let sidecar = {
        let Ok(mut guard) = runtime.lock() else {
            return;
        };
        if !generation_matches(guard.generation, generation) {
            return;
        }
        match spawn_sidecar(&binary, SidecarConfig::new(&app_data_dir)) {
            Ok(sidecar) => {
                let sidecar = Arc::new(Mutex::new(sidecar));
                guard.sidecar = Some(Arc::clone(&sidecar));
                Some(sidecar)
            }
            Err(_) => None,
        }
    };
    let Some(sidecar) = sidecar else {
        publish_native_error(
            app,
            runtime,
            generation,
            control,
            profile,
            "Bundled daemon did not start",
            "The packaged corecruxd process could not be launched.",
        );
        return;
    };
    let (base_url, console_url) = match sidecar.lock() {
        Ok(handle) => (handle.base_url(), handle.console_url()),
        Err(poisoned) => {
            let handle = poisoned.into_inner();
            (handle.base_url(), handle.console_url())
        }
    };
    let health = match sidecar.lock() {
        Ok(mut handle) => handle.wait_for_health(),
        Err(poisoned) => poisoned.into_inner().wait_for_health(),
    };
    if let Err(error) = health {
        shutdown_shared_sidecar(&sidecar);
        clear_shared_sidecar(runtime, &sidecar);
        publish_native_error(
            app,
            runtime,
            generation,
            control,
            profile,
            "Bundled daemon is unreachable",
            &error.to_string(),
        );
        return;
    }
    if !runtime_generation_is_current(runtime, generation) {
        shutdown_shared_sidecar(&sidecar);
        clear_shared_sidecar(runtime, &sidecar);
        return;
    }
    let upstream = match UreqUpstream::for_probe(&base_url) {
        Ok(upstream) => upstream,
        Err(_) => {
            shutdown_shared_sidecar(&sidecar);
            clear_shared_sidecar(runtime, &sidecar);
            publish_native_error(
                app,
                runtime,
                generation,
                control,
                profile,
                "Bundled daemon transport is unavailable",
                "The shell rejected the allocated sidecar origin.",
            );
            return;
        }
    };
    let report = probe_health(&upstream, None);
    if report.state == HealthState::Unreachable {
        shutdown_shared_sidecar(&sidecar);
        clear_shared_sidecar(runtime, &sidecar);
        publish_unreachable_sidecar(app, runtime, generation, profile, control, report);
        return;
    }
    publish_ready_sidecar(app, runtime, generation, profile, &base_url, report, &console_url);
}

fn publish_ready_sidecar(
    app: &AppHandle,
    runtime: &Arc<Mutex<RuntimeState>>,
    generation: u64,
    profile: &Profile,
    base_url: &str,
    report: HealthReport,
    console_url: &str,
) {
    let Some(origin) = OriginKey::parse(base_url) else {
        return;
    };
    let updates = match runtime.lock() {
        Ok(mut guard) if generation_matches(guard.generation, generation) => {
            let origins = Arc::clone(&guard.origins);
            let Ok(mut policy) = origins.write() else {
                return;
            };
            policy.bundled_sidecar = Some(origin);
            guard.statuses.insert(
                profile.name.clone(),
                StatusRecord {
                    state: report.state,
                    reason: report.reason.clone(),
                },
            );
            guard
                .runtime_capabilities
                .insert(profile.name.clone(), report.runtime_capabilities.clone());
            Some(tray_updates(&guard))
        }
        Ok(_) | Err(_) => None,
    };
    if let Some(updates) = updates {
        apply_tray_updates(app, Arc::clone(runtime), generation, updates);
        set_window_status(app, Arc::clone(runtime), generation, &profile.name, report.state);
        navigate(app, Arc::clone(runtime), generation, console_url);
    }
}

fn publish_unreachable_sidecar(
    app: &AppHandle,
    runtime: &Arc<Mutex<RuntimeState>>,
    generation: u64,
    profile: &Profile,
    control: &ProxyControl,
    report: HealthReport,
) {
    if !runtime_generation_is_current(runtime, generation) {
        return;
    }
    let page = StatusPage {
        status: 503,
        title: "Bundled daemon is unreachable".to_string(),
        profile: profile.name.clone(),
        message: report
            .reason
            .unwrap_or_else(|| "The sidecar stopped answering after startup.".to_string()),
        retry: Some("Choose Retry in the tray to restart only the shell-owned daemon.".to_string()),
    };
    publish_page(app, runtime, generation, control, page, HealthState::Unreachable);
}

fn publish_ready(
    app: &AppHandle,
    runtime: &Arc<Mutex<RuntimeState>>,
    generation: u64,
    profile: &Profile,
    report: HealthReport,
    console_url: &str,
) {
    let updates = {
        let Ok(mut guard) = runtime.lock() else {
            return;
        };
        if !generation_matches(guard.generation, generation) {
            None
        } else {
            guard.statuses.insert(
                profile.name.clone(),
                StatusRecord {
                    state: report.state,
                    reason: report.reason.clone(),
                },
            );
            guard
                .runtime_capabilities
                .insert(profile.name.clone(), report.runtime_capabilities);
            Some(tray_updates(&guard))
        }
    };
    if let Some(updates) = updates {
        apply_tray_updates(app, Arc::clone(runtime), generation, updates);
        set_window_status(app, Arc::clone(runtime), generation, &profile.name, report.state);
        navigate(app, Arc::clone(runtime), generation, console_url);
    }
}

fn publish_native_error(
    app: &AppHandle,
    runtime: &Arc<Mutex<RuntimeState>>,
    generation: u64,
    control: &ProxyControl,
    profile: &Profile,
    title: &str,
    reason: &str,
) {
    let page = StatusPage {
        status: 503,
        title: title.to_string(),
        profile: profile.name.clone(),
        message: reason.to_string(),
        retry: Some("No plaintext or environment fallback was attempted. Choose Retry in the tray.".to_string()),
    };
    publish_page(app, runtime, generation, control, page, HealthState::Unreachable);
}

fn publish_page(
    app: &AppHandle,
    runtime: &Arc<Mutex<RuntimeState>>,
    generation: u64,
    control: &ProxyControl,
    page: StatusPage,
    state: HealthState,
) {
    if !runtime_generation_is_current(runtime, generation) || control.show_status(page.clone()).is_err() {
        return;
    }
    let updates = {
        let Ok(mut guard) = runtime.lock() else {
            return;
        };
        if !generation_matches(guard.generation, generation) {
            None
        } else {
            guard.statuses.insert(
                page.profile.clone(),
                StatusRecord {
                    state,
                    reason: Some(page.message.clone()),
                },
            );
            guard.runtime_capabilities.remove(&page.profile);
            Some(tray_updates(&guard))
        }
    };
    if let Some(updates) = updates {
        apply_tray_updates(app, Arc::clone(runtime), generation, updates);
        set_window_status(app, Arc::clone(runtime), generation, &page.profile, state);
        navigate(
            app,
            Arc::clone(runtime),
            generation,
            &format!(
                "{}/?generation={generation}&attempt={}",
                control.origin(),
                state_label(state)
            ),
        );
    }
}

fn show_current_error(app: &AppHandle, runtime: &Arc<Mutex<RuntimeState>>, title: &str, message: &str) {
    let current = runtime.lock().ok().and_then(|guard| {
        guard
            .proxy
            .as_ref()
            .map(|proxy| (guard.generation, guard.profiles.active_profile.clone(), proxy.control()))
    });
    let Some((generation, profile, control)) = current else {
        return;
    };
    let page = StatusPage {
        status: 503,
        title: title.to_string(),
        profile,
        message: message.to_string(),
        retry: Some("Choose Retry in the tray.".to_string()),
    };
    publish_page(app, runtime, generation, &control, page, HealthState::Unreachable);
}

fn runtime_generation_is_current(runtime: &Arc<Mutex<RuntimeState>>, generation: u64) -> bool {
    runtime
        .lock()
        .ok()
        .is_some_and(|guard| generation_matches(guard.generation, generation))
}

fn connecting_page(profile: &str) -> StatusPage {
    StatusPage {
        status: 503,
        title: "Connecting to Crux".to_string(),
        profile: profile.to_string(),
        message: "The native shell is checking /healthz and /v1/version.".to_string(),
        retry: Some("Connection attempts are bounded and their state remains visible here.".to_string()),
    }
}

fn stop_previous(runtime: &Arc<Mutex<RuntimeState>>, mut proxy: Option<ProxyHandle>, sidecar: Option<SharedSidecar>) {
    if let Some(proxy) = proxy.as_mut() {
        let _ = proxy.shutdown();
    }
    if let Some(sidecar) = sidecar {
        shutdown_shared_sidecar(&sidecar);
        clear_shared_sidecar(runtime, &sidecar);
    }
}

fn clear_shared_sidecar(runtime: &Arc<Mutex<RuntimeState>>, stopped: &SharedSidecar) {
    let clear = |guard: &mut RuntimeState| {
        if guard
            .sidecar
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, stopped))
        {
            guard.sidecar = None;
        }
    };
    match runtime.lock() {
        Ok(mut guard) => clear(&mut guard),
        Err(poisoned) => clear(&mut poisoned.into_inner()),
    }
}

fn shutdown_shared_sidecar(sidecar: &SharedSidecar) {
    match sidecar.lock() {
        Ok(mut handle) => {
            let _ = handle.shutdown();
        }
        Err(poisoned) => {
            let _ = poisoned.into_inner().shutdown();
        }
    }
}

fn shutdown_owned_resources(app: &AppHandle) {
    let Some(managed) = app.try_state::<ManagedState>() else {
        return;
    };
    let (mut proxy, sidecar) = match managed.0.lock() {
        Ok(mut guard) => {
            guard.generation = next_generation(guard.generation);
            (guard.proxy.take(), guard.sidecar.take())
        }
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            guard.generation = next_generation(guard.generation);
            (guard.proxy.take(), guard.sidecar.take())
        }
    };
    if let Some(proxy) = proxy.as_mut() {
        let _ = proxy.shutdown();
    }
    if let Some(sidecar) = sidecar {
        shutdown_shared_sidecar(&sidecar);
    }
}

fn tray_updates(state: &RuntimeState) -> Vec<TrayUpdate> {
    state
        .profile_menu
        .iter()
        .map(|entry| {
            let status = state.statuses.get(&entry.name).cloned().unwrap_or(StatusRecord {
                state: HealthState::Unreachable,
                reason: None,
            });
            TrayUpdate {
                item: entry.item.clone(),
                text: menu_label(&entry.name, &status),
                checked: entry.name == state.profiles.active_profile,
            }
        })
        .collect()
}

fn apply_tray_updates(app: &AppHandle, runtime: Arc<Mutex<RuntimeState>>, generation: u64, updates: Vec<TrayUpdate>) {
    let scheduler = app.clone();
    let _ = scheduler.run_on_main_thread(move || {
        if !runtime_generation_is_current(&runtime, generation) {
            return;
        }
        for update in updates {
            let _ = update.item.set_text(update.text);
            let _ = update.item.set_checked(update.checked);
        }
    });
}

fn menu_label(profile: &str, status: &StatusRecord) -> String {
    let profile = menu_safe(profile);
    let reason = status
        .reason
        .as_deref()
        .map(concise_reason)
        .filter(|reason| !reason.is_empty());
    match reason {
        Some(reason) => format!("{profile} — {}: {}", state_label(status.state), menu_safe(&reason)),
        None => format!("{profile} — {}", state_label(status.state)),
    }
}

fn concise_reason(reason: &str) -> String {
    reason
        .chars()
        .map(|character| if character.is_control() { ' ' } else { character })
        .take(80)
        .collect()
}

fn menu_safe(value: &str) -> String {
    value.replace('&', "&&")
}

const fn state_label(state: HealthState) -> &'static str {
    match state {
        HealthState::Ok => "ok",
        HealthState::Degraded => "degraded",
        HealthState::Unreachable => "unreachable",
    }
}

fn current_window(app: &AppHandle, runtime: &Arc<Mutex<RuntimeState>>, generation: u64) -> Option<WebviewWindow<Wry>> {
    let label = runtime
        .lock()
        .ok()
        .and_then(|guard| generation_matches(guard.generation, generation).then(|| guard.window_label.clone()))?;
    app.get_webview_window(&label)
}

fn set_window_status(
    app: &AppHandle,
    runtime: Arc<Mutex<RuntimeState>>,
    generation: u64,
    profile: &str,
    state: HealthState,
) {
    let title = if state == HealthState::Ok {
        format!("Crux — {profile}")
    } else {
        format!("Crux — {profile} — {}", state_label(state))
    };
    let scheduler = app.clone();
    let ui = app.clone();
    let _ = scheduler.run_on_main_thread(move || {
        if !runtime_generation_is_current(&runtime, generation) {
            return;
        }
        if let Some(window) = current_window(&ui, &runtime, generation) {
            let _ = window.set_title(&title);
        }
    });
}

fn clear_profile_storage(app: &AppHandle, runtime: &Arc<Mutex<RuntimeState>>, generation: u64) -> Result<(), ()> {
    let Some(window) = current_window(app, runtime, generation) else {
        return Err(());
    };
    window.clear_all_browsing_data().map_err(|_| ())
}

fn navigate(app: &AppHandle, runtime: Arc<Mutex<RuntimeState>>, generation: u64, url: &str) {
    let Ok(url) = Url::parse(url) else {
        navigation_failed(app, runtime, generation);
        return;
    };
    let scheduler = app.clone();
    let ui = app.clone();
    let callback_runtime = Arc::clone(&runtime);
    let scheduled = scheduler.run_on_main_thread(move || {
        if !runtime_generation_is_current(&callback_runtime, generation) {
            return;
        }
        if let Some(window) = current_window(&ui, &callback_runtime, generation) {
            if window.navigate(url).is_err() {
                navigation_failed(&ui, callback_runtime, generation);
            }
        } else {
            navigation_failed(&ui, callback_runtime, generation);
        }
    });
    if scheduled.is_err() {
        navigation_failed(app, runtime, generation);
    }
}

fn navigation_failed(app: &AppHandle, runtime: Arc<Mutex<RuntimeState>>, generation: u64) {
    let (profile, control, updates) = {
        let Ok(mut guard) = runtime.lock() else {
            return;
        };
        if !generation_matches(guard.generation, generation) {
            return;
        }
        let Some(proxy) = guard.proxy.as_ref() else {
            return;
        };
        let control = proxy.control();
        let profile = guard.profiles.active_profile.clone();
        guard.statuses.insert(
            profile.clone(),
            StatusRecord {
                state: HealthState::Unreachable,
                reason: Some("the webview could not navigate to the active profile".to_string()),
            },
        );
        guard.runtime_capabilities.remove(&profile);
        (profile, control, tray_updates(&guard))
    };
    let page = StatusPage {
        status: 503,
        title: "Active profile could not be displayed".to_string(),
        profile: profile.clone(),
        message: "The native webview rejected navigation to the active profile.".to_string(),
        retry: Some("Choose Retry in the tray. No credential was exposed to the page.".to_string()),
    };
    if control.show_status(page).is_err() {
        return;
    }
    apply_tray_updates(app, Arc::clone(&runtime), generation, updates);

    let Ok(status_url) = Url::parse(&format!(
        "{}/?generation={generation}&navigation=blocked",
        control.origin()
    )) else {
        return;
    };
    let scheduler = app.clone();
    let ui = app.clone();
    let _ = scheduler.run_on_main_thread(move || {
        if !runtime_generation_is_current(&runtime, generation) {
            return;
        }
        if let Some(window) = current_window(&ui, &runtime, generation) {
            let _ = window.set_title(&format!("Crux — {profile} — unreachable"));
            let _ = window.navigate(status_url);
        }
    });
}

fn shared_origin_is_allowed(origins: &Arc<RwLock<OriginPolicy>>, url: &Url) -> bool {
    origins
        .read()
        .ok()
        .is_some_and(|policy| origin_is_allowed(&policy, url.as_str()))
}

fn handle_local_plan_navigation(app: &AppHandle, window_label: &str, window_generation: u64, url: &Url) -> bool {
    if url.scheme() != "file" {
        return false;
    }
    let requested_path = match url.to_file_path() {
        Ok(path) => path,
        Err(()) => return true,
    };
    let authorized = app.try_state::<ManagedState>().and_then(|managed| {
        let root = managed.0.lock().ok().and_then(|guard| {
            if guard.window_label != window_label || !generation_matches(guard.generation, window_generation) {
                return None;
            }
            guard
                .profiles
                .active_profile()
                .ok()
                .and_then(|profile| profile.local_plan_root.clone())
        })?;
        authorize_local_plan_path(root, requested_path).ok()
    });
    if let Some(path) = authorized {
        queue_local_plan(app, window_generation, path);
    }
    true
}

fn queue_external_link(app: &AppHandle, window_generation: u64, url: &Url) {
    if !is_public_http_link(url.as_str()) {
        return;
    }
    let Some(managed) = app.try_state::<ManagedState>() else {
        return;
    };
    let target = url.as_str().to_string();
    let pending = PendingOpen::PublicHttp(target.clone());
    let queued = managed.0.lock().ok().and_then(|mut guard| {
        if !generation_matches(guard.generation, window_generation) || guard.pending_open.is_some() {
            return None;
        }
        guard.pending_open = Some(pending.clone());
        let host = url.host_str().unwrap_or("external site");
        let authority = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        Some((
            guard.generation,
            guard.open_external_item.clone(),
            format!(
                "Open external link in browser — {}",
                menu_safe(&format!("{}://{authority}", url.scheme()))
            ),
        ))
    });
    let Some((generation, item, label)) = queued else {
        return;
    };
    let runtime = Arc::clone(&managed.0);
    let scheduler = app.clone();
    let _ = scheduler.run_on_main_thread(move || {
        let still_pending = runtime.lock().ok().is_some_and(|guard| {
            generation_matches(guard.generation, generation) && guard.pending_open.as_ref() == Some(&pending)
        });
        if still_pending {
            let _ = item.set_text(label);
            let _ = item.set_enabled(true);
        }
    });
}

fn queue_local_plan(app: &AppHandle, window_generation: u64, path: PathBuf) {
    let Some(managed) = app.try_state::<ManagedState>() else {
        return;
    };
    let pending = PendingOpen::LocalPlan(path.clone());
    let queued = managed.0.lock().ok().and_then(|mut guard| {
        if !generation_matches(guard.generation, window_generation) || guard.pending_open.is_some() {
            return None;
        }
        guard.pending_open = Some(pending.clone());
        let label = path.file_name().and_then(|name| name.to_str()).map_or_else(
            || "Open local plan".to_string(),
            |name| format!("Open local plan — {}", menu_safe(name)),
        );
        Some((guard.generation, guard.open_external_item.clone(), label))
    });
    let Some((generation, item, label)) = queued else {
        return;
    };
    let runtime = Arc::clone(&managed.0);
    let scheduler = app.clone();
    let _ = scheduler.run_on_main_thread(move || {
        let still_pending = runtime.lock().ok().is_some_and(|guard| {
            generation_matches(guard.generation, generation) && guard.pending_open.as_ref() == Some(&pending)
        });
        if still_pending {
            let _ = item.set_text(label);
            let _ = item.set_enabled(true);
        }
    });
}

fn open_in_system_browser(url: &Url) {
    if !is_public_http_link(url.as_str()) {
        return;
    }
    let Some(mut command) = browser_command(url.as_str()) else {
        return;
    };
    spawn_system_handler(&mut command);
}

fn open_local_plan_in_system_handler(path: &Path) {
    let Some(mut command) = local_plan_command(path) else {
        return;
    };
    spawn_system_handler(&mut command);
}

fn spawn_system_handler(command: &mut Command) {
    command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    let _ = command.spawn();
}

#[cfg(target_os = "linux")]
fn browser_command(url: &str) -> Option<Command> {
    let mut command = Command::new("/usr/bin/xdg-open");
    command.arg(url);
    Some(command)
}

#[cfg(target_os = "windows")]
fn browser_command(url: &str) -> Option<Command> {
    let mut command = Command::new(r"C:\Windows\System32\rundll32.exe");
    command.arg("url.dll,FileProtocolHandler").arg(url);
    Some(command)
}

#[cfg(target_os = "macos")]
fn browser_command(url: &str) -> Option<Command> {
    let mut command = Command::new("/usr/bin/open");
    command.arg(url);
    Some(command)
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn browser_command(_url: &str) -> Option<Command> {
    None
}

#[cfg(target_os = "linux")]
fn local_plan_command(path: &Path) -> Option<Command> {
    let mut command = Command::new("/usr/bin/xdg-open");
    command.arg(path);
    Some(command)
}

#[cfg(target_os = "windows")]
fn local_plan_command(path: &Path) -> Option<Command> {
    let mut command = Command::new(r"C:\Windows\System32\rundll32.exe");
    command.arg("url.dll,FileProtocolHandler").arg(path);
    Some(command)
}

#[cfg(target_os = "macos")]
fn local_plan_command(path: &Path) -> Option<Command> {
    let mut command = Command::new("/usr/bin/open");
    command.arg(path);
    Some(command)
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn local_plan_command(_path: &Path) -> Option<Command> {
    None
}

/// Locate the packaged sidecar exactly as the original bundled-only shell did.
fn resolve_sidecar_binary() -> std::io::Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let directory = executable.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "current executable has no parent directory",
        )
    })?;
    let name = if cfg!(windows) { "corecruxd.exe" } else { "corecruxd" };
    Ok(directory.join(name))
}
