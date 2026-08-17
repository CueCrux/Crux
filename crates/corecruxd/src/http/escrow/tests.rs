// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! M3b gate: the escrow properties asserted against a running daemon rather
//! than against the crate's types.
//!
//! The crate's own tests prove `WrappedDek` carries nothing usable. These prove
//! the daemon that persists it does not add anything back — not in the fact
//! store, not in a receipt payload, not in a log line.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::http::tests::{bind_test_state_to_root_passport_key, test_app_state};
use axum::body::to_bytes;
use crux_escrow::release::{ReleaseState, RELEASE_DELAY};
use crux_escrow::{unwrap_dek, RecoveryCode, VaultSetup};

const VAULT: &str = "vault-01HTEST";
const DEK: [u8; 32] = [7u8; 32];

/// A daemon that can actually sign. Every escrow mutation is receipted, so a
/// state without a loadable passport key cannot complete one — which is the
/// intended behaviour, not a test inconvenience.
fn state() -> AppState {
    let mut state = test_app_state(8);
    bind_test_state_to_root_passport_key(&mut state);
    state
}

async fn body_json(response: Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    serde_json::from_slice(&bytes).expect("json body")
}

/// A vault set up exactly as a customer's client would: DEK wrapped locally,
/// only the ciphertext handed to the daemon.
fn client_side_setup() -> (RecoveryCode, PutWrappedDekBody) {
    let setup = VaultSetup::new(&DEK, VAULT).expect("setup");
    let code = setup.code().clone();
    let blob = setup.acknowledge();
    (
        code,
        PutWrappedDekBody {
            nonce: blob.nonce,
            ciphertext: blob.ciphertext,
        },
    )
}

async fn store_dek(state: &AppState, body: PutWrappedDekBody) -> Response {
    put_wrapped_dek(
        State(state.clone()),
        HeaderMap::new(),
        Path(VAULT.to_string()),
        Json(body),
    )
    .await
}

async fn all_facts(state: &AppState) -> Vec<corecrux_memory::Fact> {
    let store = state.fact_store.read().await;
    store
        .query(&corecrux_memory::fact_store::FactQuery {
            top_k: usize::MAX,
            ..Default::default()
        })
        .facts
}

// ── the DEK half of the gate ────────────────────────────────────────

#[tokio::test]
async fn a_live_daemon_stores_a_wrapped_dek_and_returns_it() {
    let state = state();
    let (code, body) = client_side_setup();

    assert_eq!(store_dek(&state, body).await.status(), StatusCode::OK);

    let response = get_wrapped_dek(State(state.clone()), HeaderMap::new(), Path(VAULT.to_string())).await;
    assert_eq!(response.status(), StatusCode::OK);
    let returned: WrappedDek = serde_json::from_value(body_json(response).await).expect("wrapped dek");

    // The round trip is only meaningful if the blob still opens: the customer's
    // recovery code must recover the original DEK from what the daemon handed back.
    assert_eq!(unwrap_dek(&returned, &code).expect("unwrap"), DEK);
}

#[tokio::test]
async fn a_rewrap_returns_the_new_blob_not_the_old_one() {
    // The fact store is versioned — re-storing appends. Handing back an older
    // version would give the customer a blob their current code cannot open.
    let state = state();
    let (_old_code, old_body) = client_side_setup();
    assert_eq!(store_dek(&state, old_body).await.status(), StatusCode::OK);

    let (new_code, new_body) = client_side_setup();
    assert_eq!(store_dek(&state, new_body).await.status(), StatusCode::OK);

    let response = get_wrapped_dek(State(state.clone()), HeaderMap::new(), Path(VAULT.to_string())).await;
    let returned: WrappedDek = serde_json::from_value(body_json(response).await).expect("wrapped dek");
    assert_eq!(unwrap_dek(&returned, &new_code).expect("unwrap"), DEK);
}

/// The M1 gate, restated against a live store: a dump of everything the daemon
/// persisted yields nothing usable.
#[tokio::test]
async fn a_dump_of_the_live_store_yields_nothing() {
    let state = state();
    let (code, body) = client_side_setup();
    assert_eq!(store_dek(&state, body).await.status(), StatusCode::OK);

    let facts = all_facts(&state).await;
    let dump = serde_json::to_vec(&facts).expect("dump");

    assert!(
        !dump.windows(DEK.len()).any(|w| w == DEK),
        "the DEK reached the fact store"
    );
    let rendered = code.render().expect("render");
    assert!(
        !String::from_utf8_lossy(&dump).contains(&rendered),
        "the recovery code reached the fact store"
    );

    // And the escrow facts are private, so sync never pushes the ciphertext to a
    // remote the customer did not choose.
    let escrow: Vec<_> = facts
        .iter()
        .filter(|f| f.entity.starts_with(ESCROW_ENTITY_PREFIX))
        .collect();
    assert!(!escrow.is_empty(), "nothing was stored");
    assert!(
        corecrux_memory::fact_privacy::global_policy().is_always_private(&escrow[0].entity),
        "escrow facts must be born private"
    );
}

#[tokio::test]
async fn the_receipt_binds_the_ciphertext_without_carrying_it() {
    let state = state();
    let (_code, body) = client_side_setup();
    let expected = blake3::hash(&body.ciphertext).to_hex().to_string();
    let ciphertext = body.ciphertext.clone();
    assert_eq!(store_dek(&state, body).await.status(), StatusCode::OK);

    let path = crate::http::observations::observation_file_path(&state.data_dir, &vault_entity(VAULT));
    let records = read_observations_strict(&path).expect("chain");
    let stored = records.iter().find(|r| r.kind == KIND_DEK_STORED).expect("receipt");
    assert_eq!(stored.payload["ciphertext_blake3"], expected);

    let payload = serde_json::to_vec(&stored.payload).expect("payload");
    assert!(
        !payload
            .windows(ciphertext.len().min(32))
            .any(|w| ciphertext.starts_with(w) && w.len() >= 16),
        "the receipt duplicated ciphertext into a second durability class"
    );
}

#[tokio::test]
async fn a_bad_vault_id_is_refused_rather_than_sanitised() {
    let state = state();
    let (_code, body) = client_side_setup();
    // Two ids that sanitised to the same filename would share a receipt chain.
    let response = put_wrapped_dek(
        State(state.clone()),
        HeaderMap::new(),
        Path("../../etc/passwd".to_string()),
        Json(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ── the release half of the gate ────────────────────────────────────

async fn open_release(state: &AppState, holder: &str) -> Response {
    post_release(
        State(state.clone()),
        HeaderMap::new(),
        Path(VAULT.to_string()),
        Json(PostReleaseBody {
            account_holder: holder.to_string(),
        }),
    )
    .await
}

/// The account holder in an auth-off test state is the daemon's own passport
/// fingerprint, since no passport claim is presented.
fn holder_of(state: &AppState) -> String {
    state.passport_fpr.clone()
}

#[tokio::test]
async fn a_release_is_reconstructable_from_the_stored_receipts() {
    let state = state();
    let holder = holder_of(&state);
    let opened = open_release(&state, &holder).await;
    assert_eq!(opened.status(), StatusCode::OK);
    let request: ReleaseRequest = serde_json::from_value(body_json(opened).await).expect("release");

    // The GET path has no in-memory state to fall back on: it reads the JSONL
    // off disk and replays it. Equality here is the gate.
    let read = get_release(State(state.clone()), HeaderMap::new(), Path(request.id.to_string())).await;
    assert_eq!(read.status(), StatusCode::OK);
    let replayed: ReleaseRequest = serde_json::from_value(body_json(read).await).expect("release");
    assert_eq!(replayed, request);
    assert_eq!(replayed.state, ReleaseState::Pending);
    assert_eq!(replayed.available_at, request.requested_at + RELEASE_DELAY);
}

#[tokio::test]
async fn a_release_cannot_complete_before_the_delay_elapses() {
    let state = state();
    let holder = holder_of(&state);
    let request: ReleaseRequest =
        serde_json::from_value(body_json(open_release(&state, &holder).await).await).expect("release");

    let response = post_release_complete(State(state.clone()), HeaderMap::new(), Path(request.id.to_string())).await;
    // 425 Too Early. There is no override, so there is nothing else to assert.
    assert_eq!(response.status(), StatusCode::TOO_EARLY);
}

#[tokio::test]
async fn a_passport_that_is_not_the_account_holder_is_refused() {
    let state = state();
    let response = open_release(&state, "passport:someone-else").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_replayed_request_does_not_open_a_second_window() {
    let state = state();
    let holder = holder_of(&state);
    assert_eq!(open_release(&state, &holder).await.status(), StatusCode::OK);
    // The pointer fact plus the replayed chain is what makes this idempotent
    // rather than a second, independently-completable release.
    assert_eq!(open_release(&state, &holder).await.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_cancelled_release_can_never_be_completed() {
    let state = state();
    let holder = holder_of(&state);
    let request: ReleaseRequest =
        serde_json::from_value(body_json(open_release(&state, &holder).await).await).expect("release");

    // No devices are paired in a bare test daemon, so nobody is notified and
    // nobody can cancel — which is exactly what the timeline should show.
    assert!(request.notified_devices.is_empty());
    let response = post_release_cancel(
        State(state.clone()),
        HeaderMap::new(),
        Path(request.id.to_string()),
        Json(PostCancelBody {
            device: "device:phone".to_string(),
        }),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "an unnotified device cancelled"
    );
}

#[tokio::test]
async fn a_tampered_receipt_chain_does_not_replay() {
    let state = state();
    let holder = holder_of(&state);
    let request: ReleaseRequest =
        serde_json::from_value(body_json(open_release(&state, &holder).await).await).expect("release");
    let path =
        crate::http::observations::observation_file_path(&state.data_dir, &release_session(&request.id.to_string()));

    // Drop the opening event. The chain no longer explains itself, and a read
    // must fail loudly rather than return a request that looks fine.
    let original = std::fs::read_to_string(&path).expect("chain");
    let mut lines: Vec<&str> = original.lines().collect();
    assert!(!lines.is_empty());
    lines.remove(0);
    std::fs::write(&path, lines.join("\n")).expect("rewrite");

    let response = get_release(State(state.clone()), HeaderMap::new(), Path(request.id.to_string())).await;
    assert_ne!(response.status(), StatusCode::OK, "a doctored chain replayed as valid");

    // And a garbled line is rejected outright rather than skipped.
    std::fs::write(&path, format!("{original}\nnot json\n")).expect("rewrite");
    let response = get_release(State(state.clone()), HeaderMap::new(), Path(request.id.to_string())).await;
    assert_ne!(response.status(), StatusCode::OK, "a garbled chain replayed as valid");
}

#[tokio::test]
async fn an_unknown_release_is_not_found() {
    let state = state();
    let response = get_release(
        State(state.clone()),
        HeaderMap::new(),
        Path("00000000-0000-0000-0000-000000000000".to_string()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── log hygiene (plan R4) ───────────────────────────────────────────

/// Nothing that could open a vault may reach a log line at `debug` or above.
///
/// Asserted by capturing the subscriber output across a full store-and-release
/// flow rather than by grepping the source, so a `tracing` call added later in a
/// helper this module calls is caught too.
#[tokio::test]
async fn no_key_material_reaches_the_logs() {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Ok(mut sink) = self.0.lock() {
                sink.extend_from_slice(buf);
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::DEBUG)
        .finish();

    let state = state();
    let (code, body) = client_side_setup();
    let ciphertext = body.ciphertext.clone();
    let holder = holder_of(&state);

    let guard = tracing::subscriber::set_default(subscriber);
    store_dek(&state, body).await;
    get_wrapped_dek(State(state.clone()), HeaderMap::new(), Path(VAULT.to_string())).await;
    let opened = open_release(&state, &holder).await;
    let request: ReleaseRequest = serde_json::from_value(body_json(opened).await).expect("release");
    post_release_complete(State(state.clone()), HeaderMap::new(), Path(request.id.to_string())).await;
    drop(guard);

    let logs = capture.0.lock().expect("captured logs").clone();
    let text = String::from_utf8_lossy(&logs);

    let rendered = code.render().expect("render");
    assert!(!text.contains(&rendered), "the recovery code was logged");
    assert!(!logs.windows(DEK.len()).any(|w| w == DEK), "the DEK was logged");
    // Hex and base64 renderings of the ciphertext are the two ways a debug line
    // typically leaks a byte buffer.
    assert!(
        !text.contains(&hex::encode(&ciphertext)),
        "the ciphertext was hex-logged"
    );
    for symbol in rendered.split('-') {
        assert!(!text.contains(symbol), "a recovery-code group was logged: {symbol}");
    }
}
