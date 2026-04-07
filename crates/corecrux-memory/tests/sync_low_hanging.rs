// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use chrono::Utc;
use corecrux_memory::fact_store::StoreFact;
use corecrux_memory::sync::{SyncClient, SyncCursor};
use corecrux_memory::{Fact, FactStore};
use serde_json::json;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[derive(Debug)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct MockResponse {
    status: &'static str,
    content_type: &'static str,
    body: String,
}

impl MockResponse {
    fn json(body: serde_json::Value) -> Self {
        Self {
            status: "200 OK",
            content_type: "application/json",
            body: body.to_string(),
        }
    }

    fn invalid_json(body: &str) -> Self {
        Self {
            status: "200 OK",
            content_type: "application/json",
            body: body.to_string(),
        }
    }
}

fn start_mock_server(
    responses: Vec<MockResponse>,
) -> (String, mpsc::Receiver<Vec<RecordedRequest>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().expect("accept connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            let request = read_request(&mut stream).expect("read request");
            requests.push(request);

            let response_bytes = format!(
                "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.status,
                response.content_type,
                response.body.len(),
                response.body
            );
            stream.write_all(response_bytes.as_bytes()).expect("write response");
            stream.flush().expect("flush response");
        }
        tx.send(requests).expect("send recorded requests");
    });

    (format!("http://{}", addr), rx, handle)
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<RecordedRequest> {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break find_header_end(&bytes);
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = find_header_end(&bytes) {
            break Some(end);
        }
    }
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "request missing headers"))?;

    let header_text = std::str::from_utf8(&bytes[..header_end])
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing method"))?
        .to_string();
    let path = request_parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing path"))?
        .to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = bytes[header_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Ok(RecordedRequest {
        method,
        path,
        headers,
        body,
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn wait_for_requests(rx: mpsc::Receiver<Vec<RecordedRequest>>, handle: thread::JoinHandle<()>) -> Vec<RecordedRequest> {
    let requests = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("receive recorded requests");
    handle.join().expect("mock server join");
    requests
}

#[test]
fn push_preview_counts_pushable_private_synced_and_deleted_facts() {
    let dir = tempfile::tempdir().unwrap();
    let client = SyncClient::new("http://localhost:14800", "test-key", dir.path());
    let mut store = FactStore::new();

    store.store(StoreFact {
        entity: "alpha".to_string(),
        key: "k1".to_string(),
        value: "one".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    });
    store.store(StoreFact {
        entity: "alpha".to_string(),
        key: "k2".to_string(),
        value: "two".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    });
    store.store(StoreFact {
        entity: "beta".to_string(),
        key: "k3".to_string(),
        value: "three".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    });
    store.store(StoreFact {
        entity: "finance:ledger".to_string(),
        key: "k4".to_string(),
        value: "secret".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    });
    store.store(StoreFact {
        entity: "flagged".to_string(),
        key: "k5".to_string(),
        value: "private".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: true,
    });

    store.store_synced(Fact {
        fact_id: "f_synced_preview".to_string(),
        entity: "remote".to_string(),
        key: "k6".to_string(),
        value: "synced".to_string(),
        source_receipt: Some("sync:http://remote:14800:f_synced_preview".to_string()),
        confidence: 1.0,
        stored_at: Utc::now(),
        tokens: 1,
        deleted: false,
        version: 1,
        supersedes: None,
        private: false,
    });

    let deleted = store.store(StoreFact {
        entity: "deleted".to_string(),
        key: "k7".to_string(),
        value: "gone".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    });
    assert!(store.delete(&deleted.fact_id));

    let preview = client.push_preview(&store);
    assert_eq!(preview.pushable_count, 3);
    assert_eq!(preview.private_count, 2);
    assert_eq!(preview.synced_count, 1);
    assert_eq!(preview.entity_summary.first(), Some(&("alpha".to_string(), 2)));
    assert!(preview.entity_summary.contains(&("beta".to_string(), 1)));
}

#[test]
fn push_returns_zero_when_no_non_private_local_facts_exist() {
    let dir = tempfile::tempdir().unwrap();
    let client = SyncClient::new("http://localhost:14800", "test-key", dir.path());
    let mut store = FactStore::new();

    store.store(StoreFact {
        entity: "finance:payroll".to_string(),
        key: "k1".to_string(),
        value: "private".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    });

    store.store_synced(Fact {
        fact_id: "f_synced_only".to_string(),
        entity: "remote".to_string(),
        key: "k2".to_string(),
        value: "synced".to_string(),
        source_receipt: Some("sync:http://remote:14800:f_synced_only".to_string()),
        confidence: 1.0,
        stored_at: Utc::now(),
        tokens: 1,
        deleted: false,
        version: 1,
        supersedes: None,
        private: false,
    });

    let deleted = store.store(StoreFact {
        entity: "deleted".to_string(),
        key: "k3".to_string(),
        value: "gone".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    });
    assert!(store.delete(&deleted.fact_id));

    let result = client.push(&store).unwrap();
    assert_eq!(result.facts_pushed, 0);

    let cursor = client.load_cursor();
    assert_eq!(cursor.push_count, 0);
    assert!(cursor.last_push_at.is_none());
}

#[test]
fn pull_paginates_tags_synced_facts_and_persists_cursor() {
    let page_one = MockResponse::json(json!({
        "facts": [
            {
                "fact_id": "f_remote_1",
                "entity": "remote-alpha",
                "key": "status",
                "value": "ready",
                "source_receipt": null,
                "confidence": 0.9,
                "stored_at": "2026-04-07T11:00:00Z",
                "tokens": 1,
                "deleted": false,
                "version": 1,
                "supersedes": null,
                "private": false
            }
        ],
        "has_more": true,
        "next_cursor": "cursor-2"
    }));
    let page_two = MockResponse::json(json!({
        "facts": [
            {
                "fact_id": "f_remote_2",
                "entity": "remote-beta",
                "key": "mode",
                "value": "live",
                "source_receipt": null,
                "confidence": 1.0,
                "stored_at": "2026-04-07T11:01:00Z",
                "tokens": 1,
                "deleted": false,
                "version": 1,
                "supersedes": null,
                "private": false
            }
        ],
        "has_more": false,
        "next_cursor": "cursor-final"
    }));
    let (base_url, rx, handle) = start_mock_server(vec![page_one, page_two]);

    let dir = tempfile::tempdir().unwrap();
    let client = SyncClient::new(&format!("{base_url}/"), "test-key", dir.path());
    client.save_cursor(&SyncCursor {
        last_pull_at: Some("2026-04-07T10:59:00+00:00".to_string()),
        last_pull_cursor: None,
        last_push_at: None,
        pull_count: 5,
        push_count: 0,
    });

    let mut store = FactStore::new();
    let result = client.pull(&mut store).unwrap();
    assert_eq!(result.facts_pulled, 2);
    assert_eq!(result.new_cursor.as_deref(), Some("cursor-final"));

    let expected_first_receipt = format!("sync:{base_url}:f_remote_1");
    let first = store.get("f_remote_1").expect("first pulled fact");
    assert_eq!(first.source_receipt.as_deref(), Some(expected_first_receipt.as_str()));
    let expected_second_receipt = format!("sync:{base_url}:f_remote_2");
    let second = store.get("f_remote_2").expect("second pulled fact");
    assert_eq!(second.source_receipt.as_deref(), Some(expected_second_receipt.as_str()));

    let cursor = client.load_cursor();
    assert_eq!(cursor.pull_count, 7);
    assert_eq!(cursor.last_pull_cursor.as_deref(), Some("cursor-final"));
    assert!(cursor.last_pull_at.is_some());

    let requests = wait_for_requests(rx, handle);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].headers.get("authorization").map(String::as_str),
        Some("Bearer test-key")
    );
    assert!(requests[0].path.contains("/v1/facts/export?limit=1000"));
    assert!(requests[0].path.contains("&since=2026-04-07T10:59:00+00:00"));
    assert!(requests[1].path.contains("&since=2026-04-07T10:59:00+00:00"));
    assert!(requests[1].path.contains("&cursor=cursor-2"));
}

#[test]
fn pull_returns_parse_error_for_invalid_json() {
    let (base_url, rx, handle) = start_mock_server(vec![MockResponse::invalid_json("{not-json")]);

    let dir = tempfile::tempdir().unwrap();
    let client = SyncClient::new(&base_url, "test-key", dir.path());
    let mut store = FactStore::new();

    let err = client.pull(&mut store).expect_err("pull should fail");
    assert!(err.contains("sync pull parse error"));

    let requests = wait_for_requests(rx, handle);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
}

#[test]
fn push_batches_local_facts_and_updates_cursor() {
    let (base_url, rx, handle) = start_mock_server(vec![
        MockResponse::json(json!({"ok": true})),
        MockResponse::json(json!({"ok": true})),
    ]);

    let dir = tempfile::tempdir().unwrap();
    let client = SyncClient::new(&format!("{base_url}/"), "test-key", dir.path());
    let mut store = FactStore::new();

    for index in 0..501 {
        store.store(StoreFact {
            entity: format!("entity-{}", index % 3),
            key: format!("key-{index}"),
            value: format!("value-{index}"),
            source_receipt: Some(format!("local-receipt-{index}")),
            confidence: 0.75,
            private: false,
        });
    }
    store.store(StoreFact {
        entity: "finance:payroll".to_string(),
        key: "private".to_string(),
        value: "skip".to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: false,
    });
    store.store_synced(Fact {
        fact_id: "f_synced_skip".to_string(),
        entity: "remote".to_string(),
        key: "k".to_string(),
        value: "synced".to_string(),
        source_receipt: Some("sync:http://remote:14800:f_synced_skip".to_string()),
        confidence: 1.0,
        stored_at: Utc::now(),
        tokens: 1,
        deleted: false,
        version: 1,
        supersedes: None,
        private: false,
    });

    let result = client.push(&store).unwrap();
    assert_eq!(result.facts_pushed, 501);

    let cursor = client.load_cursor();
    assert_eq!(cursor.push_count, 501);
    assert!(cursor.last_push_at.is_some());

    let requests = wait_for_requests(rx, handle);
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| request.method == "PUT"));
    assert!(requests.iter().all(|request| request.path == "/v1/facts/bulk"));
    assert!(requests
        .iter()
        .all(|request| { request.headers.get("authorization").map(String::as_str) == Some("Bearer test-key") }));

    let first_batch: Vec<serde_json::Value> = serde_json::from_slice(&requests[0].body).unwrap();
    let second_batch: Vec<serde_json::Value> = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(first_batch.len() + second_batch.len(), 501);
    assert!(first_batch.len() == 500 || second_batch.len() == 500);
    assert!(first_batch.len() == 1 || second_batch.len() == 1);
    assert!(first_batch
        .iter()
        .chain(second_batch.iter())
        .all(|fact| fact.get("fact_id").is_none()));
}
