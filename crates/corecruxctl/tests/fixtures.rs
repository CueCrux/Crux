// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::fs;
use std::path::PathBuf;

use corecruxctl::replay::{replay_digest_from_jsonl, ReplayDigest};
use corecruxctl::stage1_import::import_stage1_events_log;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn write_stage1_record(mut out: impl std::io::Write, payload: &str) {
    let bytes = payload.as_bytes();
    let len = u32::try_from(bytes.len()).expect("payload length fits u32");
    out.write_all(&len.to_be_bytes()).expect("write len");
    out.write_all(bytes).expect("write payload");
    let crc = crc32c::crc32c(bytes);
    out.write_all(&crc.to_be_bytes()).expect("write crc32c");
}

#[test]
fn replay_digest_matches_expected_fixture() {
    let fixtures_dir = repo_root().join("tests/fixtures_v3/minimal");
    let jsonl = fixtures_dir.join("events.v3.jsonl");
    let expected_path = fixtures_dir.join("expected_digest.json");

    let expected: ReplayDigest =
        serde_json::from_str(&fs::read_to_string(expected_path).expect("read expected digest"))
            .expect("parse expected digest");

    let actual = replay_digest_from_jsonl(&jsonl).expect("compute digest");
    assert_eq!(actual.total_events, expected.total_events);
    assert_eq!(actual.per_stream_last_seq, expected.per_stream_last_seq);
    assert_eq!(actual.digest_blake3, expected.digest_blake3);
}

#[test]
fn import_v1_produces_deterministic_digest() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let stage1_events = tmp.path().join("events.stage1");
    {
        let mut f = fs::File::create(&stage1_events).expect("create stage1 log");
        write_stage1_record(
            &mut f,
            r#"{"eventId":"evt-1","tenantId":"tenant-a","streamId":"stream-1","streamType":"answers","seq":1,"occurredAt":"2026-02-06T23:59:59Z","eventType":"test.append"}"#,
        );
        write_stage1_record(
            &mut f,
            r#"{"eventId":"evt-2","tenantId":"tenant-a","streamId":"stream-1","streamType":"answers","seq":2,"occurredAt":"2026-02-07T00:00:01Z","eventType":"test.append"}"#,
        );
    }

    let result = import_stage1_events_log(&stage1_events, tmp.path()).expect("import v1");
    assert_eq!(result.records, 2);
    let digest_path = PathBuf::from(result.expected_digest_json);
    let jsonl_path = PathBuf::from(result.output_jsonl);

    let expected: ReplayDigest =
        serde_json::from_str(&fs::read_to_string(digest_path).expect("read digest"))
            .expect("parse digest");
    let actual = replay_digest_from_jsonl(&jsonl_path).expect("compute digest");

    assert_eq!(actual.digest_blake3, expected.digest_blake3);
    assert_eq!(actual.total_events, expected.total_events);
    assert_eq!(actual.per_stream_last_seq, expected.per_stream_last_seq);
}
