// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::path::PathBuf;

use corecruxctl::ingest::{execute, IngestOptions};

#[test]
fn dry_run_chunks_fixture_directory_without_network() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures_ingest");
    let report = execute(&IngestOptions {
        path,
        tenant: "local".to_string(),
        corpus: "docs".to_string(),
        daemon_url: "http://127.0.0.1:1".to_string(),
        dry_run: true,
        embed: true,
    })?;

    assert_eq!(report.files_walked, 3);
    assert_eq!(report.files_ingested, 2);
    assert_eq!(report.skipped_files, 1);
    assert!(report.chunks >= 3);
    assert_eq!(report.documents_prepared, 2);
    assert_eq!(report.documents_sealed, 0);
    assert!(report.batches >= 1);
    assert!(report.dry_run);
    assert!(!report.embedded);
    assert!(report.seals.is_empty());
    Ok(())
}
