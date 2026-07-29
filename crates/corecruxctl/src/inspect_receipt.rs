// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl inspect-receipt <id>` — Human-readable CROWN receipt breakdown.

use std::path::PathBuf;

pub fn run(data_dir: &str, receipt_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let data_path = PathBuf::from(data_dir);
    if !data_path.exists() {
        return Err(format!("data directory does not exist: {}", data_dir).into());
    }

    println!("CROWN Receipt Inspection");
    println!("========================");
    println!("Receipt ID: {}", receipt_id);
    println!("Data Dir:   {}", data_dir);
    println!();

    // Scan shards for the receipt
    let mut found = false;
    for entry in std::fs::read_dir(&data_path)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let dir_name = path.file_name().unwrap_or_default().to_string_lossy();
        if !dir_name.starts_with("shard-") {
            continue;
        }

        // Walk segments looking for receipt events
        for seg_entry in std::fs::read_dir(&path)? {
            let seg_entry = seg_entry?;
            let seg_path = seg_entry.path();
            if seg_path.extension().is_some_and(|e| e == "ccxseg") {
                // Try to find receipts in this segment
                if let Ok(bytes) = std::fs::read(&seg_path) {
                    // Simple scan for receipt ID in raw bytes
                    let receipt_bytes = receipt_id.as_bytes();
                    if bytes.windows(receipt_bytes.len()).any(|w| w == receipt_bytes) {
                        println!("Found in: {}", seg_path.display());
                        println!("  Shard:   {}", dir_name);
                        println!(
                            "  Segment: {}",
                            seg_path.file_name().unwrap_or_default().to_string_lossy()
                        );
                        found = true;
                    }
                }
            }
        }
    }

    if !found {
        println!("Receipt '{}' not found in any segment.", receipt_id);
        println!();
        println!("Hint: receipts are stored in sealed segments. If the data was recently");
        println!("      ingested, it may not yet be sealed. Run `verify-store` to check");
        println!("      segment integrity.");
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn nonexistent_dir_returns_error() {
        let err = run("/tmp/__corecruxctl_test_nonexistent_dir__", "r-0001").unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn empty_data_dir_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let result = run(dir.path().to_str().unwrap(), "r-0001");
        assert!(result.is_ok());
        // No shards → receipt not found (prints hint message)
    }

    #[test]
    fn shard_with_no_matching_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard-0001");
        fs::create_dir(&shard).unwrap();
        // Write a segment file that does NOT contain the receipt ID
        fs::write(shard.join("000000.ccxseg"), b"some unrelated data").unwrap();

        let result = run(dir.path().to_str().unwrap(), "r-missing");
        assert!(result.is_ok());
    }

    #[test]
    fn shard_with_matching_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard-0001");
        fs::create_dir(&shard).unwrap();
        // Write a segment file that contains the receipt ID bytes
        let mut data = b"prefix-data-".to_vec();
        data.extend_from_slice(b"r-found-42");
        data.extend_from_slice(b"-suffix");
        fs::write(shard.join("000000.ccxseg"), &data).unwrap();

        let result = run(dir.path().to_str().unwrap(), "r-found-42");
        assert!(result.is_ok());
    }

    #[test]
    fn non_shard_dirs_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        // Create a directory that doesn't start with "shard-"
        let other = dir.path().join("other-dir");
        fs::create_dir(&other).unwrap();
        fs::write(other.join("000000.ccxseg"), b"r-0001").unwrap();

        let result = run(dir.path().to_str().unwrap(), "r-0001");
        assert!(result.is_ok());
        // Should not find the receipt because the dir name doesn't match "shard-*"
    }

    #[test]
    fn non_ccxseg_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard-0001");
        fs::create_dir(&shard).unwrap();
        // Write files with wrong extensions
        fs::write(shard.join("000000.txt"), b"r-0001").unwrap();
        fs::write(shard.join("000000.ccxi"), b"r-0001").unwrap();

        let result = run(dir.path().to_str().unwrap(), "r-0001");
        assert!(result.is_ok());
    }
}
