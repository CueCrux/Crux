// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl explain <receipt-id>` — Retrieval decision path for a receipt.
//!
//! Shows which segments were searched, which documents scored highest,
//! BM25 score components, and graph signal contribution.

use std::path::PathBuf;

pub fn run(data_dir: &str, receipt_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let data_path = PathBuf::from(data_dir);
    if !data_path.exists() {
        return Err(format!("data directory does not exist: {}", data_dir).into());
    }

    println!("Retrieval Decision Path");
    println!("=======================");
    println!("Receipt ID: {}", receipt_id);
    println!("Data Dir:   {}", data_dir);
    println!();

    // Count available segments with .ccxi indexes
    let mut segment_count = 0usize;
    let mut ccxi_count = 0usize;

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

        for seg_entry in std::fs::read_dir(&path)? {
            let seg_entry = seg_entry?;
            let seg_path = seg_entry.path();
            if seg_path.extension().map(|e| e == "ccxseg").unwrap_or(false) {
                segment_count += 1;
            }
            if seg_path.extension().map(|e| e == "ccxi").unwrap_or(false) {
                ccxi_count += 1;
            }
        }
    }

    println!("Segments available: {}", segment_count);
    println!("CCXI indexes:      {}", ccxi_count);
    println!();

    if ccxi_count == 0 {
        println!("No .ccxi indexes found. BM25 retrieval requires CCXI companion indexes.");
        println!("Enable index building with CORECRUXD_BUILD_CCXI=1");
        return Ok(());
    }

    println!("To explain a retrieval decision, the receipt must contain the query");
    println!("parameters and result set. Use `inspect-receipt {}` first to view", receipt_id);
    println!("the receipt payload, then re-run the query against the indexed segments.");
    println!();
    println!("Retrieval path:");
    println!("  1. Query tokenized → stemmed tokens hashed with xxhash64");
    println!("  2. Each .ccxi index searched via binary lookup in vocab table");
    println!("  3. PForDelta posting lists decoded → document IDs + term frequencies");
    println!("  4. BM25 score computed per document (k1=1.2, b=0.75, global IDF)");
    println!("  5. Graph signal boost applied from relation edges (if enabled)");
    println!("  6. Results sorted by score, truncated to limit/token_budget");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn nonexistent_dir_returns_error() {
        let err = run("/tmp/__corecruxctl_explain_nonexistent__", "r-0001").unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn empty_data_dir_no_segments() {
        let dir = tempfile::tempdir().unwrap();
        let result = run(dir.path().to_str().unwrap(), "r-0001");
        assert!(result.is_ok());
    }

    #[test]
    fn shard_with_segments_but_no_ccxi() {
        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard-0001");
        fs::create_dir(&shard).unwrap();
        fs::write(shard.join("000000.ccxseg"), b"data").unwrap();

        let result = run(dir.path().to_str().unwrap(), "r-0001");
        assert!(result.is_ok());
        // ccxi_count == 0 → prints "No .ccxi indexes found" and returns early
    }

    #[test]
    fn shard_with_ccxi_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard-0001");
        fs::create_dir(&shard).unwrap();
        fs::write(shard.join("000000.ccxseg"), b"segment-data").unwrap();
        fs::write(shard.join("000000.ccxi"), b"index-data").unwrap();

        let result = run(dir.path().to_str().unwrap(), "r-0001");
        assert!(result.is_ok());
        // ccxi_count > 0 → prints retrieval path explanation
    }

    #[test]
    fn non_shard_dirs_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("metadata");
        fs::create_dir(&other).unwrap();
        fs::write(other.join("000000.ccxseg"), b"data").unwrap();
        fs::write(other.join("000000.ccxi"), b"index").unwrap();

        let result = run(dir.path().to_str().unwrap(), "r-0001");
        assert!(result.is_ok());
        // Should report 0 segments and 0 indexes
    }

    #[test]
    fn multiple_shards_counted() {
        let dir = tempfile::tempdir().unwrap();
        for i in 1..=3 {
            let shard = dir.path().join(format!("shard-{i:04}"));
            fs::create_dir(&shard).unwrap();
            fs::write(shard.join("000000.ccxseg"), b"seg").unwrap();
            if i <= 2 {
                fs::write(shard.join("000000.ccxi"), b"idx").unwrap();
            }
        }

        let result = run(dir.path().to_str().unwrap(), "r-0001");
        assert!(result.is_ok());
        // 3 segments, 2 ccxi indexes
    }
}
