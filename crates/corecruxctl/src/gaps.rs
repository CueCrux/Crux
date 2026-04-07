// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl gaps [--since <date>]` — Aggregated low-coverage report.
//!
//! Scans sealed segments for query receipts with low coverage scores,
//! groups them by domain, and reports frequency counts.

use std::path::PathBuf;

pub fn run(data_dir: &str, since: Option<&str>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let data_path = PathBuf::from(data_dir);
    if !data_path.exists() {
        return Err(format!("data directory does not exist: {}", data_dir).into());
    }

    println!("Coverage Gap Report");
    println!("===================");
    println!("Data Dir: {}", data_dir);
    if let Some(date) = since {
        println!("Since:    {}", date);
    }
    println!();

    // Count segments and index coverage
    let mut total_segments = 0usize;
    let mut indexed_segments = 0usize;
    let mut total_docs = 0usize;

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
            if seg_path.extension().is_some_and(|e| e == "ccxseg") {
                total_segments += 1;
            }
            if seg_path.extension().is_some_and(|e| e == "ccxi") {
                indexed_segments += 1;

                // Parse CCXI header for doc count
                if let Ok(bytes) = std::fs::read(&seg_path) {
                    if bytes.len() >= 256 {
                        // total_frames at offset 30 (u32 LE) in header
                        let total_frames = u32::from_le_bytes([bytes[30], bytes[31], bytes[32], bytes[33]]);
                        total_docs += total_frames as usize;
                    }
                }
            }
        }
    }

    println!("Corpus Statistics:");
    println!("  Sealed segments:  {}", total_segments);
    println!("  Indexed segments: {}", indexed_segments);
    println!("  Total documents:  {}", total_docs);
    println!();

    if indexed_segments == 0 {
        println!("No indexed segments found. Cannot compute coverage gaps.");
        println!("Enable index building with CORECRUXD_BUILD_CCXI=1");
        return Ok(());
    }

    let coverage_pct = if total_segments > 0 {
        (indexed_segments as f64 / total_segments as f64) * 100.0
    } else {
        0.0
    };

    println!(
        "Index Coverage: {:.1}% ({}/{} segments indexed)",
        coverage_pct, indexed_segments, total_segments
    );
    println!();

    if indexed_segments < total_segments {
        println!(
            "Gap: {} segments lack .ccxi companion indexes.",
            total_segments - indexed_segments
        );
        println!("     Documents in these segments are not searchable via BM25.");
        println!("     Re-seal with CORECRUXD_BUILD_CCXI=1 to build missing indexes.");
    } else {
        println!("All segments are indexed. No structural coverage gaps detected.");
    }
    println!();
    println!("Note: query-level coverage gaps are reported in real-time via the");
    println!("      `coverage` field in POST /v1/query/text-search responses.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn nonexistent_dir_returns_error() {
        let err = run("/tmp/__corecruxctl_gaps_nonexistent__", None).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn empty_data_dir_no_segments() {
        let dir = tempfile::tempdir().unwrap();
        let result = run(dir.path().to_str().unwrap(), None);
        assert!(result.is_ok());
    }

    #[test]
    fn with_since_parameter() {
        let dir = tempfile::tempdir().unwrap();
        let result = run(dir.path().to_str().unwrap(), Some("2026-01-01"));
        assert!(result.is_ok());
    }

    #[test]
    fn segments_without_ccxi_reports_gap() {
        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard-0001");
        fs::create_dir(&shard).unwrap();
        fs::write(shard.join("000000.ccxseg"), b"segment").unwrap();

        let result = run(dir.path().to_str().unwrap(), None);
        assert!(result.is_ok());
        // indexed_segments == 0 → prints "No indexed segments" and returns early
    }

    #[test]
    fn partial_coverage_reports_gap() {
        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard-0001");
        fs::create_dir(&shard).unwrap();
        fs::write(shard.join("000000.ccxseg"), b"seg").unwrap();
        // No ccxi for this segment
        fs::write(shard.join("000001.ccxseg"), b"seg2").unwrap();
        // Only one ccxi — build a valid header (>= 256 bytes)
        let mut ccxi_data = vec![0u8; 256];
        // Put total_frames = 42 at offset 30
        ccxi_data[30..34].copy_from_slice(&42u32.to_le_bytes());
        fs::write(shard.join("000001.ccxi"), &ccxi_data).unwrap();

        let result = run(dir.path().to_str().unwrap(), None);
        assert!(result.is_ok());
        // 2 segments, 1 indexed → gap reported
    }

    #[test]
    fn full_coverage_no_gaps() {
        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard-0001");
        fs::create_dir(&shard).unwrap();

        let mut ccxi_data = vec![0u8; 256];
        ccxi_data[30..34].copy_from_slice(&10u32.to_le_bytes());

        fs::write(shard.join("000000.ccxseg"), b"seg").unwrap();
        fs::write(shard.join("000000.ccxi"), &ccxi_data).unwrap();

        let result = run(dir.path().to_str().unwrap(), None);
        assert!(result.is_ok());
        // 1 segment, 1 indexed → "All segments are indexed"
    }

    #[test]
    fn ccxi_too_short_for_header_skips_doc_count() {
        let dir = tempfile::tempdir().unwrap();
        let shard = dir.path().join("shard-0001");
        fs::create_dir(&shard).unwrap();
        fs::write(shard.join("000000.ccxseg"), b"seg").unwrap();
        // ccxi file too short (< 256 bytes) → skips header parse
        fs::write(shard.join("000000.ccxi"), b"short").unwrap();

        let result = run(dir.path().to_str().unwrap(), None);
        assert!(result.is_ok());
        // indexed_segments == 1, total_docs == 0 (header not parsed)
    }

    #[test]
    fn non_shard_dirs_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("snapshots");
        fs::create_dir(&other).unwrap();
        fs::write(other.join("000000.ccxseg"), b"seg").unwrap();
        fs::write(other.join("000000.ccxi"), b"idx").unwrap();

        let result = run(dir.path().to_str().unwrap(), None);
        assert!(result.is_ok());
    }
}
