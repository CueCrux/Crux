// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Smoke-test report types + summariser — used by `corecruxctl smoke run` and CI parity gates.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SmokeReport {
    pub ok: bool,
    pub device_index: i32,
    pub device_name: String,
    pub cuda_driver_version: Option<String>,
    pub kernel: String,
    pub n: u32,
}

pub fn run(_device_index: i32) -> Result<SmokeReport, Box<dyn std::error::Error + Send + Sync>> {
    Err("corecruxctl was built without CUDA support (Crux Daemon is CPU-only)".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn run_returns_error_on_cpu_build() {
        let result = run(0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("CPU-only"),
            "expected CPU-only message, got: {err}"
        );
    }

    #[test]
    fn run_returns_error_for_any_device_index() {
        for idx in [-1, 0, 1, 42] {
            let result = run(idx);
            assert!(result.is_err());
        }
    }

    #[test]
    fn smoke_report_serializes() {
        let report = SmokeReport {
            ok: false,
            device_index: 0,
            device_name: "cpu".to_string(),
            cuda_driver_version: None,
            kernel: "none".to_string(),
            n: 0,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["ok"], false);
        assert_eq!(json["device_name"], "cpu");
        assert!(json.get("cuda_driver_version").is_some());
    }
}
