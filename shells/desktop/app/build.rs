// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Tauri build script — generates the app context (config, capabilities, icons)
//! consumed by `tauri::generate_context!()` in `src/main.rs`.

fn main() {
    tauri_build::build();
}
