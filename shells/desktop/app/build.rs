// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Tauri build script — generates the app context (config, capabilities, icons)
//! consumed by `tauri::generate_context!()` in `src/main.rs`.

fn main() {
    tauri_build::build();
}
