#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = corecrux_storage::fuzz_scan_frames_v1_block_bytes(data);
});
