#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = corecrux_segment::decoder::decode_segment_v1(data);
});
