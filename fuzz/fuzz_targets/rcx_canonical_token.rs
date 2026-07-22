#![no_main]

use libfuzzer_sys::fuzz_target;
use rcx_capability_token::{free_local_verified_fixture, verify_token, DataEgressClass};

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = crux_session::canonical::decode(data) {
        let _ = value.encode();
    }

    let token = free_local_verified_fixture();
    let _ = token.validate_basic(1_776_989_601);
    let _ = token.permits_egress(
        data,
        1_776_989_601,
        "local",
        "corecrux.query.local",
        DataEgressClass::None,
    );
    let _ = verify_token(&token, data, 1_776_989_601);
});
