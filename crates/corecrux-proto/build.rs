// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    let proto_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto");

    let dataplane_proto = proto_dir.join("corecrux_dataplane_v1.proto");
    let observe_proto = proto_dir.join("corecrux_observe_v1.proto");

    println!("cargo:rerun-if-changed={}", dataplane_proto.display());
    println!("cargo:rerun-if-changed={}", observe_proto.display());

    tonic_build::configure().compile_protos(
        &[dataplane_proto, observe_proto],
        &[&proto_dir],
    )?;
    Ok(())
}
