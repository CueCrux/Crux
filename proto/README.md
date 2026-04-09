# CoreCrux Proto Definitions

Module: **buf.build/cuecrux/corecrux**

## Services

| Proto file | Package | Services |
|---|---|---|
| `corecrux_dataplane_v1.proto` | `corecrux.dataplane.v1` | `CoreCruxDataPlaneV1`, `CoreCruxExportV1` |
| `corecrux_observe_v1.proto` | `corecrux.observe.v1` | `CoreCruxObserveV1` |

## Generating client code

### From the Buf Schema Registry (BSR)

After the module is published, consumers can pull generated code directly:

**Go**
```bash
# Add to buf.gen.yaml or use go module proxy
go get buf.build/gen/go/cuecrux/corecrux/protocolbuffers/go
go get buf.build/gen/go/cuecrux/corecrux/grpc/go
```

**Python**
```bash
pip install cuecrux-corecrux  # if published to PyPI via BSR
# Or generate locally:
buf generate buf.build/cuecrux/corecrux
```

**TypeScript**
```bash
npm install @buf/cuecrux_corecrux.bufbuild_es @buf/cuecrux_corecrux.connectrpc_es
```

### Local generation

From the `proto/` directory:

```bash
buf generate
```

This writes generated code to `gen/go/`, `gen/python/`, and `gen/ts/` (gitignored).

## Rust

The Rust server uses `tonic-prost-build` via `crates/corecrux-proto/build.rs` and does not use buf for code generation. The proto files are the shared source of truth for both paths.

## Breaking change policy

Breaking changes are checked on every pull request against the `main` branch using `buf breaking` with the `FILE` category. This catches:

- Removing or renaming messages, fields, services, or RPCs
- Changing field numbers or types
- Changing stream/unary mode on RPCs

Non-breaking additions (new messages, new fields, new RPCs) are always safe.

Pushing to the BSR happens only on GitHub releases, so published tags are guaranteed stable.
