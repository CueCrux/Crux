# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).

# --- Builder stage ---
FROM rust:1.84-bookworm AS builder

RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY proto/ proto/

RUN cargo build --release --bin corecruxd --bin corecruxctl

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/corecruxd /usr/local/bin/corecruxd
COPY --from=builder /build/target/release/corecruxctl /usr/local/bin/corecruxctl

RUN mkdir -p /data

ENV CORECRUXD_DATA_DIR=/data
ENV CORECRUXD_BUILD_CCXI=1
ENV CORECRUX_LOG_FORMAT=json

EXPOSE 14800

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:14800/readyz || exit 1

VOLUME ["/data"]

CMD ["corecruxd"]
