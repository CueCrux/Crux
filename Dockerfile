# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).

# --- Builder stage ---
FROM rust:1.84-bookworm AS builder

RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY proto/ proto/

# Git sha for `corecruxd --version` / the boot banner. The build context does
# NOT include `.git`, so corecruxd's build.rs cannot derive it via `git` here —
# the CI Docker workflow passes it as a build-arg. Defaults to `unknown` for a
# plain `docker build` with no arg.
ARG GIT_SHA=unknown
ENV CORECRUX_GIT_SHA=${GIT_SHA}

RUN cargo build --release --bin corecruxd --bin corecruxctl

# --- Runtime stage ---
FROM debian:bookworm-slim

# git is required at runtime: the daemon's update-check (update.rs) shells out
# to `git fetch`/`git rev-list` against the /repo bind mount to compute
# ahead/behind. Without git the fetch silently fails and the banner reports a
# confidently-wrong drift count from the stale cached tracking ref.
# TODO(hygiene): evaluate cgr.dev/chainguard runtime base (CLAUDE.md §9)
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git && rm -rf /var/lib/apt/lists/*

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
