# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).

# --- Builder stage ---
# Chainguard exception (workspace CLAUDE.md §9): the build stage stays on the
# upstream `rust` image because the workspace pins its toolchain via
# rust-toolchain.toml (channel 1.88.0) and needs rustup to honour that pin;
# cgr.dev/chainguard/rust free tier is :latest-only (floating toolchain), which
# would silently drift the compiler under a pinned, reproducible release build.
FROM rust:1.88-bookworm AS builder

RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY proto/ proto/
# corecruxctl embeds integrations/claude-code/hooks/crux-observe.sh via
# include_str! (the `corecruxctl hooks install` asset), so it must be present in
# the build context for the release build to compile.
COPY integrations/ integrations/

# Git sha for `corecruxd --version` / the boot banner. The build context does
# NOT include `.git`, so corecruxd's build.rs cannot derive it via `git` here —
# the CI Docker workflow passes it as a build-arg. Defaults to `unknown` for a
# plain `docker build` with no arg.
ARG GIT_SHA=unknown
ENV CORECRUX_GIT_SHA=${GIT_SHA}

# Stamp the release version into the embedded console footer. Set to the git tag
# (e.g. v0.5.17) on tag builds, empty on main/edge and plain `docker build`. The
# `__CRUX_RELEASE__` placeholder lives in the console HTML and is compiled into
# corecruxd via include_str!, so it must be substituted before `cargo build`.
# Empty value → the console footer falls back to the build commit.
ARG RELEASE_VERSION=
RUN sed -i "s|__CRUX_RELEASE__|${RELEASE_VERSION}|g" crates/corecruxd/playground/index.html

RUN cargo build --locked --release --bin corecruxd --bin corecruxctl

# --- Runtime stage ---
# Chainguard wolfi-base (CLAUDE.md §9): rebuilt daily, zero-known-CVE target,
# minimal package set. Free tier requires the :latest tag (accepted).
FROM cgr.dev/chainguard/wolfi-base:latest

# Runtime packages:
# - ca-certificates: TLS trust for optional *opt-in* outbound features (sync,
#   remote embedding endpoints). The daemon dials nothing by default — see
#   scripts/assert-no-phone-home.sh.
# - curl: container HEALTHCHECK probe.
# - git: the update-posture probe (update.rs) shells out to `git fetch`/
#   `git rev-list` against the /repo bind mount on repo-checkout deploys to
#   compute ahead/behind. Without git the fetch silently fails and the banner
#   reports a confidently-wrong drift count from the stale cached tracking ref.
RUN apk add --no-cache ca-certificates curl git

COPY --from=builder /build/target/release/corecruxd /usr/local/bin/corecruxd
COPY --from=builder /build/target/release/corecruxctl /usr/local/bin/corecruxctl

# Non-root runtime user: wolfi-base ships `nonroot` (uid/gid 65532), the
# Chainguard/distroless convention. /data ownership transfers to named volumes
# on first use (bind-mount users must chown the host dir themselves — see
# examples/quickstart/README.md).
RUN mkdir -p /data && chown -R 65532:65532 /data

ENV CORECRUXD_DATA_DIR=/data
ENV CORECRUXD_BUILD_CCXI=1
ENV CORECRUX_LOG_FORMAT=json

EXPOSE 14800

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:14800/readyz || exit 1

VOLUME ["/data"]

USER 65532:65532

CMD ["corecruxd"]
