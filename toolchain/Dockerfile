# Public toolchain pilot; no SDK, Harmony scripts, provider CLI or browser.
# Official Rust 1.98.1 slim-bookworm Linux ARM64 platform manifest, observed
# separately by the owner. A digest pin does not qualify its runtime behavior.
FROM --platform=linux/arm64 rust:1.98.1-slim-bookworm@sha256:3ebe98baef5911f8461cf81ba05644374a3c5ef1f8a33db3977bd4175f5ff1fc

LABEL org.opencontainers.image.source="https://github.com/fvlvte/harmony-studio-projects" \
      online.harmony.upstream.source="https://github.com/rust-lang/docker-rust" \
      org.opencontainers.image.base.name="docker.io/library/rust:1.98.1-slim-bookworm" \
      org.opencontainers.image.base.digest="sha256:3ebe98baef5911f8461cf81ba05644374a3c5ef1f8a33db3977bd4175f5ff1fc" \
      online.harmony.role="public-sdk-toolchain" \
      online.harmony.contract="public-toolchain-pilot/v1" \
      online.harmony.qualification="unqualified"

# These are public Debian tools. Future admission must record the actual
# package/toolchain inventory and image ID; apt contents are not frozen here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add --toolchain 1.98.1 wasm32-unknown-unknown

ENV PATH="/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    RUSTUP_HOME="/usr/local/rustup" \
    RUSTUP_AUTO_INSTALL="0" \
    HOME="/tmp/home" \
    LANG="C.UTF-8"

USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["/usr/bin/env"]
CMD ["cargo", "+1.98.1", "--version"]
