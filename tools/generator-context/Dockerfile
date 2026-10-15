# Public formatter only. No private SDK, verifier, policy or operator files.
FROM rust:1.99.0-slim-trixie@sha256:bd61df3270f144e8b72b5e6108cd3dcd8ff3e97ffa9bc05d27061e8e82f57728
RUN rustup component add --toolchain 1.99.0 rustfmt
ENV RUSTUP_AUTO_INSTALL=0
USER 65532:65532
ENTRYPOINT ["rustfmt"]
