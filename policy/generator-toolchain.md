# Public ARM generator formatter image

Status: reviewed candidate; no hosted build or publication is implied.

`build-generator` is a manual-only sibling of `build-toolchain`. It builds on
native `ubuntu-24.04-arm` and never enters the encrypted SDK workflow. The Docker
context is exactly `tools/generator-context/{Dockerfile,.dockerignore}`: the
reviewed Rust 1.99.0 ARM64 platform manifest and one public Rustfmt installation.
There are no COPY/ADD instructions, source SDK, project source, provider CLI,
credentials or agent homes in that context. The two existing context files are
byte-pinned; the helper refuses extra files, symlinks and byte changes. Both paths
are under the existing plaintext `tools/**` Git attribute.

The workflow defaults to `checks`. `build` creates a runner-local unqualified
image and runs the generator-specific identity probe. `publish` builds and probes
that same image before invoking the sibling publisher. After owner review and a
new-repository commit, the dispatch is:

```sh
gh workflow run build-generator.yml --repo fvlvte/harmony-studio-projects --ref main -f mode=publish
```

The image is a public native formatter toolchain, with default entrypoint
`rustfmt`; it is not the SDK compiler image. Its probe overrides that entrypoint
with a fixed clean-environment shell command, verifies native Rust 1.99.0,
Cargo/Rustfmt versions and executable hashes, and requires actual isolated
container exit plus positive owned CLI/container closure. It does not require
Python or Wasm standard libraries in the image. The pinned existing Linux Owner
retains its native ARM, 16 GB total/40% available and strict PSI resource guards.
The probe keeps a single 120-second budget; the publication helper keeps its
original 300/270/30-second work/cleanup contract. The hosted build CLI is separately
bounded to 900 seconds and GitHub owns its daemon/VM lifecycle.

Only the publish step receives the workflow-scoped GitHub token. Login uses stdin
and a fresh private Docker configuration; credentials are removed before the
anonymous read and immutable pull. Publication requires the fresh probe/source/
context/image joins, distinct manifest/config digest checks and exact
`ghcr.io/fvlvte/harmony-studio-projects/generator@sha256:...` identity. A new GHCR
package may initially be private: anonymous verification must actually succeed
before a publication receipt is accepted. No raw build/probe logs are uploaded;
the success-only artifact contains the two typed public receipts.

The existing compiler context, workflow, helpers, registry role and protected SDK
catalog are unchanged. The local tests model Docker and registry responses; they
establish refusals, ownership joins and deadline/privacy handling, not a hosted
image, layer inventory, actual registry access, SDK compatibility or model pass.
After a real published image is pulled on the Mac, the existing image/tool/layer
and runtime admission contracts still determine whether it can replace the old
formatter. No SDK or live runtime is automatically approved by publication.
