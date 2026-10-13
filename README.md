# Harmony Studio Projects

This repository contains the public verification harness for Harmony projects.
Generation, provider logins, account balances, worker claims, memory, sessions,
training inputs and private operational receipts stay outside GitHub Actions.
The intended build boundary is a reviewed generated project plus an exact,
precompiled Rust dependency closure. A separate trusted producer prepares that
closure from encrypted engine inputs.

## Current status

The reviewed initial source commit remains
`d642105c37620107915cadc76442c368d1c0d1ef`. The current keyless Linux ARM checks
at commit `42f9` passed all 71 tests with no skips. The public toolchain build and
isolated identity probe also passed; neither qualifies the SDK or its runtime.
Ten focused encrypted-evidence selection controls passed separately in the local
Root-owned runner. Actual SDK production and cipher delivery have not run.
No SDK release or GitHub secret has been created. Verification, trusted source,
export and public-recipient catalogs start empty. A manual request refuses before
network, decryption or Docker work unless its exact tuple is independently reviewed
and entered in the applicable catalog.

The initial harness includes 24 bundle-guard tests, 7 exporter tests, 19 consumer
tests and 9 producer tests. The toolchain probe adds 12 controls, including one
Linux-only finite-child check. The three Linux-only cases are skipped on macOS;
the initial two passed in GitHub's keyless Linux checks. Docker and image
observations in the probe's unit tests are modeled. Actual tiny Rust compiler/link
controls ran separately under
1.98.1 and 1.99.0. Each compiled a generic engine and its
dependency for Wasm, linked a separate consumer using only the library closure,
rejected a missing dependency, accepted the restored dependency and rejected a
native consumer using Wasm artifacts. These checks do not qualify the full
Moonlight SDK, browser gameplay, native tests or a funded Harmony generation.

## Git-crypt boundary

The repository has a new, separate git-crypt key. The main Project AG key is not
reused. `.gitattributes` encrypts files by default; only the reviewed README,
workflow, harness, test, policy and public toolchain directories are plaintext for bootstrapping
Actions and public review. Keep engine source and private SDK inputs outside
those plaintext directories. Never put a credential, key, transcript or private
receipt in a plaintext exception.

The 454 reviewed SDK files and six trusted starter files are committed under
`engine/sdk`. Their 460 Git blobs were checked for git-crypt's ciphertext header
and decrypted back to the exact reviewed hashes before publication. A sample
retrieved from GitHub was independently confirmed to contain ciphertext.

Git-crypt protects selected Git blobs at rest. It does not hide file names, Git
history metadata, decrypted files or compiler diagnostics. Do not run generated
project code in the trusted source-decryption stage. The separately scoped SDK
key is used only during trusted preparation and removed before credential-free
dependency prefetch and compilation. It is never passed to the generated-project
compiler or browser. Publishing a compiled library also does not conceal every
implementation detail; see the Rust boundary below.

The local key backup is held outside this checkout. Its value and location are
not part of the public repository, workflow logs or uploaded artifacts. A future
trusted producer may receive a separately scoped key through its dedicated
manual preparation step; provider credentials must never be GitHub secrets.

## Manual verification

`verify-project.yml` uses the public Linux ARM runner and pinned action commits.
It has read-only repository permissions and does not persist checkout
credentials. Its default `checks` mode exercises the public fixtures; the
`verify` mode requires an exact approved SDK/project/hash tuple and fresh UUID.
There are no pull-request or fork triggers.

For local focused checks with Python 3.9 or later:

```sh
python3 -I -B -W error -m unittest discover -s tests -p 'test_bundle_guard.py' -v
python3 -I -B -W error -m unittest discover -s tests -p 'test_opaque_sdk.py' -v
python3 -I -B -W error -m unittest discover -s tests -p 'test_ci_verify.py' -v
python3 -I -B -W error -m unittest discover -s tests -p 'test_ci_build_sdk.py' -v
python3 -I -B -W error -m unittest discover -s tests -p 'test_probe_toolchain.py' -v
```

The real consumer harness requires Linux and Docker. SDK/project assets come
from this repository's reviewed release catalog, with exact byte counts and
SHA256 checks. The compiler and browser images also need immutable registry
references and reviewed image identities/contracts. Arbitrary download URLs or
shell commands are not workflow inputs.

Compilation uses an unprivileged, read-only container with no network, no
capabilities, no additional privileges, two CPUs, eight GiB memory and no extra
swap. The browser gets a separate two GiB container only after compiler cleanup
is positively observed. The lifecycle owner retains child process ownership
through cleanup and refuses unknown closure. Neither container mounts agent
homes, `.git`, provider credentials, a decryption key, the Docker socket or raw
private SDK source.

Raw diagnostics remain private to the ephemeral runner. Uploads are limited to
a fixed public result and an exact admitted web inventory. A successful smoke
check is browser boot evidence; complete game rules, reset, win and responsive
layout checks need their own actual gameplay acceptance.

The consumer retains its original 3,900-second deadline through final public
copying, receipt persistence and output. Four focused controls reject late
completion or interruption in the old implementation and pass after the fix;
the original failure remains primary. An upload requires actual verifier exit
zero, together with the guarded receipt and inventory.

## SDK preparation and export

`ci_build_sdk.py` is the separate trusted producer harness. Its source tuple is
reviewed independently of generated projects. Preparation validates encrypted
source identity, freezes the allowed tree and removes the fresh decrypt checkout
and key. Public dependency prefetch has no provider credentials. Compilation
runs offline using the frozen inputs and selected public registry dependencies.
Raw Cargo events, source paths and execution receipts are retained privately.

The existing local compiler image contains private Harmony verifier scripts and
must not be published as the public toolchain. [The toolchain pilot](toolchain/README.md)
uses an observed immutable official Rust ARM64 base and public Debian tools. Its
Dockerfile has no `COPY` or `ADD`. The manual workflow checks the dedicated
context and builds a local unqualified image without a registry login or push.
Its follow-up probe measures the actual image ID, full compiler identity,
standard-library inventory and public package versions in a separate isolated
container. The probe keeps one 120-second budget through cleanup and receipt
persistence. Its only uploaded artifact is the fixed public receipt after an
actual successful probe exit; raw evidence stays in the ephemeral runner.
Image-build provenance, SDK qualification and ABI qualification remain separate
requirements. A passing probe does not establish those requirements. The proposed
manual publication step targets this repository's own GHCR package with an explicit
source label. Publication still requires a fresh image/probe join, immutable
manifest and config identities, and actual anonymous public access. Those checks
have not run for the publication candidate; the earlier local image ID is not a
fetchable registry reference.

The proposed producer return encrypts only the exact Cargo-bound compiled file
inventory and fixed private metadata projections to an approved public age
recipient. A separate success-only upload contains exactly `evidence.tar.age` and
`cipher-receipt.json`. The private identity stays local; CI installs only the
pinned public age binary and receives no decryption identity. Source, the 460-file
encrypted SDK input, source key, raw Cargo logs and provider/agent state are absent
from that return. Host `.rmeta` bytes may return for private inspection with an
explicit unqualified format status; public bundle format checks stay strict.
Cipher delivery grants no public SDK, ABI, full-feature or confidentiality approval.

`opaque_sdk.py` is an explicit exporter, not a compiler or an approval service.
It requires five independently pinned documents: policy, producer receipt,
upload inventory, public SDK manifest and private successful Cargo closure
receipt. It joins compiler identity, target, feature/profile selection, lockfile,
Rust flags, trusted input/environment policy and artifact inventory. It runs the
bundle guard before and after copying an exact artifact directory into a fresh
output. An export is reported as `OPAQUE_SDK_EXPORTED_NOT_QUALIFIED`; a JSON
assertion supplied by an operator cannot prove real compiler execution.

`bundle_guard.py` admits only an exact reviewed inventory for its selected
surface. It rejects unlisted files, private Rust source outside a deliberate
public facade, agent state, key/credential paths, logs, transcripts, encrypted
payloads on public surfaces, nested archives, symlinks and hardlinks. Known
credential/transcript marker checks supplement the inventory policy. They do
not prove that arbitrary text or binary data contains no secret. Current public
limits are 64 MiB per file and 512 MiB per tree; actual SDK size is still an
acceptance input. See [the policy contract](policy/README.md) for schemas and
commands.

Current metadata-envelope admission supports the observed Wasm32 Rust 1.98.1
and 1.99.0 version-10 formats. The link-record codecs differ and are bound to the
primary metadata's compiler release. Unknown, native and Wasm64 metadata
wrappers are refused until separately supported and qualified. Actual 1.99.0
tiny libraries passed the real guard, exporter, mutation/source-extra refusal,
restoration and downstream link controls; 1.98.1 tiny libraries passed a separate
real format check. These are fixture controls, not full SDK approval.

## Rust compatibility and confidentiality

A Rust `.rlib` does not bundle the full dependency graph. Downstream consumers
need the matching transitive libraries and metadata, target standard library,
host proc-macro libraries and native link inputs. Pin the compiler's complete
verbose identity, host and target, flags, features, profile and all file hashes.
Canonical Project AG currently uses Rust 1.99.0; the retained Harmony SDK/image
family uses 1.98.1. These are distinct artifact families and must not be mixed.

Precompiled libraries can omit raw engine source while preserving Rust APIs.
Their metadata still exposes types and dependency relationships, and generic or
inline code requires implementation information. Fat LTO uses LLVM bitcode.
Objects, constants, shaders and symbols can also be inspected. Stripping debug
data and remapping source paths improve hygiene; they do not establish complete
source or algorithm confidentiality.

If hiding those implementation details is required, use a restricted binding
facade with opaque handles and bounded calls/events. That entails an API
migration: current Bevy `App`, `World`, derives/resources and generic callbacks
cannot be preserved merely by replacing source with one `.rlib`.

## Feature profiles

The first intended pilot is the existing Moonlight 2D/UI API for
`wasm32-unknown-unknown` with `web-webgl2`. Every compatible feature set needs its
own compiled and accepted closure:

- `web-webgl2` and `web-webgpu` are mutually exclusive browser profiles.
- `3d`, `scene` and `fog_media` need their corresponding render/dependency graphs;
  `fog_media` includes the patched PBR graph.
- `websocket` and `packed-assets` preserve their target-specific runtime and
  asset contracts. Library packaging does not add session/auth policy.
- Android activity, desktop and mobile builds require their own target libraries
  and host-tool closure. Wasm libraries cannot run native Rust tests.
- Private QA/fixture features stay outside shipped bundles. Desktop development
  ray tracing is not supported in the browser/mobile profile.

There is no universal browser `--all-features` artifact. Preserve features by
qualifying compatible profiles individually. Precompilation may reduce cold
build cost; final linking and fat LTO still need measured memory/time evidence.

## Acceptance before catalog approval

An actual SDK needs successful trusted production, exact artifact/provenance
review, a source-free consumer link with relevant dependency rejection controls,
optimized Wasm/binding/size checks and a source-free browser boot. Game-specific
match/mismatch/win/restart and desktop/compact gameplay remain separate checks.
Native authored tests run with a separately accepted native target. Funded
account/worker/settlement/publication checks run through Harmony's production
authority after the build path is qualified; this repository neither claims jobs
nor changes balances.
