# Public bundle admission

The bundle guard admits one exact reviewed inventory for one public surface. A
caller must obtain the expected policy SHA-256 from a protected, independently
reviewed catalog or controller. A payload, project request, pull request, model,
or producer cannot authorize itself by supplying its own expected hash. The
current catalog is empty: no actual opaque SDK or public facade is approved.
The existing source-export SDK is private and must be refused.

Public repository storage and public runtime payloads have different boundaries.
Encrypted engine inputs may be stored separately for a trusted producer under the
repository's git-crypt policy. They are never admitted to model context, generated
compiler inputs, browser inputs, or uploads. Only a trusted producer may decrypt
such inputs and propose a compiled artifact closure for independent review. The
guard rejects git-crypt ciphertext, credentials, known agent state, and known
provider transcripts in every public profile, even when their bytes match an
otherwise approved file row. It does not decrypt files.

## Surfaces and roles

- **public-sdk** admits reviewed opaque Rust libraries, metadata, host procedural
  macro binaries, explicit native link dependencies, documented public facade
  files, exact build metadata, and public assets. The role names are opaque_rlib,
  opaque_metadata, opaque_proc_macro, opaque_native_link, public_facade,
  build_metadata, and public_asset.
- **model-context** admits only public_facade and public_document. Rust sources,
  compiled libraries, private SDK implementations, and provider state are refused.
- **public-project** admits authorized project_source, public_asset, and
  public_document files. It does not authorize SDK implementation sources.
- **public-upload** admits only public_asset files from a dedicated export tree.
  Source bundles, SDK artifacts, producer controls, and raw executor logs are not
  upload files.

Every role belongs to an explicit file row. No directory glob, extension alone,
filename convention, archive label, or secret-pattern scan creates authorization.
Rust public facade source is permitted only beneath facade/ in public-sdk.
Project source is limited to src/, tests/, assets/, public/, or the explicit root
project metadata names maintained in tools/bundle_guard.py. Build metadata is
limited to Cargo.toml, Cargo.lock, build.json, size-budget.json,
rust-toolchain.toml, .cargo/config.toml, and sdk-manifest.json. All other hidden
files are refused. Cargo target/cache directories are refused; reviewed libraries
can use a distinct layout such as lib/wasm32-unknown-unknown/.

The compiled roles check format boundaries rather than compiler correctness.
Libraries must be standard ar archives, never thin external-reference archives;
their members must be recognized object or Rust metadata entries, never source
files or nested archives. Metadata starts with the Rust metadata marker. Object
and macro roles require a recognized object-file marker. Actual compiler,
toolchain, dependency closure, target, profile, API compatibility, and runtime
qualification remain the producer/exporter and maintained acceptance owners'
responsibility. The guard does not build or load these artifacts.

## Exact control schemas

All schemas reject extra keys, duplicate JSON keys, nonfinite numbers, noninteger
sizes, duplicate paths, case collisions, and file/directory collisions. SHA-256
values are 64 lowercase hexadecimal characters. UUIDs use canonical lowercase
hyphenated form. source_revision is a lowercase 40-character Git revision or a
64-character source inventory digest. Control JSON files are at most 2 MiB.

The trusted policy has exactly these fields:

~~~json
{
  "schema_version": 1,
  "review_id": "00000000-0000-4000-8000-000000000001",
  "surface": "public-sdk",
  "producer_receipt_sha256": "<exact SHA-256 of the producer receipt bytes>",
  "files": [
    {"path": "<canonical relative file>", "role": "<allowed role>",
     "bytes": 1, "sha256": "<exact file SHA-256>"}
  ]
}
~~~

The independently pinned producer receipt has exactly these fields:

~~~json
{
  "schema_version": 1,
  "producer": "trusted-rust-artifact-producer/1",
  "source_revision": "<reviewed Git revision or source inventory SHA-256>",
  "authorization_id": "00000000-0000-4000-8000-000000000002",
  "surface": "public-sdk",
  "files": [
    {"path": "<canonical relative file>", "bytes": 1, "sha256": "<exact file SHA-256>"}
  ]
}
~~~

The producer identifiers are trusted-rust-artifact-producer/1 for public-sdk,
reviewed-public-context/1 for model-context, authorized-project-export/1 for
public-project, and controller-web/v1 for public-upload. These strings are not
signatures. Their authority comes from the independently protected policy hash
and its exact receipt-byte join. Actual compiler and closure qualification is
separate evidence and must not be inferred from an accepted producer string.

The upload manifest is a projection with no private source or control metadata:

~~~json
{
  "schema_version": 1,
  "files": [
    {"path": "<canonical relative file>", "bytes": 1, "sha256": "<exact file SHA-256>"}
  ]
}
~~~

All three inventories must match exactly after sorting by path. Placeholder
strings in these examples are intentionally not valid digests and cannot be
used as an admission policy.

## Invocation and consumer contract

The CLI accepts exactly one payload mode, a directory or a ZIP archive. Keep the
policy, producer receipt, upload manifest, and fresh report outside the payload
directory. ZIP files are inspected before extraction; unknown or private member
names are rejected before their bodies are opened.

~~~text
python3 -I -B tools/bundle_guard.py --surface public-sdk \
  --archive SDK.zip --policy reviewed-policy.json \
  --policy-sha256 PROTECTED_POLICY_SHA256 \
  --provenance producer-receipt.json --manifest upload-manifest.json \
  --report FRESH_REPORT.json
~~~

Use --root DIRECTORY instead of --archive ZIP for a dedicated directory.
--producer-receipt is an alias for --provenance. A successful report has exactly
schema_version, state, surface, files, policy_sha256, provenance_sha256, and
manifest_sha256. state is passed. Rejection produces a fixed code with no payload
text or raw private paths. Reports are created exclusively with mode 0600 and
are never overwritten. An existing report causes failure.

Python callers use validate_bundle(root=..., archive=None, surface=...,
policy_path=..., policy_sha256=..., provenance_path=..., manifest_path=...). The
API returns a passed report or raises BundleError carrying a fixed code; it
never returns a failed report as a successful result.

An authoritative CLI acceptance requires exit status zero and the matching
fresh passed report with the expected policy, provenance, and manifest digests.
A leftover report after failed receipt persistence is not acceptance. API
callers must require the passed state and preserve their own execution evidence.
The guard observes bytes during its call; consumers must copy or upload only the
exact admitted files, recheck size and hash at consumption, and refuse later
changes. Never replace the manifest with a wildcard upload of the directory.

For a dynamically generated web export, a protected controller may create a
new policy and controller-web/v1 receipt from the actual admitted project,
reviewed compiler result, and dedicated web inventory. The controller must bind
the project's authorization and source revision and preserve its actual
compiler/browser closure evidence. A project or model cannot submit its own
replacement policy to authorize unreviewed output. The browser receives only
the admitted web export after compiler teardown, with no SDK or producer input.

## Filesystem and content bounds

The guard permits at most 4096 files, 64 MiB per file, and 512 MiB in total.
Paths are canonical relative ASCII POSIX paths at most 240 characters long.
Directories and files are traversed through file descriptors without following
symlinks. Regular single-link files and stable inode, size, mode, and timestamps
are required. Symlinks, hardlinks, sockets, FIFOs, devices, aliases, encrypted ZIP
members, unsupported archive members, case collisions, and nested archives are
refused. Directory inventories are checked again after all bodies are hashed;
ZIP archive identity is checked before and after its members are read.

Known .codex, .cursor, .claude, .ssh, .agents, auth, credential, agent-memory,
cache, provider-log, transcript, rollout, private SDK source-pack, and key-file
names are refused. Additional body checks reject git-crypt ciphertext, private
key headers, known credential assignments and JSON fields, known reasoning and
provider-transcript records, and known private host-path fields. JSON-shaped
.bin and .txt payloads receive the same structural JSON checks as .json files.
These checks are supplemental defenses, not proof that arbitrary or encoded
bytes contain no secrets. Review must account for constants, symbols, paths,
and metadata that compiled artifacts can embed.

The guard cannot determine model training data, inspect unavailable provider
memory, or prove semantic confidentiality of every binary. Independent producer
review, protected policy authority, isolated execution, explicit file closure,
and actual maintained acceptance remain necessary. Encrypted data or a passing
synthetic test cannot substitute for these boundaries.

## Qualification evidence

tests/test_bundle_guard.py authors modeled positive and negative admission cases,
including opaque format shapes, source-export refusal before member-body reads,
provenance drift, exact inventory checks, filesystem special objects, ciphertext,
known credential and transcript payloads, and fixed failure reports. These
fixtures are not an actual compiled SDK or provider run. Test execution and
counts must be recorded by the executor. A real opaque SDK requires separate
reviewed toolchain and dependency receipts, a reviewed public facade catalog,
and actual generated-project compiler/browser acceptance before activation.
