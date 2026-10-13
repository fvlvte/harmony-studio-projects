#!/usr/bin/env python3
"""Return only encrypted, source-bound compiled evidence; never approve an SDK.

Recipient/tool authority is protected source. Recipient entries require separate review. Only a
public X25519 recipient reaches CI; private identity/keygen stays local to Root.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request
import uuid

APPROVED_EVIDENCE_RECIPIENTS = {'root-age132-linux-arm-v1': {'age_binary_bytes': 6540637,
                              'age_binary_sha256': '41b072352f4561018949623c674d16ef704019b9108a9bbdbd21292efebfc94f',
                              'authorization_id': '1983a072-6dbd-453c-b8a4-24e1a8ef1f10',
                              'qualification_receipt_sha256': 'c70cea151b7a8b26522ba95fc5aaab1eecec3e55609706b33d475c14a21a60d5',
                              'recipient': 'age1v0w3kt6zs3jt8ppahv2qlkk7s4rd995a6ssdha3zflgg4l4q3s8ql6xzcn'}}
VERSION = "1.3.2"
ARCHIVE_URL = "https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-arm64.tar.gz"
ARCHIVE_SHA = "6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4"
ARCHIVE_BYTES = 17771923
MAX_FILE, MAX_TOTAL, MAX_JSON, MAX_TAR, MAX_CIPHER = 64 << 20, 512 << 20, 2 << 20, 520 << 20, 528 << 20
ARCHIVE_NAMES = {"age", "age/age-keygen", "age/age-plugin-tag", "age/age-plugin-batchpass", "age/age-plugin-pq",
                 "age/age-plugin-tagpq", "age/age", "age/LICENSE", "age/age-inspect"}
STOP = None


# Frozen codes from the named public sealer, selection, producer, owner, and
# compiler-identity validators. Runtime dependencies cannot extend this list.
PUBLIC_REFUSAL_CODES = frozenset({
    'absolute_path_required',
    'age_binary_missing',
    'age_binary_pin',
    'age_release_bound',
    'age_release_inventory',
    'age_release_member',
    'age_release_pin',
    'age_release_redirect',
    'age_release_status',
    'age_version',
    'archive_inventory',
    'archive_path',
    'artifact_bijection',
    'artifact_changed',
    'artifact_collision',
    'artifact_count',
    'artifact_directory_alias',
    'artifact_format_magic',
    'artifact_identity',
    'artifact_identity_changed',
    'artifact_inventory',
    'artifact_metadata_invalid',
    'artifact_metadata_mismatch',
    'artifact_output_path',
    'artifact_path',
    'artifact_pin_changed',
    'artifact_role',
    'artifact_role_mismatch',
    'artifact_root_changed',
    'artifact_total_bound',
    'asset_deadline',
    'asset_hash',
    'asset_pin',
    'asset_redirect',
    'asset_size',
    'asset_transport',
    'browser_blank',
    'browser_boot_refused',
    'browser_cleanup_or_web_drift',
    'browser_cli_cleanup',
    'browser_deadline',
    'browser_eof',
    'browser_output_bound',
    'browser_png',
    'browser_png_filter',
    'browser_png_shape',
    'browser_png_size',
    'browser_protocol_bound',
    'browser_runtime_error',
    'build_policy_drift',
    'bundle_guard_refused',
    'cargo_build_not_passed',
    'cargo_contract_mismatch',
    'cargo_dependency_count',
    'cargo_dependency_kind',
    'cargo_dependency_kinds',
    'cargo_dependency_reference',
    'cargo_features',
    'cargo_graph_shape',
    'cargo_inventory_mismatch',
    'cargo_json_bound',
    'cargo_json_invalid',
    'cargo_metadata_invalid',
    'cargo_node_count',
    'cargo_node_identity',
    'cargo_package_count',
    'cargo_package_duplicate',
    'cargo_receipt_mismatch',
    'cargo_root',
    'cargo_targets',
    'case_required',
    'catalog_asset_set',
    'catalog_repository',
    'catalog_tuple',
    'catalog_unapproved',
    'cipher_copy_changed',
    'cipher_format',
    'ciphertext_history_review_mismatch',
    'cleanup_identity',
    'cli_cleanup_unknown',
    'cli_not_closed',
    'command_deadline',
    'command_failed',
    'command_output_bound',
    'compile_closure_join',
    'compile_closure_shape',
    'compile_inventory_join',
    'compile_not_closed',
    'compile_not_successful',
    'compile_original_deadline',
    'compile_receipt_join',
    'compiler_contract',
    'compiler_failed_or_unknown',
    'compiler_identity_mismatch',
    'compiler_not_closed',
    'compiler_receipt',
    'compiler_target_drift',
    'compiler_verbose_mismatch',
    'container_caps',
    'container_cleanup_unknown',
    'container_command_failed',
    'container_contract',
    'container_filesystem_caps',
    'container_id',
    'container_identity',
    'container_mounts',
    'container_not_closed',
    'container_phase_set',
    'copy_bound',
    'copy_hash',
    'copy_identity',
    'copy_path',
    'cpu_affinity',
    'deadline_or_signal',
    'disk_floor',
    'docker_endpoint',
    'duplicate_json_key',
    'encrypted_artifact_refused',
    'encrypted_checkout_dirty',
    'encrypted_source_refused',
    'evidence_deadline',
    'evidence_recipient_contract',
    'evidence_recipient_unapproved',
    'evidence_reserve_exhausted',
    'evidence_root',
    'evidence_source_changed',
    'extract_directory',
    'extract_hash',
    'extract_size',
    'final_cleanup_unknown',
    'fixed_sdk_source_root',
    'foreign_container_present',
    'fresh_tool_root',
    'guard_refused',
    'guard_unavailable',
    'helper_missing',
    'image_contract',
    'image_environment',
    'image_identity',
    'image_inventory',
    'image_pin',
    'image_registry_pin',
    'image_source_policy',
    'input_changed',
    'input_digest_mismatch',
    'input_identity',
    'interrupted',
    'invalid_artifact_root',
    'invalid_authorization',
    'invalid_compiler',
    'invalid_crate',
    'invalid_crate_files',
    'invalid_crates',
    'invalid_dependencies',
    'invalid_digest',
    'invalid_features',
    'invalid_input_file',
    'invalid_inventory',
    'invalid_inventory_row',
    'invalid_output',
    'invalid_path',
    'invalid_producer',
    'invalid_profile',
    'invalid_role',
    'invalid_roots',
    'invalid_sdk_manifest',
    'invalid_source_identity',
    'inventory_bound',
    'inventory_too_large',
    'json_bound',
    'key_disposition_unknown',
    'key_env_in_build',
    'manual_own_repository_required',
    'memory_pressure',
    'metadata_bound',
    'metadata_list',
    'metadata_string',
    'missing_linkable_crate',
    'moonlight_artifact_missing',
    'mount_identity',
    'mount_path',
    'native_link_closure_requires_review',
    'native_linux_arm_required',
    'nonreaping_primitive_required',
    'open_dependency_graph',
    'operation_identity',
    'optimization_policy_drift',
    'output_changed',
    'output_inside_input',
    'owned_session',
    'owner_journal_or_count',
    'owner_receipt',
    'payload_total_bound',
    'plaintext_changed',
    'plaintext_review_required',
    'plaintext_source_refused',
    'prep_tool_identity',
    'prep_tool_pins',
    'prepare_deadline',
    'prepare_failed_or_unknown',
    'prepared_context_drift',
    'private_case_required',
    'private_json_mode',
    'private_metadata_inventory',
    'private_receipt_required',
    'private_record_inventory',
    'private_source_input',
    'producer_deadline',
    'producer_digest_mismatch',
    'project_authority',
    'provenance_inventory_mismatch',
    'public_browser_fields',
    'public_compiler_reference',
    'public_copy_drift',
    'public_destination_exists',
    'public_file_fields',
    'public_inventory',
    'public_receipt_fields',
    'public_receipt_hash',
    'public_receipt_shape',
    'public_receipt_state',
    'public_run_identity',
    'publication_deadline',
    'receipt_changed',
    'receipt_context_drift',
    'registry_alias_refused',
    'registry_copy_failed',
    'registry_credentials_refused',
    'registry_entry_missing',
    'registry_entry_type',
    'registry_io_failure',
    'registry_no_space',
    'registry_os_error',
    'registry_permission_denied',
    'registry_prefetch_command',
    'registry_prefetch_deadline',
    'registry_quota_exceeded',
    'registry_read_only',
    'regular_file_required',
    'release_asset_identity',
    'repository_identity',
    'resource_floor',
    'response_deadline',
    'run_identity',
    'sdk_inventory_mismatch',
    'sdk_key_identity',
    'sdk_profile',
    'seal_cli_unknown',
    'sealed_source_format',
    'sealed_source_size',
    'self_referential_manifest',
    'separate_sdk_key_required',
    'signal_or_deadline',
    'source_authorization',
    'source_bound',
    'source_catalog_identity',
    'source_catalog_pin',
    'source_catalog_schema',
    'source_catalog_tuple',
    'source_catalog_unapproved',
    'source_changed_during_compile',
    'source_contract_hash',
    'source_directory_refused',
    'source_empty',
    'source_inventory_drift',
    'source_or_cleanup_unknown',
    'source_pin_changed',
    'source_pins',
    'source_root',
    'source_still_encrypted',
    'symlink_path_refused',
    'target_mismatch',
    'tool_inventory',
    'tool_root',
    'tool_root_required',
    'toolchain_drift',
    'toolchain_image_identity',
    'unaccepted_cargo_receipt',
    'unbound_artifact',
    'unreachable_crate',
    'unreviewed_sdk_manifest',
    'web_drift',
    'web_entry',
    'web_guard_inventory',
    'web_identity',
    'web_inventory',
    'web_link',
    'web_missing',
    'web_size',
})
FAILURE_STAGES = frozenset(('admission', 'helpers', 'resource_admission', 'case_context', 'install_tool', 'owner_setup', 'tool_pin', 'tool_version', 'payload', 'archive', 'encrypt', 'owner_cleanup', 'postseal_integrity', 'delivery', 'receipt', 'final_validation', 'response', 'final_cleanup', 'terminal_deadline', 'internal_error'))


def refusal_code(error):
    if (isinstance(error, ValueError) and type(error.args) is tuple
            and len(error.args) == 1 and type(error.args[0]) is str
            and error.args[0] in PUBLIC_REFUSAL_CODES):
        return error.args[0]
    return "internal_error"


def exception_category(error, producer=None, verify=None):
    kind = type(error)
    if kind is json.JSONDecodeError: return "json_error"
    if kind in (TimeoutError, subprocess.TimeoutExpired): return "timeout"
    if kind is KeyError: return "key_error"
    if kind is TypeError: return "type_error"
    if kind in (OSError, PermissionError, FileNotFoundError, FileExistsError,
                IsADirectoryError, NotADirectoryError, InterruptedError,
                BlockingIOError, ChildProcessError, ConnectionError,
                BrokenPipeError, ConnectionAbortedError, ConnectionRefusedError,
                ConnectionResetError, ProcessLookupError):
        return "os_error"
    # Only these exact classes from already source-pinned public modules count.
    value_types = (ValueError, getattr(producer, "Refused", None),
                   getattr(verify, "Refused", None), getattr(verify, "ResourceRefused", None))
    if kind in value_types: return "value_error"
    return "unexpected"


def require(value, code):
    if not value: raise ValueError(code)


def canonical(value): return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(raw): return hashlib.sha256(raw).hexdigest()


def regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum, "input_identity")
        raw = stream.read(maximum + 1); after = os.fstat(stream.fileno()); visible = path.lstat()
        require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k) == getattr(visible, k)
                for k in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")), "input_changed")
        return raw


def snapshot():
    root = Path(__file__).resolve().parent
    return {name: digest(regular(root / name, 128 << 10)) for name in
            ("ci_build_sdk.py", "ci_verify.py", "opaque_sdk.py", "bundle_guard.py", "seal_sdk_evidence.py", "evidence_selection.py")}


def module(name, pins):
    path = Path(__file__).resolve().with_name(name + ".py"); raw = regular(path, 128 << 10)
    require(digest(raw) == pins[path.name], "source_pin_changed")
    spec = importlib.util.spec_from_file_location("sealed_" + name, path)
    result = importlib.util.module_from_spec(spec); exec(compile(raw, str(path), "exec"), result.__dict__)
    return result


def recipient():
    ident = os.environ.get("SDK_EVIDENCE_RECIPIENT", "")
    row = APPROVED_EVIDENCE_RECIPIENTS.get(ident)
    require(isinstance(row, dict) and set(row) == {"recipient", "age_binary_sha256", "age_binary_bytes",
            "qualification_receipt_sha256", "authorization_id"}, "evidence_recipient_unapproved")
    require(re.fullmatch(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", row["recipient"])
            and all(re.fullmatch(r"[0-9a-f]{64}", row[k]) for k in ("age_binary_sha256", "qualification_receipt_sha256"))
            and type(row["age_binary_bytes"]) is int and 0 < row["age_binary_bytes"] <= 32 << 20
            and str(uuid.UUID(row["authorization_id"])) == row["authorization_id"], "evidence_recipient_contract")
    return row


def private_json(path, verify):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, "private_json_mode")
    raw = regular(path, MAX_JSON)
    return verify.document(raw, MAX_JSON), raw


def tool(root, row):
    require(root.is_absolute() and root.resolve() == root and root.is_dir() and not root.is_symlink()
            and root.stat().st_uid == os.getuid() and stat.S_IMODE(root.stat().st_mode) == 0o700, "tool_root")
    require({p.name for p in root.iterdir()} == {"age"}, "tool_inventory")
    raw = regular(root / "age", 32 << 20)
    require(len(raw) == row["age_binary_bytes"] and digest(raw) == row["age_binary_sha256"]
            and raw[:6] == b"\x7fELF\x02\x01" and int.from_bytes(raw[18:20], "little") == 183
            and os.access(root / "age", os.X_OK), "age_binary_pin")
    return root / "age"


class Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self): self.count = 0
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        self.count += 1; url = urllib.parse.urlsplit(newurl)
        require(self.count <= 3 and url.scheme == "https" and url.hostname in
                {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
                and not url.username and not url.password and url.port in (None, 443), "age_release_redirect")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def install(root, row, clock):
    require(root.is_absolute() and root.resolve() == root and not root.exists() and not root.is_symlink(), "fresh_tool_root")
    clock(); opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirects())
    with opener.open(urllib.request.Request(ARCHIVE_URL, headers={"User-Agent": "sealed-sdk-evidence/1"}), timeout=8) as response:
        require(response.status == 200, "age_release_status")
        data = bytearray()
        while True:
            clock(); block = response.read(1 << 20)
            if not block: break
            data.extend(block); require(len(data) <= ARCHIVE_BYTES, "age_release_bound")
    require(len(data) == ARCHIVE_BYTES and digest(data) == ARCHIVE_SHA, "age_release_pin"); clock()
    root.mkdir(mode=0o700); found = False; total = 0; count = 0; seen = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            clock(); count += 1; total += member.size; path = PurePosixPath(member.name)
            name = member.name.rstrip("/") if member.isdir() else member.name
            require(name in ARCHIVE_NAMES and name not in seen and (member.isdir() if name == "age" else member.isfile()), "age_release_inventory")
            seen.add(name)
            require(count <= 9 and 0 <= member.size <= 32 << 20 and total <= 64 << 20 and not path.is_absolute()
                    and all(p not in ("", ".", "..") for p in path.parts) and path.parts and path.parts[0] == "age"
                    and (member.isfile() or member.isdir()) and not member.issym() and not member.islnk()
                    and not member.pax_headers, "age_release_member")
            if member.name != "age/age": continue
            require(not found and member.isfile(), "age_release_member"); found = True
            source = archive.extractfile(member); require(source is not None, "age_release_member")
            raw = source.read(member.size + 1); require(len(raw) == member.size, "age_release_member")
            fd = os.open(root / "age", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
            with os.fdopen(fd, "wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    require(seen == ARCHIVE_NAMES and count == 9, "age_release_inventory")
    require(found, "age_binary_missing"); tool(root, row); clock()


def artifact_bytes(root, item, *, with_identity=False):
    relative = PurePosixPath(item["compiler_output"])
    # No traversal or recursive compiler-output/cache collection. Every ancestor
    # is opened relative to its retained FD with O_NOFOLLOW.
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        leaf = os.open(relative.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
        with os.fdopen(leaf, "rb") as source:
            before = os.fstat(source.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == item["bytes"], "artifact_identity")
            raw = source.read(MAX_FILE + 1); after = os.fstat(source.fileno())
            visible = os.stat(relative.name, dir_fd=fd, follow_symlinks=False)
            fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
            require(len(raw) == item["bytes"] and len(raw) <= MAX_FILE and digest(raw) == item["sha256"]
                    and all(getattr(before, k) == getattr(after, k) == getattr(visible, k) for k in fields),
                    "artifact_pin_changed")
        # Metadata returns under the exact Cargo/file/hash join for private
        # inspection. Its byte format and ABI are deliberately unqualified;
        # the public bundle guard retains its stricter supported-format rules.
        require(raw.startswith(b"!<arch>\n") if item["role"] == "opaque_rlib" else
                relative.suffix == ".rmeta" if item["role"] == "opaque_metadata" else
                raw[:6] == b"\x7fELF\x02\x01" and int.from_bytes(raw[18:20], "little") == 183, "artifact_format_magic")
        return (raw, tuple(getattr(before, k) for k in fields)) if with_identity else raw
    finally: os.close(fd)


def bound_artifact_selection(candidate, receipt, selection, exporter):
    chosen = selection.exact_artifact_selection(candidate, receipt)
    # This is the producer's exact maintained plain-inventory serialization,
    # including its no-newline scope; do not substitute this module's canonical.
    inventory_sha = exporter.digest(exporter.canonical(exporter.plain_inventory(candidate["artifact_inventory"])))
    require(receipt["artifact_inventory_sha256"] == inventory_sha, "compile_inventory_join")
    return chosen


def payload(case, producer, verify, selection, context, row, operation, pins, clock):
    candidate, candidate_raw = private_json(case / "artifact-candidate.private.json", verify)
    receipt, receipt_raw = private_json(case / "cargo-closure.private.json", verify)
    closed, closed_raw = private_json(case / "producer-closure.private.json", verify)
    require(set(candidate) == {"schema_version", "state", "operation", "source_revision", "authorization_id", "input_inventory_sha256",
            "environment_policy_sha256", "profile", "features", "compiler", "target", "resources_closed", "files", "artifact_inventory",
            "cargo_metadata", "cargo_receipt_sha256", "gaps"}
            and set(receipt) == {"schema_version", "producer", "source_revision", "authorization_id", "state", "exit_code", "timed_out",
            "resources_closed", "unknown_owners", "compiler", "target", "features", "profile", "rustflags_sha256", "lockfile_sha256",
            "input_inventory_sha256", "environment_policy_sha256", "artifact_inventory_sha256"}
            and set(closed) == {"schema_version", "operation", "state", "source_pins", "cli", "containers", "kernel_observation_source",
            "original_exit_code", "stop_signal", "source_unchanged", "started_monotonic", "hard_monotonic"}, "private_metadata_inventory")
    record_keys = {"package_id", "name", "version", "target", "features", "profile", "kind", "compiler_output", "public_path", "role"}
    require(all(set(record) == record_keys for record in candidate["files"]), "private_record_inventory")
    require(candidate["operation"] == operation and candidate["source_revision"] == row["source_revision"]
            and candidate["authorization_id"] == row["authorization_id"]
            and candidate["cargo_receipt_sha256"] == digest(receipt_raw), "compile_receipt_join")
    require(closed["schema_version"] == 1 and closed["state"] == "COMPILE_OWNER_CLOSURE_SOURCE_SNAPSHOT"
            and closed["operation"] == operation and closed["source_pins"] == pins and closed["original_exit_code"] == 0
            and closed["stop_signal"] is None and closed["source_unchanged"] is True, "compile_closure_join")
    # Reuse the same strict snapshot projection, excluding every argv/log/mount.
    class ClosedOwner: pass
    historical = ClosedOwner(); historical.journal_failed = False
    historical.children = closed["cli"]; historical.containers = closed["containers"]
    check = selection.owner_closure_projection(historical, operation, pins)
    require(all(closed[k] == check[k] for k in check), "compile_closure_shape")
    require(closed["started_monotonic"] == context["started_monotonic"]
            and closed["hard_monotonic"] == context["started_monotonic"] + 3900, "compile_original_deadline")
    chosen = bound_artifact_selection(candidate, receipt, selection, module("opaque_sdk", pins))
    projected = {k: candidate[k] for k in ("schema_version", "state", "operation", "source_revision", "authorization_id",
        "input_inventory_sha256", "environment_policy_sha256", "profile", "features", "compiler", "target", "resources_closed",
        "files", "artifact_inventory", "cargo_receipt_sha256", "gaps")}
    projected["cargo_graph"] = selection.cargo_graph_projection(candidate["cargo_metadata"])
    projected["artifact_format_status"] = [{"path": item["path"], "state":
        "format_unqualified_private_return" if item["role"] == "opaque_metadata" else
        "magic_sanity_only_not_qualified"} for item in chosen]
    bodies = {"metadata/artifact-candidate.json": canonical(projected), "metadata/cargo-closure.json": receipt_raw,
              "metadata/producer-closure.json": canonical(closed)}
    require(all(len(raw) <= MAX_JSON for raw in bodies.values()), "metadata_bound")
    total = sum(len(raw) for raw in bodies.values()); identities = {}
    for item in chosen:
        clock(); raw, identity = artifact_bytes(case / "compiler-output", item, with_identity=True)
        identities[item["path"]] = identity
        bodies[item["path"]] = raw; total += len(raw); require(total <= MAX_TOTAL, "payload_total_bound")
    inventory = [{"path": path, "bytes": len(raw), "sha256": digest(raw)} for path, raw in sorted(bodies.items())]
    inventory_raw = canonical({"schema_version": 1, "files": inventory})
    require(len(inventory_raw) <= MAX_JSON, "inventory_bound")
    bodies["metadata/inventory.json"] = inventory_raw
    clock(); require(snapshot() == pins, "source_pin_changed")
    return bodies, digest(inventory_raw), len(inventory) + 1, {"candidate": digest(candidate_raw), "receipt": digest(receipt_raw), "closed": digest(closed_raw)}, chosen, identities


def archive_payload(path, bodies, clock):
    require(sum(len(raw) for raw in bodies.values()) <= MAX_TOTAL + MAX_JSON, "payload_total_bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, raw in sorted(bodies.items()):
                clock(); member = tarfile.TarInfo(name); member.size = len(raw)
                member.mode = 0o600; member.uid = member.gid = member.mtime = 0; member.uname = member.gname = ""
                tar.addfile(member, io.BytesIO(raw))
        stream.flush(); os.fsync(stream.fileno())
    clock(); raw = regular(path, MAX_TAR); return digest(raw), path.lstat()


def main(argv=None):
    global STOP
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True, choices=("admit", "install", "seal"))
    parser.add_argument("--case", type=Path); parser.add_argument("--tool-root", type=Path)
    args = parser.parse_args(argv); owner = None; verify = None; result = 1; primary = None
    producer = None; stage = "admission"
    # Facts concern this sealer's Owner only; None is unobserved, booleans describe the latest close attempt.
    diagnostic = {"failure_stage": "admission", "refusal_code": None, "exception_category": None,
                  "owner_close_called": None, "owner_close_succeeded": None, "cleanup_refusal_code": None}
    def close_owner():
        diagnostic["owner_close_called"] = True
        diagnostic["owner_close_succeeded"] = False
        value = owner.close()
        diagnostic["owner_close_succeeded"] = value is True
        return value
    def late_failure(failure_stage, code, error=None):
        if diagnostic["refusal_code"] is None:
            diagnostic.update(failure_stage=failure_stage, refusal_code=code,
                              exception_category=exception_category(error, producer, verify) if error is not None else None)
    public_created = False; plain = None; plain_identity = None; hard = None; scope = False; STOP = None
    def clock():
        require(STOP is None, "interrupted"); require(hard is not None and time.monotonic() < hard - 30, "evidence_deadline")
    def stopped(signum, frame):
        global STOP
        if STOP is None: STOP = signum
        if verify is not None and verify.STOP is None: verify.STOP = signum
    try:
        pins = snapshot(); producer = module("ci_build_sdk", pins); selection = module("evidence_selection", pins)
        row, operation = producer.approval(os.environ); approved = recipient()
        if args.phase == "admit":
            print(canonical({"schema_version": 1, "state": "evidence_tuple_admitted_not_qualified", "SDK_qualified": False}).decode(), end="")
            return 0
        stage = "helpers"
        verify, _ = producer.helpers(); verify.STOP = None
        stage = "resource_admission"
        verify.linux_resources()
        require(args.tool_root is not None, "tool_root_required")
        if args.phase == "install":
            started = time.monotonic(); hard = started + 120
        else:
            stage = "case_context"
            require(args.case is not None and args.case.is_absolute() and args.case.resolve() == args.case, "case_required")
            context = producer.prepared(args.case, row, operation, verify)
            started = context["started_monotonic"]; hard = started + 3900
        scope = True
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM): signal.signal(number, stopped)
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        signal.setitimer(signal.ITIMER_REAL, max(.001, hard - time.monotonic())); clock()
        if args.phase == "install":
            stage = "install_tool"
            install(args.tool_root, approved, clock)
            evidence = args.tool_root.parent / ("age-install-evidence-" + uuid.uuid4().hex); evidence.mkdir(mode=0o700)
            stage = "owner_setup"
            owner = verify.Owner(evidence, started=hard - 3900)
        else:
            evidence = args.case / "seal-private"; evidence.mkdir(mode=0o700)
            stage = "owner_setup"
            owner = verify.Owner(evidence, started=started)
        diagnostic["owner_close_called"] = False
        stage = "tool_pin"
        binary = tool(args.tool_root, approved)
        stage = "tool_version"
        observed = owner.command([str(binary), "--version"], 5).decode().strip()
        require(observed in (VERSION, "v" + VERSION), "age_version")
        if args.phase == "seal":
            stage = "payload"
            clock(); require(shutil.disk_usage(args.case).free >= 10 * 1024**3, "disk_floor")
            bodies, inventory_sha, count, receipts, chosen, identities = payload(args.case, producer, verify, selection, context, row, operation, pins, clock)
            stage = "archive"
            plain = evidence / "selected-evidence.tar"; plain_sha, plain_identity = archive_payload(plain, bodies, clock)
            del bodies
            cipher = evidence / "evidence.tar.age"
            stage = "encrypt"
            owner.command([str(binary), "--encrypt", "--recipient", approved["recipient"], "--output", str(cipher), str(plain)],
                          min(60, owner.remaining(60)))
            stage = "owner_cleanup"
            clock(); require(close_owner() and owner.children and all(r["reaped"] and r["group_closed"] for r in owner.children), "seal_cli_unknown")
            stage = "postseal_integrity"
            tool(args.tool_root, approved); require(snapshot() == pins, "source_pin_changed")
            for name, wanted in (("artifact-candidate.private.json", receipts["candidate"]), ("cargo-closure.private.json", receipts["receipt"]),
                                 ("producer-closure.private.json", receipts["closed"])):
                require(digest(regular(args.case / name, MAX_JSON)) == wanted, "receipt_changed")
            for item in chosen:
                clock(); _, identity = artifact_bytes(args.case / "compiler-output", item, with_identity=True)
                require(identity == identities[item["path"]], "artifact_identity_changed")
            current = plain.lstat(); require((current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
                    == (plain_identity.st_dev, plain_identity.st_ino, plain_identity.st_size, plain_identity.st_mtime_ns)
                    and digest(regular(plain, MAX_TAR)) == plain_sha, "plaintext_changed")
            plain.unlink(); plain = None
            cipher_raw = regular(cipher, MAX_CIPHER)
            require(cipher_raw.startswith(b"age-encryption.org/v1\n") and len(cipher_raw) > 100, "cipher_format")
            stage = "delivery"
            clock(); public = Path.cwd() / ".sdk-cipher-evidence"; public.mkdir(mode=0o700); public_created = True
            final = public / "evidence.tar.age"
            fd = os.open(final, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream: stream.write(cipher_raw); stream.flush(); os.fsync(stream.fileno())
            clock(); require(digest(regular(final, MAX_CIPHER)) == digest(cipher_raw), "cipher_copy_changed")
            stage = "receipt"
            receipt = {"schema_version": 1, "state": "ENCRYPTED_PRIVATE_PRODUCER_EVIDENCE_DELIVERED_NOT_QUALIFIED",
                "operation_id": operation, "source_revision": row["source_revision"], "cipher_bytes": len(cipher_raw), "cipher_sha256": digest(cipher_raw),
                "recipient_sha256": digest(approved["recipient"].encode()), "age_binary_sha256": approved["age_binary_sha256"],
                "plaintext_inventory_sha256": inventory_sha, "files_count": count, "compile_original_exit": 0,
                "owned_compile_closed": True, "owned_seal_cli_closed": True, "sdk_qualified": False, "abi_qualified": False}
            verify.save(public / "cipher-receipt.json", receipt)
            require({p.name for p in public.iterdir()} == {"evidence.tar.age", "cipher-receipt.json"}, "public_inventory")
        stage = "final_validation"
        clock(); require(close_owner() and snapshot() == pins, "source_or_cleanup_unknown")
        stage = "response"
        print(canonical({"schema_version": 1, "state": "public_age_installed" if args.phase == "install" else "encrypted_evidence_delivered_not_qualified", "SDK_qualified": False}).decode(), end="", flush=True)
        clock(); result = 0
    except Exception as error:
        primary = "encrypted_evidence_refused_or_failed"
        diagnostic.update(failure_stage=stage if stage in FAILURE_STAGES else "internal_error",
                          refusal_code=refusal_code(error), exception_category=exception_category(error, producer, verify))
    finally:
        if owner is not None:
            try:
                if not close_owner():
                    result = 1
                    diagnostic["cleanup_refusal_code"] = "source_or_cleanup_unknown"
                    late_failure("final_cleanup", "source_or_cleanup_unknown")
            except Exception as error:
                result = 1
                diagnostic["cleanup_refusal_code"] = refusal_code(error)
                late_failure("final_cleanup", refusal_code(error), error)
        if STOP is not None or (hard is not None and time.monotonic() >= hard - 30):
            result = 1
            late_failure("terminal_deadline", "interrupted" if STOP is not None else "evidence_deadline")
        if result != 0 and public_created and verify is not None:
            try: verify.save(Path.cwd() / ".sdk-cipher-evidence/cipher-receipt.json", {"schema_version": 1, "state": "failed", "code": primary or "cleanup_or_deadline_unknown", "sdk_qualified": False})
            except Exception: pass
        if diagnostic["refusal_code"] is not None:
            try: print(canonical({"schema_version": 1, "state": "failed", "code": primary or "cleanup_or_deadline_unknown",
                                  "SDK_qualified": False, **diagnostic}).decode(), end="", flush=True)
            except OSError: pass
        if scope:
            signal.setitimer(signal.ITIMER_REAL, 0)
            for number in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM): signal.signal(number, signal.SIG_DFL)
    if result == 0 and (STOP is not None or hard is None or time.monotonic() >= hard - 30): return 1
    return result


if __name__ == "__main__": raise SystemExit(main())
