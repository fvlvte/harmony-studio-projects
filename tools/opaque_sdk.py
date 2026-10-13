#!/usr/bin/env python3
"""Copy an explicitly reviewed Rust artifact closure; never build or qualify it.

No repository, SDK source ZIP, credential home, compiler log or Cargo cache is
discovered here. All input inventories and producer evidence are explicit. A
successful export proves copying/guard checks, not binary confidentiality, API
compatibility, compiler execution or generated-project acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import uuid

MAX_JSON = 2 * 1024 * 1024
MAX_FILES = 4096
MAX_BYTES = 2 * 1024 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\Z")
ROLES = {"opaque_rlib", "opaque_metadata", "opaque_proc_macro",
         "opaque_native_link", "public_facade", "build_metadata", "public_asset"}
COMPILED = {"opaque_rlib", "opaque_metadata", "opaque_proc_macro", "opaque_native_link"}
PRODUCER = "trusted-rust-artifact-producer/1"


class ExportError(ValueError):
    """Fixed public error codes only; private paths/payloads stay private."""


def require(value, code):
    if not value:
        raise ExportError(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def exact(value, keys, code):
    require(isinstance(value, dict) and value.keys() == set(keys), code)


def sha(value):
    require(isinstance(value, str) and SHA.fullmatch(value), "invalid_digest")
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def no_duplicates(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate_json_key")
        result[name] = value
    return result


def path_name(value):
    require(isinstance(value, str) and len(value) <= 240, "invalid_path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.parts and str(path) == value,
            "invalid_path")
    require(all(re.fullmatch(r"[A-Za-z0-9_.+-]+", part) and part not in (".", "..")
                for part in path.parts), "invalid_path")
    return value


def pinned_json(path, expected):
    sha(expected)
    require(path.is_absolute(), "absolute_path_required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= MAX_JSON, "invalid_input_file")
        data = bytearray()
        while len(data) <= MAX_JSON:
            block = os.read(fd, 65536)
            if not block:
                break
            data.extend(block)
        after = os.fstat(fd)
        require(identity(before) == identity(after) and len(data) == before.st_size,
                "input_changed")
        require(digest(data) == expected, "input_digest_mismatch")
        try:
            return json.loads(data, object_pairs_hook=no_duplicates,
                              parse_constant=lambda _: (_ for _ in ()).throw(ExportError("nonfinite_json")))
        except (UnicodeError, json.JSONDecodeError):
            raise ExportError("invalid_json") from None
    finally:
        os.close(fd)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_gid)


def inventory(rows, with_roles=False):
    require(isinstance(rows, list) and 1 <= len(rows) <= MAX_FILES, "invalid_inventory")
    expected_keys = {"path", "bytes", "sha256"} | ({"role"} if with_roles else set())
    result = {}
    total = 0
    for row in rows:
        exact(row, expected_keys, "invalid_inventory_row")
        name = path_name(row["path"])
        require(name not in result and type(row["bytes"]) is int
                and 0 < row["bytes"] <= MAX_BYTES, "invalid_inventory_row")
        sha(row["sha256"])
        if with_roles:
            require(row["role"] in ROLES, "invalid_role")
        result[name] = row
        total += row["bytes"]
    require(total <= MAX_BYTES, "inventory_too_large")
    return result


def plain_inventory(rows):
    return sorted(({key: row[key] for key in ("path", "bytes", "sha256")}
                   for row in rows), key=lambda row: row["path"])


def compiler(value, expected_release, expected_host):
    exact(value, {"release", "commit_hash", "commit_date", "host", "llvm_version",
                  "verbose_version", "executable_sha256", "sysroot_sha256"}, "invalid_compiler")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["release"] or "")
            and value["release"] == expected_release and value["host"] == expected_host,
            "compiler_identity_mismatch")
    require(re.fullmatch(r"[0-9a-f]{40}", value["commit_hash"] or "")
            and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value["commit_date"] or "")
            and IDENT.fullmatch(value["host"] or "")
            and re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", value["llvm_version"] or ""),
            "invalid_compiler")
    verbose = value["verbose_version"]
    require(isinstance(verbose, str) and len(verbose) <= 1024, "invalid_compiler")
    lines = verbose.splitlines()
    first = re.fullmatch(r"rustc " + re.escape(expected_release)
            + r" \(([0-9a-f]{7,40}) ([0-9]{4}-[0-9]{2}-[0-9]{2})\)", lines[0]) if lines else None
    require(len(lines) == 7 and first is not None
            and value["commit_hash"].startswith(first.group(1))
            and value["commit_date"] == first.group(2)
            and lines[1:] == ["binary: rustc", "commit-hash: " + value["commit_hash"],
                "commit-date: " + value["commit_date"], "host: " + expected_host,
                "release: " + expected_release, "LLVM version: " + value["llvm_version"]],
            "compiler_verbose_mismatch")
    sha(value["executable_sha256"])
    sha(value["sysroot_sha256"])


def sdk_contract(value, expected_release, expected_host, expected_target):
    exact(value, {"schema_version", "kind", "compiler", "target", "features", "profile",
                  "rustflags_sha256", "lockfile_sha256", "input_inventory_sha256",
                  "environment_policy_sha256", "cargo_receipt_sha256", "roots", "crates", "files"},
          "invalid_sdk_manifest")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["kind"] == "rust-precompiled-sdk/1", "invalid_sdk_manifest")
    compiler(value["compiler"], expected_release, expected_host)
    require(value["target"] == expected_target and IDENT.fullmatch(expected_target),
            "target_mismatch")
    features = value["features"]
    require(isinstance(features, list) and len(features) <= 64
            and all(isinstance(item, str) and IDENT.fullmatch(item) for item in features)
            and features == sorted(set(features)), "invalid_features")
    require(not ("web-webgl2" in features and "web-webgpu" in features), "invalid_features")
    require(not (expected_target == "wasm32-unknown-unknown" and "raytracing" in features),
            "invalid_features")
    profile = value["profile"]
    exact(profile, {"name", "opt_level", "lto", "codegen_units", "panic", "debug", "incremental"},
          "invalid_profile")
    require(IDENT.fullmatch(profile["name"] or "") and profile["opt_level"] in ("0", "1", "2", "3", "s", "z")
            and profile["lto"] in ("off", "thin", "fat") and type(profile["codegen_units"]) is int
            and 1 <= profile["codegen_units"] <= 256 and profile["panic"] in ("abort", "unwind")
            and profile["debug"] is False and profile["incremental"] is False, "invalid_profile")
    for key in ("rustflags_sha256", "lockfile_sha256", "input_inventory_sha256",
                "environment_policy_sha256", "cargo_receipt_sha256"):
        sha(value[key])
    files = inventory(value["files"], with_roles=True)
    require("sdk-manifest.json" not in files, "self_referential_manifest")
    crates = value["crates"]
    require(isinstance(crates, list) and 1 <= len(crates) <= MAX_FILES, "invalid_crates")
    nodes = {}
    claimed = set()
    for crate in crates:
        exact(crate, {"identity", "name", "version", "kind", "features", "dependencies", "files"},
              "invalid_crate")
        key = sha(crate["identity"])
        require(key not in nodes and IDENT.fullmatch(crate["name"] or "")
                and IDENT.fullmatch(crate["version"] or "")
                and crate["kind"] in ("target", "host_proc_macro", "native_link"), "invalid_crate")
        require(isinstance(crate["features"], list)
                and crate["features"] == sorted(set(crate["features"]))
                and all(isinstance(item, str) and IDENT.fullmatch(item) for item in crate["features"]),
                "invalid_crate")
        require(isinstance(crate["dependencies"], list)
                and len(crate["dependencies"]) == len(set(crate["dependencies"]))
                and all(isinstance(item, str) and SHA.fullmatch(item) for item in crate["dependencies"]),
                "invalid_dependencies")
        require(isinstance(crate["files"], list) and crate["files"] and len(crate["files"]) == len(set(crate["files"])),
                "invalid_crate_files")
        allowed = {"target": {"opaque_rlib", "opaque_metadata"},
                   "host_proc_macro": {"opaque_proc_macro"}, "native_link": {"opaque_native_link"}}[crate["kind"]]
        for name in crate["files"]:
            require(name in files and name not in claimed and files[name]["role"] in allowed,
                    "invalid_crate_files")
            claimed.add(name)
        if crate["kind"] == "target":
            require(any(files[name]["role"] == "opaque_rlib" for name in crate["files"]),
                    "missing_linkable_crate")
        nodes[key] = crate
    require(claimed == {name for name, row in files.items() if row["role"] in COMPILED},
            "unbound_artifact")
    require(all(dep in nodes for crate in crates for dep in crate["dependencies"]),
            "open_dependency_graph")
    roots = value["roots"]
    require(isinstance(roots, list) and roots and len(roots) == len(set(roots))
            and all(root in nodes for root in roots), "invalid_roots")
    reached, pending = set(), list(roots)
    while pending:
        key = pending.pop()
        if key not in reached:
            reached.add(key)
            pending.extend(nodes[key]["dependencies"])
    require(reached == set(nodes), "unreachable_crate")
    return files


def proof_join(policy, producer, upload, sdk, cargo, sdk_rows, sdk_hash, cargo_hash):
    exact(policy, {"schema_version", "review_id", "surface", "producer_receipt_sha256", "files"}, "invalid_policy")
    exact(producer, {"schema_version", "producer", "source_revision", "authorization_id", "surface", "files"},
          "invalid_producer")
    exact(upload, {"schema_version", "files"}, "invalid_upload_manifest")
    require(all(type(value["schema_version"]) is int and value["schema_version"] == 1
                for value in (policy, producer, upload))
            and policy["surface"] == producer["surface"] == "public-sdk"
            and producer["producer"] == PRODUCER, "invalid_producer")
    require(re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", producer["source_revision"] or ""),
            "invalid_source_identity")
    for identity_value in (policy["review_id"], producer["authorization_id"]):
        require(str(uuid.UUID(identity_value)) == identity_value, "invalid_authorization")
    approved = inventory(policy["files"], with_roles=True)
    manifest_row = approved.get("sdk-manifest.json")
    require(manifest_row is not None and manifest_row["role"] == "build_metadata"
            and manifest_row["sha256"] == sdk_hash, "unreviewed_sdk_manifest")
    require({name: row for name, row in approved.items() if name != "sdk-manifest.json"} == sdk_rows,
            "sdk_inventory_mismatch")
    plain = plain_inventory(list(approved.values()))
    require(plain == plain_inventory(list(inventory(producer["files"]).values()))
            == plain_inventory(list(inventory(upload["files"]).values())), "provenance_inventory_mismatch")
    exact(cargo, {"schema_version", "producer", "source_revision", "authorization_id", "state", "exit_code",
                  "timed_out", "resources_closed", "unknown_owners", "compiler", "target", "features",
                  "profile", "rustflags_sha256", "lockfile_sha256", "input_inventory_sha256",
                  "environment_policy_sha256", "artifact_inventory_sha256"}, "invalid_cargo_receipt")
    require(type(cargo["schema_version"]) is int and cargo["schema_version"] == 1
            and cargo["producer"] == PRODUCER and cargo["state"] == "COMPILED_CLOSURE_PRODUCED"
            and type(cargo["exit_code"]) is int and cargo["exit_code"] == 0
            and cargo["timed_out"] is False and cargo["resources_closed"] is True
            and cargo["unknown_owners"] == []
            and cargo["source_revision"] == producer["source_revision"]
            and cargo["authorization_id"] == producer["authorization_id"], "unaccepted_cargo_receipt")
    require(sdk["cargo_receipt_sha256"] == cargo_hash, "cargo_receipt_mismatch")
    for key in ("compiler", "target", "features", "profile", "rustflags_sha256", "lockfile_sha256",
                "input_inventory_sha256", "environment_policy_sha256"):
        require(cargo[key] == sdk[key], "cargo_contract_mismatch")
    require(cargo["artifact_inventory_sha256"] == digest(canonical(plain_inventory(list(sdk_rows.values())))),
            "cargo_inventory_mismatch")
    return approved


def guard(root, policy_path, policy_hash, producer_path, upload_path):
    path = Path(__file__).with_name("bundle_guard.py")
    require(path.is_file() and not path.is_symlink(), "guard_unavailable")
    module_name = "opaque_sdk_bundle_guard"
    previous = sys.modules.get(module_name)
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        report = module.validate_bundle(root=root, archive=None, surface="public-sdk",
            policy_path=policy_path, policy_sha256=policy_hash,
            provenance_path=producer_path, manifest_path=upload_path)
    except Exception:
        raise ExportError("bundle_guard_refused") from None
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
    require(report.get("state") == "passed", "bundle_guard_refused")


def open_root(root):
    require(root.is_absolute(), "absolute_path_required")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        require(not current.is_symlink(), "symlink_path_refused")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    require(stat.S_ISDIR(os.fstat(fd).st_mode), "invalid_artifact_root")
    return fd


def open_leaf(root_fd, name):
    fd = os.dup(root_fd)
    try:
        parts = PurePosixPath(name).parts
        for part in parts[:-1]:
            successor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = successor
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)


def copy_checked(root_fd, row, output_fd):
    fd = open_leaf(root_fd, row["path"])
    destination_fd = os.dup(output_fd)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size == row["bytes"], "artifact_metadata_mismatch")
        for part in PurePosixPath(row["path"]).parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=destination_fd)
            except FileExistsError:
                pass
            successor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=destination_fd)
            os.close(destination_fd)
            destination_fd = successor
        checksum = hashlib.sha256()
        count, prefix = 0, b""
        target_fd = os.open(PurePosixPath(row["path"]).name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=destination_fd)
        with os.fdopen(target_fd, "wb") as output:
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                if not prefix:
                    prefix = block[:16]
                count += len(block)
                require(count <= row["bytes"], "artifact_changed")
                checksum.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(destination_fd)
        require(not prefix.startswith(b"\x00GITCRYPT\x00"), "encrypted_source_refused")
        require(count == row["bytes"] and checksum.hexdigest() == row["sha256"]
                and identity(before) == identity(os.fstat(fd)), "artifact_changed")
    finally:
        os.close(fd)
        os.close(destination_fd)


def export(args):
    input_pins = [(args.policy, args.policy_sha256), (args.provenance, args.provenance_sha256),
                  (args.manifest, args.manifest_sha256), (args.sdk_manifest, args.sdk_manifest_sha256),
                  (args.cargo_receipt, args.cargo_receipt_sha256)]
    policy, producer, upload, sdk, cargo = [pinned_json(path, pin) for path, pin in input_pins]
    require(policy.get("producer_receipt_sha256") == args.provenance_sha256, "producer_digest_mismatch")
    rows = sdk_contract(sdk, args.expected_rust_release, args.expected_host, args.expected_target)
    approved = proof_join(policy, producer, upload, sdk, cargo, rows,
                          args.sdk_manifest_sha256, args.cargo_receipt_sha256)
    root = args.artifact_root
    output = args.output
    require(root.is_absolute() and output.is_absolute() and not output.exists()
            and not output.is_symlink() and output.parent.is_dir(), "invalid_output")
    root_fd = open_root(root)
    parent_fd = open_root(output.parent)
    stage = output
    output_fd = None
    try:
        require(root != output.parent and not output.parent.is_relative_to(root), "output_inside_input")
        guard(root, args.policy, args.policy_sha256, args.provenance, args.manifest)
        require((os.lstat(root).st_dev, os.lstat(root).st_ino)
                == (os.fstat(root_fd).st_dev, os.fstat(root_fd).st_ino), "artifact_root_changed")
        root_identity = identity(os.fstat(root_fd))
        # Exclusive creation claims this output. Partial failed exports are
        # retained and remain unqualified; no rename replaces a racing path.
        stage.mkdir(mode=0o700)
        output_fd = open_root(stage)
        for row in sorted(approved.values(), key=lambda item: item["path"]):
            copy_checked(root_fd, row, output_fd)
        require(identity(os.fstat(root_fd)) == root_identity, "artifact_root_changed")
        for path, pin in input_pins:
            pinned_json(path, pin)
        guard(stage, args.policy, args.policy_sha256, args.provenance, args.manifest)
        require(not output.is_symlink()
                and (os.lstat(output).st_dev, os.lstat(output).st_ino)
                    == (os.fstat(output_fd).st_dev, os.fstat(output_fd).st_ino)
                and os.stat(output.parent).st_ino == os.fstat(parent_fd).st_ino
                and os.stat(output.parent).st_dev == os.fstat(parent_fd).st_dev, "output_changed")
        os.fsync(output_fd)
        os.fsync(parent_fd)
        return {"schema_version": 1, "state": "OPAQUE_SDK_EXPORTED_NOT_QUALIFIED",
                "files": len(approved), "bytes": sum(row["bytes"] for row in approved.values()),
                "target": sdk["target"], "rust_release": sdk["compiler"]["release"],
                "policy_sha256": args.policy_sha256, "sdk_manifest_sha256": args.sdk_manifest_sha256,
                "cargo_receipt_sha256": args.cargo_receipt_sha256,
                "runtime_qualified": False, "source_confidentiality_proven": False}
    finally:
        os.close(root_fd)
        os.close(parent_fd)
        if output_fd is not None:
            os.close(output_fd)
        # A failed fresh stage is retained for the operator; no broad cleanup.


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("policy", "provenance", "manifest", "sdk-manifest", "cargo-receipt"):
        parser.add_argument("--" + name, type=Path, required=True)
        parser.add_argument("--" + name + "-sha256", required=True)
    for name in ("artifact-root", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("expected-rust-release", "expected-host", "expected-target"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        report = export(args)
    except (ExportError, OSError, ValueError, TypeError, KeyError, AttributeError):
        print(json.dumps({"schema_version": 1, "state": "REFUSED", "error_code": "opaque_sdk_refused",
                          "runtime_qualified": False}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
