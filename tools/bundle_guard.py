#!/usr/bin/env python3
"""Admit an exact reviewed public bundle; policy trust belongs to the caller.

This checks inventory, provenance, formats and known private material. It does
not prove arbitrary bytes secret-free or reveal what a model was trained on.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import uuid
import zipfile

MAX_FILES, MAX_FILE, MAX_TOTAL, MAX_CONTROL = 4096, 64 << 20, 512 << 20, 2 << 20
HEX = re.compile(r"[0-9a-f]{64}\Z")
SURFACES = ("public-sdk", "model-context", "public-upload", "public-project")
PRIVATE_PARTS = frozenset({
    ".git", ".codex", ".cursor", ".claude", ".agents", ".ssh", ".aws", ".config",
    ".cache", ".env.local.d", "__pycache__", "target", "cache", "caches", "logs",
    "transcripts", "rollouts", "rollout_summaries", "sessions", "agent-memory",
    "agent_memory", "memories", "sourcepack", "source-pack", "source_pack",
    "private-sdk", "private_sdk", "vendor", "crates",
})
PRIVATE_NAMES = frozenset({
    "auth.json", "credentials", "credentials.json", "credential-store.json",
    "agents.md", "claude.md", "skill.md", "memory.md", "login.json", "execution.json",
    "claim.json", "dispatch.json", "completion.json", "ack.json", "posted.json",
    "publication.json", "controller-evidence.json", "rpc-diagnostics.jsonl",
    "source.zip", "sdk.zip", "template.zip",
    "thoughts.txt", "thoughts.md", "reasoning.txt", "reasoning.md", "reasoning.json",
    "analysis.txt", "provider-response.json", "rollout.json", "session.json",
    "messages.json", "conversation.json",
})
KEY_EXTENSIONS = frozenset({".pem", ".key", ".p12", ".pfx", ".keystore", ".kdbx", ".seed", ".secret"})
ARCHIVE_EXTENSIONS = frozenset({".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar"})
WEB_EXTENSIONS = frozenset((
    ".html .css .js .mjs .wasm .json .png .jpg .jpeg .webp .gif .svg .avif .glb "
    ".gltf .bin .ktx2 .basis .ttf .otf .woff .woff2 .ogg .wav .mp3 .mp4 .txt .wgsl .wesl"
).split())
TEXT_EXTENSIONS = frozenset(".md .json .toml .lock .rs .py .js .mjs .ts .tsx .jsx .html .css .txt .wgsl .wesl .yaml .yml".split())
BUILD_NAMES = frozenset(("Cargo.toml", "Cargo.lock", "build.json", "size-budget.json",
                       "rust-toolchain.toml", ".cargo/config.toml", "sdk-manifest.json"))
ROLES = {
    "public-sdk": {"opaque_rlib", "opaque_metadata", "opaque_proc_macro", "opaque_native_link",
                   "public_facade", "build_metadata", "public_asset"},
    "model-context": {"public_facade", "public_document"},
    "public-upload": {"public_asset"},
    "public-project": {"project_source", "public_asset", "public_document"},
}
PRODUCERS = {"public-sdk": {"trusted-rust-artifact-producer/1"},
             "model-context": {"reviewed-public-context/1"},
             "public-upload": {"controller-web/v1"},
             "public-project": {"authorized-project-export/1"}}


class BundleError(ValueError):
    """Only fixed codes cross the diagnostic boundary."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(ok, code):
    if not ok:
        raise BundleError(code)


def document(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def nonfinite(_):
        raise BundleError("nonfinite_json")
    def finite_float(value):
        parsed = float(value)
        require(math.isfinite(parsed), "nonfinite_json")
        return parsed
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise BundleError("invalid_json") from None


def fields(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), "invalid_fields")


def schema(value):
    require(type(value["schema_version"]) is int and value["schema_version"] == 1, "invalid_schema")


def canonical_uuid(value):
    try:
        require(isinstance(value, str) and str(uuid.UUID(value)) == value, "invalid_authorization")
    except (ValueError, AttributeError, TypeError):
        raise BundleError("invalid_authorization") from None


def path_name(value, *, surface, directory=False):
    require(isinstance(value, str) and 0 < len(value) <= 240
            and re.fullmatch(r"[A-Za-z0-9._/-]+", value) is not None, "unsafe_path")
    parts = value.split("/")
    require(not value.startswith("/") and all(p not in ("", ".", "..") for p in parts), "unsafe_path")
    folded = [p.casefold() for p in parts]
    require(not any(p in PRIVATE_PARTS for p in folded), "private_path")
    require(not any(p.startswith(".") for p in parts)
            or surface == "public-sdk" and value in (".cargo/config.toml", ".cargo")
            and (not directory or value == ".cargo"), "private_path")
    if not directory:
        name, suffix = folded[-1], PurePosixPath(folded[-1]).suffix
        require(name not in PRIVATE_NAMES and not name.startswith((".env", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"))
                and suffix not in KEY_EXTENSIONS, "credential_or_private_control")
        require(suffix not in ARCHIVE_EXTENSIONS and suffix not in (".jsonl", ".log", ".pyc"), "nested_archive_or_transcript")
    return value


def role_name(path, role, surface):
    require(isinstance(role, str) and role in ROLES[surface], "role_not_allowed")
    suffix = PurePosixPath(path).suffix.lower()
    if role == "opaque_rlib":
        require(suffix == ".rlib", "opaque_library_type")
    elif role == "opaque_metadata":
        require(suffix == ".rmeta", "opaque_metadata_type")
    elif role == "opaque_proc_macro":
        require(suffix in (".so", ".dylib", ".dll"), "opaque_macro_type")
    elif role == "opaque_native_link":
        require(suffix in (".a", ".lib", ".o", ".obj"), "opaque_link_type")
    elif role == "public_facade":
        require(suffix in (".md", ".json", ".ts", ".js", ".mjs")
                or surface == "public-sdk" and suffix == ".rs" and path.startswith("facade/"),
                "unreviewable_facade_type")
    elif role == "build_metadata":
        require(path in BUILD_NAMES, "unexpected_build_metadata")
    elif role == "public_document":
        require(suffix in (".md", ".txt", ".json"), "document_type")
    elif role == "public_asset":
        require(suffix in WEB_EXTENSIONS, "public_asset_type")
    elif role == "project_source":
        roots = {"Cargo.toml", "Cargo.lock", "README.md", "package.json", "package-lock.json",
                 "pnpm-lock.yaml", "yarn.lock", "pyproject.toml", "requirements.txt", "go.mod", "go.sum"}
        require(path in roots or path.startswith(("src/", "tests/", "assets/", "public/")), "project_source_scope")
        require(suffix in TEXT_EXTENSIONS | WEB_EXTENSIONS, "project_source_type")
    require(suffix != ".rs" or role in ("public_facade", "project_source"), "private_rust_source")


def inventory(entries, *, surface, policy=False):
    require(isinstance(entries, list) and 1 <= len(entries) <= MAX_FILES, "file_count")
    result, folded, total = {}, set(), 0
    for entry in entries:
        fields(entry, ("path", "bytes", "sha256", "role") if policy else ("path", "bytes", "sha256"))
        name = path_name(entry["path"], surface=surface)
        require(name.casefold() not in folded, "case_collision")
        folded.add(name.casefold())
        require(type(entry["bytes"]) is int and 0 <= entry["bytes"] <= MAX_FILE, "file_size")
        require(isinstance(entry["sha256"], str) and HEX.fullmatch(entry["sha256"]) is not None, "file_hash")
        if policy:
            role_name(name, entry["role"], surface)
        total += entry["bytes"]
        require(total <= MAX_TOTAL, "total_size")
        result[name] = dict(entry)
    for name in folded:
        require(not any("/".join(name.split("/")[:n]) in folded for n in range(1, len(name.split("/")))),
                "file_directory_collision")
    return result


def state(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink)


def read_regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum, "nonregular_input")
        data = stream.read(maximum + 1)
        require(state(before) == state(os.fstat(stream.fileno())) and len(data) == before.st_size, "input_changed")
        return data


def binary_object(data):
    return data.startswith((b"\x7fELF", b"\0asm", b"BC\xc0\xde", b"\xcf\xfa\xed\xfe",
                            b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
                            b"\x64\x86", b"\x4c\x01", b"\0\0\xff\xff", b"MZ"))


def bounded_uleb(data, position, limit, code):
    """Canonical unsigned 32-bit LEB, bounded by the containing section."""
    value = 0
    for index in range(5):
        require(position < limit, code)
        byte = data[position]; position += 1
        require(index < 4 or byte <= 15, code)
        value |= (byte & 127) << (7 * index)
        if not byte & 128:
            require(index == 0 or byte != 0, code)
            return value, position
    raise BundleError(code)


def wasm_metadata_section(data, wanted):
    """Rust's wasm32 metadata wrapper, not an arbitrary executable module.

    rustc_codegen_ssa/back/metadata.rs::create_metadata_file_for_wasm emits
    linking version 2, then exactly the selected custom metadata section.
    Wasm64 imports and other object formats need separate qualification.
    """
    code = "wasm_metadata_wrapper"
    require(data.startswith(b"\0asm\x01\0\0\0"), code)
    position = 8; bodies = []
    for expected in (b"linking", wanted):
        require(position < len(data) and data[position] == 0, code)
        length, position = bounded_uleb(data, position + 1, len(data), code)
        end = position + length
        require(end <= len(data), code)
        size, position = bounded_uleb(data, position, end, code)
        require(size == len(expected) and position + size <= end
                and data[position:position + size] == expected, code)
        position += size
        bodies.append(data[position:end]); position = end
    require(position == len(data) and bodies[0] == b"\x02", code)
    return bodies[1]


def rust_metadata(data):
    # Supported encoding is the observed rustc 1.98.1/1.99.0 version 10.
    # Toolchain compatibility is still bound by the producer/SDK receipts.
    body = data if data.startswith(b"rust") else wasm_metadata_section(data, b".rmeta")
    code = "opaque_metadata_format"
    ending = b"rust-end-file"
    require(len(body) >= 30 and body[:8] == b"rust\0\0\0\x0a" and body.endswith(ending), code)
    limit = len(body) - len(ending)
    root = int.from_bytes(body[8:16], "little")
    size, position = bounded_uleb(body, 16, limit, code)
    require(0 < size <= 256 and position + size < limit and body[position + size] == 0xc1, code)
    version = re.fullmatch(rb"rustc ([0-9]+)\.([0-9]+)\.([0-9]+) \([0-9a-f]{7,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\)",
                           body[position:position + size])
    require(version is not None, code)
    require(position + size < root < limit, code)
    return tuple(int(part) for part in version.groups())


def rust_metadata_link(data):
    """Bounded Rust Vec<String>/Vec<Option<String>>, including all sentinels."""
    body = wasm_metadata_section(data, b".rmeta-link")
    code = "opaque_metadata_link_format"
    ending = b"rust-end-file"
    require(body.endswith(ending), code)
    limit = len(body) - len(ending); position = 0
    def basename():
        nonlocal position
        size, position = bounded_uleb(body, position, limit, code)
        require(0 < size <= 240 and position + size < limit and body[position + size] == 0xc1, code)
        raw = body[position:position + size]; position += size + 1
        require(re.fullmatch(rb"[A-Za-z0-9_+-][A-Za-z0-9._+-]*", raw) is not None, code)
        return raw.decode("ascii")
    count, position = bounded_uleb(body, position, limit, code)
    require(count <= MAX_FILES * 4, code)
    objects = [basename() for _ in range(count)]
    require(len(set(objects)) == len(objects) and all(PurePosixPath(name).suffix.lower() in (".o", ".obj")
                                                    for name in objects), code)
    # 1.98.1 encodes the first vector only. 1.99.0 adds native filenames.
    # The archive caller binds this distinction to its primary metadata.
    if position == limit: return set(objects), False
    count, position = bounded_uleb(body, position, limit, code)
    require(count <= MAX_FILES * 4, code)
    native = []
    for _ in range(count):
        require(position < limit and body[position] in (0, 1), code)
        present = body[position]; position += 1
        if present: native.append(basename())
    require(position == limit, code)
    return set(objects + native), True


def ar_members(data):
    require(data.startswith(b"!<arch>\n"), "opaque_archive_format")
    offset, table, count, headers = 8, b"", 0, 0
    object_names, link, metadata_version = set(), None, None
    while offset < len(data):
        headers += 1
        require(headers <= MAX_FILES * 4, "opaque_archive_member_count")
        require(offset + 60 <= len(data), "opaque_archive_truncated")
        header = data[offset:offset + 60]
        require(header[58:60] == bytes((96, 10)), "opaque_archive_header")
        try:
            length, name = int(header[48:58].decode("ascii").strip()), header[:16].decode("ascii").strip()
        except (UnicodeError, ValueError):
            raise BundleError("opaque_archive_header") from None
        require(length >= 0 and offset + 60 + length <= len(data), "opaque_archive_truncated")
        payload = data[offset + 60:offset + 60 + length]
        offset += 60 + length + length % 2
        require(offset <= len(data), "opaque_archive_truncated")
        if name == "//":
            require(not table, "opaque_archive_duplicate_names")
            table = payload
            continue
        if name.startswith("#1/"):
            try:
                size = int(name[3:])
                require(0 < size <= len(payload), "opaque_archive_header")
                name = payload[:size].rstrip(b"\0").decode("ascii")
            except (ValueError, UnicodeError):
                raise BundleError("opaque_archive_header") from None
            payload = payload[size:]
        elif name.startswith("/") and name[1:].isdigit():
            start = int(name[1:])
            end = table.find(b"/\n", start)
            require(0 <= start < len(table) and end >= start, "opaque_archive_header")
            try:
                name = table[start:end].decode("ascii")
            except UnicodeError:
                raise BundleError("opaque_archive_header") from None
        if name in ("/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"):
            continue
        name = name.rstrip("/")
        require("/" not in name and "\\" not in name and not name.startswith(".")
                and (PurePosixPath(name).suffix.lower() in (".o", ".obj", ".rmeta")
                     or name == "lib.rmeta-link"), "opaque_archive_source_member")
        if name == "lib.rmeta-link":
            require(link is None, "opaque_metadata_link_duplicate")
            link = rust_metadata_link(payload)
        elif name.endswith(".rmeta"):
            version = rust_metadata(payload)
            if name == "lib.rmeta":
                require(metadata_version is None, "opaque_metadata_duplicate")
                metadata_version = version
        else:
            require(binary_object(payload), "opaque_object_format")
            object_names.add(name)
        count += 1
    require(offset == len(data) and count > 0, "opaque_archive_empty")
    if link is not None:
        require(metadata_version in ((1, 98, 1), (1, 99, 0))
                and link[1] == (metadata_version == (1, 99, 0)), "opaque_metadata_link_family")
        require(link[0] <= object_names, "opaque_metadata_link_reference")


def known_material(data, path, role):
    require(not data.startswith(b"\0GITCRYPT\0"), "encrypted_public_payload")
    require(re.search(b"-----BEGIN " + b"(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", data) is None,
            "private_key_material")
    suffix = PurePosixPath(path).suffix.lower()
    if role in ("opaque_rlib", "opaque_native_link") and suffix in (".rlib", ".a", ".lib"):
        ar_members(data)
    elif role == "opaque_metadata":
        rust_metadata(data)
    elif role in ("opaque_proc_macro", "opaque_native_link"):
        require(binary_object(data), "opaque_object_format")
    require(not data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")),
            "nested_archive_payload")
    require(not re.search(rb"(?im)^(?:<analysis>|<thinking>|BEGIN (?:PRIVATE )?(?:REASONING|MODEL TRANSCRIPT)|"
                          rb"#+[ \t]+(?:PRIVATE REASONING|CHAIN OF THOUGHT))", data), "provider_transcript_text")
    if suffix in TEXT_EXTENSIONS:
        assignments = re.findall(
            rb"(?m)^[ \t]*(?:export[ \t]+)?(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|"
            rb"AWS_SECRET_ACCESS_KEY|HARMONY_WORKER_KEY|SSH_PRIVATE_KEY)[ \t]*=[ \t]*([^\r\n]*)", data)
        require(all(value.strip().strip(b"'\"") in
                    (b"", b"REPLACE_ME", b"<redacted>", b"[redacted]", b"<token>", b"<key>")
                    for value in assignments), "credential_assignment")
    if suffix == ".json" or suffix in (".bin", ".txt") and data.lstrip().startswith((b"{", b"[")):
        value = document(data)
        credentials = {"accesstoken", "refreshtoken", "idtoken", "apikey", "privatekey",
                       "clientsecret", "authorization", "password", "awssecretaccesskey", "githubtoken", "sshauthsock"}
        transcripts = {"reasoning", "reasoningcontent", "thinking", "systemprompt", "rawresponse",
                       "providerresponse", "toolresult", "memories", "messages"}
        placeholders = ("", "REPLACE_ME", "<redacted>", "[redacted]", "<token>", "<key>")
        def walk(node, depth=0):
            require(depth <= 32, "json_depth")
            if isinstance(node, dict):
                for key, child in node.items():
                    folded = key.casefold().replace("_", "").replace("-", "")
                    require(not (folded in credentials and child not in placeholders), "credential_json")
                    require(not (folded in transcripts and child not in ("", None, [], {})), "provider_or_memory_json")
                    if key == "type":
                        require(child not in ("reasoning", "thinking", "response_item", "session_meta", "turn_context", "event_msg"),
                                "provider_transcript_json")
                    if key == "role" and child in ("system", "assistant", "developer", "tool"):
                        require("content" not in node, "provider_transcript_json")
                    if isinstance(child, str) and folded.endswith(("path", "root", "home", "directory")):
                        require(not child.startswith(("/Users/", "/Volumes/", "/home/", "C:\\Users\\")), "private_host_path")
                    walk(child, depth + 1)
            elif isinstance(node, list):
                for child in node:
                    walk(child, depth + 1)
        walk(value)


def checked_bytes(data, entry):
    require(len(data) == entry["bytes"] and hashlib.sha256(data).hexdigest() == entry["sha256"], "payload_changed")
    known_material(data, entry["path"], entry["role"])


def tree_payload(root, expected, surface):
    absolute = Path(root).absolute()
    require(absolute.resolve() == absolute, "root_alias")
    observed, seen, directories = {}, set(), 0
    root_fd = os.open(absolute, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    def visit(fd, prefix):
        nonlocal directories
        for name in sorted(os.listdir(fd)):
            path = prefix + name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            directory = stat.S_ISDIR(info.st_mode)
            path_name(path, surface=surface, directory=directory)
            require(path.casefold() not in seen, "case_collision")
            seen.add(path.casefold())
            if directory:
                directories += 1
                require(directories <= MAX_FILES * 4, "directory_count")
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    visit(child, path + "/")
                finally:
                    os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "nonregular_payload")
                require(path in expected and info.st_size == expected[path]["bytes"], "inventory_mismatch")
                observed[path] = info
    try:
        visit(root_fd, "")
        require(set(observed) == set(expected), "inventory_mismatch")
        initial = dict(observed)
        for path in sorted(expected):
            parent = os.dup(root_fd)
            try:
                parts = path.split("/")
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    os.close(parent)
                    parent = child
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                with os.fdopen(fd, "rb") as stream:
                    before = os.fstat(stream.fileno())
                    require(state(before) == state(observed[path]), "payload_changed")
                    data = stream.read(expected[path]["bytes"] + 1)
                    require(state(before) == state(os.fstat(stream.fileno())), "payload_changed")
                checked_bytes(data, expected[path])
            finally:
                os.close(parent)
        observed.clear();seen.clear();directories = 0
        visit(root_fd, "")
        require(set(observed) == set(initial) and all(state(observed[p]) == state(initial[p]) for p in initial),
                "payload_changed")
    finally:
        os.close(root_fd)


def zip_payload(path, expected, surface):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_TOTAL + MAX_CONTROL,
                "nonregular_archive")
        with zipfile.ZipFile(stream) as archive:
            infos = archive.infolist()
            require(1 <= len(infos) <= MAX_FILES * 4, "archive_member_count")
            observed, seen = {}, set()
            for entry in infos:
                name = entry.filename.rstrip("/") if entry.is_dir() else entry.filename
                path_name(name, surface=surface, directory=entry.is_dir())
                require(name.casefold() not in seen, "case_collision")
                seen.add(name.casefold())
                mode = stat.S_IFMT(entry.external_attr >> 16)
                require(not entry.flag_bits & 1 and mode in (0, stat.S_IFREG, stat.S_IFDIR), "archive_member_type")
                if entry.is_dir():
                    require(mode in (0, stat.S_IFDIR) and entry.file_size == 0, "archive_member_type")
                    continue
                require(mode in (0, stat.S_IFREG) and name in expected and entry.file_size == expected[name]["bytes"],
                        "inventory_mismatch")
                observed[name] = entry
            require(set(observed) == set(expected), "inventory_mismatch")
            for name in sorted(expected):
                with archive.open(observed[name]) as member:
                    checked_bytes(member.read(expected[name]["bytes"] + 1), expected[name])
        require(state(before) == state(os.fstat(stream.fileno())), "archive_changed")


def _validate_bundle(*, root, archive, surface, policy_path, policy_sha256, provenance_path, manifest_path):
    require(surface in SURFACES and (root is None) != (archive is None), "invalid_surface")
    require(isinstance(policy_sha256, str) and HEX.fullmatch(policy_sha256) is not None, "untrusted_policy")
    policy_raw = read_regular(policy_path, MAX_CONTROL)
    require(hashlib.sha256(policy_raw).hexdigest() == policy_sha256, "untrusted_policy")
    policy = document(policy_raw)
    fields(policy, ("schema_version", "review_id", "surface", "producer_receipt_sha256", "files"))
    schema(policy);canonical_uuid(policy["review_id"])
    require(policy["surface"] == surface, "surface_mismatch")
    expected = inventory(policy["files"], surface=surface, policy=True)
    require(isinstance(policy["producer_receipt_sha256"], str)
            and HEX.fullmatch(policy["producer_receipt_sha256"]) is not None, "untrusted_provenance")
    provenance_raw = read_regular(provenance_path, MAX_CONTROL)
    require(hashlib.sha256(provenance_raw).hexdigest() == policy["producer_receipt_sha256"], "untrusted_provenance")
    provenance = document(provenance_raw)
    fields(provenance, ("schema_version", "producer", "source_revision", "authorization_id", "surface", "files"))
    schema(provenance);canonical_uuid(provenance["authorization_id"])
    require(isinstance(provenance["producer"], str) and provenance["producer"] in PRODUCERS[surface]
            and provenance["surface"] == surface, "untrusted_producer")
    require(isinstance(provenance["source_revision"], str)
            and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", provenance["source_revision"]) is not None,
            "unbound_source_revision")
    actual = [{k: expected[p][k] for k in ("path", "bytes", "sha256")} for p in sorted(expected)]
    plain = {entry["path"]: entry for entry in actual}
    require(inventory(provenance["files"], surface=surface) == plain, "provenance_inventory_mismatch")
    manifest_raw = read_regular(manifest_path, MAX_CONTROL)
    manifest = document(manifest_raw)
    fields(manifest, ("schema_version", "files"));schema(manifest)
    require(inventory(manifest["files"], surface=surface) == plain, "upload_inventory_mismatch")
    if root is not None:
        tree_payload(root, expected, surface)
    else:
        zip_payload(archive, expected, surface)
    return {"schema_version": 1, "state": "passed", "surface": surface, "files": actual,
            "policy_sha256": policy_sha256, "provenance_sha256": hashlib.sha256(provenance_raw).hexdigest(),
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest()}


def validate_bundle(*, root=None, archive=None, surface, policy_path,
                    policy_sha256, provenance_path, manifest_path):
    """Return a passed report or raise BundleError; never return failed."""
    try:
        return _validate_bundle(root=root, archive=archive, surface=surface, policy_path=policy_path,
                                policy_sha256=policy_sha256, provenance_path=provenance_path, manifest_path=manifest_path)
    except BundleError:
        raise
    except (OSError, KeyError, TypeError, ValueError, AttributeError, zipfile.BadZipFile, RuntimeError, EOFError):
        raise BundleError("guard_input_unavailable") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--root", type=Path);mode.add_argument("--archive", type=Path)
    parser.add_argument("--surface", required=True, choices=SURFACES)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--provenance", "--producer-receipt", dest="provenance", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    code, result = 0, None
    try:
        require(not args.report.exists() and not args.report.is_symlink(), "report_exists")
        if args.root is not None:
            root = args.root.resolve()
            require(not any(p.resolve() == root or root in p.resolve().parents
                            for p in (args.policy, args.provenance, args.manifest, args.report)), "control_inside_payload")
        result = validate_bundle(root=args.root, archive=args.archive, surface=args.surface,
                                 policy_path=args.policy, policy_sha256=args.policy_sha256,
                                 provenance_path=args.provenance, manifest_path=args.manifest)
    except BundleError as error:
        result, code = {"schema_version": 1, "state": "failed", "code": error.code}, 1
    except (OSError, KeyError, TypeError, ValueError, AttributeError):
        result, code = {"schema_version": 1, "state": "failed", "code": "guard_input_unavailable"}, 1
    try:
        fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n");stream.flush();os.fsync(stream.fileno())
    except OSError:
        print(json.dumps({"schema_version": 1, "state": "failed", "code": "report_unavailable"}))
        return 1
    print(json.dumps({"schema_version": 1, "state": result["state"]}, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
