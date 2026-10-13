#!/usr/bin/env python3
"""Trusted SDK starter producer, never a generated-project or model runner.

Source and export catalog entries require separate review. Source input is an approved encrypted-only Git bundle
ZIP for a separately keyed SDK repository. Decryption belongs to prepare only;
the frozen tree, public registry and clean toolchain are the compiler's entire
input boundary. Raw source, keys, receipts and Cargo logs are never uploaded.
Artifact collection is a candidate, not proof of ABI or metadata secrecy.
"""
from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import sys
import time
import uuid
import zipfile

# Protected, reviewed source only. Dispatch cannot supply a replacement row.
APPROVED_SOURCES = {'sdk-webgl2-initial-d642105-rust1981-arm-v1': {'archive': {'bytes': 10427140,
                                                            'name': 'encrypted-sdk-source.zip',
                                                            'sha256': 'cac68c186bf9ba71692b6cbebf40b1ca39332059acfed099fe354e7eb8ecc1ce'},
                                                'authorization_id': '084474c3-6c49-4df2-9842-098088e6e953',
                                                'build_json_sha256': '54b691be9f29660492aff228d7d4f1564ebb1076a6e70b1a485276608faeb002',
                                                'cargo_config_sha256': '480243f92658df3757aabb38f0c23373d394bc0a38bd490bb553b73a384e94a5',
                                                'ciphertext_inventory_sha256': 'a90cbe6eebc72f9b7029c05817f5c42a8f6a3150073eaa52c493ff5e6852f611',
                                                'compiler_image': 'sha256:e0a16a3dc7e3e5b3a3d9e42218c3d2f3549c90777b71cf19a3bef4cdcc4d24a7',
                                                'compiler_ref': 'ghcr.io/fvlvte/harmony-studio-projects/compiler@sha256:0ecf72666518e3c21fc05efbd64f07a1e02d9ea0df3c4f7002c0eb7f7969a7bc',
                                                'git_commit': 'd642105c37620107915cadc76442c368d1c0d1ef',
                                                'image_environment': ['PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin',
                                                                      'RUSTUP_HOME=/usr/local/rustup',
                                                                      'CARGO_HOME=/usr/local/cargo',
                                                                      'RUST_VERSION=1.98.1',
                                                                      'RUSTUP_AUTO_INSTALL=0',
                                                                      'HOME=/tmp/home',
                                                                      'LANG=C.UTF-8'],
                                                'input_inventory_sha256': 'f8c25b87ef95a8f262ccca1cbb90f7aa9c94ceacaf34329e1d0e8aeeaf44ca1c',
                                                'key_sha256': '068fae23829ccb88f3615295ca7fd0ec58db1988f1c2487fb449d096c0204934',
                                                'lockfile_sha256': '8f9c162ed96d62c67f99c2536565f67ba221906b8d7bd663f95185d2017e6157',
                                                'prep_tool_sha256': {'git': '4cda0087547ee12bef91952e1123debb4bd2ec621838b347b5ca4fdaa6fecb58',
                                                                     'git-crypt': 'da75700d5a72ee19707784fd4f80ce0a9ba7a3e9c962ff181db136ba3bc6d489'},
                                                'public_plaintext': [{'bytes': 242,
                                                                      'path': '.gitattributes',
                                                                      'sha256': '012d8d3fa0a42765c25fbb11c871dd8050532f5246ad51698668b226b326897b'},
                                                                     {'bytes': 170,
                                                                      'path': '.gitignore',
                                                                      'sha256': '63d460c1ebb532ac4639d5b504ca33b97efcc7ce63fde4c45d720a098d29ad5e'},
                                                                     {'bytes': 11228,
                                                                      'path': 'README.md',
                                                                      'sha256': '11a68b0439e11b9ad55ce8c7781a9d99900aa4546a4d5e834c067360992c7494'},
                                                                     {'bytes': 2682,
                                                                      'path': '.github/workflows/verify-project.yml',
                                                                      'sha256': 'a12156e5603e34fb299ef62ef0ceda00e910373a299d706d90046bcdc777fe4f'},
                                                                     {'bytes': 3546,
                                                                      'path': '.github/workflows/build-sdk.yml',
                                                                      'sha256': 'eea00e6f204b1fbfe580518043caf04b06210e019a5229353d961600d2a03dab'},
                                                                     {'bytes': 3322,
                                                                      'path': '.github/workflows/build-toolchain.yml',
                                                                      'sha256': 'aa7122ed11dc8a2fa6dad0965d0b2d4e97e0d41058d74dbc1fbc163b6711b18b'},
                                                                     {'bytes': 30010,
                                                                      'path': 'tools/bundle_guard.py',
                                                                      'sha256': '1922594e5b38941dd6e6f96d18e06b1e416c581f920892afdcddde5cb0c31bfc'},
                                                                     {'bytes': 21696,
                                                                      'path': 'tools/opaque_sdk.py',
                                                                      'sha256': '4a3d36ee2866c040160801a7e1cdd4a8bf6b8bf7b4f282f97d62bc32faddd712'},
                                                                     {'bytes': 46101,
                                                                      'path': 'tools/ci_verify.py',
                                                                      'sha256': '2dba26e4c5cf05f75a96973350d61959f64f6645322e6ce8a413b5ed13e328eb'},
                                                                     {'bytes': 38302,
                                                                      'path': 'tools/ci_build_sdk.py',
                                                                      'sha256': 'ea809ec033211bd2f78d09ec4d6c87159f7d2ab1bda93d05391455596a5ae924'},
                                                                     {'bytes': 19290,
                                                                      'path': 'tests/test_bundle_guard.py',
                                                                      'sha256': '44245f3698e8b965d54946f5bdc2e038161821570ccd569cea26909c360e68b6'},
                                                                     {'bytes': 10944,
                                                                      'path': 'tests/test_opaque_sdk.py',
                                                                      'sha256': 'd39ab660ea097382161b087f1f8887a3396c566ddfff336b7cc58f21f2432d51'},
                                                                     {'bytes': 21677,
                                                                      'path': 'tests/test_ci_verify.py',
                                                                      'sha256': '8c4a2b5776445ca2c083a5d9c585e622ceff48c11f269e6d788996d560027379'},
                                                                     {'bytes': 10886,
                                                                      'path': 'tests/test_ci_build_sdk.py',
                                                                      'sha256': '7f0b08105eef041668b1ec2c367a160b3098ef8ad26e7cff27bf81fb627815e7'},
                                                                     {'bytes': 10153,
                                                                      'path': 'policy/README.md',
                                                                      'sha256': 'e7c05705eb55bae48ad38d26e4937333904bb205a56d5408a23d4133ab2764bc'},
                                                                     {'bytes': 1143,
                                                                      'path': 'toolchain/Dockerfile',
                                                                      'sha256': 'ce15ce30234069509dc7c0e3ca6dc465a635cfa582f6b7fcdea18aefaa2f8c6f'},
                                                                     {'bytes': 2637,
                                                                      'path': 'toolchain/README.md',
                                                                      'sha256': 'fe55bcd57e97ca1cfa3cc27912d1ecb051abf9c6cee6054c11ec603e0f5f5cf0'},
                                                                     {'bytes': 109,
                                                                      'path': 'toolchain/.dockerignore',
                                                                      'sha256': '5458823ca8d5515f72bc59af26980774f2967bb0e166e5baa27d015e1d241c90'}],
                                                'release_tag': 'sdk-source-initial-d642105-v1',
                                                'repository': 'fvlvte/harmony-studio-projects',
                                                'source_revision': 'f8c25b87ef95a8f262ccca1cbb90f7aa9c94ceacaf34329e1d0e8aeeaf44ca1c',
                                                'toolchain_sha256': 'aab8ae8a045ac7a120b2022fa063c482c705249ab8ca1e443c5530d1ca6592cf'}}
APPROVED_EXPORTS = {}
REPOSITORY = "fvlvte/harmony-studio-projects"
RUST = "1.98.1"
TARGET = "wasm32-unknown-unknown"
HOST = "aarch64-unknown-linux-gnu"
PROFILE = {"name": "web-release", "opt_level": "s", "lto": "thin", "codegen_units": 1,
           "panic": "abort", "debug": False, "incremental": False}
FEATURES = ["web-webgl2"]
COMPILER_ENV = {"PATH": "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp/home", "LANG": "C.UTF-8", "RUSTUP_HOME": "/usr/local/rustup",
    "RUSTUP_AUTO_INSTALL": "0", "CARGO_HOME": "/registry", "CARGO_TARGET_DIR": "/out/target",
    "CARGO_BUILD_BUILD_DIR": "/out/build", "CARGO_INCREMENTAL": "0",
    # Trusted effective profile override; the approved source stays byte-identical.
    "CARGO_PROFILE_WEB_RELEASE_LTO": "thin",
    "CARGO_ENCODED_RUSTFLAGS": '\x1f'.join(["--cfg", 'getrandom_backend="wasm_js"',
                                            "--remap-path-prefix=/sdk=/public-sdk"])}
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_SOURCE = 512 * 1024**2
MAX_FILES = 20_000
PRODUCER = "trusted-rust-artifact-producer/1"


class Refused(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Refused(code)



# Frozen literal codes from this producer, the public owner/resource/download
# helpers, and the public compiler-identity validator. Never echo exception text
# based on a regex or dynamically extend this set from a runtime dependency.
PUBLIC_REFUSAL_CODES = frozenset({
    'artifact_collision', 'artifact_directory_alias', 'artifact_metadata_invalid',
    'artifact_output_path', 'artifact_role_mismatch', 'asset_deadline',
    'asset_hash', 'asset_pin', 'asset_redirect',
    'asset_size', 'asset_transport', 'build_policy_drift',
    'cargo_build_not_passed', 'cargo_json_bound', 'cargo_json_invalid',
    'cargo_metadata_invalid', 'ciphertext_history_review_mismatch', 'cleanup_identity',
    'cli_cleanup_unknown', 'command_deadline', 'command_failed',
    'command_output_bound', 'compiler_failed_or_unknown', 'compiler_identity_mismatch',
    'compiler_verbose_mismatch', 'container_cleanup_unknown', 'container_command_failed',
    'container_contract', 'container_id', 'container_identity',
    'cpu_affinity', 'deadline_or_signal', 'disk_floor',
    'docker_endpoint', 'duplicate_json_key', 'encrypted_artifact_refused',
    'encrypted_checkout_dirty', 'evidence_reserve_exhausted', 'evidence_source_changed',
    'fixed_sdk_source_root', 'foreign_container_present', 'helper_missing',
    'image_environment', 'input_changed', 'invalid_compiler',
    'invalid_digest', 'json_bound', 'key_disposition_unknown',
    'key_env_in_build', 'manual_own_repository_required', 'memory_pressure',
    'moonlight_artifact_missing', 'mount_path', 'native_link_closure_requires_review',
    'native_linux_arm_required', 'nonreaping_primitive_required', 'operation_identity',
    'optimization_policy_drift', 'owned_session', 'owner_receipt',
    'plaintext_review_required', 'plaintext_source_refused', 'prep_tool_identity',
    'prep_tool_pins', 'prepare_deadline', 'prepare_failed_or_unknown',
    'prepared_context_drift', 'private_case_required', 'private_receipt_required',
    'private_source_input', 'producer_deadline', 'public_compiler_reference',
    'registry_alias_refused', 'registry_credentials_refused', 'regular_file_required',
    'release_asset_identity', 'resource_floor', 'response_deadline',
    'sdk_key_identity', 'sealed_source_format', 'sealed_source_size',
    'separate_sdk_key_required', 'signal_or_deadline', 'source_authorization',
    'source_bound', 'source_catalog_identity', 'source_catalog_pin',
    'source_catalog_schema', 'source_catalog_tuple', 'source_catalog_unapproved',
    'source_changed_during_compile', 'source_contract_hash', 'source_directory_refused',
    'source_empty', 'source_inventory_drift', 'source_root',
    'source_still_encrypted', 'toolchain_drift', 'toolchain_image_identity',    'registry_permission_denied', 'registry_no_space', 'registry_read_only', 'registry_io_failure',
    'registry_quota_exceeded', 'registry_entry_missing', 'registry_os_error', 'registry_copy_failed',
    'registry_entry_type', 'registry_prefetch_command', 'registry_prefetch_deadline',
})
FAILURE_STAGES = frozenset({
    "admission", "prepare", "compile_context", "compile_setup",
    "compile_resource_admission", "compile_source", "compile_image",
    "compile_toolchain", "compile_prefetch", "compile_registry", "compile_cargo",
    "compile_metadata", "compile_artifacts", "compile_cleanup", "compile_receipts",
    "response", "internal_error",
})


def refusal_code(error):
    if (isinstance(error, ValueError) and type(error.args) is tuple
            and len(error.args) == 1 and type(error.args[0]) is str
            and error.args[0] in PUBLIC_REFUSAL_CODES):
        return error.args[0]
    return "internal_error"


def failure_stage(diagnostic, stage):
    if diagnostic is not None:
        diagnostic["failure_stage"] = stage if stage in FAILURE_STAGES else "internal_error"


def resource_observation(error):
    """Project only bounded host numbers from the two existing resource refusals."""
    if refusal_code(error) not in {"resource_floor", "memory_pressure"}:
        return None
    attributes = getattr(error, "__dict__", None)
    sample = attributes.get("resource_sample") if type(attributes) is dict else None
    if type(sample) is not dict or set(sample) != {"mem_total", "mem_available", "memory_psi_avg10"}:
        return None
    total, available = sample["mem_total"], sample["mem_available"]
    if (type(total) is not int or type(available) is not int
            or not 0 <= available <= total <= 2**63 - 1):
        return None
    values = sample["memory_psi_avg10"]
    if values is not None:
        if type(values) is not list or len(values) != 2:
            return None
        if any(type(value) not in (int, float) or not 0 <= value <= 100
               or not math.isfinite(value) for value in values):
            return None
        values = [float(value) for value in values]
    return {"scope": "runner_host", "mem_total": total, "mem_available": available,
            "memory_psi_avg10": values}


def public_failure(error, diagnostic):
    value = {"failure_stage": diagnostic["failure_stage"], "refusal_code": refusal_code(error),
             "owner_close_called": diagnostic["owner_close_called"],
             "owner_close_succeeded": diagnostic["owner_close_succeeded"],
             "cleanup_refusal_code": diagnostic["cleanup_refusal_code"]}
    observation = resource_observation(error)
    if observation is not None:
        value["resource_observation"] = observation
    return value


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def helpers():
    modules = []
    for name in ("ci_verify", "opaque_sdk"):
        path = Path(__file__).with_name(name + ".py")
        require(path.is_file() and not path.is_symlink(), "helper_missing")
        spec = importlib.util.spec_from_file_location("sdk_producer_" + name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)
    return modules


def approval(env):
    require(env.get("GITHUB_REPOSITORY") == REPOSITORY
            and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_REF") == "refs/heads/main", "manual_own_repository_required")
    row = APPROVED_SOURCES.get(env.get("SDK_SOURCE"))
    require(row is not None, "source_catalog_unapproved")
    require(set(row) == {"repository", "release_tag", "archive", "git_commit", "source_revision",
        "authorization_id", "input_inventory_sha256", "build_json_sha256", "cargo_config_sha256",
        "lockfile_sha256", "toolchain_sha256", "compiler_image", "compiler_ref", "image_environment", "key_sha256",
        "prep_tool_sha256", "ciphertext_inventory_sha256", "public_plaintext"},
        "source_catalog_schema")
    require(row["repository"] == REPOSITORY and env.get("SDK_SOURCE_SHA256") == row["archive"]["sha256"],
            "source_catalog_tuple")
    for key in ("source_revision", "input_inventory_sha256", "build_json_sha256", "cargo_config_sha256",
                "lockfile_sha256", "toolchain_sha256", "key_sha256", "ciphertext_inventory_sha256"):
        require(isinstance(row[key], str) and HEX.fullmatch(row[key]), "source_catalog_pin")
    require(re.fullmatch(r"[0-9a-f]{40}", row["git_commit"])
            and re.fullmatch(r"sha256:[0-9a-f]{64}", row["compiler_image"]), "source_catalog_identity")
    require(re.fullmatch(r"ghcr\.io/fvlvte/harmony-studio-projects/compiler@sha256:[0-9a-f]{64}",
                        row["compiler_ref"]), "public_compiler_reference")
    require(str(uuid.UUID(row["authorization_id"])) == row["authorization_id"], "source_authorization")
    operation = env.get("SDK_OPERATION", "")
    require(str(uuid.UUID(operation)) == operation, "operation_identity")
    require(isinstance(row["image_environment"], list)
            and all(isinstance(item, str) for item in row["image_environment"]), "image_environment")
    require(isinstance(row["prep_tool_sha256"], dict) and set(row["prep_tool_sha256"]) == {"git", "git-crypt"}
            and all(isinstance(pin, str) and HEX.fullmatch(pin) for pin in row["prep_tool_sha256"].values()),
            "prep_tool_pins")
    require(isinstance(row["public_plaintext"], list) and len(row["public_plaintext"]) <= 512,
            "plaintext_review_required")
    seen = set()
    for item in row["public_plaintext"]:
        require(isinstance(item, dict) and set(item) == {"path", "bytes", "sha256"}
                and isinstance(item["path"], str) and re.fullmatch(r"[A-Za-z0-9._/-]+", item["path"])
                and item["path"] not in seen and (item["path"] in ("README.md", "LICENSE", ".gitignore", ".gitattributes",
                     "toolchain/Dockerfile", "toolchain/README.md", "toolchain/.dockerignore")
                     or item["path"].startswith(("tools/", "tests/", "policy/", ".github/", "facade/")))
                and all(part not in ("", ".", "..", ".git", ".codex", ".cursor", ".claude", ".agents", "logs", "sessions", "memories")
                        for part in item["path"].split("/"))
                and PurePosixPath(item["path"]).name not in ("auth.json", "credentials", "credentials.json", "AGENTS.md", "CLAUDE.md", "MEMORY.md")
                and PurePosixPath(item["path"]).suffix not in (".key", ".pem", ".log", ".jsonl")
                and (not item["path"].endswith(".rs") or item["path"].startswith("facade/"))
                and not item["path"].startswith(("engine/", "crates/", "vendor/", "reference/"))
                and type(item["bytes"]) is int and 0 < item["bytes"] <= MAX_SOURCE
                and HEX.fullmatch(item["sha256"]), "plaintext_source_refused")
        seen.add(item["path"])
    return row, operation


def regular(path, maximum=MAX_SOURCE):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum, "regular_file_required")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(data) == info.st_size and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "input_changed")
        return data


def private_document(path, verify):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600, "private_receipt_required")
    return verify.document(regular(path, 2 * 1024**2))


def tree_inventory(root, *, freeze=None):
    require(root.is_dir() and not root.is_symlink(), "source_root")
    rows, total = [], 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        if base == root and ".git" in dirs:
            dirs.remove(".git")
        for name in dirs:
            require(not (base / name).is_symlink() and name not in (".git", "target", ".codex", ".cursor", ".claude"),
                    "source_directory_refused")
        for name in sorted(files):
            path = base / name
            relative = path.relative_to(root).as_posix()
            require(not any(part in (".git", ".ssh", ".codex", ".cursor", ".claude", "logs", "sessions", "memories")
                    or part.startswith(".env") for part in PurePosixPath(relative).parts)
                    and name not in ("auth.json", "credentials", "credentials.json", "AGENTS.md", "CLAUDE.md", "MEMORY.md")
                    and path.suffix.lower() not in (".key", ".pem", ".jsonl", ".log"), "private_source_input")
            data = regular(path)
            require(not data.startswith(b"\x00GITCRYPT\x00"), "source_still_encrypted")
            total += len(data)
            require(total <= MAX_SOURCE and len(rows) < MAX_FILES, "source_bound")
            rows.append({"path": relative, "bytes": len(data), "sha256": digest(data)})
            if freeze is not None:
                target = freeze / relative
                current = freeze
                for part in PurePosixPath(relative).parts[:-1]:
                    current /= part
                    current.mkdir(mode=0o700, exist_ok=True)
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(data); output.flush(); os.fsync(output.fileno())
    require(rows, "source_empty")
    return sorted(rows, key=lambda item: item["path"])


def build_policy(raw):
    value = json.loads(raw)
    require(isinstance(value, dict) and set(value) == {"schema_version", "profile", "features", "binary",
        "out_name", "wasm_opt", "size_budget"} and type(value["schema_version"]) is int
        and value["schema_version"] == 1 and value["profile"] == "web-release"
        and value["features"] == FEATURES and value["binary"] == "harmony-games"
        and value["out_name"] == "harmony_games" and value["size_budget"] == "size-budget.json",
        "build_policy_drift")
    require(value["wasm_opt"] == {"version": "133", "level": "z", "flags": ["--strip-debug", "--strip-producers",
        "--enable-bulk-memory", "--enable-nontrapping-float-to-int", "--enable-reference-types",
        "--enable-sign-ext", "--enable-mutable-globals"]}, "optimization_policy_drift")
    return value


def source_contract(root, row):
    for name, pin in (("build.json", "build_json_sha256"), (".cargo/config.toml", "cargo_config_sha256"),
                      ("rust-toolchain.toml", "toolchain_sha256"), ("examples/game/Cargo.lock", "lockfile_sha256")):
        require(digest(regular(root / name)) == row[pin], "source_contract_hash")
    build_policy(regular(root / "build.json", 65536))
    # The approved toolchain file is also byte-pinned; no canonical1.99 fallback.
    text = regular(root / "rust-toolchain.toml", 65536).decode()
    require(re.search(r'(?m)^channel\s*=\s*"1\.98\.1"\s*$', text) is not None
            and "wasm32-unknown-unknown" in text, "toolchain_drift")


def unpack_sealed(archive, output):
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist()
        require(len(entries) == 1 and entries[0].filename == "sdk.git.bundle"
                and not entries[0].is_dir() and not entries[0].flag_bits & 1
                and stat.S_IFMT(entries[0].external_attr >> 16) in (0, stat.S_IFREG)
                and 0 < entries[0].file_size <= MAX_SOURCE, "sealed_source_format")
        with zipped.open(entries[0]) as source, output.open("xb") as target:
            output.chmod(0o600); count = 0
            while block := source.read(65536):
                count += len(block); require(count <= entries[0].file_size, "sealed_source_size")
                target.write(block)
            require(count == entries[0].file_size, "sealed_source_size")


def clean_git(argv):
    return ["/usr/bin/env", "-i", "PATH=" + os.defpath, "LANG=C.UTF-8",
            "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", *argv]


ENCRYPTED_HISTORY_PROBE = r'''
import hashlib,json,os,pathlib,subprocess,sys
root=sys.argv[1]; plain={r["path"]:r for r in json.loads(sys.argv[2])};expected=sys.argv[3]
def git(*args):
    return subprocess.run(["git","-C",root,*args],check=True,capture_output=True,timeout=10).stdout
commits=git("rev-list","--all").decode().splitlines()
assert commits and len(commits)<=128
assert expected in commits
batch=subprocess.Popen(["git","-C",root,"cat-file","--batch"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
rows=[]; total=0
try:
    for commit in sorted(commits):
        entries=git("ls-tree","-r","-z",commit).split(b"\0")
        for entry in entries:
            if not entry:continue
            header,name=entry.split(b"\t",1); mode,kind,oid=header.decode().split()
            path=name.decode();assert mode in ("100644","100755") and kind=="blob"
            assert path not in (".git",) and all(p not in ("",".","..") for p in path.split("/"))
            batch.stdin.write(oid.encode()+b"\n");batch.stdin.flush()
            actual,typ,size=batch.stdout.readline().decode().split();size=int(size)
            assert actual==oid and typ=="blob" and 0<size<=512*1024**2
            prefix=batch.stdout.read(min(10,size))
            encrypted=prefix.startswith(b"\0GITCRYPT\0")
            if not encrypted:
                assert path in plain and (not path.endswith(".rs") or path.startswith("facade/"))
                assert not path.startswith(("engine/","crates/","vendor/","reference/"))
            h=hashlib.sha256(prefix);left=size-len(prefix)
            while left:
                block=batch.stdout.read(min(65536,left));assert block;h.update(block);left-=len(block)
            assert batch.stdout.read(1)==b"\n"
            if not encrypted:assert plain[path]["bytes"]==size and plain[path]["sha256"]==h.hexdigest()
            total+=size;assert total<=512*1024**2 and len(rows)<20000
            rows.append({"commit":commit,"path":path,"blob":oid,"bytes":size,"sha256":h.hexdigest(),"encrypted":encrypted})
    batch.stdin.close();assert batch.wait(timeout=5)==0
finally:
    if batch.poll() is None:
        batch.terminate()
        try:batch.wait(timeout=3)
        except subprocess.TimeoutExpired:batch.kill();batch.wait(timeout=3)
    batch.stdout.close()
raw=(json.dumps(rows,sort_keys=True,separators=(",",":"))+"\n").encode()
print(json.dumps({"commits":len(commits),"blob_records":len(rows),"ciphertext_inventory_sha256":hashlib.sha256(raw).hexdigest()}))
'''


def prepare(case, row, operation, verify, started):
    case.mkdir(mode=0o700, exist_ok=False)
    evidence = case / "prepare-private"; evidence.mkdir(mode=0o700)
    owner = verify.Owner(evidence, started=started)
    checkout, key = case / "decrypt-checkout", case / "decrypt-new-key"
    frozen = case / "frozen-sdk"; frozen.mkdir(mode=0o700)
    primary, clean = "failed", False
    try:
        verify.linux_resources()
        for name, pin in row["prep_tool_sha256"].items():
            require(digest(regular(Path("/usr/bin") / name, 32 * 1024**2)) == pin, "prep_tool_identity")
        archive = case / "encrypted-source.zip"
        verify.download(REPOSITORY, row["release_tag"], row["archive"], archive,
                        time.monotonic() + owner.remaining(120))
        bundle = case / "sdk.git.bundle"; unpack_sealed(archive, bundle)
        owner.command(clean_git(["git", "-c", "core.hooksPath=/dev/null", "clone", "--no-checkout", "--no-local",
                                 str(bundle), str(checkout)]), 60)
        owner.command(clean_git(["git", "-C", str(checkout), "config", "core.hooksPath", "/dev/null"]), 5)
        owner.command(clean_git(["git", "-C", str(checkout), "config", "core.fsmonitor", "false"]), 5)
        history = json.loads(owner.command(clean_git([sys.executable, "-I", "-B", "-c", ENCRYPTED_HISTORY_PROBE,
                    str(checkout), json.dumps(row["public_plaintext"], separators=(",", ":")), row["git_commit"]]), 120))
        require(history["ciphertext_inventory_sha256"] == row["ciphertext_inventory_sha256"],
                "ciphertext_history_review_mismatch")
        owner.command(clean_git(["git", "-C", str(checkout), "checkout", "--detach", row["git_commit"]]), 60)
        # git-crypt is invoked only here; no key is passed to Docker or build.
        require(not owner.command(clean_git(["git", "-C", str(checkout), "status", "--porcelain"]), 5).strip(),
                "encrypted_checkout_dirty")
        raw = os.environ.pop("SDK_NEW_GITCRYPT_KEY_B64", None)
        require(isinstance(raw, str) and 0 < len(raw) <= 65536, "separate_sdk_key_required")
        decoded = base64.b64decode(raw, validate=True)
        require(0 < len(decoded) <= 32768 and digest(decoded) == row["key_sha256"], "sdk_key_identity")
        with key.open("xb") as output: key.chmod(0o600); output.write(decoded)
        del decoded, raw
        # git dispatches git-crypt with the explicit fresh checkout as cwd.
        owner.command(clean_git(["git", "-C", str(checkout), "crypt", "unlock", str(key)]), 60)
        sdk_source = checkout / "engine" / "sdk"
        require(sdk_source.is_dir() and not (checkout / "engine").is_symlink() and not sdk_source.is_symlink(),
                "fixed_sdk_source_root")
        original = tree_inventory(sdk_source, freeze=frozen)
        require(digest(canonical(original)) == row["input_inventory_sha256"]
                and tree_inventory(frozen) == original, "source_inventory_drift")
        source_contract(frozen, row)
        for path in sorted(frozen.rglob("*"), reverse=True): path.chmod(0o555 if path.is_dir() else 0o444)
        frozen.chmod(0o555)
        primary = "prepared"
    finally:
        # Includes git-crypt's cached key in the fresh checkout .git directory.
        try:
            clean = owner.close()
        finally:
            try:
                if key.exists(): key.unlink()
            finally:
                if checkout.exists(): shutil.rmtree(checkout)
        require(not key.exists() and not checkout.exists(), "key_disposition_unknown")
    require(clean and primary == "prepared", "prepare_failed_or_unknown")
    require(verify.STOP is None and time.monotonic() < owner.hard, "prepare_deadline")
    value = {"schema_version": 1, "state": "TRUSTED_SOURCE_PREPARED", "operation": operation,
        "source_catalog": os.environ["SDK_SOURCE"], "source_archive_sha256": row["archive"]["sha256"],
        "started_monotonic": started, "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "input_inventory_sha256": row["input_inventory_sha256"], "key_removed": True, "resources_closed": True}
    verify.save(case / "prepared.private.json", value)
    require(verify.STOP is None and time.monotonic() < owner.hard, "prepare_deadline")


def prepared(case, row, operation, verify):
    value = private_document(case / "prepared.private.json", verify)
    require(value["state"] == "TRUSTED_SOURCE_PREPARED" and value["operation"] == operation
        and value["source_catalog"] == os.environ["SDK_SOURCE"]
        and value["source_archive_sha256"] == row["archive"]["sha256"]
        and value["input_inventory_sha256"] == row["input_inventory_sha256"]
        and value["key_removed"] is True and value["resources_closed"] is True
        and not (case / "decrypt-new-key").exists() and not (case / "decrypt-checkout").exists()
        and value["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        and 0 <= time.monotonic() - value["started_monotonic"] < 3870, "prepared_context_drift")
    require("SDK_NEW_GITCRYPT_KEY_B64" not in os.environ, "key_env_in_build")
    return value


def container(owner, row, operation, phase, source, registry, output):
    require(all(path.is_absolute() and "," not in str(path) and "\x00" not in str(path)
                for path in (source, registry, output)), "mount_path")
    name = "harmony-sdk-" + phase + "-" + uuid.uuid4().hex
    owned = {"name": name, "image": row["compiler_image"], "phase": phase,
             "operation": operation, "absent": False, "identity_verified": False,
             "image_environment": row["image_environment"]}
    owner.containers.append(owned); owner.journal()
    network = "bridge" if phase == "prefetch" else "none"
    args = ["create", "--name", name, "--label", "online.harmony.operation=" + operation,
        "--network", network, "--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--memory", "8g", "--memory-swap", "8g",
        "--cpus", "2", "--cpuset-cpus", "0,1", "--pids-limit", "256", "--ipc", "private",
        "--cgroupns", "private", "--ulimit", "nofile=1024:1024",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=512m,mode=1777", "--workdir", "/sdk",
        "--mount", "type=bind,src=" + str(source) + ",dst=/sdk,readonly",
        "--mount", "type=bind,src=" + str(registry) + ",dst=/registry" + ("" if phase == "prefetch" else ",readonly"),
        "--mount", "type=bind,src=" + str(output) + ",dst=/out", "--entrypoint", "/usr/bin/env", row["compiler_ref"],
        "-i", *(key + "=" + value for key, value in COMPILER_ENV.items())]
    return owned, args


def prefetch_command():
    # Cargo's explicit targets retain the Wasm and host dependency closure.
    return ["cargo", "+" + RUST, "fetch", "--locked", "--manifest-path", "examples/game/Cargo.toml",
            "--target", TARGET, "--target", HOST]


REGISTRY_PREFETCH_GUEST = r'''
import errno,json,os,pathlib,stat,subprocess,sys,time
EXPECTED=['cargo','+1.98.1','fetch','--locked','--manifest-path','examples/game/Cargo.toml',
          '--target','wasm32-unknown-unknown','--target','aarch64-unknown-linux-gnu']
FORBIDDEN={'credentials','credentials.toml','auth.json','.docker','.codex','.cursor','.claude'}
CODES={'registry_alias_refused','registry_credentials_refused','registry_entry_type',
       'registry_entry_changed','registry_prefetch_command','registry_prefetch_deadline',
       'registry_permission_denied','registry_no_space','registry_read_only','registry_io_failure',
       'registry_quota_exceeded','registry_entry_missing','registry_os_error','registry_guest_failed'}
def code(error):
    if isinstance(error,OSError):
        return {errno.EACCES:'registry_permission_denied',errno.EPERM:'registry_permission_denied',
                errno.ENOSPC:'registry_no_space',errno.EROFS:'registry_read_only',errno.EIO:'registry_io_failure',
                errno.EDQUOT:'registry_quota_exceeded',errno.ENOENT:'registry_entry_missing',
                errno.ELOOP:'registry_alias_refused'}.get(error.errno,'registry_os_error')
    if isinstance(error,ValueError) and len(error.args)==1 and type(error.args[0]) is str and error.args[0] in CODES:
        return error.args[0]
    return 'registry_guest_failed'
def need(value,refusal):
    if not value:raise ValueError(refusal)
def normalize_registry(root,deadline):
    counts={'directories':0,'files':0}
    def remaining():need(time.monotonic()<deadline,'registry_prefetch_deadline')
    def visit(parent,depth):
        remaining()
        with os.scandir(parent) as stream:entries=sorted(item.name for item in stream)
        for name in entries:
            remaining()
            if depth==0:need(name not in FORBIDDEN,'registry_credentials_refused')
            before=os.stat(name,dir_fd=parent,follow_symlinks=False)
            need(not stat.S_ISLNK(before.st_mode),'registry_alias_refused')
            directory=stat.S_ISDIR(before.st_mode)
            need(directory or stat.S_ISREG(before.st_mode) and before.st_nlink==1,'registry_entry_type')
            flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_DIRECTORY if directory else 0)
            child=os.open(name,flags,dir_fd=parent)
            try:
                held=os.fstat(child)
                need((held.st_dev,held.st_ino,stat.S_IFMT(held.st_mode))==
                     (before.st_dev,before.st_ino,stat.S_IFMT(before.st_mode)),'registry_entry_changed')
                os.fchmod(child,0o755 if directory else 0o644)
                counts['directories' if directory else 'files']+=1
                if directory:visit(child,depth+1)
                visible=os.stat(name,dir_fd=parent,follow_symlinks=False)
                need((visible.st_dev,visible.st_ino,stat.S_IFMT(visible.st_mode))==
                     (held.st_dev,held.st_ino,stat.S_IFMT(held.st_mode)),'registry_entry_changed')
            finally:os.close(child)
    # The root is created by the host runner with mode0777. Do not chmod it:
    # guest UID65532 owns its Cargo children, not the host-owned mount root.
    fd=os.open(root,os.O_RDONLY|os.O_NOFOLLOW|os.O_DIRECTORY|os.O_NONBLOCK)
    try:visit(fd,0)
    finally:os.close(fd)
    remaining()
    return counts
def run_prefetch(command,root,maximum):
    need(command==EXPECTED,'registry_prefetch_command')
    need(type(maximum) in (int,float) and 0<maximum<=300,'registry_prefetch_deadline')
    deadline=time.monotonic()+maximum
    result=subprocess.run(command,check=False,timeout=maximum)
    if result.returncode!=0:raise SystemExit(result.returncode if result.returncode>0 else 128-result.returncode)
    return normalize_registry(root,deadline)
def main():
    try:
        counts=run_prefetch(json.loads(sys.argv[1]),pathlib.Path('/registry'),float(sys.argv[2]))
        print(json.dumps({'schema_version':1,'state':'public_registry_normalized',**counts},sort_keys=True),flush=True)
        return 0
    except subprocess.TimeoutExpired:
        print('registry_prefetch_deadline',file=sys.stderr);return 78
    except Exception as error:
        print(code(error),file=sys.stderr);return 78
if __name__=='__main__':raise SystemExit(main())
'''


def registry_os_error(error):
    # Never inspect OSError paths or shutil.Error's path/message tuples.
    return {errno.EACCES: "registry_permission_denied", errno.EPERM: "registry_permission_denied",
            errno.ENOSPC: "registry_no_space", errno.EROFS: "registry_read_only",
            errno.EIO: "registry_io_failure", errno.EDQUOT: "registry_quota_exceeded",
            errno.ENOENT: "registry_entry_missing", errno.ELOOP: "registry_alias_refused"}.get(
                error.errno, "registry_os_error")


def copy_registry(registry, runtime_registry):
    try:
        require(registry.is_dir() and not registry.is_symlink(), "registry_alias_refused")
        for path in registry.rglob("*"):
            kind = path.lstat().st_mode
            require(not stat.S_ISLNK(kind), "registry_alias_refused")
            require(stat.S_ISDIR(kind) or stat.S_ISREG(kind), "registry_entry_type")
        # Copy the public seed only. The original normalized tree stays intact.
        shutil.copytree(registry, runtime_registry, symlinks=False)
        runtime_registry.chmod(0o777)
        for path in runtime_registry.rglob("*"): path.chmod(0o777 if path.is_dir() else 0o666)
    except shutil.Error:
        raise Refused("registry_copy_failed") from None
    except OSError as error:
        raise Refused(registry_os_error(error)) from None



def start(owner, owned, create_args, command, maximum):
    if owned["phase"] == "prefetch":
        require(command == prefetch_command(), "registry_prefetch_command")
        require(type(maximum) in (int, float) and 0 < maximum <= 300, "registry_prefetch_deadline")
        command = ["python3", "-I", "-B", "-c", REGISTRY_PREFETCH_GUEST,
                   json.dumps(command, separators=(",", ":")), str(maximum)]
    raw = owner.docker(create_args + command, 15)
    cid = raw.decode().strip(); require(re.fullmatch(r"[0-9a-f]{64}", cid), "container_id")
    owned["cid"] = cid
    value = owner.inspect(cid)
    expected_mounts = []
    for index, arg in enumerate(create_args):
        if arg == "--mount":
            options = dict(part.split("=", 1) for part in create_args[index + 1].split(",") if "=" in part)
            expected_mounts.append((options["src"], options["dst"], not create_args[index + 1].endswith(",readonly")))
    actual_mounts = sorted((item["Source"], item["Destination"], item["RW"]) for item in value["Mounts"] if item["Type"] == "bind")
    require(value["Id"] == cid and value["Name"] == "/" + owned["name"] and value["Image"] == owned["image"]
        and value["Config"]["Labels"].get("online.harmony.operation") == owned["operation"]
        and value["Config"]["User"] == "65532:65532" and value["HostConfig"]["ReadonlyRootfs"] is True
        and value["HostConfig"]["Memory"] == value["HostConfig"]["MemorySwap"] == 8 * 1024**3
        and value["HostConfig"]["PidsLimit"] == 256 and value["HostConfig"]["CapDrop"] == ["ALL"]
        and value["HostConfig"]["NanoCpus"] == 2_000_000_000
        and value["HostConfig"]["NetworkMode"] == ("bridge" if owned["phase"] == "prefetch" else "none")
        and value["HostConfig"]["CpusetCpus"] == "0,1"
        and value["HostConfig"]["SecurityOpt"] == ["no-new-privileges"]
        and value["HostConfig"]["Privileged"] is False and value["HostConfig"]["PidMode"] == ""
        and not value["HostConfig"].get("Devices") and not value["HostConfig"].get("DeviceRequests")
        and not value["HostConfig"].get("PortBindings") and not value["Config"].get("ExposedPorts")
        and value["Config"]["Entrypoint"] == ["/usr/bin/env"]
        and value["Config"].get("Env", []) == owned["image_environment"]
        and value["HostConfig"]["IpcMode"] == "private" and value["HostConfig"]["CgroupnsMode"] == "private"
        and value["Config"]["Cmd"] == ["-i", *(key + "=" + item for key, item in COMPILER_ENV.items()), *command]
        and actual_mounts == sorted(expected_mounts)
        and all(item["Type"] == "bind" or item["Type"] == "tmpfs" and item["Destination"] == "/tmp"
                for item in value["Mounts"])
        and value["HostConfig"]["Tmpfs"] == {"/tmp": "rw,nosuid,nodev,noexec,size=512m,mode=1777"},
        "container_contract")
    owned["identity_verified"] = True; owner.journal()
    raw = owner.docker(["start", "--attach", cid], maximum)
    require(owner.inspect(cid)["State"]["ExitCode"] == 0, "container_command_failed")
    owner.remove(owned)
    return raw


def cargo_events(raw):
    require(len(raw) <= 8 * 1024**2, "cargo_json_bound")
    events = []
    for line in raw.splitlines():
        value = json.loads(line)
        require(isinstance(value, dict) and isinstance(value.get("reason"), str), "cargo_json_invalid")
        events.append(value)
    require(any(value.get("reason") == "build-finished" and value.get("success") is True for value in events)
            and not any(value.get("reason") == "build-finished" and value.get("success") is not True for value in events),
            "cargo_build_not_passed")
    return events


def artifact_candidate(events, metadata):
    """Preserve exact emitted file paths; never guess archive/library filenames."""
    require(isinstance(metadata, dict) and isinstance(metadata.get("packages"), list)
            and isinstance(metadata.get("resolve", {}).get("nodes"), list), "cargo_metadata_invalid")
    packages = {item["id"]: item for item in metadata["packages"]}
    records = []
    for event in events:
        if event["reason"] == "build-script-executed":
            require(not event.get("linked_libs"), "native_link_closure_requires_review")
        if event["reason"] != "compiler-artifact": continue
        require(event.get("package_id") in packages and isinstance(event.get("features"), list)
                and isinstance(event.get("filenames"), list), "artifact_metadata_invalid")
        kind = event.get("target", {}).get("kind", [])
        if "custom-build" in kind: continue
        for name in event["filenames"]:
            path = PurePosixPath(name)
            require(path.is_absolute() and ".." not in path.parts and path.is_relative_to("/out/target"), "artifact_output_path")
            if path.suffix not in (".rlib", ".rmeta", ".so", ".dylib", ".dll"): continue
            host_macro = "proc-macro" in kind
            host_library = not host_macro and not path.is_relative_to("/out/target/" + TARGET)
            require((host_macro and path.suffix in (".so", ".dylib", ".dll"))
                    or (not host_macro and path.suffix in (".rlib", ".rmeta")), "artifact_role_mismatch")
            package = packages[event["package_id"]]
            records.append({"package_id": event["package_id"], "name": package["name"], "version": package["version"],
                "target": HOST if host_macro or host_library else TARGET, "features": sorted(event["features"]),
                "profile": event["profile"], "kind": "host_proc_macro" if host_macro else "host_library" if host_library else "target",
                "compiler_output": str(path.relative_to("/out")),
                "public_path": "lib/" + (HOST if host_macro or host_library else TARGET) + "/" + path.name,
                "role": "opaque_proc_macro" if host_macro else "opaque_metadata" if path.suffix == ".rmeta" else "opaque_rlib"})
    require(records and any(item["name"] == "moonlight" and item["role"] == "opaque_rlib" for item in records),
            "moonlight_artifact_missing")
    require(len({item["public_path"] for item in records}) == len(records), "artifact_collision")
    # Cargo resolve nodes and complete emitted artifacts remain PRIVATE until
    # a reviewed graph adapter proves Rust crate/disambiguator and ABI closure.
    return records


TOOLCHAIN_PROBE = r'''
import hashlib,json,os,pathlib,subprocess
def out(argv):
    return subprocess.run(argv,check=True,capture_output=True,text=True,timeout=5).stdout.strip()
actual=pathlib.Path(out(["rustup","which","--toolchain","1.98.1","rustc"])).resolve(strict=True)
verbose=out([str(actual),"-vV"])+"\n"
lines=verbose.splitlines(); fields=dict(line.split(": ",1) for line in lines[1:])
assert fields["release"]=="1.98.1" and fields["host"]=="aarch64-unknown-linux-gnu"
root=pathlib.Path(out([str(actual),"--print","sysroot"]))
items=[]; total=0
for target in (fields["host"],"wasm32-unknown-unknown"):
    base=root/"lib/rustlib"/target/"lib"
    for path in sorted(base.iterdir()):
        assert path.is_file() and not path.is_symlink()
        data=path.read_bytes();total+=len(data);assert total<=2*1024**3
        items.append({"path":str(path.relative_to(root)),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()})
assert items
encoded=(json.dumps(items,sort_keys=True,separators=(",",":"))+"\n").encode()
print(json.dumps({"release":fields["release"],"commit_hash":fields["commit-hash"],
"commit_date":fields["commit-date"],"host":fields["host"],"llvm_version":fields["LLVM version"],
"verbose_version":verbose,"executable_sha256":hashlib.sha256(actual.read_bytes()).hexdigest(),
"sysroot_sha256":hashlib.sha256(encoded).hexdigest()},sort_keys=True))
'''


def artifact_inventory(output, records):
    result = []
    for item in records:
        relative = PurePosixPath(item["compiler_output"])
        require(not relative.is_absolute() and ".." not in relative.parts, "artifact_output_path")
        path = output.joinpath(*relative.parts)
        current = output
        for part in relative.parts[:-1]:
            current /= part
            require(current.is_dir() and not current.is_symlink(), "artifact_directory_alias")
        data = regular(path)
        require(not data.startswith(b"\x00GITCRYPT\x00"), "encrypted_artifact_refused")
        result.append({"path": item["public_path"], "role": item["role"], "bytes": len(data), "sha256": digest(data)})
    return sorted(result, key=lambda item: item["path"])


def evidence_modules():
    path = Path(__file__).with_name("seal_sdk_evidence.py")
    spec = importlib.util.spec_from_file_location("sdk_evidence", path)
    sealing = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sealing)
    pins = sealing.snapshot()
    selection = sealing.module("evidence_selection", pins)
    return sealing, selection, pins


def compile(case, row, operation, verify, diagnostic=None):
    failure_stage(diagnostic, "compile_context")
    context = prepared(case, row, operation, verify)
    sealing, selection, evidence_pins = evidence_modules()
    sealing.recipient()  # Protected tuple admitted before any SDK compiler work.
    failure_stage(diagnostic, "compile_setup")
    evidence = case / "build-private"; evidence.mkdir(mode=0o700, exist_ok=False)
    owner = verify.Owner(evidence, started=context["started_monotonic"])
    candidate, primary = None, "failed"
    clean, primary_error = False, None
    try:
        source, registry, output = case / "frozen-sdk", case / "public-registry", case / "compiler-output"
        registry.mkdir(mode=0o777, exist_ok=False); output.mkdir(mode=0o777, exist_ok=False)
        registry.chmod(0o777); output.chmod(0o777)
        source_before = tree_inventory(source)
        failure_stage(diagnostic, "compile_resource_admission")
        verify.linux_resources(); require(shutil.disk_usage(case).free >= 10 * 1024**3, "disk_floor")
        failure_stage(diagnostic, "compile_source")
        require(digest(canonical(source_before)) == row["input_inventory_sha256"], "source_inventory_drift")
        source_contract(source, row)
        require(not owner.docker(["ps", "--all", "--quiet"]).strip(), "foreign_container_present")
        failure_stage(diagnostic, "compile_image")
        owner.docker(["image", "pull", row["compiler_ref"]], min(120, owner.remaining(120)))
        image = json.loads(owner.docker(["image", "inspect", row["compiler_ref"]]))[0]
        require(image["Id"] == row["compiler_image"] and image["Architecture"] == "arm64" and image["Os"] == "linux"
                and row["compiler_ref"] in image.get("RepoDigests", [])
                and image["Config"].get("Env", []) == row["image_environment"]
                and not image["Config"].get("Volumes"), "toolchain_image_identity")
        failure_stage(diagnostic, "compile_toolchain")
        probe, args = container(owner, row, operation, "toolchain", source, registry, output)
        compiler_identity = json.loads(start(owner, probe, args, ["python3", "-I", "-B", "-c", TOOLCHAIN_PROBE],
                                            min(60, owner.remaining(60))))
        _, exporter = helpers()
        exporter.compiler(compiler_identity, RUST, HOST)
        failure_stage(diagnostic, "compile_prefetch")
        prefetch, args = container(owner, row, operation, "prefetch", source, registry, output)
        start(owner, prefetch, args, prefetch_command(), min(300, owner.remaining(300)))
        failure_stage(diagnostic, "compile_registry")
        require(not any((registry / name).exists() for name in ("credentials", "credentials.toml", "auth.json",
                        ".docker", ".codex", ".cursor", ".claude")), "registry_credentials_refused")
        # Cargo may update sqlite/lock bookkeeping even offline. Preserve the
        # prefetched seed and use a separate credential-free writable copy.
        runtime_registry = case / "runtime-registry"
        copy_registry(registry, runtime_registry)
        failure_stage(diagnostic, "compile_cargo")
        compiler, args = container(owner, row, operation, "compile", source, runtime_registry, output)
        # The runtime copy is writable public cache, never the host's CARGO_HOME.
        mount_index = next(i + 1 for i, item in enumerate(args) if item == "--mount" and "dst=/registry" in args[i + 1])
        args[mount_index] = args[mount_index].removesuffix(",readonly")
        compile_remaining = owner.remaining(3600) - 120  # Reserve metadata60 + seal60 inside original3900.
        require(compile_remaining > 0, "evidence_reserve_exhausted")
        raw = start(owner, compiler, args, ["cargo", "+" + RUST, "build", "--offline", "--frozen",
            "--manifest-path", "examples/game/Cargo.toml", "--target", TARGET, "--profile", "web-release",
            "--bin", "harmony-games", "--features", "web-webgl2", "--jobs", "1", "--message-format=json"],
            min(3600, compile_remaining))
        events = cargo_events(raw)
        # Metadata is read only, offline, in the same source/toolchain boundary.
        failure_stage(diagnostic, "compile_metadata")
        meta, args = container(owner, row, operation, "metadata", source, runtime_registry, output)
        mount_index = next(i + 1 for i, item in enumerate(args) if item == "--mount" and "dst=/registry" in args[i + 1])
        args[mount_index] = args[mount_index].removesuffix(",readonly")
        metadata = json.loads(start(owner, meta, args, ["cargo", "+" + RUST, "metadata", "--offline", "--locked",
            "--format-version", "1", "--manifest-path", "examples/game/Cargo.toml", "--filter-platform", TARGET,
            "--features", "web-webgl2"],
            min(60, owner.remaining(60))))
        failure_stage(diagnostic, "compile_artifacts")
        candidate = artifact_candidate(events, metadata)
        require(tree_inventory(source) == source_before, "source_changed_during_compile")
        primary = "built_not_qualified"
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if diagnostic is not None:
            diagnostic["owner_close_called"] = True
            diagnostic["owner_close_succeeded"] = False
        try:
            clean = owner.close()
        except Exception as cleanup_error:
            if diagnostic is not None:
                diagnostic["cleanup_refusal_code"] = refusal_code(cleanup_error)
            # Cleanup may fail, but must not replace an earlier command failure.
            if primary_error is None:
                failure_stage(diagnostic, "compile_cleanup")
                raise
        else:
            if diagnostic is not None:
                diagnostic["owner_close_succeeded"] = clean is True
                if clean is not True:
                    diagnostic["cleanup_refusal_code"] = "compiler_failed_or_unknown"
    failure_stage(diagnostic, "compile_cleanup")
    require(clean and primary == "built_not_qualified", "compiler_failed_or_unknown")
    failure_stage(diagnostic, "compile_receipts")
    require(verify.STOP is None and time.monotonic() < owner.hard, "producer_deadline")
    require(sealing.snapshot() == evidence_pins, "evidence_source_changed")
    closure = selection.owner_closure_projection(owner, operation, evidence_pins)
    closure.update(original_exit_code=0, stop_signal=verify.STOP, source_unchanged=True,
                   started_monotonic=context["started_monotonic"], hard_monotonic=owner.hard)
    verify.save(case / "producer-closure.private.json", closure)
    require(verify.STOP is None and time.monotonic() < owner.hard, "producer_deadline")
    files = artifact_inventory(output, candidate)
    require(verify.STOP is None and time.monotonic() < owner.hard, "producer_deadline")
    cargo_receipt = {"schema_version": 1, "producer": PRODUCER, "source_revision": row["source_revision"],
        "authorization_id": row["authorization_id"], "state": "COMPILED_CLOSURE_PRODUCED", "exit_code": 0,
        "timed_out": False, "resources_closed": True, "unknown_owners": [], "compiler": compiler_identity,
        "target": TARGET, "features": FEATURES, "profile": PROFILE,
        "rustflags_sha256": digest(COMPILER_ENV["CARGO_ENCODED_RUSTFLAGS"].encode()),
        "lockfile_sha256": row["lockfile_sha256"], "input_inventory_sha256": row["input_inventory_sha256"],
        "environment_policy_sha256": digest(canonical(COMPILER_ENV)),
        "artifact_inventory_sha256": exporter.digest(exporter.canonical(exporter.plain_inventory(files)))}
    verify.save(case / "cargo-closure.private.json", cargo_receipt)
    require(verify.STOP is None and time.monotonic() < owner.hard, "producer_deadline")
    # This private candidate has no approved facade or public artifact policy.
    # Do not invent an SDK manifest or ABI proof from Cargo package labels.
    verify.save(case / "artifact-candidate.private.json", {"schema_version": 1, "state": primary,
        "operation": operation, "source_revision": row["source_revision"], "authorization_id": row["authorization_id"],
        "input_inventory_sha256": row["input_inventory_sha256"], "environment_policy_sha256": digest(canonical(COMPILER_ENV)),
        "profile": PROFILE, "features": FEATURES, "compiler": compiler_identity, "target": TARGET,
        "resources_closed": True, "files": candidate, "artifact_inventory": files, "cargo_metadata": metadata,
        "cargo_receipt_sha256": digest(regular(case / "cargo-closure.private.json")),
        "gaps": ["rust_crate_identity_and_dependency_graph_join",
                 "independently_approved_public_facade", "independent_export_policy", "downstream_ABI_qualification"]})
    require(verify.STOP is None and time.monotonic() < owner.hard, "producer_deadline")
    return primary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("admit", "prepare", "compile"), required=True)
    parser.add_argument("--case", type=Path)
    args = parser.parse_args(argv)
    # Close facts are tracked by compile; prepare has a separate, untracked owner.
    diagnostic = {"failure_stage": "admission", "owner_close_called": None,
                  "owner_close_succeeded": None, "cleanup_refusal_code": None}
    try:
        row, operation = approval(os.environ)
        if args.phase == "admit":
            print(json.dumps({"schema_version": 1, "state": "approved_source_tuple", "runtime_qualified": False}))
            return 0
        require(args.case is not None and args.case.is_absolute() and not args.case.is_symlink(), "private_case_required")
        verify, _ = helpers()
        verify.STOP = None
        failure_stage(diagnostic, "prepare" if args.phase == "prepare" else "compile_context")
        started = time.monotonic() if args.phase == "prepare" else prepared(args.case, row, operation, verify)["started_monotonic"]
        hard = started + 3900
        def stop(number, _frame):
            if verify.STOP is None: verify.STOP = number
        old = {number: signal.signal(number, stop) for number in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)}
        signal.setitimer(signal.ITIMER_REAL, max(0.001, hard - time.monotonic()))
        try:
            if args.phase == "prepare":
                prepare(args.case, row, operation, verify, started)
                state = "prepared_private_source"
            else:
                state = compile(args.case, row, operation, verify, diagnostic)
            failure_stage(diagnostic, "response")
            require(verify.STOP is None and time.monotonic() < hard, "signal_or_deadline")
            print(json.dumps({"schema_version": 1, "state": state, "runtime_qualified": False,
                              "exported": False, "public_sdk_approved": False}), flush=True)
            require(verify.STOP is None and time.monotonic() < hard, "response_deadline")
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            for number, handler in old.items(): signal.signal(number, handler)
        return 0 if verify.STOP is None and time.monotonic() < hard else 78
    except Exception as error:
        # Only fixed stage/code and actual close facts: no raw exception, Cargo
        # diagnostic, private path, key or source data enters public output.
        print(json.dumps({"schema_version": 1, "state": "refused_or_failed", "runtime_qualified": False,
                          "exported": False, "error_code": "trusted_sdk_producer_refused",
                          **public_failure(error, diagnostic)}))
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
