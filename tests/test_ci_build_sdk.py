"""Trusted producer controls; no source approval, key, model or Docker workload.

Cargo JSON below is a modeled fixture. The finite child test proves only the
public owner command boundary on Linux; it is not a physical SDK build.
"""
import ast
import contextlib
import copy
import errno
import io
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import uuid
import zipfile

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("ci_build_sdk", ROOT / "tools/ci_build_sdk.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class ProducerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.row = {"repository": build.REPOSITORY, "release_tag": "fixture-v1",
            "archive": {"name": "encrypted-source.zip", "bytes": 10, "sha256": "a" * 64},
            "git_commit": "b" * 40, "source_revision": "c" * 64,
            "authorization_id": str(uuid.uuid4()), "input_inventory_sha256": "d" * 64,
            "build_json_sha256": "e" * 64, "cargo_config_sha256": "f" * 64,
            "lockfile_sha256": "0" * 64, "toolchain_sha256": "1" * 64,
            "compiler_image": "sha256:" + "2" * 64,
            "compiler_ref": "ghcr.io/fvlvte/harmony-studio-projects/compiler@sha256:" + "3" * 64,
            "image_environment": ["PATH=/usr/bin"], "key_sha256": "4" * 64,
            "prep_tool_sha256": {"git": "5" * 64, "git-crypt": "6" * 64},
            "ciphertext_inventory_sha256": "7" * 64, "public_plaintext": []}
        self.env = {"GITHUB_REPOSITORY": build.REPOSITORY, "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main",
            "SDK_SOURCE": "fixture", "SDK_SOURCE_SHA256": "a" * 64, "SDK_OPERATION": str(uuid.uuid4())}
        self.metadata = {"packages": [{"id": "path+file:///sdk/moonlight#moonlight@0.3.0", "name": "moonlight", "version": "0.3.0"}],
                         "resolve": {"nodes": []}}
        self.event = {"reason": "compiler-artifact", "package_id": self.metadata["packages"][0]["id"],
            "features": ["web-webgl2"], "target": {"kind": ["lib"]}, "profile": {"opt_level": "s"},
            "filenames": ["/out/target/wasm32-unknown-unknown/web-release/deps/libmoonlight-abc.rlib"]}

    def test_empty_catalog_refuses_before_helpers_key_or_network(self):
        with patch.object(build, "APPROVED_SOURCES", {}):
            self.assertEqual(build.APPROVED_SOURCES, {})
            self.assertEqual(build.APPROVED_EXPORTS, {})
            with patch.dict(os.environ, self.env, clear=True), patch.object(build, "helpers") as helper:
                result = build.main(["--phase", "prepare", "--case", str(self.root / "case")])
            self.assertEqual(result, 78)
            helper.assert_not_called()
            self.assertFalse((self.root / "case").exists())

    def test_only_manual_own_repository_exact_archive_and_public_ref_admitted(self):
        with patch.object(build, "APPROVED_SOURCES", {"fixture": self.row}):
            self.assertEqual(build.approval(self.env)[0], self.row)
            for key, value in (("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REPOSITORY", "foreign/repo"),
                               ("GITHUB_REF", "refs/heads/unreviewed"), ("SDK_SOURCE_SHA256", "9" * 64)):
                changed = {**self.env, key: value}
                with self.subTest(key=key), self.assertRaises(build.Refused): build.approval(changed)
        bad = {**self.row, "compiler_ref": self.row["compiler_image"]}
        with patch.object(build, "APPROVED_SOURCES", {"fixture": bad}), self.assertRaises(build.Refused):
            build.approval(self.env)
        for name in ("engine/sdk/build.json", "tools/auth.json", "../README.md", "tools/.codex/auth.json"):
            bad = {**self.row, "public_plaintext": [{"path": name, "bytes": 1, "sha256": "8" * 64}]}
            with self.subTest(name=name), patch.object(build, "APPROVED_SOURCES", {"fixture": bad}), self.assertRaises(build.Refused):
                build.approval(self.env)

    def test_reviewed_public_toolchain_dockerfile_does_not_admit_private_state(self):
        data = (ROOT / "toolchain/Dockerfile").read_bytes()
        expected = "7d2dd2c7a6565aa81d03c7db45cad52ac27c81d6dfd1cecd616cb842e5302c20"
        self.assertEqual(hashlib.sha256(data).hexdigest(), expected)
        item = {"path": "toolchain/Dockerfile", "bytes": len(data), "sha256": expected}
        row = {**self.row, "public_plaintext": [item]}
        with patch.object(build, "APPROVED_SOURCES", {"fixture": row}):
            self.assertEqual(build.approval(self.env)[0]["public_plaintext"], [item])
        for name in ("toolchain/private-state.json", "toolchain/auth.json", "toolchain/.docker/config.json",
                     "toolchain/new.key", "toolchain/build.log", "toolchain/credentials.toml",
                     "toolchain/engine/src/lib.rs", "toolchain/nested/Dockerfile"):
            changed = {**self.row, "public_plaintext": [{**item, "path": name}]}
            with self.subTest(name=name), patch.object(build, "APPROVED_SOURCES", {"fixture": changed}), self.assertRaises(build.Refused):
                build.approval(self.env)

    def test_trusted_build_json_rejects_extra_fields_and_feature_profile_drift(self):
        policy = {"schema_version": 1, "profile": "web-release", "features": ["web-webgl2"],
            "binary": "harmony-games", "out_name": "harmony_games", "size_budget": "size-budget.json",
            "wasm_opt": {"version": "133", "level": "z", "flags": ["--strip-debug", "--strip-producers",
                "--enable-bulk-memory", "--enable-nontrapping-float-to-int", "--enable-reference-types",
                "--enable-sign-ext", "--enable-mutable-globals"]}}
        self.assertEqual(build.build_policy(json.dumps(policy).encode()), policy)
        for key, value in (("jobs", 1), ("profile", "release"), ("features", ["web-webgpu"]), ("schema_version", True)):
            with self.subTest(key=key), self.assertRaises(build.Refused):
                build.build_policy(json.dumps({**policy, key: value}).encode())

    def test_sealed_archive_allows_only_bundle_not_raw_sdk_or_gitcrypt_claim(self):
        archive = self.root / "sealed.zip"
        with zipfile.ZipFile(archive, "w") as zipped: zipped.writestr("sdk.git.bundle", b"modeled encrypted-only git bundle")
        build.unpack_sealed(archive, self.root / "bundle")
        self.assertEqual((self.root / "bundle").read_bytes(), b"modeled encrypted-only git bundle")
        for name in ("crates/moonlight/src/lib.rs", "../sdk.git.bundle", ".git/config"):
            other = self.root / (str(uuid.uuid4()) + ".zip")
            with zipfile.ZipFile(other, "w") as zipped: zipped.writestr(name, b"reject")
            with self.subTest(name=name), self.assertRaises(build.Refused):
                build.unpack_sealed(other, self.root / str(uuid.uuid4()))

    def test_source_inventory_refuses_symlink_credentials_and_undecrypted_blob(self):
        source = self.root / "source"; source.mkdir()
        (source / "Cargo.toml").write_text("[workspace]\n")
        self.assertEqual(build.tree_inventory(source)[0]["sha256"], build.digest(b"[workspace]\n"))
        for name, content in (("auth.json", b"private"), ("file.rs", b"\x00GITCRYPT\x00ciphertext")):
            path = source / name; path.write_bytes(content)
            with self.subTest(name=name), self.assertRaises(build.Refused): build.tree_inventory(source)
            path.unlink()
        (source / "linked.rs").symlink_to(source / "Cargo.toml")
        with self.assertRaises(OSError): build.tree_inventory(source)

    def test_cargo_events_require_positive_finish_and_never_guess_artifact_paths(self):
        raw = build.canonical(self.event) + build.canonical({"reason": "build-finished", "success": True})
        events = build.cargo_events(raw)
        record = build.artifact_candidate(events, self.metadata)[0]
        self.assertEqual(record["public_path"], "lib/wasm32-unknown-unknown/libmoonlight-abc.rlib")
        self.assertEqual(record["compiler_output"], "target/wasm32-unknown-unknown/web-release/deps/libmoonlight-abc.rlib")
        bad = {**self.event, "filenames": ["/sdk/crates/moonlight/src/lib.rs"]}
        with self.assertRaises(build.Refused): build.artifact_candidate([bad], self.metadata)
        with self.assertRaises(build.Refused): build.cargo_events(build.canonical({"reason": "build-finished", "success": False}))
        with self.assertRaises(build.Refused):
            build.artifact_candidate(events + [{"reason": "build-script-executed", "linked_libs": ["static=unknown"]}], self.metadata)

    def test_container_role_has_only_source_registry_output_mounts_and_no_swap(self):
        class Owner:
            containers = []
            def journal(self): pass
        owner = Owner()
        for phase, network in (("prefetch", "bridge"), ("compile", "none")):
            row, args = build.container(owner, self.row, self.env["SDK_OPERATION"], phase,
                                       self.root / "frozen", self.root / "registry", self.root / "output")
            self.assertEqual(args[args.index("--network") + 1], network)
            self.assertEqual(args[args.index("--memory") + 1], "8g")
            self.assertEqual(args[args.index("--memory-swap") + 1], "8g")
            self.assertEqual(args[args.index("--user") + 1], "65532:65532")
            mounts = [args[i + 1] for i, value in enumerate(args) if value == "--mount"]
            self.assertEqual(len(mounts), 3)
            self.assertTrue(mounts[0].endswith("dst=/sdk,readonly"))
            self.assertEqual(mounts[1].endswith(",readonly"), phase != "prefetch")
            self.assertNotIn("SDK_NEW_GITCRYPT_KEY_B64", "\n".join(args))
            self.assertEqual(row["image"], self.row["compiler_image"])

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "waitid"), "Linux nonreaping owner boundary")
    def test_real_finite_child_reports_toy_json_and_closes_owned_group(self):
        verify, _ = build.helpers()
        evidence = self.root / "owner"; evidence.mkdir()
        owner = verify.Owner(evidence)
        raw = build.canonical(self.event) + build.canonical({"reason": "build-finished", "success": True})
        with patch.object(verify, "linux_resources", return_value={}):
            observed = owner.command([sys.executable, "-c", "import sys;sys.stdout.buffer.write(" + repr(raw) + ")"], 5)
            self.assertEqual(len(build.cargo_events(observed)), 2)
            self.assertTrue(owner.close())
        self.assertTrue(owner.children)
        self.assertTrue(all(row["reaped"] and row["group_closed"] and row["returncode"] == 0 for row in owner.children))


    def _compile_failure(self, phase, error=None, *, cleanup=True, setup_collision=False):
        # Execute main -> compile -> real container argument construction, with
        # command transport/lifecycle modeled. This does not run Docker or an SDK.
        case = self.root / uuid.uuid4().hex; case.mkdir()
        source = case / "frozen-sdk"; source.mkdir(); (source / "Cargo.toml").write_text("[workspace]\n")
        row = {**self.row, "input_inventory_sha256": build.digest(build.canonical(build.tree_inventory(source)))}
        if setup_collision: (case / "public-registry").mkdir()
        owners, commands = [], []
        class Owner:
            def __init__(self, evidence, started):
                self.hard = started + 3900; self.containers = []; self.close_calls = 0; owners.append(self)
            def journal(self): pass
            def remaining(self, maximum): return maximum
            def docker(self, argv, maximum=None):
                if argv[:2] == ["image", "inspect"]:
                    return json.dumps([{"Id": row["compiler_image"], "Architecture": "arm64", "Os": "linux",
                        "RepoDigests": [row["compiler_ref"]], "Config": {"Env": row["image_environment"]}}]).encode()
                return b""
            def close(self):
                self.close_calls += 1
                if isinstance(cleanup, BaseException): raise cleanup
                return cleanup
        verify = types.SimpleNamespace(STOP=None, Owner=Owner, linux_resources=lambda: None)
        exporter = types.SimpleNamespace(compiler=lambda *args: None)
        sealing = types.SimpleNamespace(recipient=lambda: None)
        def start(owner, owned, args, command, maximum):
            commands.append((owned["phase"], command))
            if owned["phase"] == phase: raise error if error is not None else build.Refused("command_failed")
            return b'{}' if owned["phase"] == "toolchain" else b""
        stdout = io.StringIO()
        with patch.dict(os.environ, self.env, clear=True), \
             patch.object(build, "APPROVED_SOURCES", {"fixture": row}), \
             patch.object(build, "helpers", return_value=(verify, exporter)), \
             patch.object(build, "prepared", return_value={"started_monotonic": build.time.monotonic()}), \
             patch.object(build, "evidence_modules", return_value=(sealing, None, {})), \
             patch.object(build, "source_contract"), patch.object(build, "start", side_effect=start), \
             patch.object(build.shutil, "disk_usage", return_value=types.SimpleNamespace(free=20 * 1024**3)), \
             contextlib.redirect_stdout(stdout):
            exit_code = build.main(["--phase", "compile", "--case", str(case)])
        value = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 78)
        self.assertEqual(value["state"], "refused_or_failed")
        self.assertEqual(value["error_code"], "trusted_sdk_producer_refused")
        self.assertFalse(value["runtime_qualified"])
        self.assertFalse(value["exported"])
        self.assertEqual(owners[0].close_calls, 1)
        self.assertTrue(value["owner_close_called"])
        return value, commands, stdout.getvalue()

    def test_compile_command_failures_report_exact_stage_and_close_owner(self):
        for phase, stage, prefix in (("toolchain", "compile_toolchain", ["python3", "-I", "-B", "-c"]),
                                    ("prefetch", "compile_prefetch", ["cargo", "+1.98.1", "fetch"]),
                                    ("compile", "compile_cargo", ["cargo", "+1.98.1", "build"])):
            with self.subTest(phase=phase):
                value, commands, _ = self._compile_failure(phase)
                self.assertEqual(value["failure_stage"], stage)
                self.assertEqual(value["refusal_code"], "command_failed")
                self.assertTrue(value["owner_close_succeeded"])
                self.assertIsNone(value["cleanup_refusal_code"])
                self.assertEqual(commands[-1][0], phase)
                self.assertEqual(commands[-1][1][:len(prefix)], prefix)

    def test_cleanup_failure_preserves_original_command_failure_and_stage(self):
        sentinel = "PRIVATE_KEY_PAYLOAD_DO_NOT_EMIT"
        for cleanup, code in ((False, "compiler_failed_or_unknown"), (ValueError(sentinel), "internal_error")):
            with self.subTest(code=code):
                value, _, output = self._compile_failure("compile", cleanup=cleanup)
                self.assertEqual(value["failure_stage"], "compile_cargo")
                self.assertEqual(value["refusal_code"], "command_failed")
                self.assertFalse(value["owner_close_succeeded"])
                self.assertEqual(value["cleanup_refusal_code"], code)
                self.assertNotIn(sentinel, output)

    def test_unknown_exception_payloads_never_enter_public_failure(self):
        sentinel = "PRIVATE_KEY_PAYLOAD_DO_NOT_EMIT"
        for error in (ValueError(sentinel), build.Refused("command_failed\n" + sentinel),
                      ValueError("command_failed", sentinel), OSError(sentinel)):
            with self.subTest(error_type=type(error).__name__):
                value, _, output = self._compile_failure("compile", error)
                self.assertEqual(value["failure_stage"], "compile_cargo")
                self.assertEqual(value["refusal_code"], "internal_error")
                self.assertTrue(value["owner_close_succeeded"])
                self.assertNotIn(sentinel, output)
        self.assertEqual(build.refusal_code(ValueError("compiler_identity_mismatch")), "compiler_identity_mismatch")
        self.assertEqual(build.refusal_code(ValueError("new_unreviewed_refusal")), "internal_error")

    def test_setup_failure_after_owner_creation_still_closes_owner(self):
        value, commands, _ = self._compile_failure("compile", setup_collision=True)
        self.assertEqual(value["failure_stage"], "compile_setup")
        self.assertEqual(value["refusal_code"], "internal_error")
        self.assertTrue(value["owner_close_succeeded"])
        self.assertEqual(commands, [])

    def test_prepare_failure_after_modeled_close_has_unknown_compile_close_facts(self):
        # Prepare has its own owner. Main must not report compile-close facts as
        # false when that untracked owner already closed before prepare failed.
        closed = []
        class PrepareOwner:
            def close(self): closed.append(True); return True
        owner = PrepareOwner()
        verify = types.SimpleNamespace(STOP=None)
        def prepare(*args):
            self.assertTrue(owner.close())
            raise build.Refused("prepare_failed_or_unknown")
        stdout = io.StringIO()
        with patch.dict(os.environ, self.env, clear=True), \
             patch.object(build, "APPROVED_SOURCES", {"fixture": self.row}), \
             patch.object(build, "helpers", return_value=(verify, None)), \
             patch.object(build, "prepare", side_effect=prepare), contextlib.redirect_stdout(stdout):
            exit_code = build.main(["--phase", "prepare", "--case", str(self.root / "prepare-case")])
        value = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 78)
        self.assertEqual(closed, [True])
        self.assertEqual(value["failure_stage"], "prepare")
        self.assertEqual(value["refusal_code"], "prepare_failed_or_unknown")
        self.assertIsNone(value["owner_close_called"])
        self.assertIsNone(value["owner_close_succeeded"])
        self.assertIsNone(value["cleanup_refusal_code"])

    def test_actual_probe_scripts_join_the_same_public_toy_sysroot_inventory(self):
        # Execute both maintained embedded scripts with public toy files and
        # mocked command transport. No rustc, SDK, Docker or external child runs.
        compiler = self.root / "toy-rustc"; compiler.write_bytes(b"public-toy-not-a-compiler")
        root = self.root / "toy-sysroot"
        for target in (build.HOST, build.TARGET):
            directory = root / "lib/rustlib" / target / "lib"; directory.mkdir(parents=True)
            (directory / "libtoy.rlib").write_bytes(("public-toy-" + target).encode())
        verbose = "rustc 1.98.1 (1111111 2026-01-01)\nbinary: rustc\ncommit-hash: " + "1" * 40 + \
            "\ncommit-date: 2026-01-01\nhost: " + build.HOST + "\nrelease: 1.98.1\nLLVM version: 21.1.1\n"
        def command(argv, **options):
            self.assertEqual(options, {"check": True, "capture_output": True, "text": True, "timeout": 5})
            values = {("rustup", "which", "--toolchain", "1.98.1", "rustc"): str(compiler),
                (str(compiler), "-vV"): verbose, (str(compiler), "--print", "sysroot"): str(root),
                ("dpkg-query", "-W", "-f", "${Package}\t${Version}\n", "python3", "ca-certificates", "libc6"):
                    "python3\t3.11.2\nca-certificates\t20230311\nlibc6\t2.36\n",
                ("cargo", "+1.98.1", "--version"): "cargo 1.98.1", ("rustup", "--version"): "rustup 1.28.2",
                ("python3", "--version"): "Python 3.11.2"}
            self.assertIn(tuple(argv), values)
            return types.SimpleNamespace(stdout=values[tuple(argv)])
        guest_tree = ast.parse((ROOT / "tools/probe_toolchain.py").read_text())
        guest = next(node.value.value for node in guest_tree.body if isinstance(node, ast.Assign)
                     and any(isinstance(name, ast.Name) and name.id == "GUEST" for name in node.targets))
        observed = []
        for script in (build.TOOLCHAIN_PROBE, guest):
            stdout = io.StringIO()
            with patch("subprocess.run", side_effect=command), contextlib.redirect_stdout(stdout):
                exec(compile(script, "public-toy-probe", "exec"), {})
            observed.append(json.loads(stdout.getvalue()))
        self.assertEqual(observed[0]["sysroot_sha256"], observed[1]["sysroot_sha256"])
        self.assertEqual(observed[0]["executable_sha256"], observed[1]["executable_sha256"])
        self.assertEqual(observed[1]["sysroot_files"], {build.HOST: 1, build.TARGET: 1})


    def _registry_guest(self):
        namespace = {"__name__": "public_registry_test"}
        exec(compile(build.REGISTRY_PREFETCH_GUEST, "public-registry-prefetch", "exec"), namespace)
        return namespace

    def test_public_cache_guest_normalizes_modes_without_changing_toy_bytes_or_root(self):
        # Real public toy filesystem; no Docker/Linux UID ownership claim.
        registry = self.root / "public-cache"; registry.mkdir(); registry.chmod(0o777)
        for name in ("registry/index", "registry/cache", "registry/src/toy"):
            (registry / name).mkdir(parents=True, exist_ok=True)
        files = {".global-cache": b"public-sqlite-toy", ".package-cache": b"",
                 "registry/index/config.json": b'{"public":true}',
                 "registry/cache/toy.crate": b"public-crate-toy",
                 "registry/src/toy/lib.rs": b"pub fn toy() {}\n"}
        for name, value in files.items():
            path = registry / name; path.write_bytes(value); path.chmod(0o600)
        for path in registry.rglob("*"):
            if path.is_dir(): path.chmod(0o700)
        before = {name: ((registry / name).stat().st_ino, build.digest(value)) for name, value in files.items()}
        guest = self._registry_guest()
        counts = guest["normalize_registry"](registry, build.time.monotonic() + 10)
        self.assertEqual(counts["files"], len(files))
        self.assertEqual(counts["directories"], 5)
        self.assertEqual(registry.stat().st_mode & 0o777, 0o777)
        for path in registry.rglob("*"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o755 if path.is_dir() else 0o644)
        self.assertEqual({name: ((registry / name).stat().st_ino, build.digest((registry / name).read_bytes()))
                          for name in files}, before)

    def test_guest_cache_refuses_alias_special_hardlink_credentials_and_expired_deadline(self):
        guest = self._registry_guest()
        for kind, code in (("symlink", "registry_alias_refused"), ("fifo", "registry_entry_type"),
                           ("hardlink", "registry_entry_type"), ("credentials", "registry_credentials_refused")):
            registry = self.root / ("refuse-" + kind); registry.mkdir()
            outside = self.root / ("outside-" + kind); outside.write_bytes(b"public-outside-toy"); outside.chmod(0o600)
            if kind == "symlink": (registry / "alias").symlink_to(outside)
            elif kind == "fifo": os.mkfifo(registry / "special")
            elif kind == "hardlink": os.link(outside, registry / "alias")
            else: (registry / "credentials.toml").write_bytes(b"public-sentinel-not-a-key")
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "^" + code + "$"):
                guest["normalize_registry"](registry, build.time.monotonic() + 10)
            self.assertEqual(outside.read_bytes(), b"public-outside-toy")
            self.assertEqual(outside.stat().st_mode & 0o777, 0o600)
        empty = self.root / "expired-cache"; empty.mkdir()
        with self.assertRaisesRegex(ValueError, "^registry_prefetch_deadline$"):
            guest["normalize_registry"](empty, build.time.monotonic() - 1)

    def test_fetch_guest_normalizes_only_after_success_with_exact_two_targets(self):
        guest = self._registry_guest(); command = build.prefetch_command()
        self.assertEqual(command, ["cargo", "+1.98.1", "fetch", "--locked", "--manifest-path", "examples/game/Cargo.toml",
                                   "--target", "wasm32-unknown-unknown", "--target", "aarch64-unknown-linux-gnu"])
        registry = self.root / "fetch-cache"; registry.mkdir()
        cached = registry / ".global-cache"; cached.write_bytes(b"public-cache-toy"); cached.chmod(0o600)
        with patch.object(guest["subprocess"], "run", return_value=types.SimpleNamespace(returncode=17)) as fetch:
            with self.assertRaises(SystemExit) as rejected:
                guest["run_prefetch"](command, registry, 20)
            self.assertEqual(rejected.exception.code, 17)
            fetch.assert_called_once_with(command, check=False, timeout=20)
        self.assertEqual(cached.stat().st_mode & 0o777, 0o600)
        with patch.object(guest["subprocess"], "run", return_value=types.SimpleNamespace(returncode=0)) as fetch:
            self.assertEqual(guest["run_prefetch"](command, registry, 20)["files"], 1)
            fetch.assert_called_once_with(command, check=False, timeout=20)
        self.assertEqual(cached.stat().st_mode & 0o777, 0o644)
        with patch.object(guest["subprocess"], "run") as fetch, self.assertRaisesRegex(ValueError, "^registry_prefetch_command$"):
            guest["run_prefetch"](command[:-2], registry, 20)
        fetch.assert_not_called()

    def test_actual_start_wraps_only_prefetch_inside_unchanged_container_contract(self):
        # Actual start/container helpers; Docker transport and inspect are modeled.
        cid = "6" * 64; removed = []
        class Owner:
            def __init__(self): self.containers = []; self.created = None
            def journal(self): pass
            def docker(self, argv, maximum):
                if argv[0] == "create": self.created = argv; return cid.encode()
                self_assert.assertEqual(argv, ["start", "--attach", cid])
                return b'{"state":"public_registry_normalized"}'
            def inspect(self, actual):
                self_assert.assertEqual(actual, cid)
                command = self.created[self.created.index(self_row["compiler_ref"]) + 1:]
                mounts = []
                for index, item in enumerate(self.created):
                    if item == "--mount":
                        raw = self.created[index + 1]; parts = dict(part.split("=", 1) for part in raw.split(",") if "=" in part)
                        mounts.append({"Type": "bind", "Source": parts["src"], "Destination": parts["dst"],
                                       "RW": not raw.endswith(",readonly")})
                return {"Id": cid, "Name": "/" + owned["name"], "Image": self_row["compiler_image"],
                    "Config": {"Labels": {"online.harmony.operation": owned["operation"]}, "User": "65532:65532",
                        "Entrypoint": ["/usr/bin/env"], "Env": self_row["image_environment"], "Cmd": command},
                    "State": {"ExitCode": 0}, "Mounts": mounts,
                    "HostConfig": {"ReadonlyRootfs": True, "Memory": 8 * 1024**3, "MemorySwap": 8 * 1024**3,
                        "PidsLimit": 256, "CapDrop": ["ALL"], "NanoCpus": 2_000_000_000,
                        "NetworkMode": "bridge" if owned["phase"] == "prefetch" else "none", "CpusetCpus": "0,1",
                        "SecurityOpt": ["no-new-privileges"], "Privileged": False, "PidMode": "", "IpcMode": "private",
                        "CgroupnsMode": "private", "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=512m,mode=1777"}}}
            def remove(self, entry): removed.append(entry)
        self_assert, self_row = self, self.row
        for phase, requested in (("prefetch", build.prefetch_command()), ("compile", ["cargo", "+1.98.1", "build"])):
            owner = Owner(); owned, args = build.container(owner, self.row, self.env["SDK_OPERATION"], phase,
                                                          self.root / "source", self.root / "registry", self.root / "output")
            build.start(owner, owned, args, requested, 20)
            actual = owner.created[owner.created.index(self.row["compiler_ref"]) + 1 + 1 + len(build.COMPILER_ENV):]
            if phase == "prefetch":
                self.assertEqual(actual[:4], ["python3", "-I", "-B", "-c"])
                self.assertEqual(actual[4], build.REGISTRY_PREFETCH_GUEST)
                self.assertEqual(json.loads(actual[5]), requested)
                self.assertEqual(float(actual[6]), 20)
            else: self.assertEqual(actual, requested)
            self.assertEqual(len(owner.containers), 1)
            self.assertIs(removed[-1], owned)

    def test_host_copy_errors_are_finite_redacted_and_keep_compile_owner_close(self):
        sentinel = "PRIVATE_CACHE_PATH_AND_PAYLOAD_DO_NOT_EMIT"
        cases = [(PermissionError(errno.EACCES, sentinel, sentinel), "registry_permission_denied"),
                 (OSError(errno.ENOSPC, sentinel, sentinel), "registry_no_space"),
                 (OSError(errno.EDQUOT, sentinel, sentinel), "registry_quota_exceeded"),
                 (OSError(errno.EROFS, sentinel, sentinel), "registry_read_only"),
                 (OSError(errno.EIO, sentinel, sentinel), "registry_io_failure"),
                 (OSError(errno.ENOENT, sentinel, sentinel), "registry_entry_missing"),
                 (OSError(errno.EBUSY, sentinel, sentinel), "registry_os_error"),
                 (build.shutil.Error([(sentinel, sentinel, sentinel)]), "registry_copy_failed")]
        for error, expected in cases:
            with self.subTest(expected=expected), patch.object(build.shutil, "copytree", side_effect=error):
                value, commands, output = self._compile_failure("compile")
            self.assertEqual(value["failure_stage"], "compile_registry")
            self.assertEqual(value["refusal_code"], expected)
            self.assertTrue(value["owner_close_succeeded"])
            self.assertIsNone(value["cleanup_refusal_code"])
            self.assertEqual(commands[-1][0], "prefetch")
            self.assertNotIn(sentinel, output)

    def test_host_runtime_copy_preserves_normalized_seed_and_refuses_special_entries(self):
        registry = self.root / "seed"; registry.mkdir(); registry.chmod(0o777)
        (registry / "src").mkdir(); (registry / "src").chmod(0o755)
        (registry / "src/lib.rs").write_bytes(b"pub fn public_toy() {}\n")
        (registry / "src/lib.rs").chmod(0o644)
        (registry / ".global-cache").write_bytes(b"public-cache-toy"); (registry / ".global-cache").chmod(0o644)
        before = {str(path.relative_to(registry)): (path.stat().st_ino, path.stat().st_mode & 0o777,
                  None if path.is_dir() else build.digest(path.read_bytes())) for path in registry.rglob("*")}
        runtime = self.root / "runtime"; build.copy_registry(registry, runtime)
        self.assertEqual(runtime.stat().st_mode & 0o777, 0o777)
        for path in runtime.rglob("*"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o777 if path.is_dir() else 0o666)
            if path.is_file(): self.assertEqual(path.read_bytes(), (registry / path.relative_to(runtime)).read_bytes())
        self.assertEqual({str(path.relative_to(registry)): (path.stat().st_ino, path.stat().st_mode & 0o777,
                         None if path.is_dir() else build.digest(path.read_bytes())) for path in registry.rglob("*")}, before)
        for kind, code in (("symlink", "registry_alias_refused"), ("fifo", "registry_entry_type")):
            special = registry / ("special-" + kind)
            if kind == "symlink": special.symlink_to(registry / "src/lib.rs")
            else: os.mkfifo(special)
            with self.subTest(kind=kind), self.assertRaisesRegex(build.Refused, "^" + code + "$"):
                build.copy_registry(registry, self.root / ("runtime-" + kind))
            special.unlink()





    def _resource_probe(self, total_kib=20_000_000, available_kib=12_000_000,
                        psi="some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"):
        # Actual public Linux-resource function; kernel files/platform are modeled.
        verify, _ = build.helpers()
        reads = []
        class KernelFile:
            def __init__(self, name): self.name = str(name)
            def read_text(self):
                reads.append(self.name)
                if self.name == "/proc/meminfo":
                    return f"MemTotal: {total_kib} kB\nMemAvailable: {available_kib} kB\n"
                self_assert.assertEqual(self.name, "/proc/pressure/memory")
                return psi
        self_assert = self
        with patch.object(verify, "Path", KernelFile), \
             patch.object(verify.platform, "system", return_value="Linux"), \
             patch.object(verify.platform, "machine", return_value="aarch64"), \
             patch.object(verify.os, "sched_getaffinity", return_value={0, 1}, create=True):
            try:
                value, error = verify.linux_resources(), None
            except verify.Refused as refused:
                value, error = None, refused
        return verify, value, error, reads

    def test_actual_host_pressure_refusal_carries_numbers_without_changing_zero_success(self):
        verify, value, error, reads = self._resource_probe(available_kib=8_000_000)
        self.assertIsNone(error)
        self.assertEqual(value, {"mem_total": 20_000_000 * 1024, "mem_available": 8_000_000 * 1024,
                                 "memory_psi_avg10": ["0.00", "0.00"]})
        self.assertEqual(reads, ["/proc/meminfo", "/proc/pressure/memory"])
        for some, full in (("0.01", "0.00"), ("0.00", "0.02"), ("0.000001", "0.00")):
            with self.subTest(some=some, full=full):
                verify, value, error, _ = self._resource_probe(
                    psi=f"some avg10={some} avg60=0.00 avg300=0.00 total=1\nfull avg10={full} avg60=0.00 avg300=0.00 total=0\n")
                self.assertIsNone(value)
                self.assertIsInstance(error, verify.ResourceRefused)
                self.assertEqual(error.args, ("memory_pressure",))
                self.assertEqual(build.resource_observation(error), {
                    "scope": "runner_host", "mem_total": 20_000_000 * 1024,
                    "mem_available": 12_000_000 * 1024, "memory_psi_avg10": [float(some), float(full)]})
        verify, _, error, _ = self._resource_probe(psi="some avg10=0.01 avg60=0.00 avg300=0.00 total=1\n")
        self.assertIsInstance(error, verify.ResourceRefused)
        self.assertEqual(error.args, ("memory_pressure",))
        self.assertIsNone(build.resource_observation(error)["memory_psi_avg10"])

    def test_resource_floor_keeps_original_order_threshold_and_unobserved_psi(self):
        for total, available in ((20_000_000, 7_999_999), (15_624_999, 15_624_999)):
            with self.subTest(total=total, available=available):
                verify, value, error, reads = self._resource_probe(total, available)
                self.assertIsNone(value)
                self.assertIsInstance(error, verify.ResourceRefused)
                self.assertEqual(error.args, ("resource_floor",))
                self.assertEqual(reads, ["/proc/meminfo"])
                self.assertEqual(build.resource_observation(error), {
                    "scope": "runner_host", "mem_total": total * 1024,
                    "mem_available": available * 1024, "memory_psi_avg10": None})

    def test_resource_projection_refuses_extra_untyped_nonfinite_and_unbounded_values(self):
        base = {"mem_total": 20_000_000 * 1024, "mem_available": 12_000_000 * 1024,
                "memory_psi_avg10": [0.01, 0.0]}
        bad = [
            {**base, "private_path": "PRIVATE_RESOURCE_PAYLOAD_DO_NOT_EMIT"},
            {**base, "mem_total": True}, {**base, "mem_available": "PRIVATE_RESOURCE_PAYLOAD_DO_NOT_EMIT"},
            {**base, "mem_total": 2**63}, {**base, "mem_available": base["mem_total"] + 1},
            {**base, "memory_psi_avg10": [float("nan"), 0.0]},
            {**base, "memory_psi_avg10": [float("inf"), 0.0]},
            {**base, "memory_psi_avg10": [-0.01, 0.0]},
            {**base, "memory_psi_avg10": [100.01, 0.0]},
            {**base, "memory_psi_avg10": [2**4096, 0.0]},
            {**base, "memory_psi_avg10": [True, 0.0]},
            {**base, "memory_psi_avg10": ["PRIVATE_RESOURCE_PAYLOAD_DO_NOT_EMIT", 0.0]},
            {**base, "memory_psi_avg10": [0.0]}, {**base, "memory_psi_avg10": (0.0, 0.0)},
        ]
        diagnostic = {"failure_stage": "compile_cargo", "owner_close_called": True,
                      "owner_close_succeeded": True, "cleanup_refusal_code": None}
        for sample in bad:
            with self.subTest(sample_type=type(sample["memory_psi_avg10"]).__name__):
                error = build.Refused("memory_pressure"); error.resource_sample = sample
                self.assertIsNone(build.resource_observation(error))
                value = build.public_failure(error, diagnostic)
                self.assertNotIn("resource_observation", value)
                self.assertNotIn("PRIVATE_RESOURCE_PAYLOAD_DO_NOT_EMIT", json.dumps(value))
        error = build.Refused("command_failed"); error.resource_sample = base
        self.assertIsNone(build.resource_observation(error))

    def test_compile_resource_observation_preserves_primary_when_cleanup_also_fails(self):
        _, _, error, _ = self._resource_probe(
            psi="some avg10=0.03 avg60=0.00 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
        for cleanup, code in ((False, "compiler_failed_or_unknown"),
                              (ValueError("PRIVATE_CLEANUP_PAYLOAD_DO_NOT_EMIT"), "internal_error")):
            with self.subTest(cleanup_code=code):
                value, commands, output = self._compile_failure("compile", error=error, cleanup=cleanup)
                self.assertEqual(value["failure_stage"], "compile_cargo")
                self.assertEqual(value["refusal_code"], "memory_pressure")
                self.assertFalse(value["owner_close_succeeded"])
                self.assertEqual(value["cleanup_refusal_code"], code)
                self.assertEqual(value["resource_observation"], {
                    "scope": "runner_host", "mem_total": 20_000_000 * 1024,
                    "mem_available": 12_000_000 * 1024, "memory_psi_avg10": [0.03, 0.0]})
                self.assertEqual(commands[-1][0], "compile")
                self.assertNotIn("PRIVATE_CLEANUP_PAYLOAD_DO_NOT_EMIT", output)

    def test_other_failure_projection_is_unchanged_and_has_no_resource_field(self):
        diagnostic = {"failure_stage": "compile_cargo", "owner_close_called": True,
                      "owner_close_succeeded": True, "cleanup_refusal_code": None}
        error = ValueError("PRIVATE_RESOURCE_PAYLOAD_DO_NOT_EMIT")
        error.resource_sample = {"mem_total": 20_000_000 * 1024, "mem_available": 12_000_000 * 1024,
                                 "memory_psi_avg10": [0.01, 0.0]}
        self.assertEqual(build.public_failure(error, diagnostic), {
            "failure_stage": "compile_cargo", "refusal_code": "internal_error",
            "owner_close_called": True, "owner_close_succeeded": True, "cleanup_refusal_code": None})


    def test_owner_command_resource_failure_survives_modeled_teardown_fault(self):
        # Actual Owner.command, modeled child/selector; no process or Docker run.
        for fault in ("finish", "selector"):
            with self.subTest(fault=fault):
                verify, _, resource_error, _ = self._resource_probe(
                    psi="some avg10=0.03 avg60=0.00 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
                owner = object.__new__(verify.Owner)
                owner.evidence = self.root / ("modeled-command-" + fault); owner.evidence.mkdir(mode=0o700)
                row = {"process": types.SimpleNamespace(stdout=object(), stderr=object()),
                       "reaped": False, "group_closed": False}
                owner.children = [row]
                class Selector:
                    closed = False
                    def register(self, *args): pass
                    def get_map(self): return {"modeled": object()}
                    def close(self):
                        self.closed = True
                        if fault == "selector": raise verify.Refused("cli_cleanup_unknown")
                selector = Selector()
                teardown = verify.Refused("cli_cleanup_unknown") if fault == "finish" else None
                with patch.object(owner, "remaining", return_value=10), \
                     patch.object(owner, "spawn", return_value=row), \
                     patch.object(owner, "finish", side_effect=teardown, return_value=False) as finish, \
                     patch.object(verify.selectors, "DefaultSelector", return_value=selector), \
                     patch.object(verify, "linux_resources", side_effect=resource_error), \
                     self.assertRaises(verify.Refused) as caught:
                    owner.command(["public-modeled-command"], 10)
                self.assertIs(caught.exception, resource_error)
                self.assertEqual(caught.exception.args, ("memory_pressure",))
                self.assertEqual(build.resource_observation(caught.exception)["memory_psi_avg10"], [0.03, 0.0])
                finish.assert_called_once_with(row, natural=False)
                self.assertTrue(selector.closed)
                self.assertIs(owner.children[0], row)
                self.assertFalse(row["group_closed"])

if __name__ == "__main__": unittest.main()
