"""Trusted producer controls; no source approval, key, model or Docker workload.

Cargo JSON below is a modeled fixture. The finite child test proves only the
public owner command boundary on Linux; it is not a physical SDK build.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
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


if __name__ == "__main__": unittest.main()
