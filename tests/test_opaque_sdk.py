"""Exporter boundary tests using explicit modeled artifacts, not a compiled SDK.

These tests do not qualify Rust artifacts or hide generic metadata. A trusted
tiny Rust compiler fixture and actual guarded downstream link remain separate.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

SPEC = importlib.util.spec_from_file_location("opaque_sdk", Path(__file__).parents[1] / "tools/opaque_sdk.py")
sdk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sdk)


class ExportTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.node = "a" * 64
        compiler = {"release": "1.99.0", "commit_hash": "b" * 40, "commit_date": "2026-09-01",
                    "host": "x86_64-unknown-linux-gnu", "llvm_version": "22.1.0",
                    "verbose_version": "rustc 1.99.0 (bbbbbbb 2026-09-01)\nbinary: rustc\ncommit-hash: "
                    + "b" * 40 + "\ncommit-date: 2026-09-01\nhost: x86_64-unknown-linux-gnu\nrelease: 1.99.0\nLLVM version: 22.1.0\n",
                    "executable_sha256": "c" * 64, "sysroot_sha256": "d" * 64}
        # Modeled member bytes. The real bundle guard is intentionally separate
        # from these metadata/copy controls, not replaced by a compile claim.
        self.binary = b"!<arch>\nMODELED-NOT-A-COMPILED-SDK\n"
        leaf = self.artifacts / "lib/wasm32-unknown-unknown/libexample-a.rlib"
        leaf.parent.mkdir(parents=True)
        leaf.write_bytes(self.binary)
        rows = [{"path": "lib/wasm32-unknown-unknown/libexample-a.rlib", "role": "opaque_rlib",
                 "bytes": len(self.binary), "sha256": sdk.digest(self.binary)}]
        self.contract = {"schema_version": 1, "kind": "rust-precompiled-sdk/1", "compiler": compiler,
                         "target": "wasm32-unknown-unknown", "features": ["web-webgl2"],
                         "profile": {"name": "web-release", "opt_level": "s", "lto": "fat",
                                     "codegen_units": 1, "panic": "abort", "debug": False, "incremental": False},
                         "rustflags_sha256": "e" * 64, "lockfile_sha256": "f" * 64,
                         "input_inventory_sha256": "0" * 64, "environment_policy_sha256": "1" * 64,
                         "cargo_receipt_sha256": "2" * 64, "roots": [self.node],
                         "crates": [{"identity": self.node, "name": "example", "version": "0.1.0",
                                     "kind": "target", "features": [], "dependencies": [],
                                     "files": [rows[0]["path"]]}], "files": rows}
        authorization = str(uuid.uuid4())
        self.cargo = {"schema_version": 1, "producer": sdk.PRODUCER, "source_revision": "3" * 40,
                      "authorization_id": authorization, "state": "COMPILED_CLOSURE_PRODUCED",
                      "exit_code": 0, "timed_out": False, "resources_closed": True, "unknown_owners": [],
                      **{key: self.contract[key] for key in ("compiler", "target", "features", "profile",
                         "rustflags_sha256", "lockfile_sha256", "input_inventory_sha256", "environment_policy_sha256")},
                      "artifact_inventory_sha256": sdk.digest(sdk.canonical(sdk.plain_inventory(rows)))}
        cargo_path, cargo_hash = self.write_json("cargo.json", self.cargo)
        self.contract["cargo_receipt_sha256"] = cargo_hash
        sdk_path, sdk_hash = self.write_json("artifacts/sdk-manifest.json", self.contract)
        approved = rows + [{"path": "sdk-manifest.json", "role": "build_metadata",
                            "bytes": sdk_path.stat().st_size, "sha256": sdk_hash}]
        self.producer = {"schema_version": 1, "producer": sdk.PRODUCER, "source_revision": "3" * 40,
                         "authorization_id": authorization, "surface": "public-sdk",
                         "files": sdk.plain_inventory(approved)}
        provenance, provenance_hash = self.write_json("producer.json", self.producer)
        self.policy = {"schema_version": 1, "review_id": str(uuid.uuid4()), "surface": "public-sdk",
                       "producer_receipt_sha256": provenance_hash, "files": approved}
        policy, policy_hash = self.write_json("policy.json", self.policy)
        manifest, manifest_hash = self.write_json("upload.json", {"schema_version": 1,
                                                                 "files": sdk.plain_inventory(approved)})
        self.args = SimpleNamespace(policy=policy, policy_sha256=policy_hash,
            provenance=provenance, provenance_sha256=provenance_hash,
            manifest=manifest, manifest_sha256=manifest_hash,
            sdk_manifest=sdk_path, sdk_manifest_sha256=sdk_hash,
            cargo_receipt=cargo_path, cargo_receipt_sha256=cargo_hash,
            artifact_root=self.artifacts, output=self.root / "output",
            expected_rust_release="1.99.0", expected_host="x86_64-unknown-linux-gnu",
            expected_target="wasm32-unknown-unknown")

    def write_json(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = sdk.canonical(value) + b"\n"
        path.write_bytes(data)
        return path, sdk.digest(data)

    def contract_check(self, contract):
        return sdk.sdk_contract(contract, self.args.expected_rust_release,
                                self.args.expected_host, self.args.expected_target)

    def test_explicit_copy_keeps_binary_bytes_and_never_reports_qualification(self):
        with patch.object(sdk, "guard") as guard:
            report = sdk.export(self.args)
        self.assertEqual(guard.call_count, 2)
        self.assertEqual((self.args.output / "lib/wasm32-unknown-unknown/libexample-a.rlib").read_bytes(), self.binary)
        self.assertEqual(sorted(str(p.relative_to(self.args.output)) for p in self.args.output.rglob("*") if p.is_file()),
                         ["lib/wasm32-unknown-unknown/libexample-a.rlib", "sdk-manifest.json"])
        self.assertEqual(report["state"], "OPAQUE_SDK_EXPORTED_NOT_QUALIFIED")
        self.assertIs(report["runtime_qualified"], False)
        self.assertIs(report["source_confidentiality_proven"], False)

    def test_mixed_rust_release_host_target_and_verbose_identity_are_rejected(self):
        for field, value in (("release", "1.98.1"), ("host", "aarch64-apple-darwin"),
                             ("commit_date", "2026-09-02")):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.contract)
                changed["compiler"][field] = value
                with self.assertRaises(sdk.ExportError):
                    self.contract_check(changed)
        changed = copy.deepcopy(self.contract)
        changed["target"] = "x86_64-unknown-linux-gnu"
        with self.assertRaisesRegex(sdk.ExportError, "target_mismatch"):
            self.contract_check(changed)

    def test_unresolved_dependency_unbound_file_and_metadata_only_crate_are_rejected(self):
        changed = copy.deepcopy(self.contract)
        changed["crates"][0]["dependencies"] = ["9" * 64]
        with self.assertRaisesRegex(sdk.ExportError, "open_dependency_graph"):
            self.contract_check(changed)
        changed = copy.deepcopy(self.contract)
        changed["files"].append({"path": "lib/wasm32-unknown-unknown/extra.rmeta", "role": "opaque_metadata",
                                 "bytes": 8, "sha256": "8" * 64})
        with self.assertRaisesRegex(sdk.ExportError, "unbound_artifact"):
            self.contract_check(changed)
        changed = copy.deepcopy(self.contract)
        changed["files"][0]["role"] = "opaque_metadata"
        with self.assertRaisesRegex(sdk.ExportError, "missing_linkable_crate"):
            self.contract_check(changed)

    def test_failed_unknown_or_contract_drift_cargo_receipt_is_refused(self):
        rows = self.contract_check(self.contract)
        upload = {"schema_version": 1, "files": self.producer["files"]}
        for key, value in (("exit_code", 143), ("timed_out", True), ("resources_closed", False),
                           ("unknown_owners", [123]), ("target", "aarch64-apple-darwin")):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.cargo)
                changed[key] = value
                with self.assertRaises(sdk.ExportError):
                    sdk.proof_join(self.policy, self.producer, upload, self.contract, changed, rows,
                                   self.args.sdk_manifest_sha256, self.args.cargo_receipt_sha256)

    def test_unreviewed_extra_file_or_inventory_byte_drift_is_refused(self):
        rows = self.contract_check(self.contract)
        changed = copy.deepcopy(self.policy)
        changed["files"][0]["bytes"] += 1
        with self.assertRaisesRegex(sdk.ExportError, "sdk_inventory_mismatch"):
            sdk.proof_join(changed, self.producer, {"schema_version": 1, "files": self.producer["files"]},
                self.contract, self.cargo, rows, self.args.sdk_manifest_sha256, self.args.cargo_receipt_sha256)
        with patch.object(sdk, "guard", side_effect=sdk.ExportError("bundle_guard_refused")):
            with self.assertRaises(sdk.ExportError):
                sdk.export(self.args)
        self.assertFalse(self.args.output.exists())

    def test_binary_mutation_and_leaf_symlink_refuse_without_claiming_success(self):
        leaf = self.artifacts / "lib/wasm32-unknown-unknown/libexample-a.rlib"
        leaf.write_bytes(self.binary + b"drift")
        with patch.object(sdk, "guard"):
            with self.assertRaisesRegex(sdk.ExportError, "artifact_metadata_mismatch"):
                sdk.export(self.args)
        leaf.unlink()
        leaf.symlink_to(self.args.cargo_receipt)
        self.args.output = self.root / "other-output"
        with patch.object(sdk, "guard"):
            with self.assertRaises(OSError):
                sdk.export(self.args)

    def test_existing_output_is_preserved_and_duplicate_json_is_rejected(self):
        self.args.output.mkdir()
        sentinel = self.args.output / "sentinel"
        sentinel.write_text("keep")
        with self.assertRaisesRegex(sdk.ExportError, "invalid_output"):
            sdk.export(self.args)
        self.assertEqual(sentinel.read_text(), "keep")
        path = self.root / "duplicate.json"
        data = b'{"x":1,"x":2}'
        path.write_bytes(data)
        with self.assertRaisesRegex(sdk.ExportError, "duplicate_json_key"):
            sdk.pinned_json(path, sdk.digest(data))


if __name__ == "__main__":
    unittest.main()
