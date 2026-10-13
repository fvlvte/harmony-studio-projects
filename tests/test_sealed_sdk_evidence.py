"""Modeled selection/privacy controls, not SDK/age/runner qualification.

Actual age toy crypto and actual compiled closure are separate Root evidence.
These tests never read private SDK source, generate identities or run Docker.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def load(name):
    path = ROOT / "tools" / (name + ".py")
    spec = importlib.util.spec_from_file_location("modeled_" + name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
seal, selection, exporter = load("seal_sdk_evidence"), load("evidence_selection"), load("opaque_sdk")


def candidate():
    compiler = {"release": "1.98.1", "host": selection.HOST}
    shared = {"source_revision": "a" * 64, "authorization_id": "00000000-0000-0000-0000-000000000001",
        "input_inventory_sha256": "b" * 64, "environment_policy_sha256": "c" * 64, "compiler": compiler,
        "target": selection.TARGET, "features": ["web-webgl2"], "profile": {"name": "web-release"}}
    artifact = {"public_path": "lib/wasm32-unknown-unknown/libtoy.rlib",
                "compiler_output": "target/wasm32-unknown-unknown/web-release/deps/libtoy.rlib",
                "target": selection.TARGET, "role": "opaque_rlib"}
    inventory = {"path": artifact["public_path"], "role": "opaque_rlib", "bytes": 8, "sha256": "d" * 64}
    body = {**shared, "schema_version": 1, "state": "built_not_qualified", "resources_closed": True,
            "files": [artifact], "artifact_inventory": [inventory]}
    receipt = {**shared, "state": "COMPILED_CLOSURE_PRODUCED", "exit_code": 0, "timed_out": False,
               "resources_closed": True, "unknown_owners": [], "artifact_inventory_sha256":
               exporter.digest(exporter.canonical(exporter.plain_inventory(body["artifact_inventory"])))}
    return body, receipt


class SelectionTest(unittest.TestCase):
    def test_empty_recipient_catalog_refuses_without_any_network_or_key(self):
        with patch.object(seal, "APPROVED_EVIDENCE_RECIPIENTS", {}):
            self.assertEqual(seal.APPROVED_EVIDENCE_RECIPIENTS, {})
            with patch.dict(os.environ, {"SDK_EVIDENCE_RECIPIENT": "unapproved"}, clear=True), \
                 patch.object(seal.urllib.request, "build_opener", side_effect=AssertionError("network reached")):
                with self.assertRaisesRegex(ValueError, "evidence_recipient_unapproved"): seal.recipient()

    def test_exact_candidate_inventory_and_original_context_join(self):
        body, receipt = candidate(); selected = selection.exact_artifact_selection(body, receipt)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["compiler_output"], body["files"][0]["compiler_output"])
        self.assertEqual(seal.bound_artifact_selection(body, receipt, selection, exporter), selected)
        with self.assertRaisesRegex(ValueError, "compile_inventory_join"):
            seal.bound_artifact_selection(body, {**receipt, "artifact_inventory_sha256": "0" * 64}, selection, exporter)
        changed_inventory = copy.deepcopy(body)
        changed_inventory["artifact_inventory"][0]["sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "compile_inventory_join"):
            seal.bound_artifact_selection(changed_inventory, receipt, selection, exporter)
        for key, value in (("source_revision", "0" * 64), ("resources_closed", False), ("state", "failed")):
            changed = copy.deepcopy(body); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): selection.exact_artifact_selection(changed, receipt)

    def test_missing_extra_duplicate_role_path_and_byte_drift_refuse(self):
        body, receipt = candidate()
        mutations = []
        changed = copy.deepcopy(body); changed["artifact_inventory"] = []; mutations.append(changed)
        changed = copy.deepcopy(body); changed["artifact_inventory"].append(changed["artifact_inventory"][0]); mutations.append(changed)
        changed = copy.deepcopy(body); changed["files"][0]["compiler_output"] = "../source.rs"; mutations.append(changed)
        changed = copy.deepcopy(body); changed["files"][0]["role"] = "source"; mutations.append(changed)
        changed = copy.deepcopy(body); changed["artifact_inventory"][0]["bytes"] = selection.MAX_ARTIFACT + 1; mutations.append(changed)
        changed = copy.deepcopy(body); changed["artifact_inventory"][0]["bytes"] = True; mutations.append(changed)
        for number, changed in enumerate(mutations):
            with self.subTest(number=number), self.assertRaises(ValueError): selection.exact_artifact_selection(changed, receipt)

    def test_failed_or_unknown_compile_cannot_become_evidence_selection(self):
        body, receipt = candidate()
        for key, value in (("exit_code", 1), ("timed_out", True), ("unknown_owners", [123]), ("resources_closed", False)):
            changed = {**receipt, key: value}
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "compile_not_closed"):
                selection.exact_artifact_selection(body, changed)

    def test_cargo_graph_preserves_typed_edges_but_omits_arbitrary_payload(self):
        metadata = {"packages": [{"id": "toy", "name": "toy", "version": "0.1.0", "features": {"web": []},
            "description": "RAW_MUST_NOT_RETURN", "metadata": {"thoughts": "RAW_MUST_NOT_RETURN"},
            "targets": [{"name": "toy", "kind": ["lib"], "crate_types": ["rlib"], "src_path": "/sdk/private.rs"}]}],
            "resolve": {"root": "toy", "nodes": [{"id": "toy", "dependencies": [], "deps": [], "features": ["web"]}]}}
        projected = selection.cargo_graph_projection(metadata)
        self.assertEqual(projected["resolve"], metadata["resolve"])
        self.assertEqual(projected["packages"][0]["features"], {"web": []})
        self.assertNotIn("RAW_MUST_NOT_RETURN", json.dumps(projected))
        self.assertNotIn("/sdk/private.rs", json.dumps(projected))
        changed = copy.deepcopy(metadata); changed["resolve"]["nodes"][0]["dependencies"] = ["missing"]
        with self.assertRaisesRegex(ValueError, "cargo_dependency_reference"): selection.cargo_graph_projection(changed)

    def test_closure_projection_omits_argv_logs_and_requires_all_four_actual_phases(self):
        owner = types.SimpleNamespace(journal_failed=False, children=[{"pid": 10, "pgid": 10, "reaped": True,
            "group_closed": True, "returncode": 0, "argv": ["PRIVATE_LOG_PAYLOAD"]}], containers=[])
        for i, phase in enumerate(("toolchain", "prefetch", "compile", "metadata")):
            owner.containers.append({"cid": str(i) * 64, "name": "modeled-" + phase, "image": "sha256:" + "e" * 64,
                "operation": "modeled", "phase": phase, "absent": True, "identity_verified": True})
        result = selection.owner_closure_projection(owner, "modeled", {"producer": "f" * 64})
        self.assertNotIn("PRIVATE_LOG_PAYLOAD", json.dumps(result))
        owner.children[0]["group_closed"] = False
        with self.assertRaisesRegex(ValueError, "cli_not_closed"):
            selection.owner_closure_projection(owner, "modeled", {"producer": "f" * 64})

    def test_nonregular_and_symlink_artifact_never_read_as_compiled_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); target = root / "target/deps"; target.mkdir(parents=True)
            (target / "libtoy.rlib").symlink_to(root / "missing")
            item = {"compiler_output": "target/deps/libtoy.rlib", "bytes": 8, "sha256": "0" * 64, "role": "opaque_rlib"}
            with self.assertRaises(OSError): seal.artifact_bytes(root, item)
            (target / "libtoy.rlib").unlink(); os.mkfifo(target / "libtoy.rlib")
            with self.assertRaisesRegex(ValueError, "artifact_identity"): seal.artifact_bytes(root, item)


    def test_unknown_metadata_private_return_keeps_exact_hash_and_regular_fd_contract(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); target = root / "target/deps"; target.mkdir(parents=True)
            # Deliberately unknown synthetic bytes: this proves private return,
            # not a native Rust metadata, public-format or ABI qualification.
            raw = b"SYNTHETIC_UNQUALIFIED_METADATA\x00\x01\x02"
            metadata = target / "libhost.rmeta"; metadata.write_bytes(raw)
            body, receipt = candidate()
            body["files"] = [{"public_path": "lib/" + selection.HOST + "/libhost.rmeta",
                "compiler_output": "target/deps/libhost.rmeta", "target": selection.HOST, "role": "opaque_metadata"}]
            body["artifact_inventory"] = [{"path": body["files"][0]["public_path"], "role": "opaque_metadata",
                "bytes": len(raw), "sha256": seal.digest(raw)}]
            receipt["artifact_inventory_sha256"] = exporter.digest(exporter.canonical(exporter.plain_inventory(body["artifact_inventory"])))
            selected = seal.bound_artifact_selection(body, receipt, selection, exporter)[0]
            self.assertEqual(seal.artifact_bytes(root, selected), raw)
            with self.assertRaisesRegex(ValueError, "artifact_pin_changed"):
                seal.artifact_bytes(root, {**selected, "sha256": "0" * 64})
            wrong_suffix = target / "libhost.rs"; wrong_suffix.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "artifact_format_magic"):
                seal.artifact_bytes(root, {**selected, "compiler_output": "target/deps/libhost.rs"})
            metadata.unlink(); metadata.symlink_to(root / "missing")
            with self.assertRaises(OSError): seal.artifact_bytes(root, selected)
            metadata.unlink(); os.mkfifo(metadata)
            with self.assertRaisesRegex(ValueError, "artifact_identity"): seal.artifact_bytes(root, selected)

    def test_source_snapshot_change_is_detected_without_loading_sdk_or_key(self):
        before = seal.snapshot()
        self.assertEqual(set(before), {"ci_build_sdk.py", "ci_verify.py", "opaque_sdk.py", "bundle_guard.py",
                                      "seal_sdk_evidence.py", "evidence_selection.py"})
        changed = {**before, "ci_build_sdk.py": "0" * 64}
        with self.assertRaisesRegex(ValueError, "source_pin_changed"): seal.module("ci_build_sdk", changed)

    def test_archive_builder_uses_exact_fixed_regular_members_and_rejects_expired_io(self):
        import tarfile
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "selected.tar"
            bodies = {"metadata/inventory.json": b'{"fixture":true}\n', "lib/wasm32-unknown-unknown/libtoy.rlib": b"!<arch>\n"}
            seal.archive_payload(path, bodies, lambda: None)
            with tarfile.open(path) as tar:
                self.assertEqual({m.name for m in tar}, set(bodies))
                self.assertTrue(all(m.isfile() and m.uid == m.gid == m.mtime == 0 for m in tar.getmembers()))
            def expired(): raise ValueError("evidence_deadline")
            with self.assertRaisesRegex(ValueError, "evidence_deadline"):
                seal.archive_payload(Path(d) / "late.tar", bodies, expired)


if __name__ == "__main__": unittest.main()
