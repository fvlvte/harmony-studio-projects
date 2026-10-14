"""Modeled selection/privacy controls, not SDK/age/runner qualification.

Actual age toy crypto and actual compiled closure are separate Root evidence.
These tests never read private SDK source, generate identities or run Docker.
"""
import copy
import contextlib
import io
import time
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

    def test_exact_selection_preserves_target_build_roots_and_all_compiled_roles(self):
        for root in ("target", "build"):
            for triple, role, filename in ((selection.TARGET, "opaque_rlib", "libtoy.rlib"),
                    (selection.TARGET, "opaque_metadata", "libtoy.rmeta"),
                    (selection.HOST, "opaque_rlib", "libhost.rlib"),
                    (selection.HOST, "opaque_proc_macro", "libmacro.so")):
                with self.subTest(root=root, triple=triple, role=role):
                    body, receipt = candidate()
                    source = root + "/" + ((triple + "/") if triple == selection.TARGET else "") + "web-release/deps/" + filename
                    path = f"lib/{triple}/{filename}"
                    body["files"] = [{"public_path": path, "compiler_output": source, "target": triple, "role": role}]
                    body["artifact_inventory"] = [{"path": path, "role": role, "bytes": 8, "sha256": "d" * 64}]
                    receipt["artifact_inventory_sha256"] = exporter.digest(exporter.canonical(exporter.plain_inventory(body["artifact_inventory"])))
                    selected = seal.bound_artifact_selection(body, receipt, selection, exporter)
                    self.assertEqual(selected, [{"compiler_output": source, **body["artifact_inventory"][0]}])
                    with self.assertRaisesRegex(ValueError, "compile_inventory_join"):
                        seal.bound_artifact_selection(body, {**receipt, "artifact_inventory_sha256": "0" * 64}, selection, exporter)

    def test_build_root_selection_retains_path_role_bijection_and_private_fd_refusals(self):
        for source in ("build-other/deps/libtoy.rlib", "target-other/deps/libtoy.rlib",
                       "build/../target/deps/libtoy.rlib", "/out/build/deps/libtoy.rlib",
                       "sdk/crates/deps/libtoy.rlib"):
            body, receipt = candidate(); body["files"][0]["compiler_output"] = source
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "artifact_path"):
                selection.exact_artifact_selection(body, receipt)
        for root in ("target", "build"):
            for source_triple, claimed_triple in ((selection.TARGET, selection.HOST),
                                                 (selection.HOST, selection.TARGET)):
                body, receipt = candidate()
                source = root + "/" + ((selection.TARGET + "/") if source_triple == selection.TARGET else "") + "web-release/deps/libtoy.rlib"
                path = f"lib/{claimed_triple}/libtoy.rlib"
                body["files"][0].update(compiler_output=source, target=claimed_triple, public_path=path)
                body["artifact_inventory"][0]["path"] = path
                with self.subTest(root=root, source_triple=source_triple, claimed_triple=claimed_triple), \
                        self.assertRaisesRegex(ValueError, "artifact_role"):
                    selection.exact_artifact_selection(body, receipt)
        body, receipt = candidate()
        body["files"][0].update(public_path=f"lib/{selection.TARGET}/libtoy.rs", compiler_output="build/deps/libtoy.rs")
        body["artifact_inventory"][0]["path"] = body["files"][0]["public_path"]
        with self.assertRaisesRegex(ValueError, "artifact_role"):
            selection.exact_artifact_selection(body, receipt)
        body, receipt = candidate(); body["files"][0]["compiler_output"] = "build/deps/libtoy.rlib"
        duplicate = copy.deepcopy(body["files"][0]); duplicate["compiler_output"] = "target/deps/libtoy.rlib"
        body["files"].append(duplicate); body["artifact_inventory"].append(copy.deepcopy(body["artifact_inventory"][0]))
        with self.assertRaisesRegex(ValueError, "artifact_inventory"):
            selection.exact_artifact_selection(body, receipt)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); folder = root / "build/deps"; folder.mkdir(parents=True)
            raw = b"!<arch>\nPUBLIC_MODELED_ONLY"; artifact = folder / "libtoy.rlib"; artifact.write_bytes(raw)
            item = {"compiler_output": "build/deps/libtoy.rlib", "bytes": len(raw), "sha256": seal.digest(raw), "role": "opaque_rlib"}
            self.assertEqual(seal.artifact_bytes(root, item), raw)
            with self.assertRaisesRegex(ValueError, "artifact_pin_changed"):
                seal.artifact_bytes(root, {**item, "sha256": "0" * 64})
            artifact.unlink(); artifact.symlink_to(root / "missing")
            with self.assertRaises(OSError): seal.artifact_bytes(root, item)
            artifact.unlink(); os.mkfifo(artifact)
            with self.assertRaisesRegex(ValueError, "artifact_identity"):
                seal.artifact_bytes(root, item)

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


class SealerDiagnosticTests(unittest.TestCase):
    """Actual main/caller with modeled transport and owner; no SDK, age or Docker."""

    def failure(self, error, *, where="payload", cleanup=True):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as temporary:
            case = Path(temporary).resolve() / "case"; case.mkdir()
            calls = []; start = time.monotonic()
            class Owner:
                def __init__(self, evidence, started): self.children = []; self.hard = started + 3900
                def command(self, argv, maximum):
                    calls.append(("command", maximum))
                    if len([c for c in calls if c[0] == "command"]) == 2 and where == "encrypt": raise error
                    return b"1.3.2\n"
                def remaining(self, maximum): return maximum
                def close(self):
                    calls.append(("close", None))
                    if isinstance(cleanup, Exception): raise cleanup
                    return cleanup
            verify = types.SimpleNamespace(STOP=None, Owner=Owner, linux_resources=lambda: None)
            producer = types.SimpleNamespace(approval=lambda env: ({}, "toy-operation"), helpers=lambda: (verify, None),
                prepared=lambda *args: {"started_monotonic": start})
            def module(name, pins):
                if name == "ci_build_sdk": return producer
                if name == "evidence_selection": return selection
                raise AssertionError("unexpected helper")
            if where == "context": producer.prepared = lambda *args: (_ for _ in ()).throw(error)
            def payload(*args):
                if where == "payload": raise error
                return {"metadata/toy.json": b"{}\n"}, "a" * 64, 1, {}, [], {}
            output = io.StringIO()
            with patch.object(seal, "snapshot", return_value={"toy": "a" * 64}), \
                    patch.object(seal, "module", side_effect=module), \
                    patch.object(seal, "recipient", return_value={"recipient": "age1-public-toy-only"}), \
                    patch.object(seal, "tool", return_value=Path("/public/toy/age")), \
                    patch.object(seal, "payload", side_effect=payload), \
                    patch.object(seal.shutil, "disk_usage", return_value=types.SimpleNamespace(free=20 * 1024**3)), \
                    patch.object(seal.signal, "signal"), patch.object(seal.signal, "setitimer"), \
                    contextlib.redirect_stdout(output):
                code = seal.main(["--phase", "seal", "--case", str(case), "--tool-root", str(case / "age")])
            raw = output.getvalue(); value = json.loads(raw)
            self.assertEqual(code, 1)
            self.assertEqual(value["state"], "failed")
            self.assertEqual(value["code"], "encrypted_evidence_refused_or_failed")
            self.assertFalse(value["SDK_qualified"])
            self.assertEqual(set(value), {"schema_version", "state", "code", "SDK_qualified", "failure_stage", "refusal_code",
                                         "exception_category", "owner_close_called", "owner_close_succeeded", "cleanup_refusal_code"})
            return value, calls, raw

    def test_failure_before_owner_keeps_close_facts_unknown(self):
        value, calls, _ = self.failure(ValueError("prepared_context_drift"), where="context")
        self.assertEqual(value["failure_stage"], "case_context")
        self.assertEqual(value["refusal_code"], "prepared_context_drift")
        self.assertIsNone(value["owner_close_called"])
        self.assertIsNone(value["owner_close_succeeded"])
        self.assertEqual(calls, [])

    def test_payload_fixed_refusal_reports_stage_and_actual_successful_close(self):
        value, calls, _ = self.failure(ValueError("compile_closure_join"))
        self.assertEqual(value["failure_stage"], "payload")
        self.assertEqual(value["refusal_code"], "compile_closure_join")
        self.assertEqual(value["exception_category"], "value_error")
        self.assertTrue(value["owner_close_called"])
        self.assertTrue(value["owner_close_succeeded"])
        self.assertIsNone(value["cleanup_refusal_code"])
        self.assertEqual(calls, [("command", 5), ("close", None)])

    def test_primary_refusal_survives_cleanup_false_and_exception_without_details(self):
        for cleanup, expected in ((False, "source_or_cleanup_unknown"), (ValueError("command_failed"), "command_failed"),
                                  (PermissionError("PRIVATE_CLEANUP_DETAIL"), "internal_error")):
            with self.subTest(expected=expected):
                value, _, raw = self.failure(ValueError("compile_inventory_join"), cleanup=cleanup)
                self.assertEqual(value["failure_stage"], "payload")
                self.assertEqual(value["refusal_code"], "compile_inventory_join")
                self.assertEqual(value["exception_category"], "value_error")
                self.assertTrue(value["owner_close_called"])
                self.assertFalse(value["owner_close_succeeded"])
                self.assertEqual(value["cleanup_refusal_code"], expected)
                self.assertNotIn("PRIVATE_CLEANUP_DETAIL", raw)

    def test_unknown_value_and_os_errors_never_emit_private_payload(self):
        errors = [(ValueError("PRIVATE_SOURCE_OR_TOKEN"), "value_error"), (ValueError(["PRIVATE_SOURCE_OR_TOKEN"]), "value_error"),
                  (KeyError("PRIVATE_SOURCE_OR_TOKEN"), "key_error"), (TypeError("PRIVATE_SOURCE_OR_TOKEN"), "type_error"),
                  (PermissionError("PRIVATE_SOURCE_OR_TOKEN"), "os_error"), (TimeoutError("PRIVATE_SOURCE_OR_TOKEN"), "timeout"),
                  (json.JSONDecodeError("PRIVATE_SOURCE_OR_TOKEN", "PRIVATE_BODY", 0), "json_error"),
                  (RuntimeError("PRIVATE_SOURCE_OR_TOKEN"), "unexpected")]
        for error, category in errors:
            with self.subTest(category=category):
                value, _, raw = self.failure(error)
                self.assertEqual(value["refusal_code"], "internal_error")
                self.assertEqual(value["exception_category"], category)
                self.assertNotIn("PRIVATE_SOURCE_OR_TOKEN", raw)
                self.assertNotIn("PRIVATE_BODY", raw)

    def test_encryption_command_failure_reports_exact_stage(self):
        value, calls, _ = self.failure(ValueError("command_failed"), where="encrypt")
        self.assertEqual(value["failure_stage"], "encrypt")
        self.assertEqual(value["refusal_code"], "command_failed")
        self.assertTrue(value["owner_close_called"])
        self.assertTrue(value["owner_close_succeeded"])
        self.assertEqual(calls, [("command", 5), ("command", 60), ("close", None)])



class PrivateCandidateBoundaryTests(unittest.TestCase):
    """Real private-input/projector/FD checks; modeled artifacts and age, no SDK."""

    def fixture(self, case, *, retained_graph_large=False, target_count=1):
        verify = load("ci_verify")
        producer = load("ci_build_sdk")
        operation = "00000000-0000-0000-0000-000000000002"
        start = time.monotonic(); pins = seal.snapshot()
        body, receipt = candidate()
        body["profile"] = receipt["profile"] = copy.deepcopy(producer.PROFILE)
        raw = b"!<arch>\nPUBLIC_MODELED_ONLY_NOT_COMPILED"
        record = body["files"][0]
        record.update(package_id="toy", name="toy", version="0.1.0", features=["web-webgl2"],
                      profile=copy.deepcopy(producer.PROFILE), kind=["lib"])
        item = body["artifact_inventory"][0]
        item.update(bytes=len(raw), sha256=seal.digest(raw))
        output = case / "compiler-output" / record["compiler_output"]
        output.parent.mkdir(parents=True); output.write_bytes(raw)
        receipt.update(schema_version=1, producer="trusted-rust-artifact-producer/1",
                       rustflags_sha256="e" * 64, lockfile_sha256="f" * 64,
                       artifact_inventory_sha256=exporter.digest(exporter.canonical(exporter.plain_inventory(body["artifact_inventory"]))))
        verify.save(case / "cargo-closure.private.json", receipt)
        package = {"id": "toy", "name": "toy", "version": "0.1.0", "features": {"web": []},
                   "targets": [{"name": "toy" if i == 0 else "public-example-" + str(i),
                                "kind": ["lib"] if i == 0 else ["example"],
                                "crate_types": ["rlib"] if i == 0 else ["bin"],
                                "src_path": "/public/modeled.rs"} for i in range(target_count)],
                   "metadata": {"omitted_public_fixture": "MUST_BE_OMITTED" + "X" * (seal.MAX_JSON + 1)}}
        if retained_graph_large:
            package["features"]["web"] = [str(i) + "Y" * 1024 for i in range(2100)]
        body.update(operation=operation, cargo_receipt_sha256=seal.digest((case / "cargo-closure.private.json").read_bytes()),
                    cargo_metadata={"packages": [package], "resolve": {"root": "toy", "nodes": [
                        {"id": "toy", "dependencies": [], "deps": [], "features": ["web"]}]}}, gaps=["modeled_not_qualified"])
        verify.save(case / "artifact-candidate.private.json", body)
        owner = types.SimpleNamespace(journal_failed=False,
            children=[{"pid": 10, "pgid": 10, "reaped": True, "group_closed": True, "returncode": 0}], containers=[])
        for i, phase in enumerate(("toolchain", "prefetch", "compile", "metadata")):
            owner.containers.append({"cid": str(i) * 64, "name": "modeled-" + phase,
                "image": "sha256:" + "e" * 64, "operation": operation, "phase": phase,
                "absent": True, "identity_verified": True})
        closed = selection.owner_closure_projection(owner, operation, pins)
        closed.update(original_exit_code=0, stop_signal=None, source_unchanged=True,
                      started_monotonic=start, hard_monotonic=start + 3900)
        verify.save(case / "producer-closure.private.json", closed)
        return verify, body, {"source_revision": body["source_revision"], "authorization_id": body["authorization_id"]}, \
            operation, {"started_monotonic": start}, pins

    def test_large_private_candidate_projects_under_unchanged_return_limit(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as temporary:
            case = Path(temporary).resolve()
            verify, body, row, operation, context, pins = self.fixture(case)
            path = case / "artifact-candidate.private.json"
            self.assertGreater(path.stat().st_size, seal.MAX_JSON)
            self.assertLess(path.stat().st_size, seal.MAX_PRIVATE_CANDIDATE)
            with self.assertRaisesRegex(ValueError, "input_identity"):
                seal.private_json(path, verify)  # Every other private JSON keeps its 2 MiB default.
            bodies, _, _, receipts, chosen, _ = seal.payload(case, None, verify, selection, context, row, operation, pins, lambda: None)
            projected = json.loads(bodies["metadata/artifact-candidate.json"])
            self.assertNotIn("cargo_metadata", projected)
            self.assertIn("cargo_graph", projected)
            self.assertNotIn("MUST_BE_OMITTED", bodies["metadata/artifact-candidate.json"].decode())
            self.assertTrue(all(len(raw) <= seal.MAX_JSON for name, raw in bodies.items() if name.startswith("metadata/")))
            self.assertEqual(receipts["candidate"], seal.digest(seal.regular(path, seal.MAX_PRIVATE_CANDIDATE)))
            # The archive preserves the same exact artifact bytes; payload now
            # retains a bounded lazy source instead of every artifact in RAM.
            import tarfile
            streamed = case / "streamed.tar"
            seal.archive_payload(streamed, bodies, lambda: None)
            with tarfile.open(streamed) as archive:
                self.assertEqual(archive.extractfile(chosen[0]["path"]).read(), b"!<arch>\nPUBLIC_MODELED_ONLY_NOT_COMPILED")
            self.assertEqual((seal.MAX_FILE, seal.MAX_TOTAL, seal.MAX_JSON, seal.MAX_TAR, seal.MAX_CIPHER),
                             (64 << 20, 2 << 30, 2 << 20, (2 << 30) + (8 << 20), (2 << 30) + (16 << 20)))

    def test_large_projected_metadata_still_refuses(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as temporary:
            case = Path(temporary).resolve()
            verify, _, row, operation, context, pins = self.fixture(case, retained_graph_large=True)
            self.assertLess((case / "artifact-candidate.private.json").stat().st_size, seal.MAX_PRIVATE_CANDIDATE)
            with self.assertRaisesRegex(ValueError, "metadata_bound"):
                seal.payload(case, None, verify, selection, context, row, operation, pins, lambda: None)

    def test_private_candidate_limit_preserves_fd_identity_mode_and_json_refusals(self):
        verify = load("ci_verify")
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as temporary:
            root = Path(temporary).resolve(); path = root / "candidate.json"
            with path.open("wb") as stream: stream.truncate(seal.MAX_PRIVATE_CANDIDATE + 1)
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "input_identity"):
                seal.private_json(path, verify, seal.MAX_PRIVATE_CANDIDATE)
            path.unlink(); verify.save(path, {"toy": True})
            self.assertEqual(seal.private_json(path, verify, seal.MAX_PRIVATE_CANDIDATE)[0], {"toy": True})
            link = root / "hardlink"; os.link(path, link)
            with self.assertRaisesRegex(ValueError, "input_identity"):
                seal.private_json(path, verify, seal.MAX_PRIVATE_CANDIDATE)
            link.unlink(); path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private_json_mode"):
                seal.private_json(path, verify, seal.MAX_PRIVATE_CANDIDATE)
            path.unlink(); path.symlink_to(root / "missing")
            with self.assertRaisesRegex(ValueError, "private_json_mode"):
                seal.private_json(path, verify, seal.MAX_PRIVATE_CANDIDATE)
            path.unlink(); os.mkfifo(path, 0o600)
            with self.assertRaisesRegex(ValueError, "private_json_mode"):
                seal.private_json(path, verify, seal.MAX_PRIVATE_CANDIDATE)
            path.unlink(); path.write_bytes(b'{"toy":1,"toy":2}'); path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
                seal.private_json(path, verify, seal.MAX_PRIVATE_CANDIDATE)

    def test_projector_preserves_all_437_targets_under_bounded_512_policy(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as temporary:
            case = Path(temporary).resolve()
            verify, body, row, operation, context, pins = self.fixture(case, target_count=437)
            bodies, _, _, _, _, _ = seal.payload(case, None, verify, selection, context, row, operation, pins, lambda: None)
            projected = json.loads(bodies["metadata/artifact-candidate.json"])["cargo_graph"]["packages"][0]["targets"]
            expected = [{key: item[key] for key in ("name", "kind", "crate_types")}
                        for item in body["cargo_metadata"]["packages"][0]["targets"]]
            self.assertEqual(len(projected), 437)
            self.assertEqual(projected, expected)  # Every target and its order survive; no clipping/filtering.
            self.assertLessEqual(len(bodies["metadata/artifact-candidate.json"]), seal.MAX_JSON)
            self.assertNotIn("MUST_BE_OMITTED", bodies["metadata/artifact-candidate.json"].decode())

    def test_projector_refuses_513_targets_and_invalid_target_container_shapes(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as temporary:
            case = Path(temporary).resolve()
            verify, body, row, operation, context, pins = self.fixture(case, target_count=513)
            with self.assertRaisesRegex(ValueError, "cargo_targets"):
                seal.payload(case, None, verify, selection, context, row, operation, pins, lambda: None)
            metadata = copy.deepcopy(body["cargo_metadata"])
            metadata["packages"][0]["targets"] = metadata["packages"][0]["targets"][:512]
            self.assertEqual(len(selection.cargo_graph_projection(metadata)["packages"][0]["targets"]), 512)
            for value in (None, {}, (), "targets", 1, True):
                changed = copy.deepcopy(metadata); changed["packages"][0]["targets"] = value
                with self.subTest(value_type=type(value).__name__), self.assertRaisesRegex(ValueError, "cargo_targets"):
                    selection.cargo_graph_projection(changed)
            for key, value, code in (("name", None, "metadata_string"), ("kind", "lib", "metadata_list"),
                                     ("crate_types", None, "metadata_list")):
                changed = copy.deepcopy(metadata); changed["packages"][0]["targets"][0][key] = value
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, code):
                    selection.cargo_graph_projection(changed)

    def test_actual_main_rechecks_large_candidate_after_modeled_encryption_and_rejects_drift(self):
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as temporary:
                root = Path(temporary).resolve(); case = root / "case"; case.mkdir()
                verify, body, row, operation, context, pins = self.fixture(case)
                calls = []
                class Owner:
                    def __init__(self, evidence, started): self.hard = started + 3900; self.children = []
                    def remaining(self, maximum): return maximum
                    def command(self, argv, maximum):
                        calls.append(("command", maximum))
                        self.children.append({"reaped": True, "group_closed": True})
                        if "--version" in argv: return b"1.3.2\n"
                        self_path = Path(argv[argv.index("--output") + 1])
                        self_path.write_bytes(b"age-encryption.org/v1\n" + b"MODELED_NOT_REAL_ENCRYPTION" * 8); self_path.chmod(0o600)
                        if changed:
                            mutated = copy.deepcopy(body); mutated["cargo_metadata"]["packages"][0]["description"] = "public fixture drift"
                            verify.save(case / "artifact-candidate.private.json", mutated)
                        return b""
                    def close(self): calls.append(("close", None)); return True
                producer = types.SimpleNamespace(approval=lambda env: (row, operation), helpers=lambda: (verify, None),
                    prepared=lambda *args: context)
                def module(name, module_pins):
                    self.assertEqual(module_pins, pins)
                    return {"ci_build_sdk": producer, "evidence_selection": selection, "opaque_sdk": exporter}[name]
                output = io.StringIO(); old_cwd = Path.cwd()
                try:
                    os.chdir(root)
                    with patch.object(seal, "module", side_effect=module), patch.object(verify, "Owner", Owner), \
                            patch.object(verify, "linux_resources", return_value=None), \
                            patch.object(seal, "recipient", return_value={"recipient": "age1-public-modeled-only", "age_binary_sha256": "e" * 64}), \
                            patch.object(seal, "tool", return_value=Path("/public/modeled-age")), \
                            patch.object(seal.shutil, "disk_usage", return_value=types.SimpleNamespace(free=20 * 1024**3)), \
                            patch.object(seal.signal, "signal"), patch.object(seal.signal, "setitimer"), contextlib.redirect_stdout(output):
                        code = seal.main(["--phase", "seal", "--case", str(case), "--tool-root", str(root / "age")])
                finally: os.chdir(old_cwd)
                observations = [json.loads(line) for line in output.getvalue().splitlines()]
                self.assertEqual(len(observations), 2)
                sizes, value = observations
                self.assertEqual(sizes, {"schema_version": 1, "state": "declared_artifact_sizes_not_qualified",
                                         "SDK_qualified": False, **seal.declared_artifact_sizes(body, selection)})
                self.assertEqual(code, 1 if changed else 0)
                self.assertFalse(value["SDK_qualified"])
                if changed:
                    self.assertEqual(value["failure_stage"], "postseal_integrity")
                    self.assertEqual(value["refusal_code"], "receipt_changed")
                    self.assertTrue(value["owner_close_succeeded"])
                    self.assertFalse((root / ".sdk-cipher-evidence").exists())
                else:
                    self.assertEqual(value["state"], "encrypted_evidence_delivered_not_qualified")
                    self.assertEqual({p.name for p in (root / ".sdk-cipher-evidence").iterdir()}, {"evidence.tar.age", "cipher-receipt.json"})
                self.assertEqual([v for v in calls if v[0] == "command"], [("command", 5), ("command", 60)])



class StreamingPrivateEvidenceTests(unittest.TestCase):
    """Actual small-file streams; large-budget rows are declarations, not SDK."""
    def sized_candidate(self, count):
        body, receipt = candidate()
        body["files"], body["artifact_inventory"] = [], []
        for i in range(count):
            filename = "libtoy-" + str(i) + ".rlib"
            path = "lib/" + selection.TARGET + "/" + filename
            body["files"].append({"public_path": path,
                "compiler_output": "build/" + selection.TARGET + "/web-release/deps/" + filename,
                "target": selection.TARGET, "role": "opaque_rlib"})
            body["artifact_inventory"].append({"path": path, "role": "opaque_rlib",
                "bytes": selection.MAX_ARTIFACT, "sha256": "d" * 64})
        receipt["artifact_inventory_sha256"] = exporter.digest(exporter.canonical(exporter.plain_inventory(body["artifact_inventory"])))
        return body, receipt

    def test_private_two_gib_selection_boundary_is_complete_and_public_guard_is_unchanged(self):
        body, receipt = self.sized_candidate(32)
        self.assertEqual(sum(x["bytes"] for x in body["artifact_inventory"]), 2 << 30)
        self.assertEqual(seal.bound_artifact_selection(body, receipt, selection, exporter),
            sorted([{"compiler_output": row["compiler_output"], **item}
                    for row, item in zip(body["files"], body["artifact_inventory"])], key=lambda x: x["path"]))
        body, receipt = self.sized_candidate(33)
        body["artifact_inventory"][-1]["bytes"] = 1
        receipt["artifact_inventory_sha256"] = exporter.digest(exporter.canonical(exporter.plain_inventory(body["artifact_inventory"])))
        self.assertEqual(sum(x["bytes"] for x in body["artifact_inventory"]), (2 << 30) + 1)
        with self.assertRaisesRegex(ValueError, "artifact_total_bound"):
            seal.bound_artifact_selection(body, receipt, selection, exporter)
        guard = load("bundle_guard")
        self.assertEqual((guard.MAX_FILE, guard.MAX_TOTAL), (64 << 20, 512 << 20))
        self.assertEqual((seal.MAX_TAR, seal.MAX_CIPHER), ((2 << 30) + (8 << 20), (2 << 30) + (16 << 20)))

    def test_declared_witness_is_numeric_fixed_and_rejects_unsafe_shape(self):
        body, _ = candidate()
        body["artifact_inventory"][0]["path"] = "PRIVATE_PATH_MUST_NOT_PROJECT"
        value = seal.declared_artifact_sizes(body, selection)
        self.assertEqual(value, {"artifact_count": 1, "artifact_total_bytes": 8, "artifact_max_bytes": 8})
        self.assertNotIn("PRIVATE", json.dumps(value))
        for bad in (True, False, -1, 0, 1.0, "8", seal.MAX_FILE + 1):
            changed = copy.deepcopy(body); changed["artifact_inventory"][0]["bytes"] = bad
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "artifact_inventory"):
                seal.declared_artifact_sizes(changed, selection)
        for rows in (None, {}, [], [body["artifact_inventory"][0]] * (selection.MAX_ARTIFACTS + 1)):
            with self.subTest(rows_type=type(rows).__name__), self.assertRaisesRegex(ValueError, "artifact_count"):
                seal.declared_artifact_sizes({"artifact_inventory": rows}, selection)
        changed = copy.deepcopy(body); changed["artifact_inventory"][0]["raw_secret"] = "MUST_NOT_PROJECT"
        with self.assertRaisesRegex(ValueError, "artifact_inventory"):
            seal.declared_artifact_sizes(changed, selection)

    def test_tar_streams_exact_artifact_and_detects_drift_then_restores(self):
        import tarfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); leaf = root / "build/deps/libtoy.rlib"; leaf.parent.mkdir(parents=True)
            raw = b"!<arch>\n" + b"PUBLIC_MODELED_BYTES" * 8192; leaf.write_bytes(raw)
            item = {"compiler_output": "build/deps/libtoy.rlib", "bytes": len(raw), "sha256": seal.digest(raw), "role": "opaque_rlib"}
            _, identity = seal.artifact_bytes(root, item, with_identity=True)
            name = "lib/" + selection.TARGET + "/libtoy.rlib"
            source = seal.ArtifactSource(root, item, identity)
            sha, _ = seal.archive_payload(root / "positive.tar", {name: source, "metadata/inventory.json": b"{}\n"}, lambda: None)
            self.assertEqual(sha, seal.digest((root / "positive.tar").read_bytes()))
            with tarfile.open(root / "positive.tar") as archive:
                self.assertEqual(archive.extractfile(name).read(), raw)
                self.assertTrue(all(x.isfile() and x.mode == 0o600 and x.uid == x.gid == x.mtime == 0 for x in archive))
            leaf.write_bytes(b"!<arch>\n" + b"CHANGED_BYTES_______" * 8192)
            with self.assertRaisesRegex(ValueError, "artifact_pin_changed"):
                seal.archive_payload(root / "changed.tar", {name: source}, lambda: None)
            leaf.write_bytes(raw)
            _, restored_identity = seal.artifact_bytes(root, item, with_identity=True)
            seal.archive_payload(root / "restored.tar", {name: seal.ArtifactSource(root, item, restored_identity)}, lambda: None)
            with tarfile.open(root / "restored.tar") as archive:
                self.assertEqual(archive.extractfile(name).read(), raw)

    def test_stream_hash_exact_bound_and_deadline_are_checked_each_block(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "public-toy"; raw = b"X" * 131073; path.write_bytes(raw)
            with patch.object(seal, "STREAM_BLOCK", 32768):
                calls = []
                def clock(): calls.append(True)
                sha, size, _ = seal.stream_file(path, len(raw), clock)
                self.assertEqual((sha, size), (seal.digest(raw), len(raw)))
                self.assertGreater(len(calls), 4)
                with self.assertRaisesRegex(ValueError, "input_identity"):
                    seal.stream_file(path, len(raw) - 1, clock)
                def expired():
                    calls.append(True)
                    if len(calls) > 2: raise ValueError("evidence_deadline")
                calls.clear()
                with self.assertRaisesRegex(ValueError, "evidence_deadline"):
                    seal.stream_file(path, len(raw), expired)

    def test_cipher_stream_copy_hash_identity_and_fresh_restore(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); source = root / "public-toy.age"
            raw = b"age-encryption.org/v1\n" + b"NOT_REAL_CRYPTO" * 8192; source.write_bytes(raw)
            wanted, size, identity = seal.stream_file(source, seal.MAX_CIPHER, lambda: None, prefix=b"age-encryption.org/v1\n")
            destination = root / "copied.age"
            self.assertEqual(seal.copy_cipher(source, destination, wanted, identity, lambda: None), size)
            self.assertEqual(destination.read_bytes(), raw)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): seal.copy_cipher(source, destination, wanted, identity, lambda: None)
            source.write_bytes(raw + b"changed")
            with self.assertRaisesRegex(ValueError, "input_changed"):
                seal.copy_cipher(source, root / "drift.age", wanted, identity, lambda: None)
            source.write_bytes(raw)
            wanted, _, identity = seal.stream_file(source, seal.MAX_CIPHER, lambda: None, prefix=b"age-encryption.org/v1\n")
            self.assertEqual(seal.copy_cipher(source, root / "restored.age", wanted, identity, lambda: None), len(raw))
            self.assertEqual((root / "restored.age").read_bytes(), raw)

    def test_payload_cap_includes_metadata_and_archive_refuses_overflow(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); bodies = {"metadata/inventory.json": b"X" * 129}
            with patch.object(seal, "MAX_TOTAL", 64), patch.object(seal, "MAX_JSON", 64):
                with self.assertRaisesRegex(ValueError, "payload_total_bound"):
                    seal.archive_payload(root / "overflow.tar", bodies, lambda: None)
            self.assertFalse((root / "overflow.tar").exists())
            with patch.object(seal, "MAX_TAR", 64):
                with self.assertRaisesRegex(ValueError, "input_identity"):
                    seal.archive_payload(root / "tar-overflow.tar", {"metadata/inventory.json": b"{}"}, lambda: None)


if __name__ == "__main__": unittest.main()
