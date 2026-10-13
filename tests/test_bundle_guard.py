"""Modeled admission boundaries; these fixtures are not a compiled SDK."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid
import zipfile

GUARD = Path(__file__).resolve().parents[1] / "tools" / "bundle_guard.py"
spec = importlib.util.spec_from_file_location("studio_bundle_guard", GUARD)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def uleb(value):
    result = bytearray()
    while True:
        byte = value & 127; value >>= 7
        result.append(byte | (128 if value else 0))
        if not value: return bytes(result)


def metadata_blob(release=b"1.99.0"):
    """Modeled format-10 envelope, not an actual Rust CrateRoot."""
    version = b"rustc " + release + b" (000000000 2026-09-28)"
    text = uleb(len(version)) + version + b"\xc1"
    root = 16 + len(text)
    return b"rust\0\0\0\x0a" + root.to_bytes(8, "little") + text + b"\x01\x02\x03\x04rust-end-file"


def wasm_metadata(payload, name=b".rmeta", linking=b"\x02"):
    def section(name, body):
        raw = uleb(len(name)) + name + body
        return b"\0" + uleb(len(raw)) + raw
    return b"\0asm\x01\0\0\0" + section(b"linking", linking) + section(name, payload)


def link_blob(objects=("unit.o",), native=(), legacy=False):
    def text(value):
        raw = value.encode("ascii")
        return uleb(len(raw)) + raw + b"\xc1"
    prefix = uleb(len(objects)) + b"".join(text(name) for name in objects)
    if not legacy:
        prefix += uleb(len(native)) + b"".join(b"\0" if name is None else b"\x01" + text(name) for name in native)
    return prefix + b"rust-end-file"


def ar(name="lib.rmeta", payload=None):
    if payload is None: payload = metadata_blob()
    header = (name + "/").ljust(16).encode() + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
    header += b"100644".ljust(8) + str(len(payload)).encode().ljust(10) + bytes((96, 10))
    return b"!<arch>\n" + header + payload + (b"\n" if len(payload) % 2 else b"")


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "payload"
        self.root.mkdir()
        self.policy = self.base / "policy.json"
        self.provenance = self.base / "producer.json"
        self.manifest = self.base / "upload.json"

    def prepare(self, files, surface="public-sdk", producer=None):
        self.surface = surface
        producer = producer or next(iter(guard.PRODUCERS[surface]))
        rows, reviewed = [], []
        for name, (data, role) in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            row = {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            rows.append(row)
            reviewed.append({**row, "role": role})
        receipt = {"schema_version": 1, "producer": producer, "source_revision": "a" * 40,
                   "authorization_id": str(uuid.uuid4()), "surface": surface, "files": rows}
        self.provenance.write_bytes(encoded(receipt))
        policy = {"schema_version": 1, "review_id": str(uuid.uuid4()), "surface": surface,
                  "producer_receipt_sha256": hashlib.sha256(self.provenance.read_bytes()).hexdigest(),
                  "files": reviewed}
        self.policy.write_bytes(encoded(policy))
        self.manifest.write_bytes(encoded({"schema_version": 1, "files": rows}))
        self.policy_sha = hashlib.sha256(self.policy.read_bytes()).hexdigest()
        return policy

    def validate(self, archive=None):
        return guard.validate_bundle(root=None if archive else self.root, archive=archive,
                                     surface=self.surface, policy_path=self.policy,
                                     policy_sha256=self.policy_sha,
                                     provenance_path=self.provenance, manifest_path=self.manifest)

    def rejection(self, code, archive=None):
        with self.assertRaises(guard.BundleError) as raised:
            self.validate(archive)
        self.assertEqual(raised.exception.code, code)

    def test_reviewed_facade_and_modeled_opaque_formats_pass_tree_and_zip(self):
        self.prepare({
            "facade/api/lib.rs": (b"pub struct PublicId(pub u64);\n", "public_facade"),
            "lib/public.rlib": (ar(), "opaque_rlib"),
            "lib/public.rmeta": (metadata_blob(), "opaque_metadata"),
            "host/derive.so": (b"\x7fELF-modeled-host-object", "opaque_proc_macro"),
            "lib/native.a": (ar("unit.o", b"\x7fELF-modeled-object"), "opaque_native_link"),
            "sdk-manifest.json": (b'{"kind":"rust-precompiled-sdk/1"}', "build_metadata"),
        })
        report = self.validate()
        self.assertEqual(report["state"], "passed")
        self.assertEqual(len(report["files"]), 6)
        bundle = self.base / "sdk.zip"
        with zipfile.ZipFile(bundle, "w") as z:
            for p in self.root.rglob("*"):
                if p.is_file():
                    z.write(p, str(p.relative_to(self.root)))
        self.assertEqual(self.validate(bundle), report)

    def test_context_allows_documented_facade_but_not_rust_or_libraries(self):
        self.prepare({"api.md": (b"Public widget contract.\n", "public_facade")}, "model-context")
        self.assertEqual(self.validate()["state"], "passed")
        for name, data, role in [("facade.rs", b"pub struct Id;\n", "public_facade"),
                                  ("engine.rlib", ar(), "opaque_rlib")]:
            with self.subTest(name=name):
                policy = json.loads(self.policy.read_bytes())
                policy["files"] = [{"path": name, "bytes": len(data),
                                    "sha256": hashlib.sha256(data).hexdigest(), "role": role}]
                self.policy.write_bytes(encoded(policy));self.policy_sha = hashlib.sha256(self.policy.read_bytes()).hexdigest()
                with self.assertRaises(guard.BundleError):
                    self.validate()

    def test_private_paths_refuse_even_if_policy_calls_them_public(self):
        for name in [".codex/auth.json", ".cursor/settings.json", ".claude/settings.json", ".ssh/id_ed25519",
                     ".env", "assets/credentials.json", "MEMORY.md", "cache/state.json",
                     "logs/trace.txt", "rollout_summaries/one.md", "crates/engine/src/lib.rs",
                     "vendor/engine/lib.rs", "sourcepack/engine.rs"]:
            with self.subTest(name=name):
                entry = {"path": name, "bytes": 1, "sha256": "a" * 64, "role": "public_facade"}
                with self.assertRaises(guard.BundleError):
                    guard.inventory([entry], surface="public-sdk", policy=True)

    def test_source_export_zip_is_refused_before_member_body_read(self):
        self.prepare({"facade/api.md": (b"Approved API.\n", "public_facade")})
        archive = self.base / "private-sdk.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("crates/engine/src/lib.rs", b"modeled private implementation")
        with patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("body must not open")):
            self.rejection("private_path", archive)

    def test_exact_inventory_rejects_unlisted_file_and_missing_file(self):
        self.prepare({"facade/api.md": (b"Approved API.\n", "public_facade")})
        extra = self.root / "notes.txt";extra.write_text("Unreviewed.")
        self.rejection("inventory_mismatch")
        extra.unlink();(self.root / "facade/api.md").unlink()
        self.rejection("inventory_mismatch")

    def test_payload_hash_drift_refuses(self):
        self.prepare({"index.html": (b"good", "public_asset")}, "public-upload")
        (self.root / "index.html").write_bytes(b"evil")
        self.rejection("payload_changed")

    def test_policy_and_producer_bytes_are_independently_bound(self):
        self.prepare({"index.html": (b"hello", "public_asset")}, "public-upload")
        original = self.policy.read_bytes()
        self.policy.write_bytes(original + b" ")
        self.rejection("untrusted_policy")
        self.policy.write_bytes(original)
        self.provenance.write_bytes(self.provenance.read_bytes() + b" ")
        self.rejection("untrusted_provenance")

    def test_untrusted_producer_cannot_self_label_approved_sdk(self):
        self.prepare({"lib/public.rlib": (ar(), "opaque_rlib")}, producer="provider-raw-transcript/1")
        self.rejection("untrusted_producer")

    def test_upload_manifest_cannot_add_private_source_metadata(self):
        self.prepare({"index.html": (b"hello", "public_asset")}, "public-upload")
        value = json.loads(self.manifest.read_bytes());value["source"] = {"path": "source.zip"}
        self.manifest.write_bytes(encoded(value))
        self.rejection("invalid_fields")

    def test_paths_case_collisions_and_noninteger_sizes_refuse(self):
        for entries in [
            [{"path": "../outside.md", "bytes": 1, "sha256": "a" * 64}],
            [{"path": "A.md", "bytes": 1, "sha256": "a" * 64}, {"path": "a.md", "bytes": 1, "sha256": "a" * 64}],
            [{"path": "api.json", "bytes": True, "sha256": "a" * 64}],
            [{"path": "api.json", "bytes": 1.0, "sha256": "a" * 64}],
        ]:
            with self.subTest(entries=entries):
                with self.assertRaises(guard.BundleError):
                    guard.inventory(entries, surface="model-context")

    def test_symlink_hardlink_and_fifo_refuse_before_hashing(self):
        self.prepare({"index.html": (b"hello", "public_asset")}, "public-upload")
        path = self.root / "index.html";outside = self.base / "outside"
        outside.write_bytes(b"hello");path.unlink();path.symlink_to(outside)
        self.rejection("nonregular_payload")
        path.unlink();os.link(outside, path)
        self.rejection("nonregular_payload")
        path.unlink();os.mkfifo(path)
        self.rejection("nonregular_payload")

    def test_zip_duplicate_and_symlink_entries_refuse(self):
        self.prepare({"index.html": (b"hello", "public_asset")}, "public-upload")
        archive = self.base / "links.zip"
        entry = zipfile.ZipInfo("index.html");entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(archive, "w") as z:z.writestr(entry, b"hello")
        self.rejection("archive_member_type", archive)
        second = self.base / "case.zip"
        with zipfile.ZipFile(second, "w") as z:
            z.writestr("index.html", b"hello");z.writestr("INDEX.HTML", b"hello")
        self.rejection("case_collision", second)

    def test_encrypted_payload_and_nested_archive_refuse_even_with_matching_hash(self):
        for data, code in [(b"\0GITCRYPT\0modeled-ciphertext", "encrypted_public_payload"),
                           (b"PK\x03\x04modeled-nested-archive", "nested_archive_payload")]:
            with self.subTest(code=code):
                self.prepare({"data.bin": (data, "public_asset")}, "public-upload")
                self.rejection(code)

    def test_private_key_and_credential_json_and_reasoning_transcript_refuse(self):
        cases = [
            (b"-----BEGIN " + b"PRIVATE KEY-----\nmodeled-only\n", "private_key_material"),
            (b'{"access_token":"modeled-token"}', "credential_json"),
            (b'{"type":"reasoning","summary":"modeled-private-analysis"}', "provider_transcript_json"),
            (b'{"role":"assistant","content":"modeled-private-response"}', "provider_transcript_json"),
            (b'{"memories":["modeled-agent-memory"]}', "provider_or_memory_json"),
        ]
        for data, code in cases:
            with self.subTest(code=code):
                self.prepare({"data.json": (data, "public_asset")}, "public-upload")
                self.rejection(code)

    def test_opaque_archive_rejects_source_member_and_thin_reference(self):
        for data, code in [(ar("private.rs", b"modeled source"), "opaque_archive_source_member"),
                           (b"!<thin>\n", "opaque_archive_format")]:
            with self.subTest(code=code):
                self.prepare({"lib/public.rlib": (data, "opaque_rlib")})
                self.rejection(code)

    def test_rust_wasm32_metadata_and_link_wrapper_shapes_pass(self):
        primary = wasm_metadata(metadata_blob())
        link = wasm_metadata(link_blob(), b".rmeta-link")
        library = ar(payload=primary) + ar("lib.rmeta-link", link)[8:] + ar("unit.o", b"BC\xc0\xdemodeled-object")[8:]
        self.prepare({"lib/public.rlib": (library, "opaque_rlib"),
                      "lib/public.rmeta": (primary, "opaque_metadata")})
        self.assertEqual(self.validate()["state"], "passed")

    def test_rust198_link_codec_is_bound_to_primary_metadata_family(self):
        for release, legacy in ((b"1.98.1", True), (b"1.99.0", False)):
            with self.subTest(release=release):
                def library(link_legacy):
                    return (ar(payload=wasm_metadata(metadata_blob(release)))
                            + ar("lib.rmeta-link", wasm_metadata(link_blob(legacy=link_legacy), b".rmeta-link"))[8:]
                            + ar("unit.o", b"BC\xc0\xdemodeled-object")[8:])
                self.prepare({"lib/public.rlib": (library(legacy), "opaque_rlib")})
                self.assertEqual(self.validate()["state"], "passed")
                self.prepare({"lib/public.rlib": (library(not legacy), "opaque_rlib")})
                self.rejection("opaque_metadata_link_family")

    def test_wasm_metadata_requires_exact_bounded_custom_sections(self):
        valid = wasm_metadata(metadata_blob())
        cases = [b"\0asm\x01\0\0\0", valid[:-1], valid + b"\0",
                 wasm_metadata(metadata_blob(), b".rustc"), wasm_metadata(metadata_blob(), linking=b"\x03"),
                 valid[:4] + b"\x02" + valid[5:], valid[:9] + b"\x89\0" + valid[10:],
                 valid[:8] + b"\x01" + valid[9:]]
        for body in cases:
            with self.subTest(body_sha=hashlib.sha256(body).hexdigest()):
                self.prepare({"lib/public.rmeta": (body, "opaque_metadata")})
                self.rejection("wasm_metadata_wrapper")

    def test_metadata_header_root_version_string_and_end_marker_are_checked(self):
        valid = metadata_blob()
        text_end = 17 + len(b"rustc 1.99.0 (000000000 2026-09-28)")
        cases = [valid[:7] + b"\x0b" + valid[8:], valid[:8] + len(valid).to_bytes(8, "little") + valid[16:],
                 valid[:-1] + b"x", valid[:17] + b"other" + valid[22:], valid[:text_end] + b"\0" + valid[text_end+1:]]
        for raw in cases:
            for body in (raw, wasm_metadata(raw)):
                with self.subTest(body_sha=hashlib.sha256(body).hexdigest()):
                    self.prepare({"lib/public.rmeta": (body, "opaque_metadata")})
                    self.rejection("opaque_metadata_format")

    def test_metadata_link_vectors_names_sentinels_and_object_references_are_checked(self):
        valid = link_blob()
        cases = [(link_blob(("unit.rs",)), "opaque_metadata_link_format"),
                 (link_blob(("../unit.o",)), "opaque_metadata_link_format"),
                 (link_blob(("unit.o", "unit.o")), "opaque_metadata_link_format"),
                 (valid.replace(b"\xc1", b"\xc2"), "opaque_metadata_link_format"),
                 (b"\0\x01\x02rust-end-file", "opaque_metadata_link_format"),
                 (uleb(guard.MAX_FILES * 4 + 1) + b"rust-end-file", "opaque_metadata_link_format"),
                 (valid[:-13] + b"xrust-end-file", "opaque_metadata_link_format"),
                 (link_blob(("missing.o",)), "opaque_metadata_link_reference")]
        for body, code in cases:
            with self.subTest(code=code, body_sha=hashlib.sha256(body).hexdigest()):
                library = ar(payload=wasm_metadata(metadata_blob())) + ar("lib.rmeta-link", wasm_metadata(body, b".rmeta-link"))[8:]
                library += ar("unit.o", b"BC\xc0\xdemodeled-object")[8:]
                self.prepare({"lib/public.rlib": (library, "opaque_rlib")})
                self.rejection(code)

    def test_renamed_known_transcript_and_json_credentials_refuse(self):
        for data, code in [(b"<analysis>\nmodeled private reasoning", "provider_transcript_text"),
                           (b'{"refresh_token":"modeled-only"}', "credential_json")]:
            with self.subTest(code=code):
                self.prepare({"data.bin": (data, "public_asset")}, "public-upload")
                self.rejection(code)

    def test_duplicate_and_nonfinite_json_metadata_refuse(self):
        for data, code in [(b'{"label":1,"label":2}', "duplicate_json_key"),
                           (b'{"value":NaN}', "nonfinite_json"),
                           (b'{"value":1e309}', "nonfinite_json")]:
            with self.subTest(code=code):
                self.prepare({"settings.json": (data, "public_asset")}, "public-upload")
                self.rejection(code)

    def test_owned_project_and_public_web_positive_do_not_need_provider_state(self):
        self.prepare({"src/main.rs": (b"fn main() {}\n", "project_source"),
                      "README.md": (b"User-owned public project.\n", "public_document")}, "public-project")
        self.assertEqual(self.validate()["state"], "passed")
        for p in self.root.rglob("*"):
            if p.is_file():p.unlink()
        # A separate prepared output is required, not the project tree.
        self.root = self.base / "web";self.root.mkdir()
        self.prepare({"index.html": (b"<canvas></canvas>", "public_asset"),
                      "settings.json": (b'{"label":"Memory Match"}', "public_asset")}, "public-upload")
        self.assertEqual(self.validate()["state"], "passed")

    def test_cli_failure_report_is_fixed_and_existing_report_not_overwritten(self):
        sentinel = "MODELED_PRIVATE_SENTINEL"
        self.prepare({"data.json": (encoded({"access_token": sentinel}), "public_asset")}, "public-upload")
        report = self.base / "report.json"
        argv = [sys.executable, "-I", "-B", str(GUARD), "--surface", self.surface, "--root", str(self.root),
                "--policy", str(self.policy), "--policy-sha256", self.policy_sha,
                "--provenance", str(self.provenance), "--manifest", str(self.manifest), "--report", str(report)]
        result = subprocess.run(argv, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        value = json.loads(report.read_bytes())
        self.assertEqual(value, {"schema_version": 1, "state": "failed", "code": "credential_json"})
        self.assertNotIn(sentinel.encode(), result.stdout + result.stderr + report.read_bytes())
        before = report.read_bytes()
        second = subprocess.run(argv, capture_output=True, timeout=10)
        self.assertEqual(second.returncode, 1)
        self.assertEqual(report.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
