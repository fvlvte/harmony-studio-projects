"""Finite public generator controls; Docker/registry responses are modeled.

No images, network, SDK, actual publication or account credentials are used.
"""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("generator_toolchain", ROOT / "tools/generator_toolchain.py")
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)
IMAGE = "sha256:" + "a" * 64
MANIFEST = "sha256:" + "b" * 64
CID = "c" * 64


def image():
    return {"Id": IMAGE, "Architecture": "arm64", "Os": "linux", "Config": {
        "User": "65532:65532", "Entrypoint": ["rustfmt"], "Cmd": ["bash"], "WorkingDir": "",
        "Labels": None, "Env": [k + "=" + v for k, v in generator.ENV.items()],
        "Volumes": None, "ExposedPorts": None, "OnBuild": None, "Healthcheck": None},
        "RepoDigests": [generator.REGISTRY + "@" + MANIFEST]}


def tool_output():
    return ("rustc 1.99.0 (000000000 2026-10-01)\nbinary: rustc\ncommit-hash: " + "0" * 40
        + "\ncommit-date: 2026-10-01\nhost: aarch64-unknown-linux-gnu\nrelease: 1.99.0\nLLVM version: 22.1.0\n"
        + "cargo 1.99.0 (000000000 2026-10-01)\nrustfmt 1.9.0-stable (000000000 2026-10-01)\n"
        + "d" * 64 + "\n" + "e" * 64 + "\n").encode()


def container(row):
    return {"Id": CID, "Name": "/" + row["name"], "Image": IMAGE, "Mounts": [], "Config": {
        "Labels": {"online.harmony.operation": row["operation"]}, "User": "65532:65532",
        "Entrypoint": ["/usr/bin/env"], "WorkingDir": "/tmp", "Volumes": None,
        "Env": [k + "=" + v for k, v in generator.ENV.items()],
        "Cmd": ["-i", *(k + "=" + v for k, v in generator.GUEST_ENV.items()), "/bin/sh", "-c", generator.GUEST]},
        "HostConfig": {"Binds": None, "Mounts": None, "NetworkMode": "none", "ReadonlyRootfs": True,
        "Privileged": False, "CapDrop": ["ALL"], "CapAdd": None, "SecurityOpt": ["no-new-privileges"],
        "Memory": 512 * 1024**2, "MemorySwap": 512 * 1024**2, "NanoCpus": 1_000_000_000,
        "CpusetCpus": "0", "PidsLimit": 64, "PidMode": "", "IpcMode": "private", "CgroupnsMode": "private",
        "Devices": [], "DeviceRequests": None, "PortBindings": {}, "PublishAllPorts": False,
        "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"}},
        "State": {"Running": False, "ExitCode": 0, "OOMKilled": False}}


class GeneratorTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "tools").mkdir()
        shutil.copytree(ROOT / "tools/generator-context", self.root / "tools/generator-context")
        self.clock = 1000.0
        self.close_ok = True
        self.wrong_anonymous = False
        self.wrong_pull = False
        self.late_save = False
        self.bad_tools = False
        self.calls = []
        self.instances = []
        self.output = io.StringIO()
        outer = self
        class FakeOwner:
            def __init__(self, evidence, started=None):
                self.evidence = evidence
                self.hard = started + 3900
                self.work = self.hard - 30
                self.docker_config = evidence / "docker-config"
                self.docker_config.mkdir(mode=0o700)
                (self.docker_config / "config.json").write_bytes(b"{}\n")
                self.children = []
                self.containers = []
                self.journal_failed = False
                outer.instances.append(self)
            def remaining(self, maximum):
                return min(maximum, self.work - outer.clock)
            def journal(self):
                pass
            def docker(self, args, maximum=10, **kwargs):
                outer.calls.append(args)
                self.children.append({"reaped": True, "group_closed": True})
                if args[:2] == ["image", "inspect"]:
                    value = image()
                    if outer.wrong_pull and "@" in args[2]: value["RepoDigests"] = []
                    return generator.canonical([value])
                if args[0] == "create": return CID.encode()
                if args[0] == "start":
                    return tool_output().replace(b"1.99.0", b"1.98.1") if outer.bad_tools else tool_output()
                if args[0] == "login":
                    assert kwargs["data"] == b"MODELED_GITHUB_TOKEN_NOT_A_CREDENTIAL\n"
                    (self.evidence / "stdin-modeled").write_bytes(kwargs["data"])
                    (self.docker_config / "config.json").write_bytes(b'{"auths":{"ghcr.io":{"auth":"MODELED"}}}\n')
                    return b""
                if args[0] == "push": return b"tag: digest: " + MANIFEST.encode() + b" size: 100\n"
                if args[0] in ("tag", "logout", "pull"): return b""
                raise AssertionError("unexpected modeled Docker call")
            def inspect(self, identity):
                return container(self.containers[0])
            def command(self, args, maximum, **kwargs):
                self.children.append({"reaped": True, "group_closed": True})
                outer.calls.append(["anonymous-child"])
                assert "GHCR_GENERATOR_TOKEN" not in os.environ
                assert json.loads((self.docker_config / "config.json").read_bytes()) == {}
                assert not list(self.evidence.glob("stdin-*"))
                value = image()
                return generator.canonical({"manifest_digest": MANIFEST,
                    "image_id": "sha256:" + "f" * 64 if outer.wrong_anonymous else IMAGE,
                    "manifest_media_type": "application/vnd.oci.image.manifest.v1+json",
                    **{k: value[k] for k in ("Architecture", "Os", "Config")}})
            def close(self):
                if outer.close_ok:
                    for row in self.containers: row["absent"] = True
                return outer.close_ok
        def save(path, value):
            path.write_bytes(generator.canonical(value))
            if self.late_save: self.clock = 1301.0
        self.verify = types.SimpleNamespace(Owner=FakeOwner, STOP=None, document=lambda raw, maximum=2 * 1024**2: generator.document(raw),
            save=save, linux_resources=lambda: {"mem_total": 17_000_000_000, "mem_available": 12_000_000_000,
                                               "memory_psi_avg10": ["0.00", "0.00"]})
        self.env = {"GITHUB_REPOSITORY": generator.REPOSITORY, "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "1" * 40, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}

    def invoke(self, phase):
        with patch.object(Path, "cwd", return_value=self.root), patch.object(generator, "owner_module", return_value=self.verify), \
             patch.object(generator.time, "monotonic", side_effect=lambda: self.clock), patch.object(generator.signal, "signal"), \
             patch.object(generator.signal, "setitimer"), patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(self.output):
            return generator.main(["--phase", phase])

    def prepared(self):
        self.assertEqual(self.invoke("probe"), 0)
        self.calls.clear()
        self.env.update(GHCR_GENERATOR_TOKEN="MODELED_GITHUB_TOKEN_NOT_A_CREDENTIAL", GHCR_GENERATOR_ACTOR="fvlvte")

    def test_exact_two_file_context_rejects_extra_changed_symlink_and_old_compiler(self):
        context = self.root / "tools/generator-context"
        self.assertEqual(generator.context_identity(context), generator.CONTEXT_SHA)
        extra = context / "sdk.zip"
        extra.write_bytes(b"not a source archive")
        with self.assertRaisesRegex(ValueError, "public_context_inventory"): generator.context_identity(context)
        extra.unlink()
        original = (context / "Dockerfile").read_bytes()
        (context / "Dockerfile").write_bytes(original.replace(b"1.99.0", b"1.98.1"))
        with self.assertRaisesRegex(ValueError, "public_context_drift"): generator.context_identity(context)
        (context / "Dockerfile").unlink()
        (context / "Dockerfile").symlink_to(ROOT / "toolchain/Dockerfile")
        with self.assertRaises(OSError): generator.context_identity(context)
        changed = image()
        changed["Config"]["Entrypoint"] = ["/usr/bin/env"]
        with self.assertRaisesRegex(ValueError, "image_contract"): generator.image_identity(changed)

    def test_native_tools_without_guest_python_or_wasm_and_reject_wrong_version_host_hash(self):
        self.assertEqual(generator.tools_output(tool_output())["rustc_sha256"], "d" * 64)
        self.assertNotIn("python", generator.GUEST)
        self.assertNotIn("wasm32", generator.GUEST)
        for old, new in [(b"1.99.0", b"1.98.1"), (b"aarch64", b"x86_64"), (b"d" * 64, b"nohash")]:
            with self.subTest(old=old), self.assertRaises(ValueError): generator.tools_output(tool_output().replace(old, new))

    def test_image_rejects_secret_environment_root_extra_labels_and_amd64(self):
        self.assertEqual(generator.image_identity(image()), IMAGE)
        for key, value in [("User", "0"), ("Labels", {"private": "unexpected"}),
                           ("Env", image()["Config"]["Env"] + ["SECRET=MODELED"])]:
            changed = image(); changed["Config"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): generator.image_identity(changed)
        changed = image(); changed["Architecture"] = "amd64"
        with self.assertRaises(ValueError): generator.image_identity(changed)

    def test_probe_actual_caller_keeps_deadline_source_context_and_closed_identity(self):
        self.assertEqual(self.invoke("probe"), 0)
        value = json.loads((self.root / ".generator-public/receipt.json").read_bytes())
        self.assertEqual((self.instances[0].hard, self.instances[0].work), (1120.0, 1090.0))
        self.assertEqual(value["probe_source_sha256"], generator.source_identity())
        self.assertEqual(value["origin_context_digest"], generator.CONTEXT_SHA)
        self.assertTrue(value["owned_container_absent"])
        self.assertTrue(value["owned_cli_closed"])
        self.assertFalse(value["sdk_qualified"])

    def test_probe_refuses_bad_tools_or_unknown_closure(self):
        self.bad_tools = True
        self.assertEqual(self.invoke("probe"), 1)
        self.assertEqual(json.loads((self.root / ".generator-public/receipt.json").read_bytes())["state"], "failed")
        shutil.rmtree(self.root / ".generator-public")
        self.bad_tools = False; self.close_ok = False
        self.assertEqual(self.invoke("probe"), 1)

    def test_container_sandbox_has_no_source_and_refuses_relaxed_isolation(self):
        row, args = generator.container_arguments(IMAGE, "operation")
        row["cid"] = CID
        generator.container_identity(container(row), row)
        self.assertNotIn("--mount", args)
        for key, value in [("NetworkMode", "bridge"), ("MemorySwap", 1024**3), ("Privileged", True), ("PidsLimit", 128)]:
            changed = container(row); changed["HostConfig"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): generator.container_identity(changed, row)

    def test_publication_keeps_generator_identity_digest_join_and_scrubs_token(self):
        self.prepared()
        self.assertEqual(self.invoke("publish"), 0)
        value = json.loads((self.root / ".generator-public/registry.json").read_bytes())
        self.assertEqual(value["generator_ref"], generator.REGISTRY + "@" + MANIFEST)
        self.assertEqual(value["image_id"], IMAGE)
        self.assertNotEqual(value["image_id"], value["manifest_digest"])
        self.assertTrue(value["publication_credentials_removed"])
        self.assertFalse(value["sdk_qualified"])
        self.assertEqual((self.instances[-1].hard, self.instances[-1].work), (1300.0, 1270.0))
        text = json.dumps(value) + self.output.getvalue()
        self.assertNotIn("MODELED_GITHUB_TOKEN", text)
        self.assertNotIn(str(self.root), text)
        self.assertFalse(any("/compiler" in str(call) for call in self.calls))

    def test_publication_refuses_foreign_dispatch_or_failed_probe_before_login(self):
        self.prepared()
        self.env["GITHUB_REF"] = "refs/heads/untrusted"
        self.assertEqual(self.invoke("publish"), 1)
        self.assertEqual(self.calls, [])
        self.env["GITHUB_REF"] = "refs/heads/main"
        p = self.root / ".generator-public/receipt.json"
        value = json.loads(p.read_bytes()); value["state"] = "failed"; p.write_bytes(generator.canonical(value))
        self.assertEqual(self.invoke("publish"), 1)
        self.assertEqual(self.calls, [])

    def test_publication_refuses_source_receipt_or_context_drift_before_login(self):
        self.prepared()
        p = self.root / ".generator-public/receipt.json"
        value = json.loads(p.read_bytes()); value["probe_source_sha256"] = "0" * 64; p.write_bytes(generator.canonical(value))
        self.assertEqual(self.invoke("publish"), 1)
        self.assertEqual(self.calls, [])

    def test_publication_refuses_anonymous_mismatch_immutable_pull_or_cleanup_unknown(self):
        for failure in ("wrong_anonymous", "wrong_pull", "close_ok"):
            with self.subTest(failure=failure):
                self.setUp()
                self.prepared()
                setattr(self, failure, failure != "close_ok")
                self.assertEqual(self.invoke("publish"), 1)
                self.assertFalse((self.root / ".generator-public/registry.json").exists())
                self.assertEqual(json.loads((self.instances[-1].docker_config / "config.json").read_bytes()), {})
                self.assertEqual(list(self.instances[-1].evidence.glob("stdin-*")), [])

    def test_late_publication_receipt_cannot_return_zero(self):
        self.prepared(); self.late_save = True
        self.assertEqual(self.invoke("publish"), 1)
        self.assertNotIn('"state":"PUBLIC_GENERATOR_PUBLISHED_NOT_SDK_QUALIFIED"', self.output.getvalue())

    def test_actual_anonymous_entry_dispatch_and_invalid_digest_cli_refuse_before_network(self):
        with patch.object(generator, "anonymous_child") as child:
            self.assertEqual(generator.entry(["--anonymous-child", MANIFEST, IMAGE]), 0)
            child.assert_called_once_with(MANIFEST, IMAGE)
        with patch.object(generator, "anonymous_child", side_effect=ValueError("modeled")):
            self.assertEqual(generator.entry(["--anonymous-child", MANIFEST, IMAGE]), 1)
        result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools/generator_toolchain.py"),
                                 "--anonymous-child", "invalid-digest", "invalid-image"],
                                capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_workflow_native_manual_only_and_no_private_inputs_or_old_workflow_changes(self):
        text = (ROOT / ".github/workflows/build-generator.yml").read_text()
        self.assertIn("runs-on: ubuntu-24.04-arm", text)
        self.assertIn("github.event_name == 'workflow_dispatch'", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("--platform linux/arm64", text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("git-crypt", text)
        self.assertNotIn("build-sdk", text)
        for name, sha in [("tools/probe_toolchain.py", "21d55e980148aabee6fb9a0f7bb076869f5ef201dd2b43107c0ec5857c4e12e5"),
                          ("tools/publish_toolchain.py", "5f53373d89bd8cf71a8fa30b6ae9fb65a2b4569d62b146979578339f36c3dd80")]:
            self.assertEqual(generator.digest((ROOT / name).read_bytes()), sha)


if __name__ == "__main__":
    unittest.main()
