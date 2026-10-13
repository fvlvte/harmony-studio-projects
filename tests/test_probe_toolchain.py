"""Public probe controls. Docker/image observations are modeled below.

The separately marked finite Linux child tests only the maintained owner; it
does not establish an actual Docker image, compiler or SDK qualification.
"""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("probe_toolchain", ROOT / "tools/probe_toolchain.py")
probe = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(probe)
ID = "sha256:" + "a" * 64
CID = "b" * 64
RESOURCES = {"mem_total": 17_000_000_000, "mem_available": 12_000_000_000, "memory_psi_avg10": ["0.00", "0.00"]}


def image():
    return {"Id": ID, "Architecture": "arm64", "Os": "linux", "Config": {
        "User": "65532:65532", "Entrypoint": ["/usr/bin/env"], "Cmd": ["cargo", "+1.98.1", "--version"],
        "WorkingDir": "/tmp", "Labels": dict(probe.LABELS), "Env": [k + "=" + v for k, v in probe.ENV.items()],
        "Volumes": None, "ExposedPorts": None, "OnBuild": None, "Healthcheck": None}}


def container(row):
    return {"Id": CID, "Name": "/" + row["name"], "Image": ID, "Mounts": [], "Config": {
        "Labels": {**probe.LABELS, "online.harmony.operation": row["operation"]}, "User": "65532:65532",
        "Entrypoint": ["/usr/bin/env"], "WorkingDir": "/tmp", "Volumes": None,
        "Env": [k + "=" + v for k, v in probe.ENV.items()],
        "Cmd": ["-i", *(k + "=" + v for k, v in probe.GUEST_ENV.items()), "python3", "-I", "-B", "-c", probe.GUEST]},
        "HostConfig": {"Binds": None, "Mounts": None, "NetworkMode": "none", "ReadonlyRootfs": True,
        "Privileged": False, "CapDrop": ["ALL"], "CapAdd": None, "SecurityOpt": ["no-new-privileges"],
        "Memory": 512 * 1024**2, "MemorySwap": 512 * 1024**2, "NanoCpus": 1_000_000_000,
        "CpusetCpus": "0", "PidsLimit": 64, "PidMode": "", "IpcMode": "private", "CgroupnsMode": "private",
        "Devices": [], "DeviceRequests": None, "PortBindings": {}, "PublishAllPorts": False,
        "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"}},
        "State": {"Running": False, "ExitCode": 0, "OOMKilled": False}}


def compiler():
    return {"release": "1.98.1", "host": "aarch64-unknown-linux-gnu",
        "verbose_version": "rustc 1.98.1 (000000000 2026-09-28)\nbinary: rustc\ncommit-hash: " + "0" * 40
            + "\ncommit-date: 2026-09-28\nhost: aarch64-unknown-linux-gnu\nrelease: 1.98.1\nLLVM version: 22.1.0\n",
        "executable_sha256": "c" * 64, "sysroot_sha256": "d" * 64,
        "sysroot_files": {"aarch64-unknown-linux-gnu": 20, "wasm32-unknown-unknown": 18}, "sysroot_bytes": 1000,
        "packages": {"python3": "3.11.2-1+b1", "ca-certificates": "20230311+deb12u1", "libc6": "2.36-9+deb12u10"},
        "tools": {"cargo": "cargo 1.98.1 (000000000 2026-09-28)", "rustup": "rustup 1.28.2", "python": "Python 3.11.2"}}


class ProbeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        shutil.copytree(ROOT / "toolchain", self.root / "toolchain")
        self.args = ["--image", probe.IMAGE, "--context", "toolchain", "--output", ".toolchain-public/receipt.json"]
        self.clock = 1000.0; self.instances = []; self.close_ok = True; self.stop_on_close = False; self.start_error = False
        self.unresolved = None
        test = self
        class FakeOwner:
            def __init__(self, evidence, started=None):
                self.evidence = evidence; self.started = started; self.hard = started + 3900; self.work = self.hard - 30
                self.children = []; self.containers = []; self.journal_failed = False; self.calls = []; test.instances.append(self)
            def remaining(self, maximum): return min(maximum, self.work - test.clock)
            def journal(self): pass
            def docker(self, args, maximum=10, **kwargs):
                self.calls.append(args); self.children.append({"reaped": True, "group_closed": True})
                if args[:2] == ["image", "inspect"]: return probe.canonical([image()])
                if args[0] == "create": return CID.encode()
                if args[0] == "start":
                    if test.start_error: raise probe.Refused("modeled_guest_failure")
                    return probe.canonical(compiler())
                raise AssertionError("unexpected modeled Docker call")
            def inspect(self, cid): return container(self.containers[0])
            def close(self):
                if test.stop_on_close: probe.STOP = 15
                if test.close_ok:
                    for row in self.containers: row["absent"] = True
                if test.unresolved == "cli" and self.children: self.children[0]["group_closed"] = False
                if test.unresolved == "cid" and self.containers: self.containers[0]["absent"] = False
                return test.close_ok
        self.fake = types.SimpleNamespace(Owner=FakeOwner, STOP=None, linux_resources=lambda: dict(RESOURCES),
            document=lambda raw, maximum=1024**2: json.loads(raw), save=lambda path, value: path.write_bytes(probe.canonical(value)))
        self.stdout = io.StringIO()

    def run_main(self, **changes):
        with patch.object(Path, "cwd", return_value=self.root), patch.object(probe, "owner_module", return_value=self.fake), \
             patch.object(probe.time, "monotonic", side_effect=lambda: self.clock), patch.object(probe, "host_tools", return_value={}), \
             patch.object(probe.signal, "signal"), patch.object(probe.signal, "setitimer"), \
             patch.dict(os.environ, {"GITHUB_SHA": "e" * 40, "MOCK_PROVIDER_SECRET": "must-not-appear"}, clear=True), \
             contextlib.redirect_stdout(self.stdout):
            return probe.main(changes.get("args", self.args))

    def receipt(self): return json.loads((self.root / ".toolchain-public/receipt.json").read_bytes())

    def test_context_is_exact_pinned_three_files_and_refuses_extra_or_changed_payload(self):
        self.assertEqual(probe.context_identity(self.root / "toolchain"), probe.CONTEXT_SHA)
        for name in ("state.json", "sdk.zip", ".git"):
            path = self.root / "toolchain" / name; path.write_bytes(b"private modeled bytes")
            with self.subTest(name=name), self.assertRaisesRegex(probe.Refused, "public_context_inventory"):
                probe.context_identity(self.root / "toolchain")
            path.unlink()
        (self.root / "toolchain/Dockerfile").write_bytes(b"FROM unreviewed\n")
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.instances, [])
        self.assertEqual(self.receipt()["code"], "public_context_drift")

    def test_image_requires_actual_id_arm64_linux_and_closed_config_not_labels_alone(self):
        self.assertEqual(probe.image_identity(image()), ID)
        for key, value in (("Id", "mutable:tag"), ("Architecture", "amd64"), ("Os", "windows")):
            changed = image(); changed[key] = value
            with self.subTest(key=key), self.assertRaises(probe.Refused): probe.image_identity(changed)
        for key, value in (("User", "0"), ("Entrypoint", ["provider-agent"]), ("Env", image()["Config"]["Env"] + ["SECRET=private"]),
                           ("Labels", probe.LABELS | {"extra": "value"}), ("Volumes", {"/sdk": {}})):
            changed = image(); changed["Config"][key] = value
            with self.subTest(key=key), self.assertRaises(probe.Refused): probe.image_identity(changed)

    def test_container_has_no_source_mount_and_exact_small_isolation(self):
        row, args = probe.container_arguments(ID, "00000000-0000-0000-0000-000000000000"); row["cid"] = CID
        self.assertNotIn("--mount", args); self.assertEqual(args[args.index("--memory") + 1], "512m")
        self.assertEqual(args[args.index("--memory-swap") + 1], "512m")
        probe.container_identity(container(row), row)
        for key, value in (("Memory", 8 * 1024**3), ("MemorySwap", 1024**3), ("NetworkMode", "bridge"),
                           ("Privileged", True), ("PidMode", "host"), ("PidsLimit", 256),
                           ("Devices", [{"PathOnHost": "/private"}]), ("Tmpfs", {"/sdk": "rw"})):
            changed = container(row); changed["HostConfig"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(probe.Refused, "container_sandbox"):
                probe.container_identity(changed, row)
        changed = container(row); changed["Mounts"] = [{"Type": "bind", "Source": "/private", "Destination": "/sdk", "RW": False}]
        with self.assertRaises(probe.Refused): probe.container_identity(changed, row)

    def test_compiler_receipt_rejects_mixed_target_version_extra_fields_and_unbounded_inventory(self):
        self.assertEqual(probe.compiler_identity(compiler()), compiler())
        for key, value in (("release", "1.99.0"), ("host", "x86_64-unknown-linux-gnu"),
                           ("sysroot_bytes", 3 * 1024**3), ("executable_sha256", "mutable"),
                           ("sysroot_files", {"wasm32-unknown-unknown": True}), ("private_path", "/sdk/private.rs")):
            changed = compiler(); changed[key] = value
            with self.subTest(key=key), self.assertRaises(probe.Refused): probe.compiler_identity(changed)
        for old, new in (("rustc 1.98.1 (000000000 2026-09-28)", "rustc 1.98.1 (111111111 2026-09-28)"),
                         ("commit-date: 2026-09-28", "commit-date: 2026-09-29")):
            changed = compiler(); changed["verbose_version"] = changed["verbose_version"].replace(old, new)
            with self.subTest(new=new), self.assertRaisesRegex(probe.Refused, "probe_verbose_version"):
                probe.compiler_identity(changed)

    def test_modeled_main_requires_closed_owners_and_keeps_original_120_second_clock(self):
        self.assertEqual(self.run_main(), 0)
        owner = self.instances[0]
        self.assertEqual((owner.hard, owner.work), (1120.0, 1090.0))
        result = self.receipt()
        self.assertEqual(result["state"], "passed"); self.assertFalse(result["sdk_qualified"])
        self.assertFalse(result["build_provenance_verified_by_probe"])
        self.assertEqual(result["origin_context_digest"], probe.CONTEXT_SHA)
        self.assertEqual(result["compiler"], compiler())
        self.assertTrue(result["owned_cli_closed"] and result["owned_container_absent"])
        text = json.dumps(result) + self.stdout.getvalue()
        for forbidden in ("must-not-appear", str(self.root), "raw_stderr", "Config", "argv"):
            self.assertNotIn(forbidden, text)

    def test_cleanup_failure_never_emits_passing_receipt(self):
        self.close_ok = False
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.receipt()["state"], "failed")
        self.assertEqual(self.receipt()["code"], "cleanup_unknown")
        self.assertNotIn('"state":"passed"', self.stdout.getvalue())

    def test_guest_failure_stays_primary_when_cleanup_is_also_unknown(self):
        self.start_error = True; self.close_ok = False
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.receipt()["code"], "modeled_guest_failure")

    def test_reported_close_true_cannot_hide_unresolved_cli_or_container(self):
        for unresolved in ("cli", "cid"):
            with self.subTest(unresolved=unresolved):
                self.unresolved = unresolved
                self.assertEqual(self.run_main(), 1)
                self.assertEqual(self.receipt()["state"], "failed")
                self.assertEqual(self.receipt()["code"], "owned_closure")
                shutil.rmtree(self.root / ".toolchain-public")

    def test_signal_during_cleanup_cannot_become_success(self):
        self.stop_on_close = True
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.receipt()["code"], "interrupted")

    def test_late_receipt_write_cannot_turn_expired_budget_into_pass(self):
        def late_save(path, value):
            path.write_bytes(probe.canonical(value)); self.clock = 1121.0
        self.fake.save = late_save
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.receipt()["state"], "failed")

    def test_existing_public_receipt_is_preserved_and_attempt_refused(self):
        public = self.root / ".toolchain-public"; public.mkdir()
        original = b'{"historical":"immutable"}\n'; (public / "receipt.json").write_bytes(original)
        self.assertEqual(self.run_main(), 1)
        self.assertEqual((public / "receipt.json").read_bytes(), original)

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "waitid"), "Linux nonreaping owner boundary")
    def test_real_finite_owner_child_closes_without_docker_sdk_or_provider(self):
        owner_module = probe.owner_module()
        evidence = self.root / "finite-owner"; evidence.mkdir(mode=0o700)
        hard = owner_module.time.monotonic() + 120
        owner = owner_module.Owner(evidence, started=hard - 3900)
        with patch.object(owner_module, "linux_resources", return_value=RESOURCES):
            try:
                self.assertEqual(owner.command([sys.executable, "-c", "print('public-toy')"], 5), b"public-toy\n")
            finally: self.assertTrue(owner.close())
        self.assertAlmostEqual(owner.hard, hard, places=9)
        self.assertTrue(owner.children)
        self.assertTrue(all(r["reaped"] and r["group_closed"] and r["returncode"] == 0 for r in owner.children))
        self.assertEqual(owner.containers, [])


if __name__ == "__main__": unittest.main()
