"""Finite modeled publication controls; no Docker, registry, or credential calls.

Root may run this private source packet. These fixtures prove local refusals and
handoff joins only; they do not prove real publication or anonymous registry read.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]


def loaded(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publication = loaded("modeled_publication", HERE / "tools/publish_toolchain.py")
probe = loaded("modeled_publication_probe", HERE / "tools/probe_toolchain.py")
CONFIG = "sha256:" + "a" * 64
MANIFEST = "sha256:" + "b" * 64


def image():
    return {"Id": CONFIG, "Architecture": "arm64", "Os": "linux", "Config": {
        "User": "65532:65532", "Entrypoint": ["/usr/bin/env"], "Cmd": ["cargo", "+1.98.1", "--version"],
        "WorkingDir": "/tmp", "Labels": dict(probe.LABELS), "Env": [k + "=" + v for k, v in probe.ENV.items()],
        "Volumes": None, "ExposedPorts": None, "OnBuild": None, "Healthcheck": None},
        "RepoDigests": [publication.REGISTRY + "@" + MANIFEST]}


class PublicationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        shutil.copytree(HERE / "toolchain", self.root / "toolchain")
        public = self.root / ".toolchain-public"
        public.mkdir(mode=0o700)
        self.prior = {"schema_version": 1, "state": "passed", "scope": "public_toolchain_identity_and_cleanup_only",
            "source_revision": "c" * 40, "origin_context_digest": probe.CONTEXT_SHA, "context_files": probe.CONTEXT,
            "owned_cli_closed": True, "owned_container_absent": True, "sdk_qualified": False, "abi_qualified": False,
            "build_provenance_verified_by_probe": False, "budget_seconds": 120, "image_id": CONFIG,
            "compiler": {"release": "modeled-public-data-only"}, "host_tools": {}, "host_resources_before": {},
            "host_resources_after": {}}
        self.before = publication.canonical(self.prior)
        (public / "receipt.json").write_bytes(self.before)
        self.clock = 1000.0
        self.close_ok = True
        self.wrong_pull = False
        self.wrong_anonymous = False
        self.wrong_local = False
        self.late_save = False
        self.instances = []
        self.calls = []
        self.stdout = io.StringIO()
        outer = self
        class FakeOwner:
            def __init__(self, evidence, started=None):
                self.evidence = evidence; self.started = started
                self.hard = started + 3900; self.work = self.hard - 30
                self.docker_config = evidence / "docker-config"
                self.docker_config.mkdir(mode=0o700)
                (self.docker_config / "config.json").write_bytes(b"{}\n")
                self.children = []; self.containers = []; outer.instances.append(self)
            def remaining(self, maximum):
                return min(maximum, self.work - outer.clock)
            def docker(self, args, maximum=10, **kwargs):
                outer.calls.append(args)
                self.children.append({"reaped": True, "group_closed": True})
                if args[:2] == ["image", "inspect"]:
                    value = image()
                    if outer.wrong_local and args[2] == publication.IMAGE: value["Id"] = "sha256:" + "d" * 64
                    if outer.wrong_pull and "@" in args[2]: value["RepoDigests"] = []
                    return publication.canonical([value])
                if args[0] == "login":
                    assert kwargs["data"] == b"MODELED_GITHUB_TOKEN_NOT_A_CREDENTIAL\n"
                    (self.evidence / "stdin-modeled").write_bytes(kwargs["data"])
                    (self.docker_config / "config.json").write_bytes(b'{"auths":{"ghcr.io":{"auth":"MODELED"}}}\n')
                    return b"modeled login"
                if args[0] == "push": return b"fixed-tag: digest: " + MANIFEST.encode() + b" size: 424\n"
                if args[0] in ("tag", "logout", "pull"): return b""
                raise AssertionError("unexpected modeled Docker argument")
            def command(self, args, maximum, **kwargs):
                outer.calls.append(["modeled-anonymous-child"])
                assert json.loads((self.docker_config / "config.json").read_bytes()) == {}
                assert not list(self.evidence.glob("stdin-*"))
                assert "GHCR_PUBLISH_TOKEN" not in os.environ
                self.children.append({"reaped": True, "group_closed": True})
                value = image()
                return publication.canonical({"manifest_digest": MANIFEST, "image_id":
                    "sha256:" + "e" * 64 if outer.wrong_anonymous else CONFIG,
                    "manifest_media_type": "application/vnd.oci.image.manifest.v1+json",
                    **{key: value[key] for key in ("Architecture", "Os", "Config")}})
            def close(self): return outer.close_ok
        def save(path, value):
            path.write_bytes(publication.canonical(value))
            if outer.late_save: outer.clock = 1271.0
        self.verify = types.SimpleNamespace(Owner=FakeOwner, STOP=None, document=lambda raw, maximum=2 * 1024**2: publication.document(raw), save=save)
        self.fake_probe = types.SimpleNamespace(OWNER_SHA=publication.OWNER_SHA, CONTEXT_SHA=probe.CONTEXT_SHA,
            CONTEXT=probe.CONTEXT, owner_module=lambda: self.verify, context_identity=probe.context_identity,
            image_identity=probe.image_identity, compiler_identity=lambda value: value)
        self.environment = {"GITHUB_REPOSITORY": publication.REPOSITORY, "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "c" * 40, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
            "GHCR_PUBLISH_TOKEN": "MODELED_GITHUB_TOKEN_NOT_A_CREDENTIAL", "GHCR_PUBLISH_ACTOR": "fvlvte"}

    def invoke(self):
        with patch.object(Path, "cwd", return_value=self.root), patch.object(publication, "probe_module", return_value=self.fake_probe), \
             patch.object(publication.time, "monotonic", side_effect=lambda: self.clock), \
             patch.object(publication.signal, "signal"), patch.object(publication.signal, "setitimer"), \
             patch.dict(os.environ, self.environment, clear=True), contextlib.redirect_stdout(self.stdout):
            return publication.main([])

    def test_modeled_positive_keeps_manifest_and_config_separate_and_scrubs_credentials(self):
        self.assertEqual(self.invoke(), 0)
        value = json.loads((self.root / ".toolchain-public/registry.json").read_bytes())
        self.assertEqual(value["manifest_digest"], MANIFEST)
        self.assertEqual(value["image_id"], CONFIG)
        self.assertNotEqual(value["image_id"], value["manifest_digest"])
        self.assertFalse(value["sdk_qualified"]); self.assertFalse(value["abi_qualified"])
        self.assertEqual(value["build_daemon_scope"], "github_managed_not_independently_closed")
        self.assertEqual((self.instances[0].hard, self.instances[0].work), (1300.0, 1270.0))
        self.assertEqual(json.loads((self.instances[0].docker_config / "config.json").read_bytes()), {})
        self.assertEqual(list(self.instances[0].evidence.glob("stdin-*")), [])
        text = json.dumps(value) + self.stdout.getvalue()
        self.assertNotIn("MODELED_GITHUB_TOKEN_NOT_A_CREDENTIAL", text)
        self.assertNotIn(str(self.root), text)
        self.assertEqual((self.root / ".toolchain-public/receipt.json").read_bytes(), self.before)

    def test_failed_probe_refuses_before_any_login(self):
        self.prior["state"] = "failed"
        (self.root / ".toolchain-public/receipt.json").write_bytes(publication.canonical(self.prior))
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.instances, [])
        self.assertEqual(self.calls, [])

    def test_wrong_local_image_refuses_before_login_or_tag(self):
        self.wrong_local = True
        self.assertEqual(self.invoke(), 1)
        self.assertFalse(any(args[0] in ("login", "tag", "push") for args in self.calls))

    def test_anonymous_config_mismatch_refuses_receipt_after_credential_cleanup(self):
        self.wrong_anonymous = True
        self.assertEqual(self.invoke(), 1)
        self.assertFalse((self.root / ".toolchain-public/registry.json").exists())
        self.assertEqual(json.loads((self.instances[0].docker_config / "config.json").read_bytes()), {})

    def test_missing_immutable_pull_digest_refuses_publication(self):
        self.wrong_pull = True
        self.assertEqual(self.invoke(), 1)
        self.assertFalse((self.root / ".toolchain-public/registry.json").exists())

    def test_failed_cli_closure_never_passes(self):
        self.close_ok = False
        self.assertEqual(self.invoke(), 1)
        self.assertFalse((self.root / ".toolchain-public/registry.json").exists())

    def test_late_public_receipt_save_cannot_return_zero(self):
        self.late_save = True
        self.assertEqual(self.invoke(), 1)
        # A readable receipt is not acceptance when actual process exit is nonzero.
        self.assertTrue((self.root / ".toolchain-public/registry.json").exists())
        self.assertNotIn('"state":"PUBLIC_TOOLCHAIN_PUBLISHED_NOT_SDK_QUALIFIED"', self.stdout.getvalue())

    def test_strict_json_refuses_duplicate_keys_and_nonfinite_constants(self):
        for raw in (b'{"schema_version":1,"schema_version":1}', b'{"number":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): publication.document(raw)


if __name__ == "__main__":
    unittest.main()
