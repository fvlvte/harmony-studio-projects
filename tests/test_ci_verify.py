"""Public synthetic boundaries. Docker/SDK/provider/runner qualification is NOT run.

Subprocess/container observations below are modeled explicitly. Root separately
owns finite-child and actual runner/image/SDK/browser acceptance.
"""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import signal
import struct
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import uuid
import zipfile
import zlib

SPEC = importlib.util.spec_from_file_location("public_ci_verify", Path(__file__).resolve().parents[1] / "tools/ci_verify.py")
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


def catalogs():
    assets = {name: {"name": name + ".zip", "sha256": "a" * 64, "bytes": 100}
              for name in ("archive", "policy", "provenance", "manifest")}
    sdk = {"repository": "owner/public-repo", "release_tag": "sdk-v1", "assets": assets,
           "profile": copy.deepcopy(ci.PROFILE), "compiler_image": "sha256:" + "c" * 64,
           "browser_image": "sha256:" + "d" * 64, "compiler_contract": "opaque-compile/v1",
           "compiler_ref": "ghcr.io/owner/public-repo/compiler@sha256:" + "c"*64,
           "browser_ref": "ghcr.io/owner/public-repo/browser@sha256:" + "d"*64,
           "source_policy_sha256": "e" * 64, "compiler_entrypoint": ["opaque-compile"],
           "browser_entrypoint": ["public-browser"], "compiler_environment": [], "browser_environment": []}
    project = {"repository": "owner/public-repo", "release_tag": "project-v1", "assets": copy.deepcopy(assets),
               "sdk_catalog": "sdk-fixture", "authorization_id": str(uuid.uuid4()), "source_revision": "f" * 64}
    project["assets"]["archive"]["sha256"] = "b" * 64
    env = {"GITHUB_REPOSITORY": "owner/public-repo", "VERIFY_SDK": "sdk-fixture", "VERIFY_SDK_SHA256": "a" * 64,
           "VERIFY_PROJECT": "project-fixture", "VERIFY_PROJECT_SHA256": "b" * 64, "VERIFY_RUN_ID": str(uuid.uuid4())}
    return sdk, project, env


def smoke():
    return {"frames": 10, "canvas": True, "colours_at_least": 16, "runtime_errors": 0, "scope": "boot_only"}


def web_files(raw=b"<title>public fixture</title>"):
    return [{"path": "index.html", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}]


class AdmissionTest(unittest.TestCase):
    def test_empty_catalog_refuses_before_network_docker_or_host_probe(self):
        _, _, env = catalogs()
        with tempfile.TemporaryDirectory() as directory, patch.object(Path, "cwd", return_value=Path(directory)), \
                patch.dict(ci.APPROVED_SDKS, {}, clear=True), patch.dict(ci.APPROVED_PROJECTS, {}, clear=True), \
                patch.object(ci, "download", side_effect=AssertionError("network reached")), \
                patch.object(ci.Owner, "docker", side_effect=AssertionError("Docker reached")), \
                patch.object(ci, "linux_resources", side_effect=AssertionError("host probe reached")), \
                patch.object(ci, "STOP", None), contextlib.redirect_stdout(io.StringIO()) as output:
            env["MOCK_PROVIDER_THOUGHTS"] = "private-secret-thought"
            self.assertEqual(ci.main(env), 78)
            receipt = json.loads(output.getvalue())
            self.assertEqual(receipt, {"schema_version": 1, "run_id": env["VERIFY_RUN_ID"], "state": "blocked", "code": "catalog_unapproved"})
            self.assertNotIn("private-secret-thought", output.getvalue())
            self.assertFalse((Path(directory) / ".verify-runs").exists())

    def test_exact_catalog_tuple_profile_and_image_are_required(self):
        sdk, project, env = catalogs()
        with patch.dict(ci.APPROVED_SDKS, {"sdk-fixture": sdk}, clear=True), patch.dict(ci.APPROVED_PROJECTS, {"project-fixture": project}, clear=True):
            self.assertEqual(ci.approval(env)[3], env["VERIFY_RUN_ID"])
            for changes, code in (({"VERIFY_SDK_SHA256": "0"*64}, "catalog_tuple"),
                                  ({"GITHUB_REPOSITORY": "another/repo"}, "catalog_repository")):
                with self.subTest(changes=changes), self.assertRaisesRegex(ci.Refused, code):
                    ci.approval({**env, **changes})
            for field, value, code in (("profile", {**ci.PROFILE, "lto": "thin"}, "sdk_profile"),
                                       ("compiler_image", "image:latest", "image_pin"),
                                       ("compiler_ref", "ghcr.io/another/repo/compiler:latest", "image_registry_pin"),
                                       ("compiler_contract", "private-source-compile/v0", "compiler_contract")):
                changed = copy.deepcopy(sdk); changed[field] = value
                with self.subTest(field=field), patch.dict(ci.APPROVED_SDKS, {"sdk-fixture": changed}, clear=True), self.assertRaisesRegex(ci.Refused, code):
                    ci.approval(env)

    def test_release_url_is_same_repository_and_rejects_path_or_scheme_inputs(self):
        self.assertEqual(ci.asset_url("owner/repo", "sdk-v1", "sdk.zip"), "https://github.com/owner/repo/releases/download/sdk-v1/sdk.zip")
        for repo, tag, asset in (("https://evil.test", "v1", "sdk.zip"), ("owner/repo", "../v1", "sdk.zip"),
                                  ("owner/repo", "v1", "../../.env"), ("owner/repo", "v1", "x\n--flag")):
            with self.subTest(asset=asset), self.assertRaisesRegex(ci.Refused, "release_asset_identity"):
                ci.asset_url(repo, tag, asset)

    def test_public_receipt_has_no_raw_log_provider_or_nested_extra_fields(self):
        facts = {"sdk_sha256": "a"*64, "project_sha256": "b"*64, "files": web_files(), "browser": smoke()}
        self.assertEqual(ci.public_receipt(str(uuid.uuid4()), "passed", **facts)["state"], "passed")
        for changes in ({"raw_stderr": "Bearer secret"}, {"provider_thoughts": "secret"},
                        {"browser": {**smoke(), "raw_stderr": "secret"}}, {"files": [{**web_files()[0], "body": "secret"}]}):
            with self.subTest(changes=changes), self.assertRaises(ci.Refused):
                ci.public_receipt(str(uuid.uuid4()), "passed", **{**facts, **changes})
        for state in ("built", "unknown", "COMPLETED"):
            with self.assertRaises(ci.Refused): ci.public_receipt("", state)

    def test_image_label_alone_is_insufficient(self):
        sdk, _, _ = catalogs()
        value = {"Id": sdk["compiler_image"], "Architecture": "arm64", "Os": "linux",
                 "RepoDigests": [sdk["compiler_ref"]],
                 "Config": {"User": "65532:65532", "Labels": {"online.harmony.role": "compiler", "online.harmony.source-policy": "e"*64},
                            "Entrypoint": sdk["compiler_entrypoint"], "Env": []}}
        ci.image_identity(value, sdk["compiler_image"], "compiler", sdk)
        for change in ({"Id": "sha256:"+"0"*64}, {"Architecture": "amd64"},
                       {"RepoDigests": ["ghcr.io/another/repo/compiler@sha256:"+"c"*64]},
                       {"Config": {**value["Config"], "Env": ["SECRET=value"]}}):
            with self.subTest(change=change), self.assertRaises(ci.Refused):
                ci.image_identity({**value, **change}, sdk["compiler_image"], "compiler", sdk)


class FilesystemTest(unittest.TestCase):
    def test_guarded_archive_copies_only_exact_inventory_and_hashes(self):
        raw = b"<title>fixture</title>"; rows = web_files(raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); archive = root / "project.zip"
            with zipfile.ZipFile(archive, "w") as stream: stream.writestr("index.html", raw)
            ci.extract_guarded(archive, root / "extracted", rows)
            self.assertEqual((root / "extracted/index.html").read_bytes(), raw)
            changed = [{**rows[0], "sha256": "0"*64}]
            with self.assertRaisesRegex(ci.Refused, "extract_hash"):
                ci.extract_guarded(archive, root / "refused", changed)

    def test_fd_export_copy_refuses_link_and_source_hash_drift(self):
        raw = b"<title>fixture</title>"; rows = web_files(raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "source"; source.mkdir()
            (source / "index.html").write_bytes(raw)
            ci.copy_admitted(source, root / "copied", rows)
            self.assertEqual((root / "copied/index.html").read_bytes(), raw)
            (source / "index.html").unlink(); (source / "index.html").symlink_to(root / "copied/index.html")
            with self.assertRaises(OSError): ci.copy_admitted(source, root / "link-refused", rows)

    def test_png_requires_visible_variation_not_just_png_signature(self):
        def png(varied):
            def chunk(kind, raw): return struct.pack(">I", len(raw))+kind+raw+struct.pack(">I", zlib.crc32(kind+raw)&0xffffffff)
            rows = b"".join(b"\0"+bytes(value for x in range(32) for value in ((x*7 if varied else 0), y*7 if varied else 0, 40)) for y in range(32))
            return b"\x89PNG\r\n\x1a\n"+chunk(b"IHDR",struct.pack(">IIBBBBB",32,32,8,2,0,0,0))+chunk(b"IDAT",zlib.compress(rows))+chunk(b"IEND",b"")
        self.assertEqual(ci.png_colours(png(True)), 16)
        self.assertEqual(ci.png_colours(png(False)), 1)

    def test_exclusive_destination_failure_closes_retained_input_fd(self):
        raw=b"<title>public fixture</title>"; captured=[]; real_open=os.open
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/"source";source.mkdir();(source/"index.html").write_bytes(raw)
            target=root/"target"
            def opened(path, flags, *args, **kwargs):
                if Path(path)==target/"index.html": raise OSError("modeled destination IO fault")
                fd=real_open(path, flags, *args, **kwargs)
                if path=="index.html": captured.append(fd)
                return fd
            with patch.object(ci.os,"open",side_effect=opened),self.assertRaises(OSError):
                ci.copy_admitted(source,target,web_files(raw))
            self.assertEqual(len(captured),1)
            with self.assertRaises(OSError):os.fstat(captured[0])


class ModeledLifecycleTest(unittest.TestCase):
    def test_public_persistence_fault_leaves_no_uploaded_pass_or_raw_error(self):
        sdk,project,env=catalogs();real_save=ci.save
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);web=root/"web";web.mkdir();(web/"index.html").write_bytes(b"<title>public fixture</title>")
            fake=types.SimpleNamespace(children=[],containers=[],journal_failed=False,close=Mock(return_value=True))
            def owner(evidence, started=None):fake.evidence=evidence;return fake
            def saved(path,value):
                if path.name=="receipt.json":raise OSError("mock raw stderr Bearer private-secret")
                return real_save(path,value)
            with patch.object(Path,"cwd",return_value=root),patch.object(ci,"approval",return_value=("owner/public-repo",sdk,project,env["VERIFY_RUN_ID"])), \
                 patch.object(ci,"linux_resources",return_value={}),patch.object(ci,"Owner",side_effect=owner), \
                 patch.object(ci,"verify",return_value=(web,web_files(),smoke())),patch.object(ci,"save",side_effect=saved), \
                 patch.object(ci,"STOP",None),contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(ci.main(env),1)
            self.assertEqual(json.loads(output.getvalue())["code"],"public_handoff_unknown")
            self.assertNotIn("private-secret",output.getvalue())
            self.assertFalse((root/".verify-public").exists())

    def test_cleanup_false_or_unknown_cannot_produce_pass_or_public_web(self):
        sdk, project, env = catalogs()
        for broken in (False, OSError("mock private stderr secret")):
            with self.subTest(broken=type(broken).__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); web = root / "web"; web.mkdir(); (web / "index.html").write_bytes(b"<title>public fixture</title>")
                fake = types.SimpleNamespace(children=[], containers=[], journal_failed=False, close=Mock(side_effect=broken) if isinstance(broken, Exception) else Mock(return_value=broken))
                def owner(evidence, started=None): fake.evidence=evidence; return fake
                with patch.object(Path, "cwd", return_value=root), patch.object(ci, "approval", return_value=("owner/public-repo",sdk,project,env["VERIFY_RUN_ID"])), \
                        patch.object(ci, "linux_resources", return_value={}), patch.object(ci, "Owner", side_effect=owner), \
                        patch.object(ci, "verify", return_value=(web,web_files(),smoke())), patch.object(ci,"STOP",None), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(ci.main(env), 1)
                self.assertEqual(json.loads(output.getvalue())["state"], "failed")
                self.assertNotIn("private stderr", output.getvalue())
                self.assertFalse((root / ".verify-public/web").exists())

    def test_compiler_removed_before_source_free_browser_mount(self):
        sdk, project, env = catalogs(); events=[]; mounts=[]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); web=root/"produced-web";web.mkdir();(web/"index.html").write_bytes(b"<title>public fixture</title>")
            def docker(args, **kwargs):
                if args[:2]==["image","inspect"]:
                    role="compiler" if args[2]==sdk["compiler_ref"] else "browser"
                    return ci.canonical([{"Id":sdk[role+"_image"],"RepoDigests":[sdk[role+"_ref"]],"Architecture":"arm64","Os":"linux","Config":{"User":"65532:65532","Env":[],"Entrypoint":sdk[role+"_entrypoint"],"Labels":{"online.harmony.role":role,"online.harmony.source-policy":"e"*64}}}])
                if args[0]=="start": return ci.canonical({"schema_version":1,"run_id":env["VERIFY_RUN_ID"],"state":"built"})
                return b""
            owner=types.SimpleNamespace(evidence=root,docker=docker,remaining=lambda maximum:maximum)
            def create(owner,image,phase,run,bound):
                events.append("create-"+phase);mounts.append((phase,bound));return {"phase":phase,"cid":phase,"absent":False}
            def remove(row):events.append("remove-"+row["phase"]);row["absent"]=True
            owner.remove=remove
            with patch.object(ci,"download"),patch.object(ci,"guarded",return_value=web_files()), \
                 patch.object(ci,"extract_guarded",side_effect=lambda archive,path,files:path.mkdir()), \
                 patch.object(ci,"create",side_effect=create),patch.object(ci,"export_web",return_value=(web,web_files())), \
                 patch.object(ci,"web_guard",return_value=web_files()),patch.object(ci,"browser",return_value=smoke()):
                ci.verify(owner,"owner/public-repo",sdk,project,env["VERIFY_RUN_ID"])
            self.assertLess(events.index("remove-compiler"),events.index("create-browser"))
            self.assertEqual({target for _,target,_ in mounts[0][1]},{"/input/sdk","/input/project","/handoff"})
            self.assertEqual(len(mounts[1][1]),1)
            self.assertEqual(mounts[1][1][0][1:],("/web",True))
            self.assertNotIn(mounts[1][1][0][0], [row[0] for row in mounts[0][1]])

    def test_owned_failure_signals_group_before_reaping_and_preserves_stop(self):
        events=[]
        with tempfile.TemporaryDirectory() as directory:
            owner=ci.Owner(Path(directory),started=0);owner.hard=100;owner.work=70
            process=types.SimpleNamespace(returncode=None,stdin=None,stdout=io.BytesIO(),stderr=io.BytesIO())
            def wait(timeout):events.append("wait");process.returncode=-9;return -9
            process.wait=wait
            row={"pid":123456,"pgid":123456,"argv":["modeled"],"process":process,"reaped":False,"group_closed":False}
            owner.children.append(row)
            with patch.object(ci.time,"monotonic",return_value=90),patch.object(ci,"STOP",signal.SIGTERM), \
                    patch.object(ci.os,"killpg",side_effect=lambda pid,sig:events.append("signal")),patch.object(ci,"group_members",return_value=[]):
                self.assertTrue(owner.finish(row))
                self.assertEqual(ci.STOP,signal.SIGTERM)
                self.assertEqual(events,["signal","wait"])
                self.assertEqual(owner.remaining(5,cleanup=True),5)
                with self.assertRaises(ci.Refused):owner.remaining(5)


class ModeledPublicationDeadlineTest(unittest.TestCase):
    """Finite modeled IO and clock changes; no real blocking filesystem trial."""
    def case(self, phase, initial_failure=False):
        sdk, project, env = catalogs(); now = [100.0]; real_save = ci.save; real_copy = ci.copy_admitted
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); web = root / "web"; web.mkdir(); (web / "index.html").write_bytes(b"<title>public fixture</title>")
            fake = types.SimpleNamespace(children=[], containers=[], journal_failed=False, close=Mock(return_value=True))
            def owner(evidence, started=None): fake.evidence = evidence; return fake
            def copied(source, target, files):
                real_copy(source, target, files)
                if phase == "copy": now[0] = 5000.0
            def saved(path, value):
                real_save(path, value)
                if path.name == "receipt.json" and value["state"] == "passed":
                    if phase == "save": now[0] = 5000.0
                    if phase == "signal": ci.STOP = signal.SIGTERM
                if path.name == "receipt.json" and phase == "failed_signal": ci.STOP = signal.SIGTERM
            class Output(io.StringIO):
                def write(self, value):
                    count = super().write(value)
                    if phase == "output" and value.startswith("{") and json.loads(value)["state"] == "passed":
                        now[0] = 5000.0
                    return count
            output = Output()
            with patch.object(Path, "cwd", return_value=root), patch.object(ci, "approval", return_value=("owner/public-repo", sdk, project, env["VERIFY_RUN_ID"])), \
                 patch.object(ci, "linux_resources", return_value={}), patch.object(ci, "Owner", side_effect=owner), \
                 patch.object(ci, "verify", side_effect=ci.Refused("modeled_original_failure") if initial_failure else None, return_value=(web, web_files(), smoke())), \
                 patch.object(ci, "copy_admitted", side_effect=copied), patch.object(ci, "save", side_effect=saved), \
                 patch.object(ci.time, "monotonic", side_effect=lambda: now[0]), patch.object(ci, "STOP", None), \
                 patch.object(ci.signal, "signal"), patch.object(ci.signal, "setitimer") as timer, \
                 contextlib.redirect_stdout(output) as captured:
                code = ci.main(env)
                stopped = ci.STOP
            self.assertEqual(code, 1)
            receipt = json.loads(output.getvalue())
            # A completed stdout write may contain a now-stale passed shape;
            # nonzero exit plus failed durable receipts prevents acceptance.
            self.assertEqual(receipt["state"], "passed" if phase == "output" else "failed")
            if initial_failure: self.assertEqual(receipt["code"], "verification_failed")
            if phase in ("signal", "failed_signal"): self.assertEqual(stopped, signal.SIGTERM)
            self.assertEqual(timer.call_args_list[-1].args, (signal.ITIMER_REAL, 0))
            terminals = json.loads((fake.evidence / "terminal.json").read_bytes())
            self.assertEqual(terminals["state"], "failed")
            for public in [root / ".verify-public", *root.glob(".verify-public-stage-*")]:
                if (public / "receipt.json").exists():
                    self.assertEqual(json.loads((public / "receipt.json").read_bytes())["state"], "failed")
    def test_copy_finishing_after_original_hard_deadline_cannot_pass(self):
        self.case("copy")
    def test_success_receipt_persisted_after_original_hard_deadline_is_rewritten_failed(self):
        self.case("save")
    def test_signal_during_success_receipt_save_cannot_pass(self):
        self.case("signal")
    def test_late_signal_preserves_original_verification_failure(self):
        self.case("failed_signal", initial_failure=True)
    def test_stdout_finishing_after_original_hard_deadline_returns_nonzero(self):
        self.case("output")


@unittest.skipUnless(platform.system()=="Linux" and hasattr(os,"waitid") and hasattr(os,"WNOWAIT"),
                     "requires the actual Linux nonreaping/process-group ABI; no Darwin simulation")
class LinuxFiniteChildTest(unittest.TestCase):
    def test_actual_finite_child_is_reaped_with_group_absent(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(ci,"linux_resources",return_value={}),patch.object(ci,"STOP",None):
            owner=ci.Owner(Path(directory))
            self.assertEqual(owner.command([os.sys.executable,"-I","-B","-c","print('finite-child')"],5),b"finite-child\n")
            self.assertEqual(len(owner.children),1)
            row=owner.children[0]
            self.assertTrue(row["reaped"] and row["group_closed"])
            self.assertEqual(ci.group_members(row["pgid"]),[])
            self.assertTrue(owner.close())


if __name__ == "__main__": unittest.main()
