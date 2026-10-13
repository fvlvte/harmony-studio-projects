#!/usr/bin/env python3
"""Manual public verification. No approved catalogs exist initially.

Catalog admission is protected source, never dispatch data. The separate trusted
SDK producer may decrypt engine inputs; this consumer has no key/decrypt path.
Opaque artifacts do not claim decompiler or metadata confidentiality. Browser
boot evidence does not establish every gameplay interaction.
"""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
import zlib

# A reviewed producer must populate both catalogs in protected source. Never
# upload the old source-containing SDK as an approved opaque artifact.
APPROVED_SDKS = {}
APPROVED_PROJECTS = {}
PROFILE = {"rust": "1.98.1", "target": "wasm32-unknown-unknown", "profile": "web-release",
           "features": ["web-webgl2"], "lto": "fat", "jobs": 1}
SHA = re.compile(r"[0-9a-f]{64}\Z")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
WEB = {".html", ".css", ".js", ".mjs", ".wasm", ".png", ".jpg", ".jpeg", ".webp", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".json"}
MAX_FILE = 64 * 1024**2
MAX_TREE = 512 * 1024**2
STOP = None


class Refused(ValueError):
    pass


class ResourceRefused(Refused):
    """Fixed refusal code plus numeric runner-host observations, never paths."""
    def __init__(self, code, sample):
        super().__init__(code)
        self.resource_sample = sample


def require(value, code):
    if not value:
        raise Refused(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def document(raw, maximum=1024**2):
    require(len(raw) <= maximum, "json_bound")
    return json.loads(raw, object_pairs_hook=unique)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def run_identity(value):
    try: return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError): return False


def save(path, value):
    raw = canonical(value)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def approval(env):
    repo = env.get("GITHUB_REPOSITORY", "")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo), "repository_identity")
    sdk = APPROVED_SDKS.get(env.get("VERIFY_SDK"))
    project = APPROVED_PROJECTS.get(env.get("VERIFY_PROJECT"))
    require(sdk is not None and project is not None, "catalog_unapproved")
    require(sdk["repository"] == repo == project["repository"], "catalog_repository")
    require(env.get("VERIFY_SDK_SHA256") == sdk["assets"]["archive"]["sha256"]
            and env.get("VERIFY_PROJECT_SHA256") == project["assets"]["archive"]["sha256"], "catalog_tuple")
    require(sdk["profile"] == PROFILE and project["sdk_catalog"] == env["VERIFY_SDK"], "sdk_profile")
    require(IMAGE.fullmatch(sdk["compiler_image"]) and IMAGE.fullmatch(sdk["browser_image"])
            and sdk["compiler_image"] != sdk["browser_image"], "image_pin")
    for role in ("compiler", "browser"):
        require(re.fullmatch(re.escape("ghcr.io/" + repo.lower() + "/" + role + "@sha256:") + r"[0-9a-f]{64}",
                            sdk[role + "_ref"]), "image_registry_pin")
    require(sdk["compiler_contract"] == "opaque-compile/v1" and sdk["source_policy_sha256"]
            and SHA.fullmatch(sdk["source_policy_sha256"]), "compiler_contract")
    run = env.get("VERIFY_RUN_ID", "")
    require(run_identity(run), "run_identity")
    require(str(uuid.UUID(project["authorization_id"])) == project["authorization_id"]
            and SHA.fullmatch(project["source_revision"]), "project_authority")
    return repo, sdk, project, run


def asset_url(repository, tag, asset):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            and NAME.fullmatch(tag) and NAME.fullmatch(asset), "release_asset_identity")
    return "https://github.com/" + repository + "/releases/download/" + urllib.parse.quote(tag, safe="") + "/" + urllib.parse.quote(asset, safe="")


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == "https" and parsed.hostname in
                {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
                and parsed.port in (None, 443) and parsed.username is None and parsed.password is None,
                "asset_redirect")
        return super().redirect_request(request, fp, code, message, headers, url)


def download(repository, tag, entry, output, deadline):
    require(set(entry) == {"name", "sha256", "bytes"} and SHA.fullmatch(entry["sha256"])
            and type(entry["bytes"]) is int and 0 < entry["bytes"] <= MAX_TREE, "asset_pin")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirects())
    digest = hashlib.sha256(); count = 0
    request = urllib.request.Request(asset_url(repository, tag, entry["name"]), headers={"User-Agent": "harmony-public-verifier/1", "Accept-Encoding": "identity"})
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as writer, opener.open(request, timeout=min(30, max(0.1, deadline - time.monotonic()))) as reader:
        require(reader.status == 200 and reader.headers.get("Content-Encoding", "identity") == "identity", "asset_transport")
        while True:
            require(STOP is None and time.monotonic() < deadline, "asset_deadline")
            block = reader.read(65536)
            if not block: break
            count += len(block); require(count <= entry["bytes"], "asset_size")
            digest.update(block); writer.write(block)
        writer.flush(); os.fsync(writer.fileno())
    require(count == entry["bytes"] and digest.hexdigest() == entry["sha256"], "asset_hash")


def linux_resources():
    require(platform.system() == "Linux" and platform.machine() in {"aarch64", "arm64"}, "native_linux_arm_required")
    fields = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        fields[key] = int(value.split()[0]) * 1024
    sample = {"mem_total": fields["MemTotal"], "mem_available": fields["MemAvailable"],
              "memory_psi_avg10": None}
    if not (fields["MemTotal"] >= 16_000_000_000 and fields["MemAvailable"] * 100 >= fields["MemTotal"] * 40):
        raise ResourceRefused("resource_floor", sample)
    psi = Path("/proc/pressure/memory").read_text()
    samples = re.findall(r"^(?:some|full) avg10=([0-9.]+)", psi, re.MULTILINE)
    if not (len(samples) == 2 and all(float(value) == 0 for value in samples)):
        sample["memory_psi_avg10"] = [float(value) for value in samples] if len(samples) == 2 else None
        raise ResourceRefused("memory_pressure", sample)
    require({0, 1} <= os.sched_getaffinity(0), "cpu_affinity")
    return {"mem_total": fields["MemTotal"], "mem_available": fields["MemAvailable"], "memory_psi_avg10": samples}


def group_members(pgid):
    result = []
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            raw = path.read_text(); fields = raw[raw.rfind(")") + 2:].split()
            if int(fields[2]) == pgid and fields[0] != "Z": result.append(int(path.parent.name))
        except (FileNotFoundError, ProcessLookupError): pass
    return result


class Owner:
    """Retain every Popen until nonreaping observation and exact group cleanup."""
    def __init__(self, evidence, started=None):
        self.evidence = evidence; self.started = time.monotonic() if started is None else started
        self.hard = self.started + 3900; self.work = self.hard - 30
        self.children = []; self.containers = []; self.journal_failed = False
        self.docker_config = evidence / "docker-config"; self.docker_config.mkdir(mode=0o700)
        save(self.docker_config / "config.json", {})

    def remaining(self, maximum, cleanup=False):
        left = (self.hard if cleanup else self.work) - time.monotonic()
        require(left > 0 and (cleanup or STOP is None), "deadline_or_signal")
        return min(maximum, left)

    def journal(self):
        try:
            save(self.evidence / "owners.json", {"schema_version": 1, "owner_pid": os.getpid(),
                 "cli": [{k: v for k, v in row.items() if k != "process"} for row in self.children], "containers": self.containers})
        except OSError:
            self.journal_failed = True

    def spawn(self, argv, *, stdin=None, cleanup=False):
        require(hasattr(os, "waitid") and hasattr(os, "WNOWAIT"), "nonreaping_primitive_required")
        self.remaining(1, cleanup=cleanup)
        process = subprocess.Popen(argv, stdin=stdin if stdin is not None else subprocess.DEVNULL,
             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, close_fds=True,
             env={"PATH": os.defpath, "LANG": "C.UTF-8", "HOME": str(self.evidence)}, umask=0o077)
        # Handlers only record signals: no unwind can occur between spawn/retain.
        row = {"pid": process.pid, "pgid": process.pid, "argv": argv, "process": process, "reaped": False, "group_closed": False}
        self.children.append(row)
        require(os.getpgid(process.pid) == process.pid and os.getsid(process.pid) == process.pid, "owned_session")
        self.journal(); require(not self.journal_failed, "owner_receipt")
        return row

    def exited(self, row):
        return os.waitid(os.P_PID, row["pid"], os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None

    def finish(self, row, natural=False):
        if row["reaped"]: return row["group_closed"]
        process = row["process"]
        # Do not poll/reap then signal a recycled group. Keep the leader owned
        # and unreaped until live descendants are gone.
        if not natural or group_members(row["pgid"]):
            try: os.killpg(row["pgid"], signal.SIGKILL)
            except ProcessLookupError: pass
        process.wait(timeout=self.remaining(3, cleanup=True)); row["reaped"] = True
        row["returncode"] = process.returncode
        row["group_closed"] = not group_members(row["pgid"])
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None: stream.close()
        self.journal()
        return row["group_closed"]

    def command(self, argv, maximum, *, data=None, cleanup=False):
        deadline = time.monotonic() + self.remaining(maximum, cleanup)
        input_path = self.evidence / ("stdin-" + uuid.uuid4().hex)
        input_stream = None; row = None; selector = None; drained = False
        stdout = bytearray(); total = 0; resource_error = None
        log = self.evidence / ("cli-" + uuid.uuid4().hex + ".log")
        try:
            if data is not None:
                fd = os.open(input_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream: stream.write(data)
                input_stream = input_path.open("rb")
            # Cleanup is allowed after a recorded stop, under the original hard
            # deadline; no resource failure may prevent exact owned teardown.
            row = self.spawn(argv, stdin=input_stream, cleanup=cleanup)
            selector = selectors.DefaultSelector()
            selector.register(row["process"].stdout, selectors.EVENT_READ, "stdout")
            selector.register(row["process"].stderr, selectors.EVENT_READ, "stderr")
            with log.open("xb") as writer:
                log.chmod(0o600)
                while selector.get_map():
                    require(time.monotonic() < deadline and (cleanup or STOP is None), "command_deadline")
                    if not cleanup: linux_resources()
                    for key, _ in selector.select(min(0.25, max(0, deadline - time.monotonic()))):
                        block = os.read(key.fd, 65536)
                        if not block: selector.unregister(key.fileobj); continue
                        total += len(block); require(total <= 8 * 1024**2, "command_output_bound")
                        writer.write(block)
                        if key.data == "stdout": stdout.extend(block)
                while not self.exited(row):
                    require(time.monotonic() < deadline and (cleanup or STOP is None), "command_deadline")
                    if not cleanup: linux_resources()
                    time.sleep(0.05)
                drained = True
            require(self.finish(row, natural=True), "cli_cleanup_unknown")
            require(row["returncode"] == 0, "command_failed")
            return bytes(stdout)
        except ResourceRefused as error:
            resource_error = error
            raise
        finally:
            try:
                try:
                    if row is not None and not row["reaped"]: self.finish(row, natural=drained)
                finally:
                    if selector is not None: selector.close()
                    if input_stream is not None: input_stream.close()
            except BaseException:
                # Keep the original resource refusal; retained Owner rows still
                # require the caller's separate close/closure authority.
                if resource_error is None:
                    raise

    def docker(self, args, maximum=10, **kwargs):
        return self.command(self.docker_argv(args), maximum, **kwargs)

    def docker_argv(self, args):
        # Native hosted Linux only; never select an endpoint from dispatch data
        # or inherited DOCKER_HOST/context credentials.
        require(stat.S_ISSOCK(Path("/var/run/docker.sock").stat().st_mode), "docker_endpoint")
        return ["docker", "--host", "unix:///var/run/docker.sock", "--config", str(self.docker_config), *args]

    def inspect(self, identity, cleanup=False):
        raw = self.docker(["inspect", identity], cleanup=cleanup)
        value = document(raw); require(isinstance(value, list) and len(value) == 1, "container_identity")
        return value[0]

    def remove(self, row):
        if row.get("absent"): return
        current = self.inspect(row.get("cid") or row["name"], cleanup=True)
        require(current["Name"] == "/" + row["name"] and current["Image"] == row["image"]
                and current["Config"]["Labels"].get("online.harmony.operation") == row["operation"], "cleanup_identity")
        row["cid"] = current["Id"]; require(re.fullmatch(r"[0-9a-f]{64}", row["cid"]), "container_id")
        self.docker(["rm", "--force", row["cid"]], cleanup=True)
        # ps exact immutable CID then exact acknowledged name, never a broad rm.
        for value in (row["cid"], row["name"]):
            output = self.docker(["ps", "--all", "--quiet", "--no-trunc", "--filter", "id=" + value] if value == row["cid"] else
                                 ["ps", "--all", "--quiet", "--no-trunc", "--filter", "name=^/" + value + "$"], cleanup=True)
            require(output.strip() == b"", "container_cleanup_unknown")
        row["absent"] = True; self.journal()

    def close(self):
        clean = True
        for row in reversed(self.containers):
            try: self.remove(row)
            except (OSError, ValueError, subprocess.SubprocessError, KeyError): clean = False
        for row in self.children:
            try: clean = self.finish(row) and clean
            except (OSError, ValueError, subprocess.SubprocessError): clean = False
        return clean and not self.journal_failed


def extract_guarded(archive, root, files):
    root.mkdir(mode=0o700)
    expected = {row["path"]: row for row in files}
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        require(len(entries) == len(expected), "archive_inventory")
        seen = set()
        for entry in entries:
            path = PurePosixPath(entry.filename)
            require(not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts)
                    and "\\" not in entry.filename and entry.filename in expected and entry.filename.casefold() not in seen
                    and not entry.is_dir() and stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG), "archive_path")
            seen.add(entry.filename.casefold()); current = root
            for part in path.parent.parts:
                current = current / part
                if not current.exists(): current.mkdir(mode=0o700)
                require(current.is_dir() and not current.is_symlink(), "extract_directory")
            target = root / entry.filename; digest = hashlib.sha256(); count = 0
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as writer, source.open(entry) as reader:
                while block := reader.read(65536):
                    count += len(block); require(count <= expected[entry.filename]["bytes"] <= MAX_FILE, "extract_size")
                    digest.update(block); writer.write(block)
            require(count == expected[entry.filename]["bytes"] and digest.hexdigest() == expected[entry.filename]["sha256"], "extract_hash")
    for path in sorted(root.rglob("*"), reverse=True): path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)


def guarded(owner, tree, policy, provenance, manifest, surface, expected_sha, *, archive=True):
    report = owner.evidence / (surface + "-guard.json")
    owner.command([sys.executable, "-I", "-B", str(Path(__file__).with_name("bundle_guard.py")),
       "--archive" if archive else "--root", str(tree), "--surface", surface, "--policy", str(policy),
       "--policy-sha256", expected_sha, "--provenance", str(provenance), "--manifest", str(manifest), "--report", str(report)], 60)
    value = document(report.read_bytes())
    require(set(value) == {"schema_version", "state", "surface", "files", "policy_sha256", "provenance_sha256", "manifest_sha256"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["state"] == "passed" and value["surface"] == surface and value["policy_sha256"] == expected_sha, "guard_refused")
    return value["files"]


def image_identity(value, digest, role, sdk):
    require(value["Id"] == digest and value["Architecture"] == "arm64" and value["Os"] == "linux"
            and sdk[role + "_ref"] in value.get("RepoDigests", [])
            and value["Config"]["User"] == "65532:65532"
            and value["Config"]["Labels"].get("online.harmony.role") == role, "image_identity")
    require(value["Config"]["Entrypoint"] == sdk[role + "_entrypoint"]
            and value["Config"].get("Env", []) == sdk[role + "_environment"], "image_contract")
    if role == "compiler": require(value["Config"]["Labels"].get("online.harmony.source-policy") == sdk["source_policy_sha256"], "image_source_policy")


def create(owner, image, phase, operation, mounts):
    name = "harmony-" + phase + "-" + uuid.uuid4().hex
    row = {"name": name, "image": image, "phase": phase, "operation": operation, "absent": False, "identity_verified": False}
    owner.containers.append(row); owner.journal()
    memory, pids = ("8g", "256") if phase == "compiler" else ("2g", "128")
    args = ["create", "--interactive", "--name", name, "--label", "online.harmony.operation=" + operation,
       "--network", "none", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
       "--security-opt", "no-new-privileges", "--memory", memory, "--memory-swap", memory, "--cpus", "2",
       "--cpuset-cpus", "0,1", "--pids-limit", pids, "--ipc", "private", "--cgroupns", "private",
       "--ulimit", "nofile=1024:1024", "--tmpfs", "/tmp:rw,nosuid,noexec,size=512m,mode=1777"]
    args += ["--tmpfs", "/out:rw,nosuid,exec,size=6g,mode=1777"] if phase == "compiler" else ["--tmpfs", "/dev/shm:rw,nosuid,noexec,size=128m,mode=1777"]
    for path, target, readonly in mounts:
        require(path.resolve() == path and "," not in str(path), "mount_identity")
        args += ["--mount", "type=bind,source=" + str(path) + ",target=" + target + (",readonly" if readonly else "")]
    for name_proxy in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        args += ["--env", name_proxy + "="]
    raw = owner.docker([*args, image]); cid = raw.decode("ascii").strip()
    require(re.fullmatch(r"[0-9a-f]{64}", cid), "container_id"); row["cid"] = cid
    current = owner.inspect(cid); host = current["HostConfig"]
    expected_memory = (8 if phase == "compiler" else 2) * 1024**3
    require(current["Name"] == "/" + row["name"] and current["Image"] == image and current["Config"]["User"] == "65532:65532"
            and current["Config"]["Labels"].get("online.harmony.operation") == operation
            and host["NetworkMode"] == "none" and host["ReadonlyRootfs"] is True
            and host["Memory"] == expected_memory == host["MemorySwap"] and host["NanoCpus"] == 2_000_000_000
            and host["CpusetCpus"] == "0,1" and host["PidsLimit"] == int(pids)
            and host["Privileged"] is False and host["CapDrop"] == ["ALL"]
            and host["SecurityOpt"] == ["no-new-privileges"] and host["PidMode"] == ""
            and not host.get("Devices") and not host.get("DeviceRequests") and not host.get("PortBindings")
            and not host.get("Binds") and host["IpcMode"] == "private" and host["CgroupnsMode"] == "private", "container_caps")
    expected_tmpfs = {"/tmp": "rw,nosuid,noexec,size=512m,mode=1777"}
    expected_tmpfs["/out" if phase == "compiler" else "/dev/shm"] = (
        "rw,nosuid,exec,size=6g,mode=1777" if phase == "compiler" else "rw,nosuid,noexec,size=128m,mode=1777")
    require(host["Tmpfs"] == expected_tmpfs
            and host["Ulimits"] == [{"Name": "nofile", "Hard": 1024, "Soft": 1024}], "container_filesystem_caps")
    actual = sorted((row_mount["Source"], row_mount["Destination"], not row_mount["RW"]) for row_mount in current["Mounts"] if row_mount["Type"] == "bind")
    require(actual == sorted((str(path), target, readonly) for path, target, readonly in mounts)
            and len(current["Mounts"]) == len(mounts), "container_mounts")
    row["identity_verified"] = True; owner.journal(); return row


def export_web(handoff):
    # Only this dedicated export tree is scanned. SDK, source, compiler logs and
    # arbitrary handoff siblings never become a public upload policy.
    web = handoff / "web"; require(web.is_dir() and not web.is_symlink(), "web_missing")
    rows = []; total = 0
    for path in sorted(web.rglob("*")):
        require(not path.is_symlink(), "web_link")
        if path.is_dir(): continue
        info = path.lstat(); relative = path.relative_to(web).as_posix()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and path.suffix.lower() in WEB
                and len(rows) < 4096 and 0 <= info.st_size <= MAX_FILE, "web_inventory")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK); digest = hashlib.sha256(); count = 0
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and (before.st_dev, before.st_ino) == (info.st_dev, info.st_ino), "web_identity")
            while block := stream.read(65536): digest.update(block); count += len(block)
            after = os.fstat(stream.fileno())
        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
                == (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
                and count == info.st_size, "web_drift")
        total += count; require(total <= MAX_TREE, "web_size")
        rows.append({"path": relative, "bytes": count, "sha256": digest.hexdigest()})
    require(any(row["path"] == "index.html" for row in rows) and total > 0, "web_entry")
    return web, rows


def web_guard(owner, web, files, project):
    provenance = {"schema_version": 1, "producer": "controller-web/v1", "source_revision": project["source_revision"],
       "authorization_id": project["authorization_id"], "surface": "public-upload", "files": files}
    pp = owner.evidence / "web-provenance.json"; save(pp, provenance)
    policy = {"schema_version": 1, "review_id": project["authorization_id"], "surface": "public-upload",
       "producer_receipt_sha256": hashlib.sha256(pp.read_bytes()).hexdigest(),
       "files": [{**row, "role": "public_asset"} for row in files]}
    policy_path = owner.evidence / "web-policy.json"; save(policy_path, policy)
    manifest = owner.evidence / "web-manifest.json"; save(manifest, {"schema_version": 1, "files": files})
    return guarded(owner, web, policy_path, pp, manifest, "public-upload", hashlib.sha256(policy_path.read_bytes()).hexdigest(), archive=False)


def copy_admitted(source, target, files):
    """Copy only admitted bytes through stable nofollow FDs, not copytree links."""
    target.mkdir(mode=0o700)
    root_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for row in files:
            relative = PurePosixPath(row["path"])
            require(not relative.is_absolute() and all(part not in ("", ".", "..") for part in relative.parts)
                    and relative.as_posix() == row["path"], "copy_path")
            parent_fd = os.dup(root_fd)
            destination = target
            try:
                for part in relative.parent.parts:
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                    os.close(parent_fd); parent_fd = next_fd
                    destination = destination / part
                    if not destination.exists(): destination.mkdir(mode=0o700)
                digest = hashlib.sha256(); count = 0
                fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
                # Retain input before exclusive destination acquisition.
                with os.fdopen(fd, "rb") as reader:
                    before = os.fstat(reader.fileno())
                    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row["bytes"] <= MAX_FILE, "copy_identity")
                    out_fd = os.open(destination / relative.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(out_fd, "wb") as writer:
                        while block := reader.read(65536):
                            count += len(block); require(count <= row["bytes"], "copy_bound")
                            digest.update(block); writer.write(block)
                        after = os.fstat(reader.fileno())
                        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
                                == (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
                                and count == row["bytes"] and digest.hexdigest() == row["sha256"], "copy_hash")
                        writer.flush(); os.fsync(writer.fileno())
            finally: os.close(parent_fd)
    finally: os.close(root_fd)
    for path in sorted(target.rglob("*"), reverse=True): path.chmod(0o555 if path.is_dir() else 0o444)
    target.chmod(0o555)


def png_colours(data):
    require(data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) <= 4*1024**2, "browser_png")
    position = 8; compressed = bytearray(); shape = None
    while position < len(data):
        require(position + 12 <= len(data), "browser_png")
        size = struct.unpack(">I", data[position:position+4])[0]
        kind = data[position+4:position+8]; body = data[position+8:position+8+size]
        require(position+size+12 <= len(data), "browser_png")
        require(zlib.crc32(kind+body)&0xffffffff == struct.unpack(">I", data[position+8+size:position+12+size])[0], "browser_png")
        if kind == b"IHDR": shape = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT": compressed.extend(body)
        elif kind == b"IEND": break
        position += size+12
    require(shape is not None, "browser_png")
    width,height,depth,colour,compression,filter_method,interlace = shape
    require(32 <= width <= 4096 and 32 <= height <= 4096 and depth == 8 and colour in (2,6)
            and compression == filter_method == interlace == 0, "browser_png_shape")
    channels = 3 if colour == 2 else 4; stride = width*channels; maximum = height*(stride+1)
    decoder = zlib.decompressobj(); raw = decoder.decompress(bytes(compressed), maximum+1)
    require(len(raw) == maximum and decoder.eof and not decoder.unconsumed_tail, "browser_png_size")
    previous = bytearray(stride); colours = set()
    for y in range(height):
        offset = y*(stride+1); mode = raw[offset]; row = bytearray(raw[offset+1:offset+stride+1])
        require(mode <= 4, "browser_png_filter")
        for index in range(stride):
            left = row[index-channels] if index >= channels else 0
            up = previous[index]; corner = previous[index-channels] if index >= channels else 0
            predicted = (0,left,up,(left+up)//2)[mode] if mode < 4 else (
                left if abs(up-corner) <= abs(left-corner) and abs(up-corner) <= abs(left+up-2*corner)
                else up if abs(left-corner) <= abs(left+up-2*corner) else corner)
            row[index] = (row[index]+predicted)&255
        for x in range(0,stride,channels):
            colours.add(bytes(row[x:x+3]))
            if len(colours) >= 16: return 16
        previous = row
    return len(colours)


def browser(owner, row):
    """Bounded CDP boot smoke, using the source-free browser's pipe contract."""
    deadline = time.monotonic() + owner.remaining(120)
    child = owner.spawn(owner.docker_argv(["start", "--attach", "--interactive", row["cid"]]), stdin=subprocess.PIPE)
    process = child["process"]; selector = None; buffer = bytearray(); errors = []; sequence = 0; total = 0
    log = owner.evidence / "browser.log"
    try:
        selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ, "cdp"); selector.register(process.stderr, selectors.EVENT_READ, "log")
        with log.open("xb") as writer:
            log.chmod(0o600)
            def call(method, params=None, session=None, wait=True):
                nonlocal sequence, total
                sequence += 1; ident = sequence
                request = {"id": ident, "method": method, "params": params or {}}
                if session: request["sessionId"] = session
                process.stdin.write(canonical(request).rstrip(b"\n") + b"\0"); process.stdin.flush()
                if not wait: return None
                while True:
                    require(STOP is None and time.monotonic() < deadline, "browser_deadline"); linux_resources()
                    while b"\0" in buffer:
                        raw, _, rest = buffer.partition(b"\0"); buffer[:] = rest
                        value = document(raw, 8*1024**2)
                        if value.get("method") in {"Runtime.exceptionThrown", "Log.entryAdded"} or (value.get("method") == "Runtime.consoleAPICalled" and value.get("params", {}).get("type") == "error"): errors.append(True)
                        if value.get("id") == ident:
                            require("error" not in value and not errors, "browser_runtime_error")
                            return value.get("result", {})
                    for key, _ in selector.select(min(0.25, max(0, deadline-time.monotonic()))):
                        block = os.read(key.fd, 65536); require(block, "browser_eof")
                        total += len(block); require(total <= 8*1024**2, "browser_output_bound")
                        if key.data == "cdp": buffer.extend(block); require(len(buffer) <= 8*1024**2, "browser_protocol_bound")
                        else: writer.write(block)
            target = call("Target.createTarget", {"url": "about:blank"})["targetId"]
            session = call("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
            call("Runtime.enable", session=session); call("Page.enable", session=session)
            call("Page.navigate", {"url": "http://127.0.0.1:8765/index.html"}, session)
            result = call("Runtime.evaluate", {"expression": "new Promise(resolve=>{let n=0;function frame(){const c=document.querySelector('canvas');if(c&&c.width>=32&&c.height>=32&&++n>=10)resolve({frames:n,canvas:true});else requestAnimationFrame(frame)}requestAnimationFrame(frame)})", "awaitPromise": True, "returnByValue": True}, session)
            value = result.get("result", {}).get("value", {})
            require(value.get("frames", 0) >= 10 and value.get("canvas") is True and not errors, "browser_boot_refused")
            screenshot = call("Page.captureScreenshot", {"format": "png"}, session)
            colours = png_colours(base64.b64decode(screenshot["data"], validate=True))
            require(colours >= 16, "browser_blank")
            call("Browser.close", wait=False)
            while selector.get_map():
                require(STOP is None and time.monotonic() < deadline, "browser_deadline"); linux_resources()
                for key, _ in selector.select(min(0.25, max(0, deadline-time.monotonic()))):
                    block = os.read(key.fd, 65536)
                    if not block: selector.unregister(key.fileobj); continue
                    total += len(block); require(total <= 8*1024**2, "browser_output_bound")
                    if key.data == "cdp": buffer.extend(block)
                    else: writer.write(block)
            while not owner.exited(child):
                require(STOP is None and time.monotonic() < deadline, "browser_deadline"); linux_resources(); time.sleep(0.05)
            while b"\0" in buffer:
                raw, _, rest = buffer.partition(b"\0"); buffer[:] = rest
                event = document(raw, 8*1024**2)
                require(event.get("method") not in {"Runtime.exceptionThrown", "Log.entryAdded"}
                        and not (event.get("method") == "Runtime.consoleAPICalled" and event.get("params",{}).get("type") == "error"), "browser_runtime_error")
        require(owner.finish(child, natural=True) and child["returncode"] == 0, "browser_cli_cleanup")
        return {"frames": value["frames"], "canvas": True, "colours_at_least": colours, "runtime_errors": 0, "scope": "boot_only"}
    finally:
        try:
            if not child["reaped"]: owner.finish(child)
        finally:
            if selector is not None: selector.close()


def verify(owner, repo, sdk, project, run):
    downloaded = {}
    for surface, record in (("public-sdk", sdk), ("public-project", project)):
        assets = {}
        require(set(record["assets"]) == {"archive", "policy", "provenance", "manifest"}, "catalog_asset_set")
        for name, entry in record["assets"].items():
            path = owner.evidence / (surface + "-" + name)
            download(repo, record["release_tag"], entry, path, time.monotonic() + owner.remaining(120)); assets[name] = path
        files = guarded(owner, assets["archive"], assets["policy"], assets["provenance"], assets["manifest"], surface, record["assets"]["policy"]["sha256"])
        tree = owner.evidence / surface; extract_guarded(assets["archive"], tree, files); downloaded[surface] = tree
    for role in ("compiler", "browser"):
        digest = sdk[role + "_image"]
        owner.docker(["pull", sdk[role + "_ref"]], maximum=120)
        values = document(owner.docker(["image", "inspect", sdk[role + "_ref"]])); require(len(values) == 1, "image_inventory")
        image_identity(values[0], digest, role, sdk)
    handoff = owner.evidence / "handoff"; handoff.mkdir(mode=0o700); handoff.chmod(0o777)
    compiler = create(owner, sdk["compiler_image"], "compiler", run,
        [(downloaded["public-sdk"], "/input/sdk", True), (downloaded["public-project"], "/input/project", True), (handoff, "/handoff", False)])
    request = {"schema_version": 1, "run_id": run, "sdk": "/input/sdk", "source": "/input/project", "output": "/out/result", "handoff": "/handoff/web", "profile": PROFILE}
    raw = owner.docker(["start", "--attach", "--interactive", compiler["cid"]], maximum=min(3600, owner.remaining(3600)-150), data=canonical(request))
    receipt = document(raw)
    require(type(receipt.get("schema_version")) is int
            and receipt == {"schema_version": 1, "run_id": run, "state": "built"}, "compiler_receipt")
    owner.remove(compiler); require(compiler["absent"], "compiler_not_closed")
    produced_web, files = export_web(handoff); require(web_guard(owner, produced_web, files, project) == files, "web_guard_inventory")
    web = owner.evidence / "browser-web"; copy_admitted(produced_web, web, files)
    browser_row = create(owner, sdk["browser_image"], "browser", run, [(web, "/web", True)])
    smoke = browser(owner, browser_row); owner.remove(browser_row)
    require(browser_row["absent"] and export_web(handoff)[1] == files, "browser_cleanup_or_web_drift")
    return web, files, smoke


def public_receipt(run, state, code=None, **facts):
    require(state in {"passed", "failed", "blocked"} and (code is None or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code)), "public_receipt_shape")
    require((state != "passed" and run == "") or run_identity(run), "public_run_identity")
    value = {"schema_version": 1, "run_id": run, "state": state}
    if code: value["code"] = code
    allowed = {"sdk_sha256", "project_sha256", "files", "browser"}
    require(set(facts) <= allowed, "public_receipt_fields")
    require(not facts if state != "passed" else set(facts) == allowed, "public_receipt_state")
    if facts:
        require(SHA.fullmatch(facts["sdk_sha256"]) and SHA.fullmatch(facts["project_sha256"]), "public_receipt_hash")
        browser_facts = facts["browser"]
        require(set(browser_facts) == {"frames", "canvas", "colours_at_least", "runtime_errors", "scope"}
                and type(browser_facts["frames"]) is int and 10 <= browser_facts["frames"] <= 6000
                and browser_facts["canvas"] is True and type(browser_facts["colours_at_least"]) is int
                and browser_facts["colours_at_least"] == 16 and type(browser_facts["runtime_errors"]) is int
                and browser_facts["runtime_errors"] == 0 and browser_facts["scope"] == "boot_only", "public_browser_fields")
        rows = facts["files"]; require(isinstance(rows, list) and 0 < len(rows) <= 4096, "public_file_fields")
        seen = set(); total = 0
        for row in rows:
            require(set(row) == {"path", "bytes", "sha256"}, "public_file_fields")
            path = PurePosixPath(row["path"])
            require(not path.is_absolute() and path.as_posix() == row["path"]
                    and all(part not in ("", ".", "..") for part in path.parts)
                    and "\\" not in row["path"] and path.suffix.lower() in WEB
                    and row["path"].casefold() not in seen and type(row["bytes"]) is int
                    and 0 <= row["bytes"] <= MAX_FILE and SHA.fullmatch(row["sha256"]), "public_file_fields")
            seen.add(row["path"].casefold()); total += row["bytes"]
        require(total <= MAX_TREE and "index.html" in seen, "public_file_fields")
    return {**value, **facts}


def main(env=None):
    global STOP
    env = dict(os.environ if env is None else env); owner = None; result = None; primary = None; web = None; files = None
    run = env.get("VERIFY_RUN_ID", "")
    public = Path.cwd() / ".verify-public"
    hard = None; signal_scope = False; code = 1; staging = None

    def acceptance_clock():
        if hard is not None:
            require(STOP is None and time.monotonic() < hard, "publication_deadline")

    def failed(code):
        nonlocal primary, result
        primary = primary or code
        result = public_receipt(run, "failed", primary)

    def terminal():
        if owner is not None:
            save(owner.evidence / "terminal.json", {"schema_version": 1,
                 "state": result["state"], "code": primary, "stop_signal": STOP,
                 "owned_cli_closed": all(row["reaped"] and row["group_closed"] for row in owner.children),
                 "owned_containers_absent": all(row.get("absent") is True for row in owner.containers),
                 "journal_failed": owner.journal_failed})

    def repair_failed_receipts():
        # A failed rewrite may leave stale bytes; actual nonzero exit remains
        # mandatory evidence and prevents the action's success-only upload.
        if staging is not None:
            destination = public if public.exists() and not staging.exists() else staging
            try: save(destination / "receipt.json", result)
            except OSError: pass
        try: terminal()
        except OSError: pass

    try:
        try:
            repo, sdk, project, run = approval(env)  # Before any network or Docker.
            linux_resources()
            evidence_root = Path.cwd() / ".verify-runs"; evidence_root.mkdir(mode=0o700, exist_ok=True)
            require(not evidence_root.is_symlink() and stat.S_IMODE(evidence_root.stat().st_mode) == 0o700, "evidence_root")
            evidence = evidence_root / run; evidence.mkdir(mode=0o700)
            # Start the one absolute 3900-second budget before Owner's initial
            # receipt IO. No later phase or publication operation restarts it.
            hard = time.monotonic() + 3900
            def stopped(signum, frame):
                global STOP
                if STOP is None: STOP = signum
            signal_scope = True
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM): signal.signal(signum, stopped)
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            signal.setitimer(signal.ITIMER_REAL, max(0.001, hard - time.monotonic()))
            owner = Owner(evidence, started=hard - 3900)
            acceptance_clock()
            web, files, smoke = verify(owner, repo, sdk, project, run)
            acceptance_clock()
            result = public_receipt(run, "passed", sdk_sha256=sdk["assets"]["archive"]["sha256"], project_sha256=project["assets"]["archive"]["sha256"], files=files, browser=smoke)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            primary = "catalog_unapproved" if owner is None else "verification_failed"
            run = run if run_identity(run) else ""
            result = public_receipt(run, "blocked" if owner is None else "failed", primary)
        finally:
            try:
                closed = owner.close() if owner else True
                if not closed or STOP is not None:
                    failed("cleanup_unknown")
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                failed("cleanup_unknown")
        try:
            terminal()
            acceptance_clock()
        except (OSError, ValueError):
            failed("receipt_unknown")
        if STOP is not None:
            failed("interrupted")
        # Keep the sticky handlers and original alarm through every final copy,
        # persistence and response operation. Stale staged bytes are not proof.
        try:
            if result["state"] == "passed": acceptance_clock()
            require(not public.exists() and not public.is_symlink(), "public_destination_exists")
            staging = public.with_name(".verify-public-stage-" + uuid.uuid4().hex)
            staging.mkdir(mode=0o700)
            if result["state"] == "passed":
                require(owner is not None and owner.close(), "final_cleanup_unknown")
                acceptance_clock()
                copy_admitted(web, staging / "web", files)
                acceptance_clock()
                require(export_web(staging)[1] == files, "public_copy_drift")
                acceptance_clock()
            save(staging / "receipt.json", result)
            if result["state"] == "passed": acceptance_clock()
            os.rename(staging, public)
            if result["state"] == "passed": acceptance_clock()
            fd = os.open(public.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
            if result["state"] == "passed": acceptance_clock()
        except Exception:
            failed("publication_deadline" if hard is not None and (STOP is not None or time.monotonic() >= hard) else "public_handoff_unknown")
            repair_failed_receipts()
        try:
            terminal()
            if result["state"] == "passed": acceptance_clock()
        except (OSError, ValueError):
            failed("receipt_unknown")
            repair_failed_receipts()
        try:
            if result["state"] == "passed": acceptance_clock()
            print(canonical(result).decode(), end="", flush=True)
            if result["state"] == "passed": acceptance_clock()
        except (OSError, ValueError):
            failed("publication_deadline" if hard is not None and (STOP is not None or time.monotonic() >= hard) else "response_unknown")
            repair_failed_receipts()
        code = 0 if result["state"] == "passed" else 78 if result["state"] == "blocked" else 1
    finally:
        # Record a late signal/deadline before restoring the default handlers.
        # Rewrites remain attempts, never authority in place of actual exit.
        if result is not None and result["state"] == "passed" and hard is not None and (STOP is not None or time.monotonic() >= hard):
            failed("publication_deadline"); code = 1
            repair_failed_receipts()
        if signal_scope:
            signal.setitimer(signal.ITIMER_REAL, 0)
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM): signal.signal(signum, signal.SIG_DFL)
    # No additional IO follows this final zero-exit predicate. A signal arriving
    # during handler restoration or an expired budget cannot produce success.
    if code == 0 and (STOP is not None or hard is None or time.monotonic() >= hard):
        return 1
    return code


if __name__ == "__main__": raise SystemExit(main())
