#!/usr/bin/env python3
"""Native ARM public formatter image check/probe/publication; no SDK inputs.

The image context is the exact reviewed two-file Rust 1.99.0 generator context.
The pinned existing Owner retains CLI/container identities. GitHub owns the build
VM/daemon; probe and registry receipts do not qualify SDKs or model execution.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import uuid

REPOSITORY = "fvlvte/harmony-studio-projects"
REGISTRY = "ghcr.io/fvlvte/harmony-studio-projects/generator"
IMAGE = "harmony-public-generator:unqualified"
OWNER_SHA = "8f25f44fa4803855e562d1b25b5ca2bef85ad9c93963d120be57649d60702381"
CONTEXT = [
    {"path": ".dockerignore", "bytes": 29, "sha256": "a80a9141c954548148b2acb4ef04adcc1a7cb0131a6c2cba19c5877531cc957c"},
    {"path": "Dockerfile", "bytes": 296, "sha256": "8fcbe49b69875c9052b093e4f85d90468cc1b7079ae528fdfee7fb9663db88c3"},
]
CONTEXT_SHA = "8a6070eb50996d7fce08bfdff6ce5fe3ff218250386551c713996c4102ade601"
ENV = {"PATH": "/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
       "RUSTUP_HOME": "/usr/local/rustup", "CARGO_HOME": "/usr/local/cargo",
       "RUST_VERSION": "1.99.0", "RUSTUP_AUTO_INSTALL": "0"}
BASE_LABELS = {"org.opencontainers.image.source": "https://github.com/rust-lang/docker-rust"}
GUEST_ENV = {**ENV, "CARGO_HOME": "/tmp/cargo", "HOME": "/tmp/home", "LANG": "C.UTF-8"}
STOP = None
PROBE_CODES = frozenset({
    "input_identity", "input_bound", "input_drift", "owner_source_drift", "public_context_inventory",
    "public_context_drift", "image_environment", "image_identity", "image_contract", "probe_output_bound",
    "probe_output_shape", "probe_toolchain_version", "probe_tool_versions", "container_identity",
    "container_sandbox", "interrupted", "probe_deadline", "private_evidence_root", "image_inspect",
    "owner_receipt", "container_id", "container_exit", "image_tag_drift", "probe_source_drift",
    "source_revision", "owned_closure", "cleanup_unknown", "probe_failed", "public_destination",
    "receipt_or_deadline_unknown",
})


class Refused(ValueError):
    pass


def require(value, code):
    if not value:
        raise Refused(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def document(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= maximum, "input_identity")
        raw = bytearray()
        while block := os.read(fd, min(65536, maximum + 1 - len(raw))):
            raw.extend(block)
            require(len(raw) <= maximum, "input_bound")
        after = os.fstat(fd)
        visible = Path(path).lstat()
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k) == getattr(visible, k)
                for k in fields), "input_drift")
        return bytes(raw)
    finally:
        os.close(fd)


def source_identity():
    return digest(read(Path(__file__).resolve(), 128 * 1024))


def context_identity(path):
    require(path.is_dir() and not path.is_symlink()
            and {p.name for p in path.iterdir()} == {row["path"] for row in CONTEXT}, "public_context_inventory")
    actual = []
    for row in CONTEXT:
        raw = read(path / row["path"], 65536)
        actual.append({"path": row["path"], "bytes": len(raw), "sha256": digest(raw)})
    require(actual == CONTEXT and digest(canonical(actual)) == CONTEXT_SHA, "public_context_drift")
    return CONTEXT_SHA


def owner_module():
    path = Path(__file__).resolve().with_name("ci_verify.py")
    raw = read(path, 128 * 1024)
    require(digest(raw) == OWNER_SHA, "owner_source_drift")
    spec = importlib.util.spec_from_file_location("generator_toolchain_owner", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def environment(values):
    require(isinstance(values, list) and all(isinstance(item, str) and "=" in item for item in values), "image_environment")
    pairs = [item.split("=", 1) for item in values]
    require(len({key for key, _ in pairs}) == len(pairs), "image_environment")
    return dict(pairs)


def image_identity(value):
    require(isinstance(value, dict) and re.fullmatch(r"sha256:[0-9a-f]{64}", value.get("Id", ""))
            and value.get("Architecture") == "arm64" and value.get("Os") == "linux", "image_identity")
    config = value["Config"]
    require(config.get("User") == "65532:65532" and config.get("Entrypoint") == ["rustfmt"]
            and config.get("Cmd") in (None, []) and config.get("WorkingDir") in (None, "")
            and config.get("Labels") == BASE_LABELS and environment(config.get("Env")) == ENV
            and not config.get("Volumes") and not config.get("ExposedPorts") and not config.get("OnBuild")
            and not config.get("Healthcheck"), "image_contract")
    return value["Id"]


# Only public native tools are required. The exact generator installs neither
# Python nor a Wasm target; do not alter the context merely to satisfy a probe.
GUEST = '''set -eu
test "$(id -u)" = 65532
rustc +1.99.0 -vV
cargo +1.99.0 --version
rustfmt +1.99.0 --version
sha256sum "$(rustup which --toolchain 1.99.0 rustc)" | cut -d ' ' -f 1
sha256sum "$(rustup which --toolchain 1.99.0 rustfmt)" | cut -d ' ' -f 1
'''


def tools_output(raw):
    require(isinstance(raw, bytes) and len(raw) <= 16384, "probe_output_bound")
    lines = raw.decode("ascii").splitlines()
    require(len(lines) == 11, "probe_output_shape")
    value = {"rustc_verbose": "\n".join(lines[:7]) + "\n", "cargo": lines[7], "rustfmt": lines[8],
             "rustc_sha256": lines[9], "rustfmt_sha256": lines[10]}
    return tools_identity(value)


def tools_identity(value):
    require(isinstance(value, dict) and set(value) == {"rustc_verbose", "cargo", "rustfmt", "rustc_sha256", "rustfmt_sha256"},
            "probe_output_shape")
    require(all(isinstance(v, str) and len(v) <= 2048 for v in value.values()), "probe_output_shape")
    lines = value["rustc_verbose"].splitlines()
    first = re.fullmatch(r"rustc 1\.99\.0 \(([0-9a-f]{7,40}) ([0-9]{4}-[0-9]{2}-[0-9]{2})\)", lines[0]) if lines else None
    require(len(lines) == 7 and first is not None, "probe_toolchain_version")
    fields = dict(line.split(": ", 1) for line in lines[1:])
    require(set(fields) == {"binary", "commit-hash", "commit-date", "host", "release", "LLVM version"}
            and fields["binary"] == "rustc" and fields["host"] == "aarch64-unknown-linux-gnu"
            and fields["release"] == "1.99.0" and re.fullmatch(r"[0-9a-f]{40}", fields["commit-hash"])
            and fields["commit-hash"].startswith(first[1]) and fields["commit-date"] == first[2]
            and re.fullmatch(r"[0-9.]{1,20}", fields["LLVM version"]), "probe_toolchain_version")
    require(re.fullmatch(r"cargo 1\.99\.0 \([0-9a-f]{7,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\)", value["cargo"])
            and re.fullmatch(r"rustfmt [0-9.]+-stable \([0-9a-f]{7,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\)", value["rustfmt"])
            and all(re.fullmatch(r"[0-9a-f]{64}", value[k]) for k in ("rustc_sha256", "rustfmt_sha256")), "probe_tool_versions")
    return value


def container_arguments(image, operation):
    row = {"name": "harmony-generator-probe-" + uuid.uuid4().hex, "image": image, "operation": operation, "absent": False}
    args = ["create", "--name", row["name"], "--label", "online.harmony.operation=" + operation,
        "--network", "none", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--memory", "512m", "--memory-swap", "512m",
        "--cpus", "1", "--cpuset-cpus", "0", "--pids-limit", "64", "--ipc", "private", "--cgroupns", "private",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777", "--workdir", "/tmp",
        "--entrypoint", "/usr/bin/env", image, "-i", *(k + "=" + v for k, v in GUEST_ENV.items()),
        "/bin/sh", "-c", GUEST]
    return row, args


def container_identity(value, row):
    config, host = value["Config"], value["HostConfig"]
    require(value.get("Id") == row["cid"] and value.get("Name") == "/" + row["name"] and value.get("Image") == row["image"]
            and config.get("Labels") == {**BASE_LABELS, "online.harmony.operation": row["operation"]}
            and config.get("User") == "65532:65532" and config.get("Entrypoint") == ["/usr/bin/env"]
            and config.get("Cmd") == ["-i", *(k + "=" + v for k, v in GUEST_ENV.items()), "/bin/sh", "-c", GUEST]
            and environment(config.get("Env")) == ENV and config.get("WorkingDir") == "/tmp" and not config.get("Volumes"),
            "container_identity")
    mounts = value.get("Mounts")
    require(isinstance(mounts, list) and len(mounts) <= 1 and all(m.get("Type") == "tmpfs" and m.get("Destination") == "/tmp"
            and m.get("RW") is True and not m.get("Source") for m in mounts)
            and host.get("Binds") in (None, []) and host.get("Mounts") in (None, [])
            and host.get("NetworkMode") == "none" and host.get("ReadonlyRootfs") is True and host.get("Privileged") is False
            and host.get("CapDrop") == ["ALL"] and not host.get("CapAdd") and host.get("SecurityOpt") == ["no-new-privileges"]
            and host.get("Memory") == 512 * 1024**2 and host.get("MemorySwap") == 512 * 1024**2
            and host.get("NanoCpus") == 1_000_000_000 and host.get("CpusetCpus") == "0" and host.get("PidsLimit") == 64
            and host.get("PidMode") == "" and host.get("IpcMode") == "private" and host.get("CgroupnsMode") == "private"
            and not host.get("Devices") and not host.get("DeviceRequests") and not host.get("PortBindings")
            and not host.get("PublishAllPorts") and host.get("Tmpfs") == {"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"},
            "container_sandbox")


def probe_main():
    global STOP
    started = time.monotonic(); hard = started + 120
    owner = None; verify = None; result = None; primary = None; scope = False; code = 1; public_created = False
    operation = str(uuid.uuid4()); STOP = None
    original_source = source_identity()
    def clock():
        require(STOP is None, "interrupted")
        require(time.monotonic() < hard, "probe_deadline")
    def stopped(signum, frame):
        global STOP
        if STOP is None: STOP = signum
        if verify is not None and verify.STOP is None: verify.STOP = signum
    def failure(reason):
        nonlocal primary, result
        reason = reason if type(reason) is str and reason in PROBE_CODES else "probe_failed"
        primary = primary or reason
        result = {"schema_version": 1, "operation_id": operation, "state": "failed", "code": primary,
                  "scope": "public_generator_identity_and_cleanup_only", "sdk_qualified": False}
    try:
        try:
            scope = True
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM): signal.signal(signum, stopped)
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            signal.setitimer(signal.ITIMER_REAL, max(0.001, hard - time.monotonic()))
            context_identity(Path.cwd() / "tools/generator-context"); clock()
            verify = owner_module(); verify.STOP = STOP
            before = verify.linux_resources(); clock()
            private = Path.cwd() / ".generator-private"; private.mkdir(mode=0o700, exist_ok=True)
            require(not private.is_symlink() and private.stat().st_uid == os.getuid()
                    and stat.S_IMODE(private.stat().st_mode) == 0o700, "private_evidence_root")
            evidence = private / operation; evidence.mkdir(mode=0o700)
            # The maintained Owner's hard=started+3900 now equals this probe's
            # original absolute deadline. Its 30-second cleanup reserve remains.
            owner = verify.Owner(evidence, started=hard - 3900); clock()
            inspect = verify.document(owner.docker(["image", "inspect", IMAGE]))
            require(isinstance(inspect, list) and len(inspect) == 1, "image_inspect")
            image = image_identity(inspect[0])
            row, args_create = container_arguments(image, operation)
            owner.containers.append(row); owner.journal(); require(not owner.journal_failed, "owner_receipt")
            cid = owner.docker(args_create, 10).decode().strip()
            require(re.fullmatch(r"[0-9a-f]{64}", cid), "container_id"); row["cid"] = cid; owner.journal()
            container_identity(owner.inspect(cid), row)
            raw = owner.docker(["start", "--attach", cid], min(60, owner.remaining(60)))
            require(len(raw) <= 16384, "probe_output_bound")
            tools = tools_output(raw)
            state = owner.inspect(cid)["State"]
            require(state.get("Running") is False and state.get("ExitCode") == 0 and state.get("OOMKilled") is False, "container_exit")
            require(image_identity(verify.document(owner.docker(["image", "inspect", IMAGE]))[0]) == image, "image_tag_drift")
            require(owner.close(), "cleanup_unknown"); clock()
            after = verify.linux_resources(); context_identity(Path.cwd() / "tools/generator-context"); clock()
            require(source_identity() == original_source, "probe_source_drift")
            revision = os.environ.get("GITHUB_SHA", "")
            require(re.fullmatch(r"[0-9a-f]{40}", revision), "source_revision")
            require(owner.children and all(r["reaped"] and r["group_closed"] for r in owner.children)
                    and len(owner.containers) == 1 and row.get("absent") is True, "owned_closure")
            result = {"schema_version": 1, "operation_id": operation, "state": "passed",
                "scope": "public_generator_identity_and_cleanup_only", "sdk_qualified": False, "abi_qualified": False,
                "build_provenance_verified_by_probe": False, "source_revision": revision, "image_id": image,
                "origin_context_digest": CONTEXT_SHA, "context_files": CONTEXT, "tools": tools, "probe_source_sha256": original_source,
                "host_resources_before": before, "host_resources_after": after,
                "owned_cli_closed": True, "owned_container_absent": True, "budget_seconds": 120}
        except Refused as error: failure(str(error))
        except Exception: failure("probe_failed")
        finally:
            if owner is not None:
                try:
                    if not owner.close(): failure("cleanup_unknown")
                except Exception: failure("cleanup_unknown")
            if STOP is not None: failure("interrupted")
        try:
            if result["state"] == "passed": clock()
            public = Path.cwd() / ".generator-public"; public.mkdir(mode=0o700); public_created = True
            require(not public.is_symlink(), "public_destination")
            verify = verify or owner_module()
            verify.save(public / "receipt.json", result)
            if result["state"] == "passed": clock()
            print(canonical({"schema_version": 1, "state": result["state"], "scope": result["scope"],
                             **({"code": result["code"]} if result["state"] == "failed" else {})}).decode(), end="", flush=True)
            if result["state"] == "passed": clock()
            code = 0 if result["state"] == "passed" else 1
        except Exception:
            failure("receipt_or_deadline_unknown"); code = 1
            if verify is not None and public_created:
                try: verify.save(Path.cwd() / ".generator-public/receipt.json", result)
                except Exception: pass
            try: print(canonical({"schema_version": 1, "state": "failed", "scope": result["scope"], "code": primary}).decode(), end="", flush=True)
            except OSError: pass
    finally:
        if result is not None and result["state"] == "passed" and (STOP is not None or time.monotonic() >= hard):
            failure("probe_deadline"); code = 1
            if verify is not None and public_created:
                try: verify.save(Path.cwd() / ".generator-public/receipt.json", result)
                except Exception: pass
        if scope:
            signal.setitimer(signal.ITIMER_REAL, 0)
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM): signal.signal(signum, signal.SIG_DFL)
    if code == 0 and (STOP is not None or time.monotonic() >= hard): return 1
    return code

def anonymous_child(manifest_digest, image_id):
    """Only fixed GHCR HTTPS URLs; no inherited login or Docker configuration."""
    import urllib.error
    import urllib.parse
    import urllib.request
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "registry_digest")
    class RegistryRedirect(urllib.request.HTTPRedirectHandler):
        blob = False
        count = 0
        def redirect_request(self, request, fp, code, message, headers, new_url):
            parsed = urllib.parse.urlsplit(new_url)
            self.count += 1
            require(self.blob and self.count <= 2 and code in (301, 302, 303, 307, 308)
                    and parsed.scheme == "https" and parsed.hostname in {"ghcr.io", "pkg-containers.githubusercontent.com"}
                    and parsed.port in (None, 443) and parsed.username is None and parsed.password is None
                    and not parsed.fragment, "registry_redirect")
            # Anonymous scoped read bearer never crosses a registry redirect.
            safe_headers = {k: v for k, v in request.header_items()
                            if k.lower() not in {"host", "authorization", "cookie", "proxy-authorization"}}
            return urllib.request.Request(new_url, headers=safe_headers, method="GET")
    redirects = RegistryRedirect()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), redirects)
    def fetched(path, maximum, headers=None, *, blob=False):
        redirects.blob = blob
        redirects.count = 0
        request = urllib.request.Request("https://ghcr.io/" + path, headers=headers or {})
        with opener.open(request, timeout=15) as response:
            require(response.status == 200 and (response.geturl() == request.full_url or blob), "anonymous_registry_status")
            body = response.read(maximum + 1)
            require(len(body) <= maximum, "registry_body_bound")
            return body, dict(response.headers)
    query = urllib.parse.urlencode({"service": "ghcr.io", "scope": "repository:fvlvte/harmony-studio-projects/generator:pull"})
    token_raw, _ = fetched("token?" + query, 65536)
    token_document = document(token_raw)
    token = token_document.get("token") or token_document.get("access_token")
    require(isinstance(token, str) and 0 < len(token) <= 16384
            and "\r" not in token and "\n" not in token, "anonymous_registry_token")
    headers = {"Authorization": "Bearer " + token,
               "Accept": "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"}
    raw, response_headers = fetched("v2/fvlvte/harmony-studio-projects/generator/manifests/" + manifest_digest, 2 * 1024**2, headers)
    require("sha256:" + digest(raw) == manifest_digest, "manifest_body_digest")
    returned = next((v for k, v in response_headers.items() if k.lower() == "docker-content-digest"), None)
    require(returned == manifest_digest, "manifest_header_digest")
    manifest = document(raw)
    require(manifest.get("schemaVersion") == 2 and type(manifest["schemaVersion"]) is int
            and manifest.get("mediaType") in {"application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.v2+json"}
            and "manifests" not in manifest and manifest["config"]["digest"] == image_id,
            "single_manifest_config_join")
    raw, _ = fetched("v2/fvlvte/harmony-studio-projects/generator/blobs/" + image_id, 2 * 1024**2,
                     {"Authorization": "Bearer " + token}, blob=True)
    require("sha256:" + digest(raw) == image_id, "image_config_body_digest")
    config = document(raw)
    print(canonical({"manifest_digest": manifest_digest, "image_id": image_id,
                     "manifest_media_type": manifest["mediaType"],
                     "Architecture": config["architecture"], "Os": config["os"],
                     "Config": config["config"]}).decode(), end="", flush=True)

def publish_main():
    global STOP
    started = time.monotonic()
    hard = started + 300
    token = os.environ.pop("GHCR_GENERATOR_TOKEN", None)
    actor = os.environ.pop("GHCR_GENERATOR_ACTOR", None)
    owner = None
    verify = None
    receipt = None
    output = Path.cwd() / ".generator-public/registry.json"
    primary = None
    code = 1
    credentials_removed = False
    operation = str(uuid.uuid4())
    STOP = None
    def stopped(signum, frame):
        global STOP
        if STOP is None:
            STOP = signum
        if verify is not None and verify.STOP is None:
            verify.STOP = signum
    def clock():
        require(STOP is None and time.monotonic() < hard - 30, "publication_deadline")
    def remove_credentials():
        if owner is None:
            return
        for path in owner.evidence.glob("stdin-*"):
            value = path.lstat()
            require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == os.getuid(), "credential_file_identity")
            path.unlink()
        config = owner.docker_config / "config.json"
        if config.exists():
            value = config.lstat()
            require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == os.getuid(), "credential_file_identity")
            config.unlink()
        fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"{}\n"); stream.flush(); os.fsync(stream.fileno())
        require(document(read(config, 1024)) == {} and not list(owner.evidence.glob("stdin-*")), "credential_disposition")
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(signum, stopped)
    signal.setitimer(signal.ITIMER_REAL, max(.001, hard - time.monotonic()))
    try:
        try:
            require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
                    and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                    and os.environ.get("GITHUB_REF") == "refs/heads/main", "manual_own_repository")
            revision = os.environ.get("GITHUB_SHA", "")
            run_id = os.environ.get("GITHUB_RUN_ID", "")
            attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
            require(re.fullmatch(r"[0-9a-f]{40}", revision) and re.fullmatch(r"[1-9][0-9]*", run_id)
                    and re.fullmatch(r"[1-9][0-9]*", attempt), "github_identity")
            require(isinstance(token, str) and 0 < len(token) <= 16384 and "\n" not in token and "\r" not in token
                    and isinstance(actor, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", actor), "scoped_publication_token")
            original_source = source_identity()
            verify = owner_module()
            context_identity(Path.cwd() / "tools/generator-context")
            probe_raw = read(Path.cwd() / ".generator-public/receipt.json", 65536)
            prior = document(probe_raw)
            require(prior["schema_version"] == 1 and prior["state"] == "passed"
                    and prior["scope"] == "public_generator_identity_and_cleanup_only"
                    and prior["source_revision"] == revision and prior["origin_context_digest"] == CONTEXT_SHA
                    and prior["context_files"] == CONTEXT and prior["owned_cli_closed"] is True
                    and prior["owned_container_absent"] is True and prior["sdk_qualified"] is False
                    and prior["abi_qualified"] is False and prior["build_provenance_verified_by_probe"] is False
                    and prior["budget_seconds"] == 120 and prior["probe_source_sha256"] == original_source, "successful_probe_join")
            tools_identity(prior["tools"])
            root = Path.cwd() / ".generator-publication-private"
            root.mkdir(mode=0o700, exist_ok=True)
            require(root.is_dir() and not root.is_symlink() and root.stat().st_uid == os.getuid()
                    and stat.S_IMODE(root.stat().st_mode) == 0o700, "private_evidence_root")
            evidence = root / operation
            evidence.mkdir(mode=0o700)
            owner = verify.Owner(evidence, started=hard - 3900)
            current = verify.document(owner.docker(["image", "inspect", IMAGE]))[0]
            image_id = image_identity(current)
            require(image_id == prior["image_id"] and not output.exists() and not output.is_symlink(), "probed_image_identity")
            clock()
            try:
                owner.docker(["login", "ghcr.io", "--username", actor, "--password-stdin"], 30, data=(token + "\n").encode())
            finally:
                token = None
                for path in owner.evidence.glob("stdin-*"):
                    value = path.lstat()
                    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == os.getuid(), "credential_file_identity")
                    path.unlink()
            tag = REGISTRY + ":source-" + revision + "-" + operation.replace("-", "")
            owner.docker(["tag", image_id, tag])
            pushed = owner.docker(["push", tag], min(180, owner.remaining(180)))
            matches = re.findall(rb"(?:^|\n)[^\n]*digest: (sha256:[0-9a-f]{64}) size: [0-9]+(?:\n|$)", pushed)
            require(len(matches) == 1, "push_digest_shape")
            manifest_digest = matches[0].decode()
            generator_ref = REGISTRY + "@" + manifest_digest
            owner.docker(["logout", "ghcr.io"], 10)
            remove_credentials(); credentials_removed = True
            anonymous = verify.document(owner.command([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                        "--anonymous-child", manifest_digest, image_id], min(60, owner.remaining(60))), 2 * 1024**2)
            require(anonymous["manifest_digest"] == manifest_digest and anonymous["image_id"] == image_id,
                    "anonymous_registry_join")
            require(image_identity({"Id": image_id, **{key: anonymous[key] for key in ("Architecture", "Os", "Config")}})
                    == image_id, "registry_image_contract")
            owner.docker(["pull", generator_ref], min(90, owner.remaining(90)))
            pulled = verify.document(owner.docker(["image", "inspect", generator_ref]))[0]
            require(image_identity(pulled) == image_id and generator_ref in pulled.get("RepoDigests", []), "immutable_pull_join")
            require(image_identity(verify.document(owner.docker(["image", "inspect", IMAGE]))[0]) == image_id, "local_tag_drift")
            require(owner.close() and all(row["reaped"] and row["group_closed"] for row in owner.children)
                    and not owner.containers, "publication_cli_cleanup")
            context_identity(Path.cwd() / "tools/generator-context")
            require(read(Path.cwd() / ".generator-public/receipt.json", 65536) == probe_raw, "probe_receipt_drift")
            require(source_identity() == original_source, "probe_source_drift"); clock()
            receipt = {"schema_version": 1, "state": "PUBLIC_GENERATOR_PUBLISHED_NOT_SDK_QUALIFIED",
                "scope": "public_generator_registry_identity_and_publication_cli_cleanup_only",
                "operation_id": operation, "repository": REPOSITORY, "source_revision": revision,
                "github_run_id": run_id, "github_run_attempt": attempt, "generator_ref": generator_ref,
                "manifest_digest": manifest_digest, "manifest_media_type": anonymous["manifest_media_type"],
                "image_id": image_id, "image_environment": pulled["Config"]["Env"],
                "probe_receipt_sha256": digest(probe_raw), "probe_source_sha256": original_source,
                "owner_source_sha256": OWNER_SHA, "context_digest": CONTEXT_SHA,
                "context_files": CONTEXT, "tools": prior["tools"],
                "host_resources_before": prior["host_resources_before"], "host_resources_after": prior["host_resources_after"],
                "owned_publication_cli_closed": True, "publication_credentials_removed": credentials_removed,
                "anonymous_registry_read": True, "build_daemon_scope": "github_managed_not_independently_closed",
                "sdk_qualified": False, "abi_qualified": False, "budget_seconds": 300}
        except Exception:
            primary = "publication_failed_or_unknown"
        finally:
            if owner is not None:
                try:
                    if not owner.close(): primary = primary or "publication_cleanup_unknown"
                except Exception:
                    primary = primary or "publication_cleanup_unknown"
                try:
                    remove_credentials(); credentials_removed = True
                except Exception:
                    primary = primary or "credential_disposition_unknown"
            if STOP is not None: primary = primary or "publication_interrupted"
        if primary is None and receipt is not None:
            clock(); verify.save(output, receipt); clock()
            print(canonical({"schema_version": 1, "state": receipt["state"], "sdk_qualified": False}).decode(), end="", flush=True)
            clock(); code = 0
        else:
            print(canonical({"schema_version": 1, "state": "failed", "code": primary or "publication_failed_or_unknown"}).decode(), end="", flush=True)
    except Exception:
        code = 1
    finally:
        if code == 0 and (STOP is not None or time.monotonic() >= hard - 30): code = 1
        signal.setitimer(signal.ITIMER_REAL, 0)
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM): signal.signal(signum, signal.SIG_DFL)
    if code == 0 and (STOP is not None or time.monotonic() >= hard - 30): return 1
    return code

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True, choices=("check", "probe", "publish"))
    args = parser.parse_args(argv)
    if args.phase == "check":
        context_identity(Path.cwd() / "tools/generator-context")
        owner_module()
        print(canonical({"schema_version": 1, "state": "PUBLIC_GENERATOR_CONTEXT_CHECKED_NOT_QUALIFIED"}).decode(), end="")
        return 0
    return probe_main() if args.phase == "probe" else publish_main()


def entry(argv):
    if len(argv) == 3 and argv[0] == "--anonymous-child":
        try:
            anonymous_child(argv[1], argv[2])
        except Exception:
            return 1
        return 0
    return main(argv)


if __name__ == "__main__":
    raise SystemExit(entry(sys.argv[1:]))
