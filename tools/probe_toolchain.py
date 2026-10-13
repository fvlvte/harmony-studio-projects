#!/usr/bin/env python3
"""One public toolchain identity probe; no SDK/build/publication qualification.

The caller separately owns the image build and its daemon lifecycle. This probe
owns one isolated container and its CLI groups, under one 120-second deadline.
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
import subprocess
import sys
import time
import uuid

IMAGE = "harmony-public-toolchain:unqualified"
OWNER_SHA = "8f25f44fa4803855e562d1b25b5ca2bef85ad9c93963d120be57649d60702381"
CONTEXT = [{'path': '.dockerignore', 'bytes': 109, 'sha256': '5458823ca8d5515f72bc59af26980774f2967bb0e166e5baa27d015e1d241c90'}, {'path': 'Dockerfile', 'bytes': 1525, 'sha256': '7d2dd2c7a6565aa81d03c7db45cad52ac27c81d6dfd1cecd616cb842e5302c20'}, {'path': 'README.md', 'bytes': 3188, 'sha256': '94637eea115d8c8756b63ca11ea4ecf4ce5fa743323c1eed42f82c6678d37842'}]
CONTEXT_SHA = '81eeed9ce37a094030fc2b5d1921c2c8bee191df7486a4c3bde00e4aec0d3734'
ENV = {"PATH": "/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin", "RUSTUP_HOME": "/usr/local/rustup",
       "CARGO_HOME": "/usr/local/cargo", "RUST_VERSION": "1.98.1", "RUSTUP_AUTO_INSTALL": "0",
       "HOME": "/tmp/home", "LANG": "C.UTF-8"}
LABELS = {'org.opencontainers.image.source': 'https://github.com/fvlvte/harmony-studio-projects', 'online.harmony.upstream.source': 'https://github.com/rust-lang/docker-rust', 'org.opencontainers.image.base.name': 'docker.io/library/rust:1.98.1-slim-bookworm', 'org.opencontainers.image.base.digest': 'sha256:3ebe98baef5911f8461cf81ba05644374a3c5ef1f8a33db3977bd4175f5ff1fc', 'online.harmony.role': 'public-sdk-toolchain', 'online.harmony.contract': 'public-toolchain-pilot/v1', 'online.harmony.qualification': 'unqualified'}
GUEST_ENV = {**ENV, "CARGO_HOME": "/tmp/cargo"}
SHA = re.compile(r"[0-9a-f]{64}\Z")
STOP = None


class Refused(ValueError):
    pass


def require(value, code):
    if not value: raise Refused(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def file_hash(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, "file_identity")
        hasher = hashlib.sha256(); size = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block: break
            size += len(block); require(size <= maximum, "file_bound"); hasher.update(block)
        after = os.fstat(fd); visible = path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(size == before.st_size and all(getattr(before, k) == getattr(after, k) == getattr(visible, k)
                for k in fields), "file_drift")
        return {"bytes": size, "sha256": hasher.hexdigest()}
    finally: os.close(fd)


def context_identity(path):
    require(path.is_dir() and not path.is_symlink() and {p.name for p in path.iterdir()} == {v["path"] for v in CONTEXT},
            "public_context_inventory")
    actual = [{"path": row["path"], **file_hash(path / row["path"], 65536)} for row in CONTEXT]
    require(actual == CONTEXT and hashlib.sha256(canonical(actual)).hexdigest() == CONTEXT_SHA, "public_context_drift")
    return CONTEXT_SHA


def owner_module():
    path = Path(__file__).resolve().with_name("ci_verify.py")
    require(file_hash(path, 128 * 1024)["sha256"] == OWNER_SHA, "owner_source_drift")
    # Compile the same pinned bytes, not a second pathname import/cache lookup.
    raw = path.read_bytes(); require(hashlib.sha256(raw).hexdigest() == OWNER_SHA, "owner_source_drift")
    spec = importlib.util.spec_from_file_location("toolchain_probe_owner", path)
    module = importlib.util.module_from_spec(spec); exec(compile(raw, str(path), "exec"), module.__dict__)
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
    require(config.get("User") == "65532:65532" and config.get("Entrypoint") == ["/usr/bin/env"]
            and config.get("Cmd") == ["cargo", "+1.98.1", "--version"] and config.get("WorkingDir") == "/tmp"
            and config.get("Labels") == LABELS and environment(config.get("Env")) == ENV
            and not config.get("Volumes") and not config.get("ExposedPorts") and not config.get("OnBuild")
            and not config.get("Healthcheck"), "image_contract")
    return value["Id"]


GUEST = r'''
import hashlib,json,os,pathlib,re,stat,subprocess
def out(argv):
    value=subprocess.run(argv,check=True,capture_output=True,text=True,timeout=5).stdout.strip()
    assert len(value)<=16384
    return value
def hashed(path,maximum=256*1024**2):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);assert stat.S_ISREG(before.st_mode) and 0<before.st_size<=maximum
        total=0;digest=hashlib.sha256()
        while True:
            block=os.read(fd,1024*1024)
            if not block:break
            total+=len(block);assert total<=maximum;digest.update(block)
        after=os.fstat(fd);visible=path.lstat()
        assert total==before.st_size and all(getattr(before,k)==getattr(after,k)==getattr(visible,k) for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns'))
        return total,digest.hexdigest()
    finally:os.close(fd)
actual=pathlib.Path(out(['rustup','which','--toolchain','1.98.1','rustc'])).resolve(strict=True)
verbose=out([str(actual),'-vV'])+'\n'
fields=dict(line.split(': ',1) for line in verbose.splitlines()[1:])
assert fields['release']=='1.98.1' and fields['host']=='aarch64-unknown-linux-gnu'
root=pathlib.Path(out([str(actual),'--print','sysroot'])).resolve(strict=True)
items=[];total=0;counts={}
for target in ('aarch64-unknown-linux-gnu','wasm32-unknown-unknown'):
    base=root/'lib/rustlib'/target/'lib';count=0
    assert base.is_dir() and not base.is_symlink()
    for path in sorted(base.iterdir()):
        assert re.fullmatch(r'[A-Za-z0-9._+-]+',path.name)
        size,sha=hashed(path);total+=size;assert total<=2*1024**3
        items.append({'path':str(path.relative_to(root)),'bytes':size,'sha256':sha});count+=1
    assert count>0;counts[target]=count
encoded=(json.dumps(items,sort_keys=True,separators=(',',':'))+'\n').encode()
packages={}
for line in out(['dpkg-query','-W','-f','${Package}\t${Version}\n','python3','ca-certificates','libc6']).splitlines():
    name,version=line.split('\t');assert name in ('python3','ca-certificates','libc6') and name not in packages
    assert re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,128}',version);packages[name]=version
assert set(packages)=={'python3','ca-certificates','libc6'}
tools={name:out(argv) for name,argv in {'cargo':['cargo','+1.98.1','--version'],'rustup':['rustup','--version'],'python':['python3','--version']}.items()}
assert all(re.fullmatch(r'[A-Za-z0-9 .()+:_-]{1,256}',v) for v in tools.values())
print(json.dumps({'release':fields['release'],'host':fields['host'],'verbose_version':verbose,'executable_sha256':hashed(actual)[1],
 'sysroot_sha256':hashlib.sha256(encoded).hexdigest(),'sysroot_files':counts,'sysroot_bytes':total,'packages':packages,'tools':tools},sort_keys=True))
'''


def container_arguments(image, operation):
    name = "harmony-toolchain-probe-" + uuid.uuid4().hex
    row = {"name": name, "image": image, "operation": operation, "absent": False}
    args = ["create", "--name", name, "--label", "online.harmony.operation=" + operation,
        "--network", "none", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--memory", "512m", "--memory-swap", "512m",
        "--cpus", "1", "--cpuset-cpus", "0", "--pids-limit", "64", "--ipc", "private", "--cgroupns", "private",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777", "--workdir", "/tmp",
        "--entrypoint", "/usr/bin/env", image, "-i", *(key + "=" + value for key, value in GUEST_ENV.items()),
        "python3", "-I", "-B", "-c", GUEST]
    return row, args


def container_identity(value, row):
    config, host = value["Config"], value["HostConfig"]
    require(value.get("Id") == row["cid"] and value.get("Name") == "/" + row["name"] and value.get("Image") == row["image"]
            and config.get("Labels") == {**LABELS, "online.harmony.operation": row["operation"]}
            and config.get("User") == "65532:65532" and config.get("Entrypoint") == ["/usr/bin/env"]
            and config.get("Cmd") == ["-i", *(key + "=" + value for key, value in GUEST_ENV.items()), "python3", "-I", "-B", "-c", GUEST]
            and environment(config.get("Env")) == ENV and config.get("WorkingDir") == "/tmp" and not config.get("Volumes"),
            "container_identity")
    mounts = value.get("Mounts")
    require(isinstance(mounts, list) and len(mounts) <= 1
            and all(m.get("Type") == "tmpfs" and m.get("Destination") == "/tmp" and m.get("RW") is True
                    and not m.get("Source") for m in mounts)
            and host.get("Binds") in (None, []) and host.get("Mounts") in (None, [])
            and host.get("NetworkMode") == "none" and host.get("ReadonlyRootfs") is True and host.get("Privileged") is False
            and host.get("CapDrop") == ["ALL"] and not host.get("CapAdd") and host.get("SecurityOpt") == ["no-new-privileges"]
            and host.get("Memory") == 512 * 1024**2 and host.get("MemorySwap") == 512 * 1024**2
            and host.get("NanoCpus") == 1_000_000_000 and host.get("CpusetCpus") == "0" and host.get("PidsLimit") == 64
            and host.get("PidMode") == "" and host.get("IpcMode") == "private" and host.get("CgroupnsMode") == "private"
            and not host.get("Devices") and not host.get("DeviceRequests") and not host.get("PortBindings")
            and not host.get("PublishAllPorts") and host.get("Tmpfs") == {"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"},
            "container_sandbox")


def compiler_identity(value):
    require(isinstance(value, dict) and set(value) == {"release", "host", "verbose_version", "executable_sha256",
            "sysroot_sha256", "sysroot_files", "sysroot_bytes", "packages", "tools"}, "probe_output_shape")
    verbose = value["verbose_version"]
    require(value["release"] == "1.98.1" and value["host"] == "aarch64-unknown-linux-gnu"
            and isinstance(verbose, str) and len(verbose) <= 2048, "probe_toolchain_version")
    lines = verbose.splitlines()
    first = re.fullmatch(r"rustc 1\.98\.1 \(([0-9a-f]{7,40}) ([0-9]{4}-[0-9]{2}-[0-9]{2})\)", lines[0]) if lines else None
    require(len(lines) == 7 and first is not None
            and lines[-2:] == ["release: 1.98.1", lines[-1]] and lines[-1].startswith("LLVM version: "), "probe_verbose_version")
    fields = dict(line.split(": ", 1) for line in lines[1:])
    require(set(fields) == {"binary", "commit-hash", "commit-date", "host", "release", "LLVM version"}
            and fields["binary"] == "rustc" and fields["host"] == value["host"]
            and re.fullmatch(r"[0-9a-f]{40}", fields["commit-hash"]) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", fields["commit-date"])
            and fields["commit-hash"].startswith(first.group(1)) and fields["commit-date"] == first.group(2)
            and re.fullmatch(r"[0-9.]{1,20}", fields["LLVM version"]), "probe_verbose_version")
    require(all(isinstance(value[key], str) and SHA.fullmatch(value[key]) for key in ("executable_sha256", "sysroot_sha256"))
            and type(value["sysroot_bytes"]) is int and 0 < value["sysroot_bytes"] <= 2 * 1024**3
            and isinstance(value["sysroot_files"], dict) and set(value["sysroot_files"]) == {"aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"}
            and all(type(v) is int and 0 < v <= 4096 for v in value["sysroot_files"].values()), "probe_hash_inventory")
    require(isinstance(value["packages"], dict) and set(value["packages"]) == {"python3", "ca-certificates", "libc6"}
            and all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", v) for v in value["packages"].values())
            and isinstance(value["tools"], dict) and set(value["tools"]) == {"cargo", "rustup", "python"}
            and all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9 .()+:_-]{1,256}", v) for v in value["tools"].values()), "probe_package_versions")
    return value


def host_tools():
    result = {}
    for name in ("git", "git-crypt"):
        path = Path("/usr/bin") / name
        if not path.exists(): result[name] = {"state": "not_installed", "version_probe": "NOT_RUN"}
        else:
            require(os.access(path, os.X_OK), "host_tool_executable")
            result[name] = {"state": "installed", **file_hash(path, 64 * 1024**2), "version_probe": "NOT_RUN"}
    return result


def main(argv=None):
    global STOP
    started = time.monotonic(); hard = started + 120
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True); parser.add_argument("--context", required=True)
    parser.add_argument("--output", required=True); args = parser.parse_args(argv)
    owner = None; verify = None; result = None; primary = None; scope = False; code = 1; public_created = False
    operation = str(uuid.uuid4()); STOP = None
    def clock():
        require(STOP is None, "interrupted")
        require(time.monotonic() < hard, "probe_deadline")
    def stopped(signum, frame):
        global STOP
        if STOP is None: STOP = signum
        if verify is not None and verify.STOP is None: verify.STOP = signum
    def failure(reason):
        nonlocal primary, result
        primary = primary or reason
        result = {"schema_version": 1, "operation_id": operation, "state": "failed", "code": primary,
                  "scope": "public_toolchain_identity_and_cleanup_only", "sdk_qualified": False}
    try:
        try:
            scope = True
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM): signal.signal(signum, stopped)
            signal.signal(signal.SIGCHLD, signal.SIG_DFL)
            signal.setitimer(signal.ITIMER_REAL, max(0.001, hard - time.monotonic()))
            require(args.image == IMAGE and args.context == "toolchain" and args.output == ".toolchain-public/receipt.json", "probe_arguments")
            context_identity(Path.cwd() / args.context); clock()
            verify = owner_module(); verify.STOP = STOP
            before = verify.linux_resources(); clock()
            private = Path.cwd() / ".toolchain-private"; private.mkdir(mode=0o700, exist_ok=True)
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
            compiler = compiler_identity(verify.document(raw, 16384))
            state = owner.inspect(cid)["State"]
            require(state.get("Running") is False and state.get("ExitCode") == 0 and state.get("OOMKilled") is False, "container_exit")
            require(image_identity(verify.document(owner.docker(["image", "inspect", IMAGE]))[0]) == image, "image_tag_drift")
            require(owner.close(), "cleanup_unknown"); clock()
            after = verify.linux_resources(); tools = host_tools(); context_identity(Path.cwd() / "toolchain"); clock()
            revision = os.environ.get("GITHUB_SHA", "")
            require(not revision or re.fullmatch(r"[0-9a-f]{40}", revision), "source_revision")
            require(owner.children and all(r["reaped"] and r["group_closed"] for r in owner.children)
                    and len(owner.containers) == 1 and row.get("absent") is True, "owned_closure")
            result = {"schema_version": 1, "operation_id": operation, "state": "passed",
                "scope": "public_toolchain_identity_and_cleanup_only", "sdk_qualified": False, "abi_qualified": False,
                "build_provenance_verified_by_probe": False, "source_revision": revision, "image_id": image,
                "origin_context_digest": CONTEXT_SHA, "context_files": CONTEXT, "compiler": compiler,
                "host_resources_before": before, "host_resources_after": after, "host_tools": tools,
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
            public = Path.cwd() / ".toolchain-public"; public.mkdir(mode=0o700); public_created = True
            require(not public.is_symlink(), "public_destination")
            verify = verify or owner_module()
            verify.save(public / "receipt.json", result)
            if result["state"] == "passed": clock()
            print(canonical({"schema_version": 1, "state": result["state"], "scope": result["scope"]}).decode(), end="", flush=True)
            if result["state"] == "passed": clock()
            code = 0 if result["state"] == "passed" else 1
        except Exception:
            failure("receipt_or_deadline_unknown"); code = 1
            if verify is not None and public_created:
                try: verify.save(Path.cwd() / ".toolchain-public/receipt.json", result)
                except Exception: pass
            try: print(canonical({"schema_version": 1, "state": "failed", "scope": result["scope"], "code": primary}).decode(), end="", flush=True)
            except OSError: pass
    finally:
        if result is not None and result["state"] == "passed" and (STOP is not None or time.monotonic() >= hard):
            failure("probe_deadline"); code = 1
            if verify is not None and public_created:
                try: verify.save(Path.cwd() / ".toolchain-public/receipt.json", result)
                except Exception: pass
        if scope:
            signal.setitimer(signal.ITIMER_REAL, 0)
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM): signal.signal(signum, signal.SIG_DFL)
    if code == 0 and (STOP is not None or time.monotonic() >= hard): return 1
    return code


if __name__ == "__main__": raise SystemExit(main())
