#!/usr/bin/env python3
"""Publish only a freshly probed public toolchain; never qualify an SDK.

Root owns adoption and dispatch. GitHub owns the build daemon. This helper owns
its publication CLI sessions and credential files, under 300/270/30 seconds.
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
REGISTRY = "ghcr.io/fvlvte/harmony-studio-projects/compiler"
IMAGE = "harmony-public-toolchain:unqualified"
PROBE_SHA = "d9d854d8352f35f11967619cdbdfd1766c020071867cea6c6a46a6ae4b50e957"
OWNER_SHA = "16e6a7a77ca5e1c6fc443514e9207a6a4ee82da6780613f6c2bc9aea6bb54bd3"
STOP = None


def require(value, code):
    if not value:
        raise ValueError(code)


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
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k)
                for k in fields), "input_drift")
        return bytes(raw)
    finally:
        os.close(fd)


def probe_module():
    path = Path(__file__).resolve().with_name("probe_toolchain.py")
    raw = read(path, 128 * 1024)
    require(digest(raw) == PROBE_SHA, "probe_source_drift")
    spec = importlib.util.spec_from_file_location("publication_probe", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


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
    query = urllib.parse.urlencode({"service": "ghcr.io", "scope": "repository:fvlvte/harmony-studio-projects/compiler:pull"})
    token_raw, _ = fetched("token?" + query, 65536)
    token_document = document(token_raw)
    token = token_document.get("token") or token_document.get("access_token")
    require(isinstance(token, str) and 0 < len(token) <= 16384
            and "\r" not in token and "\n" not in token, "anonymous_registry_token")
    headers = {"Authorization": "Bearer " + token,
               "Accept": "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"}
    raw, response_headers = fetched("v2/fvlvte/harmony-studio-projects/compiler/manifests/" + manifest_digest, 2 * 1024**2, headers)
    require("sha256:" + digest(raw) == manifest_digest, "manifest_body_digest")
    returned = next((v for k, v in response_headers.items() if k.lower() == "docker-content-digest"), None)
    require(returned == manifest_digest, "manifest_header_digest")
    manifest = document(raw)
    require(manifest.get("schemaVersion") == 2 and type(manifest["schemaVersion"]) is int
            and manifest.get("mediaType") in {"application/vnd.oci.image.manifest.v1+json",
                "application/vnd.docker.distribution.manifest.v2+json"}
            and "manifests" not in manifest and manifest["config"]["digest"] == image_id,
            "single_manifest_config_join")
    raw, _ = fetched("v2/fvlvte/harmony-studio-projects/compiler/blobs/" + image_id, 2 * 1024**2,
                     {"Authorization": "Bearer " + token}, blob=True)
    require("sha256:" + digest(raw) == image_id, "image_config_body_digest")
    config = document(raw)
    print(canonical({"manifest_digest": manifest_digest, "image_id": image_id,
                     "manifest_media_type": manifest["mediaType"],
                     "Architecture": config["architecture"], "Os": config["os"],
                     "Config": config["config"]}).decode(), end="", flush=True)


def main(argv=None):
    global STOP
    started = time.monotonic()
    hard = started + 300
    token = os.environ.pop("GHCR_PUBLISH_TOKEN", None)
    actor = os.environ.pop("GHCR_PUBLISH_ACTOR", None)
    owner = None
    verify = None
    receipt = None
    output = Path.cwd() / ".toolchain-public/registry.json"
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
            require(not argv, "no_dispatch_parameters")
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
            probe = probe_module()
            verify = probe.owner_module()
            require(probe.OWNER_SHA == OWNER_SHA, "owner_source_drift")
            probe.context_identity(Path.cwd() / "toolchain")
            probe_raw = read(Path.cwd() / ".toolchain-public/receipt.json", 65536)
            prior = document(probe_raw)
            require(prior["schema_version"] == 1 and prior["state"] == "passed"
                    and prior["scope"] == "public_toolchain_identity_and_cleanup_only"
                    and prior["source_revision"] == revision and prior["origin_context_digest"] == probe.CONTEXT_SHA
                    and prior["context_files"] == probe.CONTEXT and prior["owned_cli_closed"] is True
                    and prior["owned_container_absent"] is True and prior["sdk_qualified"] is False
                    and prior["abi_qualified"] is False and prior["build_provenance_verified_by_probe"] is False
                    and prior["budget_seconds"] == 120, "successful_probe_join")
            probe.compiler_identity(prior["compiler"])
            root = Path.cwd() / ".toolchain-publication-private"
            root.mkdir(mode=0o700, exist_ok=True)
            require(root.is_dir() and not root.is_symlink() and root.stat().st_uid == os.getuid()
                    and stat.S_IMODE(root.stat().st_mode) == 0o700, "private_evidence_root")
            evidence = root / operation
            evidence.mkdir(mode=0o700)
            owner = verify.Owner(evidence, started=hard - 3900)
            current = verify.document(owner.docker(["image", "inspect", IMAGE]))[0]
            image_id = probe.image_identity(current)
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
            compiler_ref = REGISTRY + "@" + manifest_digest
            owner.docker(["logout", "ghcr.io"], 10)
            remove_credentials(); credentials_removed = True
            anonymous = verify.document(owner.command([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                        "--anonymous-child", manifest_digest, image_id], min(60, owner.remaining(60))), 2 * 1024**2)
            require(anonymous["manifest_digest"] == manifest_digest and anonymous["image_id"] == image_id,
                    "anonymous_registry_join")
            require(probe.image_identity({"Id": image_id, **{key: anonymous[key] for key in ("Architecture", "Os", "Config")}})
                    == image_id, "registry_image_contract")
            owner.docker(["pull", compiler_ref], min(90, owner.remaining(90)))
            pulled = verify.document(owner.docker(["image", "inspect", compiler_ref]))[0]
            require(probe.image_identity(pulled) == image_id and compiler_ref in pulled.get("RepoDigests", []), "immutable_pull_join")
            require(probe.image_identity(verify.document(owner.docker(["image", "inspect", IMAGE]))[0]) == image_id, "local_tag_drift")
            require(owner.close() and all(row["reaped"] and row["group_closed"] for row in owner.children)
                    and not owner.containers, "publication_cli_cleanup")
            probe.context_identity(Path.cwd() / "toolchain")
            require(read(Path.cwd() / ".toolchain-public/receipt.json", 65536) == probe_raw, "probe_receipt_drift")
            probe_module(); clock()
            receipt = {"schema_version": 1, "state": "PUBLIC_TOOLCHAIN_PUBLISHED_NOT_SDK_QUALIFIED",
                "scope": "public_toolchain_registry_identity_and_publication_cli_cleanup_only",
                "operation_id": operation, "repository": REPOSITORY, "source_revision": revision,
                "github_run_id": run_id, "github_run_attempt": attempt, "compiler_ref": compiler_ref,
                "manifest_digest": manifest_digest, "manifest_media_type": anonymous["manifest_media_type"],
                "image_id": image_id, "image_environment": pulled["Config"]["Env"],
                "probe_receipt_sha256": digest(probe_raw), "probe_source_sha256": PROBE_SHA,
                "owner_source_sha256": OWNER_SHA, "context_digest": probe.CONTEXT_SHA,
                "context_files": probe.CONTEXT, "compiler": prior["compiler"], "host_tools": prior["host_tools"],
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


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--anonymous-child":
        try:
            anonymous_child(sys.argv[2], sys.argv[3])
        except Exception:
            raise SystemExit(1)
    else:
        raise SystemExit(main(sys.argv[1:]))
