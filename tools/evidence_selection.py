"""Private proposed evidence-selection functions; NOT a dispatchable sealer.

No IO, encryption, SDK approval or runtime observation occurs here. The future
maintained caller must obtain these values from its actual owned compile, bind
source/context/receipt hashes, and implement the reviewed lifecycle proposal.
"""
from pathlib import PurePosixPath
import re

TARGET = "wasm32-unknown-unknown"
HOST = "aarch64-unknown-linux-gnu"
MAX_ARTIFACTS, MAX_ARTIFACT, MAX_TOTAL = 4096, 64 << 20, 512 << 20
SHA = re.compile(r"[0-9a-f]{64}\Z")


def require(value, code):
    if not value: raise ValueError(code)


def text(value, maximum=4096):
    require(isinstance(value, str) and 0 < len(value) <= maximum
            and all(ord(c) >= 32 and ord(c) != 127 for c in value), "metadata_string")
    return value


def identifiers(values):
    require(isinstance(values, list) and len(values) <= MAX_ARTIFACTS, "metadata_list")
    return [text(v) for v in values]


def cargo_graph_projection(metadata):
    """Omit arbitrary .metadata, diagnostics, source body and src_path fields."""
    require(isinstance(metadata, dict) and isinstance(metadata.get("packages"), list)
            and isinstance(metadata.get("resolve"), dict), "cargo_graph_shape")
    packages, ids = [], set()
    require(0 < len(metadata["packages"]) <= MAX_ARTIFACTS, "cargo_package_count")
    for package in metadata["packages"]:
        ident = text(package["id"]); require(ident not in ids, "cargo_package_duplicate"); ids.add(ident)
        features = package["features"]
        require(isinstance(features, dict) and len(features) <= MAX_ARTIFACTS, "cargo_features")
        projected = {text(k, 256): identifiers(v) for k, v in features.items()}
        targets = package["targets"]
        require(isinstance(targets, list) and len(targets) <= 128, "cargo_targets")
        packages.append({"id": ident, "name": text(package["name"], 256), "version": text(package["version"], 256),
            "features": projected, "targets": [{"name": text(t["name"], 256), "kind": identifiers(t["kind"]),
                "crate_types": identifiers(t["crate_types"])} for t in targets]})
    nodes = metadata["resolve"]["nodes"]
    require(isinstance(nodes, list) and len(nodes) <= MAX_ARTIFACTS, "cargo_node_count")
    projected_nodes, seen = [], set()
    for node in nodes:
        ident = text(node["id"]); require(ident in ids and ident not in seen, "cargo_node_identity"); seen.add(ident)
        dependencies = identifiers(node["dependencies"])
        require(set(dependencies) <= ids, "cargo_dependency_reference")
        deps = node["deps"]; require(isinstance(deps, list) and len(deps) <= MAX_ARTIFACTS, "cargo_dependency_count")
        edges = []
        for dep in deps:
            require(dep["pkg"] in ids, "cargo_dependency_reference")
            kinds = dep["dep_kinds"]; require(isinstance(kinds, list) and len(kinds) <= 128, "cargo_dependency_kinds")
            edge_kinds = []
            for kind in kinds:
                require(kind["kind"] in (None, "normal", "build", "dev"), "cargo_dependency_kind")
                target = kind["target"]
                edge_kinds.append({"kind": kind["kind"], "target": None if target is None else text(target, 2048)})
            edges.append({"name": text(dep["name"], 256), "pkg": dep["pkg"], "dep_kinds": edge_kinds})
        projected_nodes.append({"id": ident, "dependencies": dependencies, "deps": edges, "features": identifiers(node["features"])})
    root = metadata["resolve"]["root"]
    require(root is None or root in ids, "cargo_root")
    return {"packages": packages, "resolve": {"root": root, "nodes": projected_nodes}}


def exact_artifact_selection(candidate, cargo_receipt):
    require(candidate.get("schema_version") == 1 and candidate.get("state") == "built_not_qualified"
            and candidate.get("resources_closed") is True, "compile_not_successful")
    require(cargo_receipt.get("state") == "COMPILED_CLOSURE_PRODUCED" and cargo_receipt.get("exit_code") == 0
            and cargo_receipt.get("timed_out") is False and cargo_receipt.get("resources_closed") is True
            and cargo_receipt.get("unknown_owners") == [], "compile_not_closed")
    for key in ("source_revision", "authorization_id", "input_inventory_sha256", "environment_policy_sha256",
                "compiler", "target", "features", "profile"):
        require(candidate[key] == cargo_receipt[key], "receipt_context_drift")
    require(candidate["target"] == TARGET and candidate["compiler"]["release"] == "1.98.1"
            and candidate["compiler"]["host"] == HOST, "compiler_target_drift")
    rows, inventory = candidate["files"], candidate["artifact_inventory"]
    require(isinstance(rows, list) and 0 < len(rows) <= MAX_ARTIFACTS and isinstance(inventory, list)
            and len(inventory) == len(rows), "artifact_count")
    expected = {}
    for item in inventory:
        require(set(item) == {"path", "role", "bytes", "sha256"} and item["path"] not in expected
                and type(item["bytes"]) is int and 0 < item["bytes"] <= MAX_ARTIFACT
                and isinstance(item["sha256"], str) and SHA.fullmatch(item["sha256"]), "artifact_inventory")
        expected[item["path"]] = item
    require(sum(item["bytes"] for item in inventory) <= MAX_TOTAL, "artifact_total_bound")
    result, seen = [], set()
    for row in rows:
        path, source = PurePosixPath(row["public_path"]), PurePosixPath(row["compiler_output"])
        require(not path.is_absolute() and len(path.parts) == 3 and path.parts[0] == "lib"
                and path.parts[1] in (TARGET, HOST) and len(path.name) <= 100
                and re.fullmatch(r"[A-Za-z0-9_+-][A-Za-z0-9._+-]*", path.name)
                and not source.is_absolute() and len(source.parts) >= 3 and source.parts[0] == "target"
                and all(p not in ("", ".", "..") for p in source.parts) and source.name == path.name,
                "artifact_path")
        role = row["role"]
        require(role in ("opaque_rlib", "opaque_metadata", "opaque_proc_macro")
                and path.suffix in {"opaque_rlib": {".rlib"}, "opaque_metadata": {".rmeta"},
                                    "opaque_proc_macro": {".so"}}[role]
                and row["target"] == path.parts[1] and (role != "opaque_proc_macro" or row["target"] == HOST), "artifact_role")
        require(str(path) in expected and str(path) not in seen and expected[str(path)]["role"] == role, "artifact_bijection")
        seen.add(str(path)); result.append({"path": str(path), "compiler_output": str(source), **expected[str(path)]})
    require(seen == set(expected), "artifact_bijection")
    return sorted(result, key=lambda v: v["path"])


def owner_closure_projection(owner, operation, source_pins):
    """Snapshot only; caller must already have observed its actual close()."""
    require(not owner.journal_failed and owner.children and len(owner.children) <= 256, "owner_journal_or_count")
    cli = []
    for row in owner.children:
        require(type(row["pid"]) is int and row["pid"] > 0 and row["pgid"] == row["pid"]
                and row["reaped"] is True and row["group_closed"] is True and row["returncode"] == 0, "cli_not_closed")
        cli.append({k: row[k] for k in ("pid", "pgid", "reaped", "group_closed", "returncode")})
    containers = []
    require(len(owner.containers) == 4 and {r["phase"] for r in owner.containers} == {"toolchain", "prefetch", "compile", "metadata"},
            "container_phase_set")
    for row in owner.containers:
        require(row["operation"] == operation and row["absent"] is True and row["identity_verified"] is True
                and re.fullmatch(r"[0-9a-f]{64}", row["cid"]) and re.fullmatch(r"sha256:[0-9a-f]{64}", row["image"]), "container_not_closed")
        containers.append({k: row[k] for k in ("cid", "name", "image", "operation", "phase", "absent", "identity_verified")})
    require(isinstance(source_pins, dict) and source_pins and all(isinstance(v, str) and SHA.fullmatch(v) for v in source_pins.values()),
            "source_pins")
    return {"schema_version": 1, "operation": operation, "state": "COMPILE_OWNER_CLOSURE_SOURCE_SNAPSHOT",
            "source_pins": source_pins, "cli": cli, "containers": containers,
            "kernel_observation_source": "actual retained ci_verify.Owner.close; this projection does not run a new observation"}
