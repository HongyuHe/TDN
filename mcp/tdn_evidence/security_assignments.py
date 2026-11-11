"""Expose explicit laboratory security labels bound to retained device inventories."""
import hashlib
import json
from pathlib import Path

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "assignments", "decision", "coverage"]
LEAN_VIEW = "security_level_assignments"
SCOPE = "Explicit experimental security labels bound to retained Red-network and Inner-device inventories"


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    declaration = json.loads((root / "policy.json").read_text())
    require(declaration["schema"] == "security-level-assignment/v1"
            and declaration["authority"] == "supervisor-selected-experimental-policy"
            and declaration["evidenceStatus"] == "declared"
            and declaration["realClassificationApproval"] is False,
            "Expected explicit experimental policy with no classification approval claim")
    profiles = declaration["profiles"]
    require(bool(profiles) and len({p["id"] for p in profiles}) == len(profiles),
            "Missing or duplicate policy profiles")
    devices, assignments, coverage = [], [], []
    raw_ids = {"policy": "policy.json"}
    for profile in profiles:
        name = profile["id"]
        require(isinstance(name, str) and name.isidentifier(), "Invalid policy profile ID")
        inputs = {}
        for kind in ["spec", "snapshot"]:
            filename = f"{name}-{kind}.json"
            path = root / filename
            require(hashlib.sha256(path.read_bytes()).hexdigest() == profile[kind + "Sha256"],
                    "Policy source hash differs")
            inputs[kind] = json.loads(path.read_text())
            raw_ids[name + "-" + kind] = filename
        spec, snapshot = inputs["spec"], inputs["snapshot"]
        require(spec["name"] == profile["configurationId"]
                and snapshot["snapshot_id"] == profile["snapshotId"], "Policy identity differs")
        declared = {d["id"]: d for d in spec["devices"]}
        captured = {d["id"]: d for d in snapshot["devices"]}
        require(len(declared) == len(spec["devices"]) and len(captured) == len(snapshot["devices"])
                and set(declared) == set(captured), "Device inventory differs")
        inners = {k: d for k, d in declared.items() if d["role"] == "inner"}
        rows = profile["assignments"]
        require(bool(inners) and len(rows) == len(inners)
                and {r["innerDevice"] for r in rows} == set(inners), "Incomplete Inner assignment inventory")
        for row in rows:
            inner = inners[row["innerDevice"]]
            observed = captured[inner["id"]]
            require(observed["role"] == "inner" and observed["status"] == "observed"
                    and observed["observed_running"] is True
                    and row["profileLevel"] == inner["level"] == observed["security_level_id"]
                    and row["site"] == inner["site"] == observed["site"], "Unbound Inner assignment")
            require(row["network"] == inner["id"] + "/red-network", "Unbound Red network ID")
            level = row["assignedLevel"]
            require(set(level) == {"classification", "compartments", "dissemination", "otherControls"}
                    and isinstance(level["classification"], str) and bool(level["classification"].strip()),
                    "All four security dimensions must be explicit")
            for field in ["compartments", "dissemination", "otherControls"]:
                values = level[field]
                require(isinstance(values, list) and all(isinstance(x, str) and x.strip() for x in values)
                        and len(set(values)) == len(values), "Invalid security-label set")
            devices.append({"id": inner["id"], "role": "inner", "site": inner["site"], "profile": name})
            assignments.append(row | {"profile": name, "device": inner["id"], "evidenceStatus": "declared",
                                      "observation": "policy", "sourceSpec": name + "-spec",
                                      "sourceSnapshot": name + "-snapshot"})
        coverage.append({"profile": name, "innerDevices": len(inners), "assignedNetworks": len(rows),
                         "sourceSnapshotSha256": profile["snapshotSha256"]})
    require(len({r["device"] for r in assignments}) == len(assignments), "Duplicate cross-profile device")
    report = {"devices": devices, "assignments": assignments, "decision": [declaration], "coverage": coverage,
              "rawIds": raw_ids, "manifestSha256": manifest_hash, "projectionVersion": "security-level-assignment-v1",
              "scope": ["Explicit laboratory intent for the listed Red networks and Inner devices.",
                        "Snapshot profile labels identify the devices; assigned dimensions are new declared policy.",
                        "No recovered compartment state, certificate extension or real classification approval is claimed."]}
    return {"runtime_backend": "declared-experimental-policy"}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    require(observation in report["rawIds"], "Unknown security-assignment source")
    return "" if stderr else (Path(directory) / report["rawIds"][observation]).read_text()


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
