"""Validate fresh csfc-evidence/v1 bundles without inferring compliance."""
from datetime import datetime
from pathlib import Path
import argparse
import hashlib
import json

SCHEMA = "csfc-evidence/v1"
CATEGORIES = ("devices", "interfaces", "links", "routes", "filters", "tunnels", "credentials", "probes")
STATUSES = {"observed", "configured", "unavailable", "failed", "not_applicable"}
MANIFEST_FIELDS = {"schema_version", "snapshot_id", "run_id", "configuration_id", "emulation_id", "source_case_ids", "requirement_group_ids", "started_at", "ended_at", "host", "software", "code_hashes", "configuration_hashes", "files", "collection_failures", "sanitization", "inventory_complete", "convergence"}
SNAPSHOT_FIELDS = {"schema_version", "snapshot_id", "scope", *CATEGORIES, "management", "observations", "limitations"}
SUPPORTED_MATCHES = {"source_device", "destination_device", "protocol", "family", "source_port", "destination_port", "ingress_interface", "egress_interface"}
SUPPORTED_ACTIONS = {"accept", "drop", "reject"}

class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def utc(value):
    require(isinstance(value, str), "timestamp must be a string")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("invalid timestamp: " + value) from exc
    require(result.tzinfo is not None and result.utcoffset().total_seconds() == 0, "timestamp must carry UTC offset")
    return result


def safe_path(root, relative):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute(), "bundle path must be nonempty and relative")
    require(".." not in Path(relative).parts, "bundle path traversal")
    current = root
    for part in Path(relative).parts:
        current = current / part
        require(not current.is_symlink(), "bundle symlink forbidden: " + relative)
    resolved = current.resolve()
    require(resolved.is_relative_to(root.resolve()), "bundle path escapes root")
    require(resolved.is_file(), "missing bundle file: " + relative)
    return resolved


def unique_records(records, label):
    require(isinstance(records, list), label + " must be an array")
    result = {}
    for record in records:
        require(isinstance(record, dict), label + " record must be an object")
        identity = record.get("id")
        require(isinstance(identity, str) and identity, label + " record lacks nonempty id")
        require(identity not in result, "duplicate " + label + " id: " + identity)
        result[identity] = record
    return result


def complete_entry(value, name):
    require(isinstance(value, dict), "inventory_complete." + name + " must be {complete: bool, reason: string}")
    require(type(value.get("complete")) is bool, "inventory completeness must be a boolean")
    require(isinstance(value.get("reason"), str) and value["reason"].strip(), "inventory completeness requires reason")
    return value["complete"]


def validate_bundle(bundle):
    root = Path(bundle)
    manifest = json.loads(safe_path(root, "manifest.json").read_text())
    snapshot = json.loads(safe_path(root, "snapshot.json").read_text())
    require(MANIFEST_FIELDS <= manifest.keys(), "missing manifest fields: " + str(sorted(MANIFEST_FIELDS - manifest.keys())))
    require(SNAPSHOT_FIELDS <= snapshot.keys(), "missing snapshot fields: " + str(sorted(SNAPSHOT_FIELDS - snapshot.keys())))
    require(manifest["schema_version"] == snapshot["schema_version"] == SCHEMA, "unsupported schema version")
    require(manifest["snapshot_id"] == snapshot["snapshot_id"], "snapshot identity mismatch")
    require(utc(manifest["started_at"]) <= utc(manifest["ended_at"]), "reversed collection interval")
    files = {}
    for entry in manifest["files"]:
        require({"path", "sha256", "bytes", "category"} <= entry.keys(), "file entry incomplete")
        name = entry["path"]
        require(name not in files, "duplicate manifest path")
        content = safe_path(root, name).read_bytes()
        require(type(entry["bytes"]) is int and len(content) == entry["bytes"], "file size mismatch: " + name)
        require(hashlib.sha256(content).hexdigest() == entry["sha256"], "file hash mismatch: " + name)
        files[name] = entry
    require("snapshot.json" in files, "snapshot.json must be hashed")
    observations = unique_records(snapshot["observations"], "observation")
    for identity, observation in observations.items():
        require({"collector", "device_id", "started_at", "ended_at", "returncode", "raw_path", "raw_sha256", "sanitizer", "parse_status"} <= observation.keys(), "observation fields incomplete: " + identity)
        require("command" in observation or "redacted_command" in observation, "observation command missing")
        require(utc(observation["started_at"]) <= utc(observation["ended_at"]), "reversed observation interval")
        name = observation["raw_path"]
        require(name in files, "observation raw file absent from manifest: " + name)
        require(files[name]["sha256"] == observation["raw_sha256"], "observation hash mismatch")
    indices = {name: unique_records(snapshot[name], name) for name in CATEGORIES}
    all_ids = set()
    for name, index in indices.items():
        for identity, record in index.items():
            require(identity not in all_ids, "cross-category duplicate id: " + identity)
            all_ids.add(identity)
            require(record.get("status") in STATUSES, "unknown or absent record status: " + identity)
            refs = record.get("observation_ids")
            require(isinstance(refs, list) and all(ref in observations for ref in refs), "dangling observation reference: " + identity)
            if record["status"] == "observed":
                require(bool(refs), "observed fact requires provenance: " + identity)
                require(all(observations[ref]["returncode"] == 0 and observations[ref]["parse_status"] == "parsed" for ref in refs), "observed fact depends on failed/unparsed observation: " + identity)
            if "device_id" in record:
                require(record["device_id"] in indices["devices"], "unknown device reference: " + identity)
            for key in ("peer_device_id", "source_device"):
                if key in record:
                    require(record[key] in indices["devices"], "unknown " + key + ": " + identity)
    scope = snapshot["scope"]
    require(isinstance(scope, dict), "scope must be an object")
    completeness = {}
    blockers = []
    for name in (*CATEGORIES, "management"):
        require(name in manifest["inventory_complete"], "missing inventory completeness: " + name)
        completeness[name] = complete_entry(manifest["inventory_complete"][name], name)
    for category, key in (("devices", "expected_device_ids"), ("interfaces", "expected_interface_ids")):
        expected = scope.get(key)
        require(isinstance(expected, list) and len(set(expected)) == len(expected), "missing or duplicate expected inventory: " + key)
        actual = set(indices[category])
        if completeness[category]:
            require(set(expected) == actual, "complete inventory differs from expected: " + category)
            if not actual:
                blockers.append("Empty " + category + " inventory cannot support data-path conclusions")
        else:
            blockers.append("Incomplete " + category + " inventory")
    for identity, interface in indices["interfaces"].items():
        require("device_id" in interface, "interface device missing: " + identity)
    for identity, link in indices["links"].items():
        endpoints = link.get("endpoint_interface_ids")
        require(isinstance(endpoints, list) and len(endpoints) == 2, "link requires two endpoint_interface_ids: " + identity)
        require(all(endpoint in indices["interfaces"] for endpoint in endpoints), "dangling link endpoint: " + identity)
        if link.get("relation") in {"veth", "bridge_attachment", "logical_tunnel"}:
            require(link.get("physical_claim_supported") is not True, "virtual link cannot assert physical separation")
    unsupported = []
    for identity, chain in indices["filters"].items():
        require(isinstance(chain.get("ordered_rules"), list), "filter ordered_rules missing")
        rules = chain["ordered_rules"]
        ordinals = [rule.get("ordinal") for rule in rules]
        require(all(type(n) is int for n in ordinals) and ordinals == sorted(set(ordinals)), "filter rule ordering malformed")
        if chain.get("policy") not in {"accept", "drop"}:
            unsupported.append({"id":identity,"reason":"unsupported chain default"})
        for rule in rules:
            matches = rule.get("matches")
            if not isinstance(matches, dict) or not set(matches) <= SUPPORTED_MATCHES or rule.get("action") not in SUPPORTED_ACTIONS:
                unsupported.append({"id":identity,"ordinal":rule.get("ordinal"),"reason":"unsupported rule semantics; excluded from filter proofs"})
    management = snapshot["management"]
    require(isinstance(management, dict) and {"profile", "applicability", "records", "failures"} <= management.keys(), "management scope incomplete")
    require(isinstance(management["records"], list), "management records must be an array")
    if manifest["collection_failures"]:
        blockers.append("Collection failures require clause-specific review")
    if unsupported:
        blockers.append("Unsupported filters prevent any whole-policy theorem")
    counts = {name:{status:sum(r["status"] == status for r in index.values()) for status in sorted(STATUSES)} for name,index in indices.items()}
    return {"schema_version":"construction-validation-1","snapshot_id":manifest["snapshot_id"],"integrity_valid":True,"counts":counts,"inventory_complete":completeness,"unsupported_filters":unsupported,"data_path_blockers":blockers,"management_profile":management["profile"],"claims":{"physical_independence":False,"implementation_refinement":False,"all_time_behavior":False,"whole_group_establishment":False},"source_manifest_sha256":hashlib.sha256((root/"manifest.json").read_bytes()).hexdigest(),"source_snapshot_sha256":hashlib.sha256((root/"snapshot.json").read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = validate_bundle(args.bundle)
    except (EvidenceError, ValueError, OSError, TypeError, KeyError) as exc:
        report = {"integrity_valid":False,"error":str(exc)}
        if args.output:
            args.output.write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps(report,indent=2))
        raise SystemExit(1)
    if args.output:
        args.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))

if __name__ == "__main__":
    main()
