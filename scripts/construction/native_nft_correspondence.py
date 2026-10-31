"""Cross-check complete native nft inventories against raw-bound iptables chains."""
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path

from import_snapshot import parse_rule
from raw_correspondence import check_filter_correspondence
from validate_evidence import require, safe_path, utc


def read_observation(bundle, observation):
    require(observation["returncode"] == 0 and observation["parse_status"] == "parsed",
            "Unsuccessful native nft/identity observation")
    data = safe_path(bundle, observation["raw_path"]).read_bytes()
    require(hashlib.sha256(data).hexdigest() == observation["raw_sha256"],
            "Native nft/identity raw hash differs")
    raw = json.loads(data)
    require(not raw["stderr"].strip(), "Native nft/identity command reported stderr")
    return json.loads(raw["stdout"])


def address(value):
    if isinstance(value, dict):
        require(set(value) == {"prefix"} and set(value["prefix"]) == {"addr", "len"},
                "Unsupported nft address expression")
        value = str(value["prefix"]["addr"]) + "/" + str(value["prefix"]["len"])
    network = ipaddress.ip_network(value, strict=False)
    return network.version, int(network.network_address), int(network.broadcast_address)


def expected_conditions(rule):
    parse_rule(rule)
    tokens = rule["matches"]["iptables_tokens"]
    require(len(tokens) % 2 == 0, "Unpaired native iptables token")
    conditions = []
    for key, value in zip(tokens[::2], tokens[1::2]):
        if key in ["-s", "-d"]:
            conditions.append((key, address(value)))
        elif key in ["-i", "-o", "-p"]:
            conditions.append((key, value))
        elif key == "-m":
            require(value in ["multiport", "policy", "u32", "conntrack"],
                    "Unsupported native compatibility matcher")
            conditions.append(("xt", value))
        else:
            require(key in ["--dports", "--sports", "--dir", "--pol", "--reqid", "--mode", "--u32", "--ctstate"],
                    "Unsupported native match argument")
    return Counter(conditions)


def actual_conditions(expressions, action):
    require(expressions and expressions[-1] == {action: None},
            "Native nft terminal verdict differs")
    conditions = []
    for expression in expressions[:-1]:
        require(len(expression) == 1, "Ambiguous nft expression")
        if "counter" in expression:
            require(set(expression["counter"]) == {"packets", "bytes"}, "Unsupported nft counter")
            continue
        if "xt" in expression:
            require(set(expression["xt"]) == {"name", "type"} and expression["xt"]["type"] == "match",
                    "Unsupported nft compatibility action")
            conditions.append(("xt", expression["xt"]["name"]))
            continue
        require(set(expression) == {"match"}, "Unmodeled nft action or expression")
        match = expression["match"]
        require(set(match) == {"op", "left", "right"} and match["op"] == "==",
                "Unsupported nft match operation")
        left, right = match["left"], match["right"]
        if left in [{"meta": {"key": "iifname"}}, {"meta": {"key": "oifname"}}]:
            conditions.append(("-i" if left["meta"]["key"] == "iifname" else "-o", right))
        else:
            require(set(left) == {"payload"} and set(left["payload"]) == {"protocol", "field"} and
                    left["payload"]["protocol"] in ["ip", "ip6"], "Unsupported native nft payload matcher")
            field = left["payload"]["field"]
            require(field in ["saddr", "daddr", "protocol"], "Unsupported native nft header field")
            if field in ["saddr", "daddr"]:
                conditions.append(("-s" if field == "saddr" else "-d", address(right)))
            else:
                conditions.append(("-p", right))
    return Counter(conditions)


def check_ruleset(objects, chains):
    require(isinstance(objects, dict) and set(objects) == {"nftables"}, "Incomplete nft ruleset")
    expected = {(("ip" if c["family"] == 4 else "ip6"), c["table"], c["chain"]): c for c in chains}
    require(len(expected) == len(chains), "Duplicate expected nft chain")
    actual_chains = {}
    actual_rules = {}
    tables = set()
    versions = []
    for item in objects["nftables"]:
        require(len(item) == 1, "Ambiguous nft object")
        kind, value = next(iter(item.items()))
        if kind == "metainfo":
            versions.append(value["version"])
        elif kind == "table":
            require(set(value) <= {"family", "name", "handle"}, "Unsupported nft table properties")
            key = (value["family"], value["name"])
            require(key not in tables, "Duplicate nft table")
            tables.add(key)
        elif kind == "chain":
            require(set(value) <= {"family", "table", "name", "handle", "type", "hook", "prio", "policy"},
                    "Unsupported nft chain properties")
            key = (value["family"], value["table"], value["name"])
            require(key not in actual_chains, "Duplicate nft chain")
            require(value.get("type") == "filter" and value.get("hook") == value["name"].lower() and
                    value.get("prio") == 0, "Unmodeled nft hook or priority")
            actual_chains[key] = value
        elif kind == "rule":
            require(set(value) <= {"family", "table", "chain", "handle", "expr"}, "Unsupported nft rule properties")
            key = (value["family"], value["table"], value["chain"])
            actual_rules.setdefault(key, []).append(value["expr"])
        else:
            raise ValueError("Unmodeled nft object: " + kind)
    require(len(versions) == 1 and isinstance(versions[0], str), "Missing nft version")
    require(set(actual_chains) <= set(expected) and set(actual_rules) <= set(actual_chains),
            "Nft chain/rule inventory differs")
    require(tables <= {(family, table) for family, table, _ in expected} and
            {(family, table) for family, table, _ in actual_chains} <= tables,
            "Nft table inventory differs")
    implicit = []
    for key, chain in expected.items():
        if key not in actual_chains:
            require(chain["policy"] == "accept" and chain["ordered_rules"] == [],
                    "Nft omitted a nonempty or nonaccepting chain")
            implicit.append(list(key))
            continue
        require(actual_chains[key]["policy"] == chain["policy"], "Nft chain default differs")
        rules = actual_rules.get(key, [])
        require(len(rules) == len(chain["ordered_rules"]), "Nft rule count differs")
        for normalized, expressions in zip(chain["ordered_rules"], rules):
            require(actual_conditions(expressions, normalized["action"]) == expected_conditions(normalized),
                    "Nft ordered rule conditions differ")
    return {"version": versions[0], "chains": len(expected), "rules": sum(map(len, actual_rules.values())),
            "implicit_empty_accept_chains": implicit}


def check_native_nft(bundle, snapshot):
    bundle = Path(bundle)
    check_filter_correspondence(bundle, snapshot)
    devices = {device["id"]: device for device in snapshot["devices"]}
    require(len(devices) == len(snapshot["devices"]) and
            len({device["host_id"] for device in devices.values()}) == 1,
            "Native PID correspondence requires one explicit host inventory")
    inspections = [o for o in snapshot["observations"] if o["kind"] == "container-inspect"]
    hooks = [o for o in snapshot["observations"] if o["kind"] == "nft-hooks"]
    require(len(inspections) == len(hooks) == len(devices), "Incomplete native nft/identity inventory")
    by_pid = {}
    seen_devices = set()
    for observation in inspections:
        command = observation["command"]
        require(len(command) == 5 and command[:4] == ["docker", "inspect", "--format", "{{json .}}"],
                "Native identity command changed")
        device = command[4]
        require(device in devices and device not in seen_devices, "Native identity device differs")
        seen_devices.add(device)
        require(observation["device_id"] in [None, device], "Native identity metadata device differs")
        value = read_observation(bundle, observation)
        require(value["Name"] == "/" + device and value["Image"] == devices[device]["image_id"] and
                value["State"]["Running"] is True, "Native container identity/state differs")
        pid = value["State"]["Pid"]
        require(type(pid) is int and pid > 0 and pid not in by_pid, "Ambiguous native namespace PID")
        by_pid[pid] = (device, observation)
    require(seen_devices == set(devices), "Native identity coverage differs")
    results = []
    seen_pids = set()
    for observation in hooks:
        command = observation["command"]
        require(len(command) == 8 and command[:2] == ["nsenter", "-t"] and
                command[3:] == ["-n", "nft", "-j", "list", "ruleset"], "Nft namespace command changed")
        require(command[2].isdigit(), "Invalid nft namespace PID")
        pid = int(command[2])
        require(pid in by_pid and pid not in seen_pids, "Nft namespace PID is absent or duplicated")
        seen_pids.add(pid)
        device, identity = by_pid[pid]
        require(observation["device_id"] in [None, device], "Nft metadata device differs")
        require(utc(identity["ended_at"]) <= utc(observation["started_at"]) <= utc(observation["ended_at"]),
                "Nft observation precedes identity binding")
        result = check_ruleset(read_observation(bundle, observation),
                               [c for c in snapshot["filters"] if c["device_id"] == device])
        results.append({"device": device, "pid": pid, "observation_id": observation["id"],
                        "identity_observation_id": identity["id"], **result})
    return {"devices": results,
            "scope": "Complete nft table/chain/rule inventory matched to raw-bound iptables order and visible conditions. Opaque xt match parameters come from the paired iptables-save decoding contract; no independent binary netlink decoding is claimed.",
            "namespace_assumption": "Captured container PID remains the same namespace between the identity and nft read; surrounding native consistency checks remain separate."}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    bundle = Path(args.snapshot)
    snapshot = json.loads((bundle / "snapshot.json").read_text())
    result = check_native_nft(bundle, snapshot)
    report = Path(args.report)
    if report.exists():
        old = report.read_bytes()
        revisions = report.parent / "report-revisions"
        revisions.mkdir(exist_ok=True)
        saved = revisions / (hashlib.sha256(old).hexdigest() + "-" + report.name)
        if not saved.exists():
            saved.write_bytes(old)
    report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"devices": len(result["devices"]), "rules": sum(r["rules"] for r in result["devices"])}))
