"""Expose retained OVS membership and namespace-bound nft link-hook observations."""

import json
import re

from .parsers.native import ovs_rows, uuid_set, validate_native
from .parsers.native_nft import check_native_nft, read_observation
from .parsers.snapshot import require
from .saved import validated_snapshot


VERSION = "native-ovs-link-processing-v1"
VIEW = "bridge_processing"
SCOPE = [
    "OVS NORMAL supplies possible physical member destinations. No delivery guarantee is inferred.",
    "Empty link programs express the observed absence of nft bridge and netdev hooks only.",
    "The capture does not audit TC, XDP, legacy ebtables, STP, hardware offload, or host-level interference.",
    "OVS records have before/after read-backs. The complete nft ruleset has one namespace-bound read.",
    "The captured container PID is assumed to retain its namespace between identity and nft reads.",
]


def normal_tables(records):
    tables = {kind: ovs_rows(records[kind]["raw_value"])
              for kind in ["bridge", "port", "interface", "controller"]}
    require(len(tables["bridge"]) == 1 and not tables["controller"],
            "Bridge processing requires one uncontrolled OVS bridge")
    bridge = next(iter(tables["bridge"].values()))
    require(not uuid_set(bridge["controller"]) and bridge["other_config"] == ["map", []],
            "Bridge options require another processing model")
    require(bridge["datapath_type"] in {"", "system"}, "Unsupported OVS datapath")
    for port in tables["port"].values():
        require(all(port[field] == ["set", []] for field in
                    ["tag", "trunks", "vlan_mode", "bond_mode"]),
                "VLAN or bonded OVS ports require another processing model")
        require(port["other_config"] == ["map", []], "Unsupported OVS port options")
    require(records["flows"]["raw_value"].strip() == "reset_counts priority=0 actions=NORMAL",
            "Non-NORMAL OpenFlow actions require another processing model")
    for kind, reply in [("groups", "GROUP_DESC"), ("meters", "METER_CONFIG")]:
        require(re.fullmatch(r"OFPST_" + reply + r" reply \(OF1\.3\) \(xid=0x[0-9a-f]+\):\s*",
                             records[kind]["raw_value"]) is not None,
                "Nonempty OpenFlow " + kind + " require another processing model")
    return tables


def link_hook_inventory(ruleset):
    tables, chains = [], []
    for item in ruleset["nftables"]:
        require(len(item) == 1 and next(iter(item)) in {"metainfo", "table", "chain", "rule"},
                "Unsupported nft object in bridge processing inventory")
        if "table" in item:
            tables.append(item["table"])
        if "chain" in item:
            chains.append(item["chain"])
        for value in item.values():
            require(not isinstance(value, dict) or value.get("family") not in {"bridge", "netdev"},
                    "Present bridge/netdev nft objects require an explicit link-program parser")
    return {"tables": tables, "chains": chains,
            "presentFamilies": sorted({row["family"] for row in tables}),
            "absentLinkFamilies": ["bridge", "netdev"], "completeRuleset": ruleset}


def project_bridge_processing(directory, snapshot):
    native = validate_native(directory, snapshot)
    nft = check_native_nft(directory, snapshot)
    by_id = {o["id"]: o for o in snapshot["observations"]}
    device_ids = {d["id"]: i + 1 for i, d in enumerate(sorted(snapshot["devices"], key=lambda d: d["id"]))}
    port_ids = {p["id"]: i for i, p in enumerate(sorted(snapshot["interfaces"], key=lambda p: p["id"]))}
    switches = sorted(d["id"] for d in snapshot["devices"] if d["role"] == "switch")
    require(switches, "No native switch observations are present")

    def source(observation):
        return {"id": observation["id"], "kind": observation["kind"],
                "rawPath": observation["raw_path"], "sha256": observation["raw_sha256"],
                "command": observation["command"], "started": observation["started_at"],
                "finished": observation["ended_at"], "returncode": observation["returncode"]}

    result = []
    for device in switches:
        records = {r["kind"].removeprefix("native-ovs-"): r for r in snapshot["native_runtime"]
                   if r["device_id"] == device and r["kind"].startswith("native-ovs-")}
        tables = normal_tables(records)
        bridge_uuid, bridge = next(iter(tables["bridge"].items()))
        nft_binding = next(row for row in nft["devices"] if row["device"] == device)
        nft_observation = by_id[nft_binding["observation_id"]]
        identity = by_id[nft_binding["identity_observation_id"]]
        hook_inventory = link_hook_inventory(read_observation(directory, nft_observation))
        sources = [source(identity), source(nft_observation)]
        readbacks = []
        for kind, record in records.items():
            require(len(record["observation_ids"]) == 1, "Ambiguous OVS initial observation")
            initial = by_id[record["observation_ids"][0]]
            require(initial["parse_status"] == "parsed", "Unparsed initial OVS observation")
            initial_raw = json.loads((directory / initial["raw_path"]).read_text())
            require(not initial_raw["stderr"].strip(), "OVS command reported stderr")
            repeated = [o for o in snapshot["observations"] if o.get("device_id") == device
                        and o["kind"] == "convergence-native-ovs-" + kind]
            require(len(repeated) == 1, "Missing or duplicated OVS read-back")
            repeated = repeated[0]
            require(repeated["returncode"] == 0 and repeated["parse_status"] == "parsed"
                    and repeated["command"] == initial["command"], "OVS read-back command failed or differs")
            repeated_raw = json.loads((directory / repeated["raw_path"]).read_text())
            require(not repeated_raw["stderr"].strip() and
                    repeated_raw["stdout"] == initial_raw["stdout"], "OVS read-back differs")
            sources.extend([source(initial), source(repeated)])
            readbacks.append({"kind": kind, "before": initial["id"], "after": repeated["id"],
                              "sameOutput": True})
        endpoints = []
        for port_uuid in uuid_set(bridge["ports"]):
            port = tables["port"][port_uuid]
            interface_uuid, = uuid_set(port["interfaces"])
            interface = tables["interface"][interface_uuid]
            if interface["name"] == bridge["name"]:
                continue
            name = device + ":" + interface["name"]
            captured = next(p for p in snapshot["interfaces"] if p["id"] == name)
            require(captured["link_kind"] == "veth" and captured["device_id"] == device,
                    "OVS endpoint owner or link kind differs")
            require(interface["admin_state"] == interface["link_state"] == "up",
                    "OVS endpoint is not observed up")
            endpoints.append({"portId": port_ids[name], "interfaceId": name,
                "ownerId": device_ids[device], "deviceId": device, "interface": interface["name"],
                "bridge": bridge["name"], "bridgeUuid": bridge_uuid, "portUuid": port_uuid,
                "interfaceUuid": interface_uuid, "ofport": interface["ofport"],
                "ifindex": interface["ifindex"], "mtu": captured["mtu"],
                "nftInbound": {"rules": [], "fallback": "allow"},
                "nftOutbound": {"rules": [], "fallback": "allow"}})
        expected = {p["id"] for p in snapshot["interfaces"]
                    if p["device_id"] == device and p["link_kind"] == "veth"}
        require({p["interfaceId"] for p in endpoints} == expected, "OVS physical endpoint coverage differs")
        endpoints.sort(key=lambda p: p["portId"])
        result.append({"deviceId": device, "ownerId": device_ids[device], "pid": nft_binding["pid"],
            "ports": endpoints, "ovsTables": {key: list(value.values()) for key, value in tables.items()},
            "flows": records["flows"]["raw_value"], "groups": records["groups"]["raw_value"],
            "meters": records["meters"]["raw_value"], "nftInventory": hook_inventory,
            "possibleSwitching": [[a["portId"], b["portId"]] for a in endpoints for b in endpoints if a != b],
            "sources": sources, "ovsReadbacks": readbacks,
            "nftReadback": "single namespace-bound read"})
    return {"switches": result, "deviceIds": device_ids, "portIds": port_ids,
            "scope": SCOPE, "nativeValidation": native["report"], "nftValidation": nft}


def query_bridge_processing(directory, collection, device, offset, limit):
    manifest, snapshot, _ = validated_snapshot(directory)
    if device is not None:
        require(device in {d["id"] for d in snapshot["devices"]}, "Unknown device")
    projected = project_bridge_processing(directory, snapshot)
    records = [r for r in projected["switches"] if device is None or r["deviceId"] == device]
    for record in records:
        for observation in record["sources"]:
            observation["sourceUri"] = f"evidence://{collection}/raw/{observation['id']}"
    end = min(offset + limit, len(records))
    return {"collection": collection, "capability": VIEW, "projectionVersion": VERSION,
            "records": records[offset:end], "total": len(records),
            "next_offset": end if end < len(records) else None,
            "scope": SCOPE, "consistency": manifest.get("convergence"),
            "requested_capability_collected": bool(records)}
