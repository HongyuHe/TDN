"""Expose validated mixed-protocol experiments as records and Lean JSON inputs."""
import hashlib
import json
from pathlib import Path

from .parsers.execution import empty_device, association_json, state_json
from .parsers.family import encode_address
from .parsers.pairing import parse
from .parsers.macsec_provisioning import parse as parse_provisioning
from .parsers.ipsec_provisioning import parse as parse_ipsec_provisioning
from .parsers.snapshot import require
from .projections import atom_json


CAPABILITIES = ["devices", "interfaces", "routes", "policies", "states", "hooks", "mac_ports", "carriers", "links", "bridges", "key_provisioning", "ipsec_key_provisioning", "control_probes"]
LEAN_VIEW = "multi_protocol_execution"
SCOPE = "Supplemental Linux namespace experiment with separately recorded runtime backend"


def execution_values(report):
    data = report["operational"]
    device_ids = {name: i + 1 for i, name in enumerate(sorted(report["devices"]))}
    port_ids = {name: i + 1 for i, name in enumerate(sorted(data["interfaces"]))}
    devices = [empty_device()]
    ports = [{"owner": 0, "name": "", "stack": [], "payloadOrigin": False}]
    routes, port_bindings, key_bindings = [], [], []
    for name in device_ids:
        record = empty_device()
        for hook in ["INPUT", "OUTPUT", "FORWARD"]:
            rules = [rule for family in [4, 6] for rule in data["hooks"][name][family][hook]["parsed_rules"]]
            record[hook.lower() + "Rules"] = [
                {"atoms": [atom_json(atom) for atom in rule["atoms"]], "verdict": rule["verdict"]}
                for rule in rules]
        record["outbound"] = [association_json(row) for row in data["policies"][name]["out"]]
        record["inbound"] = [association_json(row) for row in data["policies"][name]["in"]]
        record["states"] = [state_json(row) for row in data["states"][name]]
        record["localAddresses"] = sorted({encode_address(a[1])
            for key, interface in data["interfaces"].items() if key.startswith(name + ":")
            for a in interface["addresses"]})
        record["recipientDomain"] = 1 if report["devices"][name]["role"] == "host" else None
        devices.append(record)
    for key, index in port_ids.items():
        device, name = key.split(":", 1)
        role = report["devices"][device]["role"]
        if role == "host":
            stack = []
        elif role == "inner":
            stack = [1] if name == "gray" else []
        elif role == "outer":
            stack = [2, 1] if name == "black" else [1]
        elif role in ["outer-firewall", "black-firewall"]:
            stack = [2, 1]
        elif role in ["encapsulator", "encapsulation"] or device in ["EA", "EB"]:
            stack = [1]
        else:
            require(device == "BF", "Unclassified mixed-profile port role")
            stack = [2, 1]
        ports.append({"owner": device_ids[device], "name": name, "stack": stack,
                      "payloadOrigin": role == "host"})
        zones = sorted({link["zone"] for link in report["architecture_links"] if key in link["endpoints"]})
        port_bindings.append({"portId": index, "interfaceId": key, "ownerId": device_ids[device],
            "ownerDeviceId": device, "declaredRole": role, "declaredZones": zones,
            "rawInterface": data["interfaces"][key], "physicalIndependence": "unavailable"})
    for row in data["routes"]:
        for key, index in port_ids.items():
            if key.startswith(row["device"] + ":"):
                routes.append({"ingress": index, "egress": port_ids[row["egress"]],
                    "low": row["low"], "high": row["high"], "prefixLength": row["prefix"],
                    "metric": row["metric"], "tablePriority": row["priority"]})
    mac_ports = []
    for row in data["mac_ports"]:
        associations = {}
        for direction in ["tx", "rx"]:
            generation = len(key_bindings) + 1
            association = {"tag": row["tag"], "sci": row[direction + "_sci"],
                "associationNumber": row[direction + "_an"], "keyGeneration": generation}
            associations[direction] = association
            key_bindings.append({"generationIndex": generation, "device": row["device"],
                "interface": row["logical"], "direction": direction,
                "installedKeyIdentifier": row[direction + "_key_id"], "association": association,
                "meaning": "Local installed association label; no claim that key identifiers prove equal secret keys"})
        mac_ports.append({"logicalPort": port_ids[row["device"] + ":" + row["logical"]],
            "physicalPort": port_ids[row["device"] + ":" + row["physical"]],
            "settings": {"controlledPortEnabled": True, "protectFrames": True,
                         "encryptFrames": True, "confidentialityOffset": 0},
            "transmitAssociation": associations["tx"], "receiveAssociations": [associations["rx"]],
            "validateStrict": True})
    provisioning = data.get("key_provisioning", [])
    for binding in key_bindings:
        matching = [entry for entry in provisioning if entry["device"] == binding["device"] and
                    entry["logical_interface"] == binding["interface"] and entry["direction"] == binding["direction"]]
        if matching:
            require(len(matching) == 1, "Ambiguous local provisioning binding")
            entry = matching[0]
            binding.update(materialReference="sha256:" + entry["key_sha256"],
                materialBytes=entry["key_bytes"], provisioningObservation=entry["observation_id"],
                peerProvisioningObservation=entry["peer_observation_id"],
                equalityMethod=entry["equality_method"], physicalInterface=entry["physical_interface"],
                meaning="Distinct local association with collector-observed private-key equality to its peer")
    for binding in key_bindings:
        if "peerProvisioningObservation" in binding:
            peer = next(other for other in key_bindings if
                other.get("provisioningObservation") == binding["peerProvisioningObservation"])
            binding["peerGenerationIndex"] = peer["generationIndex"]
    carriers = []
    for row in data["carriers"]:
        anchors = [key for key, interface in data["interfaces"].items()
                   if key.startswith(row["device"] + ":") and
                   any(a[1] == row["source"] for a in interface["addresses"])]
        require(len(anchors) == 1, "Carrier source address lacks a unique interface")
        carriers.append({"virtualPort": port_ids[row["device"] + ":" + row["interface"]],
            "routingPort": port_ids[anchors[0]], "transmit": {"protocol": "l2tpv3", "networkProtocol": "udp",
                "source": encode_address(row["source"]), "destination": encode_address(row["destination"]),
                "sourcePort": row["source_port"], "destinationPort": row["destination_port"],
                "peerSession": row["peer_session"]}, "localSession": row["local_session"]})
    source_ports = [index for key, index in port_ids.items()
                    if key.endswith(":red") and report["devices"][key.split(":")[0]]["role"] == "host"]
    result = {"devices": devices, "ports": ports, "routes": routes,
        "links": [[port_ids[a], port_ids[b]] for a, b in data["links"]],
        "bridges": [[port_ids[a], port_ids[b]] for a, b in data["bridges"]],
        "macPorts": mac_ports, "carriers": carriers, "redSources": source_ports,
        "grayPorts": sorted({port_ids[e] for link in report["architecture_links"]
                             if link["zone"] == "gray" for e in link["endpoints"]}),
        "blackPorts": sorted({port_ids[e] for link in report["architecture_links"]
                              if link["zone"] == "black" for e in link["endpoints"]}),
        "deviceIds": device_ids, "portIds": port_ids, "portBindings": port_bindings,
        "macsecKeyBindings": key_bindings, "operational": data,
        "addressEpochs": report["address_epochs"], "routeEpochs": report["route_epochs"],
        "scope": report["scope"], "projectionVersion": "mixed-execution-v1"}
    if "ipsec_key_epochs" in report:
        result["ipsecKeyBindings"] = [entry | {"deviceId": device_ids[entry["device"]],
            "state": state_json(entry["local_state"]),
            "stateIndex": devices[device_ids[entry["device"]]]["states"].index(state_json(entry["local_state"])),
            "portIds": [port_ids[port] for port in entry["local_interfaces"]]}
            for entry in report["ipsec_key_epochs"]["activeBindings"]]
        result["ipsecKeyEpochs"] = report["ipsec_key_epochs"]
        result["projectionVersion"] = "mixed-execution-v2-key-provisioning"
    return result


def validated_experiment(directory):
    directory = Path(directory)
    report = parse(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    if (directory / "macsec-provisioning.json").exists():
        report["operational"]["key_provisioning"] = parse_provisioning(directory, report)
    epochs = parse_ipsec_provisioning(directory, report)
    if epochs is not None:
        report["ipsec_key_epochs"] = epochs
        report["operational"]["ipsec_key_provisioning"] = epochs["activeBindings"]
    report["operational"]["control_probes"] = []
    control_path = directory / "ike-allowance-checks.json"
    if control_path.exists():
        checks = json.loads(control_path.read_text())["checks"]
        commands = {row["id"]: row for row in json.loads((directory / "commands.json").read_text())}
        require(len(checks) == 2, "Incomplete IKE admission checks")
        for check in checks:
            sender, receiver = commands[check["senderObservation"]], commands[check["receiverObservation"]]
            require(sender["device_id"] == "IA" and receiver["device_id"] == "IB" and receiver["returncode"] == 0,
                    "Unbound IKE admission observation")
            received = json.loads(receiver["stdout"])
            actual = received.get("receivedHex") == check["payloadHex"]
            require(check["payloadHex"] in sender["command"][-1] and
                    "10.11.0.1" in sender["command"][-1] and "10.21.0.1" in sender["command"][-1] and
                    check["received"] == actual == check["expectedReceived"], "IKE admission outcome differs")
            report["operational"]["control_probes"].append(dict(check, device="IA", receiverDevice="IB"))
    return manifest, report


def experiment_sources(directory, report):
    commands = json.loads((directory / "commands.json").read_text())
    by_id = {command["id"]: command for command in commands}
    sources = []
    for phase in report["phase_files"]:
        values = json.loads((directory / phase).read_text())
        for device, observations in values.items():
            for kind, observation in observations.items():
                command = by_id[observation["observation_id"]]
                sources.append({"id": command["id"], "device": device, "kind": kind,
                    "phase": phase, "command": command["command"],
                    "started": command.get("started_at"), "finished": command.get("ended_at"),
                    "exitCode": command["returncode"],
                    "stdoutSha256": hashlib.sha256(command["stdout"].encode()).hexdigest()})
    for entry in report["operational"].get("key_provisioning", []):
        command = by_id[entry["observation_id"]]
        sources.append({"id": command["id"], "device": entry["device"], "kind": "key_provisioning",
            "phase": "installation", "command": command["command"],
            "started": command["started_at"], "finished": command["ended_at"],
            "exitCode": command["returncode"],
            "stdoutSha256": hashlib.sha256(command["stdout"].encode()).hexdigest()})
    for entry in report.get("ipsec_key_epochs", {}).get("installations", []):
        command = by_id[entry["observation_id"]]
        sources.append({"id": command["id"], "device": entry["device"], "kind": "ipsec_key_provisioning",
            "phase": "installation", "command": command["command"],
            "started": command["started_at"], "finished": command["ended_at"],
            "exitCode": command["returncode"],
            "stdoutSha256": hashlib.sha256(command["stdout"].encode()).hexdigest()})
    for check in report["operational"].get("control_probes", []):
        for key in ["senderObservation", "receiverObservation"]:
            command = by_id[check[key]]
            sources.append({"id": command["id"], "device": command["device_id"], "kind": "control_probe",
                "phase": "admission", "command": command["command"],
                "started": command.get("started_at", command.get("start_monotonic_ns")),
                "finished": command.get("ended_at", command.get("end_monotonic_ns")), "exitCode": command["returncode"],
                "stdoutSha256": hashlib.sha256(command["stdout"].encode()).hexdigest()})
    return sources, by_id


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = validated_experiment(directory)
    allowed = set(CAPABILITIES)
    if category is not None and category not in allowed:
        raise ValueError("Unknown experiment category")
    if device is not None and device not in report["devices"]:
        raise ValueError("Unknown experiment device")
    sources, _ = experiment_sources(directory, report)
    rows = []
    for kind in sorted(allowed if category is None else [category]):
        value = report["devices"] if kind == "devices" else report["operational"].get(kind, [])
        entries = value.items() if isinstance(value, dict) else enumerate(value)
        for key, record in entries:
            if kind in {"devices", "policies", "states", "hooks"}:
                owner = str(key)
            elif kind == "interfaces":
                owner = str(key).split(":", 1)[0]
            elif isinstance(record, dict):
                owner = record.get("device")
            else:
                owner = None
            if device is not None:
                endpoints = {v.split(":", 1)[0] for v in record} if kind in {"links", "bridges"} else set()
                if owner != device and device not in endpoints:
                    continue
            relevant = [source | {"uri": f"evidence://{collection}/raw/{source['id']}"}
                        for source in sources if owner is None or source["device"] == owner]
            rows.append({"category": kind, "key": key, "device": owner,
                         "record": record, "sources": relevant})
    end = min(offset + limit, len(rows))
    return {"collection": collection, "source_kind": "saved_experiment", "total": len(rows),
        "records": rows[offset:end], "next_offset": end if end < len(rows) else None,
        "manifest_sha256": report["manifest_sha256"], "runtime_backend": manifest["runtime_backend"],
        "scope": report["scope"]}


def read_experiment_raw(directory, observation, stderr=False):
    _, report = validated_experiment(directory)
    sources, commands = experiment_sources(directory, report)
    if observation not in {source["id"] for source in sources}:
        raise ValueError("Observation is not part of the validated operational capture")
    return commands[observation].get("stderr" if stderr else "stdout", "")


def export_experiment(directory, destination):
    manifest, report = validated_experiment(directory)
    values = execution_values(report)
    values["observationBindings"] = experiment_sources(Path(directory), report)[0]
    values["provenance"] = {"manifestSha256": report["manifest_sha256"],
        "configurationId": manifest["configuration_id"], "runtimeBackend": manifest["runtime_backend"],
        "started": manifest["started_at"], "finished": manifest["ended_at"]}
    raw = (json.dumps(values, sort_keys=True, indent=2) + "\n").encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.read_bytes() != raw:
        raise ValueError("Existing experiment export differs")
    destination.write_bytes(raw)
    return {"path": str(destination), "sha256": hashlib.sha256(raw).hexdigest(),
            "view": "multi_protocol_execution", "keys": list(values)}
