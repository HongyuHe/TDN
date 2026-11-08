"""Expose declared OSPF approval from the emulation owner's routing choice."""
import ipaddress
import json
from pathlib import Path

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "approvals", "decision", "coverage"]
LEAN_VIEW = "underlay_control_policy"
SCOPE = "Declared local OSPF INPUT/OUTPUT permission at Outer Firewall outside interfaces."


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    declaration = json.loads((root / "policy.json").read_text())
    require(declaration["schema"] == "native-underlay-policy/v1"
            and declaration["authority"] == "emulation-owner"
            and declaration["source"]["kind"] == "user-instruction"
            and bool(declaration["source"]["quote"].strip()), "Missing declared policy authority")
    require(declaration["protocols"] == ["ospf"] and declaration["hooks"] == ["input", "output"]
            and declaration["multicastDestinations"] == ["224.0.0.5"]
            and declaration["peerScope"] == "directly-connected-black-peer",
            "Unsupported declared underlay policy")
    approvals, devices, raw_ids = [], {}, {"policy": "policy.json"}
    for profile, filename in declaration["profiles"].items():
        require(isinstance(profile, str) and profile.isidentifier()
                and filename == "profile-" + profile + ".json", "Invalid policy profile reference")
        raw_ids["profile-" + profile] = filename
        spec = json.loads((root / filename).read_text())
        inventory = {device["id"]: device for device in spec["devices"]}
        require(len(inventory) == len(spec["devices"]) and not set(inventory) & set(devices),
                "Duplicate declared device identity")
        devices.update(inventory)
        firewalls = [device for device in inventory.values() if device["role"] == "firewall"]
        require(bool(firewalls), "No declared Outer Firewall")
        for device in firewalls:
            ports = [port for port in device["interfaces"] if port["name"] == "outside"]
            require(len(ports) == 1 and ports[0]["zone"] == "black", "Ambiguous firewall outside port")
            endpoint = {"device": device["id"], "interface": "outside"}
            peers = [link[other] for link in spec["links"] for side, other in [("a", "b"), ("b", "a")]
                     if link[side] == endpoint]
            require(len(peers) == 1, "Ambiguous Black peer link")
            peer = inventory[peers[0]["device"]]
            require(peer["role"] == "transport", "Outside peer is not the declared Black transport")
            peer_ports = [port for port in peer["interfaces"] if port["name"] == peers[0]["interface"]]
            require(len(peer_ports) == 1 and peer_ports[0]["zone"] == "black", "Ambiguous Black peer port")
            local_address = ipaddress.ip_interface(ports[0]["address"])
            peer_address = ipaddress.ip_interface(peer_ports[0]["address"])
            require(local_address.version == peer_address.version == 4
                    and local_address.network == peer_address.network
                    and local_address.ip != peer_address.ip, "Unbound OSPF peer addresses")
            for hook, source, target in [("input", peer_address.ip, local_address.ip),
                                         ("output", local_address.ip, peer_address.ip)]:
                for destination in [target, ipaddress.ip_address("224.0.0.5")]:
                    approvals.append({"device": device["id"], "interface": "outside", "hook": hook,
                        "protocol": "ospf", "protocolNumber": 89, "family": 4,
                        "source": str(source), "destination": str(destination),
                        "sourceAddress": int(source), "destinationAddress": int(destination),
                        "peerDevice": peer["id"], "peerInterface": peers[0]["interface"],
                        "profile": profile, "evidenceStatus": "declared", "observation": "policy"})
    require(bool(approvals), "Empty declared underlay policy")
    report = {"devices": list(devices.values()), "approvals": approvals,
        "decision": [declaration | {"evidenceStatus": "declared"}],
        "coverage": [{"firewalls": len({a["device"] for a in approvals}), "approvals": len(approvals)}],
        "rawIds": raw_ids, "manifestSha256": manifest_hash, "projectionVersion": "native-underlay-policy-v1",
        "scope": [SCOPE, "Endpoints come from declared profile links, independently of observed filter rules.",
                  "The authority is emulation-owner intent. No real-world Authorizing Official approval is asserted."]}
    return {"runtime_backend": "declared-emulation-policy"}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    require(observation in report["rawIds"], "Unknown declared-policy source")
    return "" if stderr else (Path(directory) / report["rawIds"][observation]).read_text()


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
