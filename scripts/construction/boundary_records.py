"""Preserve native captures and attach explicit declared Red service inventories."""
import hashlib
import ipaddress
import json
from pathlib import Path

from outer_gray_records import project


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(native_path, intent_path, destination, underlay_path=None):
    bundle = json.loads(native_path.read_text())
    declared = json.loads(intent_path.read_text())
    projected = project(bundle)
    keys = ["components", "interfaces", "ifaceNames", "ownerNames", "policies", "tunnels",
            "pairs", "masks", "ipsecSizes", "nativeDevices", "nativeIfaces", "routes", "links", "bridges"]
    records = {key: projected.pop(key) for key in keys}
    components = {row["id"] for row in records["components"]}
    services = [row for row in declared["services"] if row["device"] in components]
    diagnostics = [row for row in declared["diagnostics"] if row["device"] in components]
    registrations = [{"device": row["device"], "protocol": row["protocol"],
                      "port": row["port"], "kind": "application"} for row in services]
    registrations += [{"device": row["device"], "protocol": row["protocol"],
                       "port": row["modelPort"], "kind": "control"} for row in diagnostics]
    by_host = {row["device"]: row for row in services}
    diagnostic_by_host = {row["device"]: row for row in diagnostics}
    endpoints = []
    for pair in declared["pairs"]:
        if pair["inner"] not in components:
            continue
        for host, address in [(pair["host"], pair["localAddress"]),
                              (pair["peerHost"], pair["peerAddress"])]:
            service = by_host[host]
            diagnostic = diagnostic_by_host[host]
            if service["address"] != address or diagnostic["address"] != address:
                raise ValueError("Declared Red host address differs from paired policy")
            for protocol, port in [("tcp", service["port"]), ("icmp", diagnostic["modelPort"])]:
                endpoints.append({"inner": pair["inner"], "address": int(ipaddress.ip_address(address)),
                                  "port": port, "protocol": protocol})
    peers = []
    for binding in bundle["ipsecTunnelBindings"]:
        item = {"source": binding["senderDeviceId"], "destination": binding["receiverDeviceId"],
                "sourceAddress": binding["seal"]["sender"], "destinationAddress": binding["seal"]["receiver"]}
        if item not in peers:
            peers.append(item)
    firewalls = []
    for device in records["components"]:
        if device["kind"] != "outerFirewall":
            continue
        inside_name = device["id"] + ":inside"
        inside = records["ifaceNames"].index(inside_name)
        neighbors = {records["ifaceNames"][right] for left, right in records["links"] if left == inside}
        candidates = {interface["device"] for interface in records["interfaces"]
                      if interface["id"] in neighbors and interface["zone"] == "black" and
                      any(component["id"] == interface["device"] and component["layer"] == "outer"
                          for component in records["components"])}
        if len(candidates) != 1:
            raise ValueError("The firewall requires an explicit non-singleton local Outer policy")
        firewalls.append({"firewall": device["id"], "outer": candidates.pop()})
    if underlay_path is None:
        underlay_path = Path("outputs/mcp/exported/v31r-underlay-policy-underlay_control_policy.json")
    underlay = json.loads(underlay_path.read_text())
    controls = []
    for approval in underlay["approvals"]:
        if approval["device"] not in components:
            continue
        if approval["protocol"] != "ospf" or approval["protocolNumber"] != 89 or approval["hook"] not in ["input", "output"]:
            raise ValueError("Unsupported declared underlay approval")
        name = approval["device"] + ":" + approval["interface"]
        if not any(row["id"] == name and row["device"] == approval["device"] for row in records["interfaces"]):
            raise ValueError("Declared control interface is absent from the capture")
        controls.append({"device": approval["device"], "interface": name, "nativeName": approval["interface"],
                         "direction": "inbound" if approval["hook"] == "input" else "outbound",
                         "hook": approval["hook"], "source": approval["sourceAddress"],
                         "destination": approval["destinationAddress"], "protocol": approval["protocol"]})
    result = {"records": records, "services": registrations, "redEndpoints": endpoints,
              "peers": peers, "firewalls": firewalls,
              "firewallInternal": [row["id"] for row in records["interfaces"]
                                   if row["device"] in {binding["firewall"] for binding in firewalls}
                                   and row["id"].endswith(":inside")],
              "controls": controls, "declaredUnderlayPolicy": underlay,
              "native": projected, "declaredRedPolicy": declared,
              "provenance": {"nativeSource": str(native_path), "nativeSHA256": digest(native_path),
                             "intentSource": str(intent_path), "intentSHA256": digest(intent_path),
                             "underlaySource": str(underlay_path), "underlaySHA256": digest(underlay_path),
                             "meaning": "Declared service and diagnostic intent remains separate from measured cases"}}
    destination.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    destination.with_stem(destination.stem + "Fields").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"destination": str(destination), "services": len(registrations),
                      "redEndpoints": len(endpoints), "peers": len(peers), "firewalls": len(firewalls), "controls": len(controls)}))


def main():
    intent = Path("outputs/mcp/exported/v31r-red-services-red_service_policy.json")
    for profile, network in [("Baseline", "baseline"), ("Shared", "shared")]:
        build(Path(f"outputs/mcp/exported/v31r-{network}-red-services-multi_protocol_execution.json"),
              intent, Path(f"data/evidence/continuation/Boundary{profile}.json"))


if __name__ == "__main__":
    main()
