"""Bind optional screening placement to complete retained interface observations."""
import argparse
import hashlib
import json
from pathlib import Path

from import_macsec_runtime import validate_files
from validate_evidence import require

SOURCE_HASHES = {
    "utility_variants_v4.py": "bf0b2240a619ae9d11335d927c28f25e4c48b1a502c6afa458aff8754801b670",
    "routing_variants.py": "cc24574714e6489f38873cb86faca6124fe5583eec48aa8e6067436d34ce9413",
    "matrix_lab.py": "91f6257bc821ad14ed1ff5c9db0575a4ac11b6f53431a86382d66a523fe062e8",
}
EXPECTED_ROLES = {"HA": "host", "HB": "host", "IA": "inner", "IB": "inner",
                  "OA": "outer", "OB": "outer", "FA": "existing-Black-screening-router",
                  "FB": "existing-Black-screening-router"}
COMMANDS = {"interfaces": ["ip", "-j", "-d", "address"],
            "routes4": ["ip", "-j", "-4", "route", "show", "table", "all"],
            "filters4": ["iptables-save"]}


def parse(path):
    path = Path(path)
    manifest_hash = validate_files(path)
    for name, digest in SOURCE_HASHES.items():
        require(hashlib.sha256((path / name).read_bytes()).hexdigest() == digest,
                "Reviewed construction source changed")
    evidence = json.loads((path / "evidence.json").read_text())
    require("error" in evidence and evidence["error"] is None, "Explicit clean collection required")
    require(evidence["configuration_id"] == "screen-existing", "Selected existing-router case required")
    devices = {row["id"]: row for row in evidence["devices"]}
    require(len(devices) == len(evidence["devices"]) and
            {name: row["role"] for name, row in devices.items()} == EXPECTED_ROLES,
            "Complete source-bound device and role inventory required")
    raw = json.loads((path / "commands.json").read_text())
    commands = {row["id"]: row for row in raw}
    require(len(commands) == len(raw), "Duplicate command identity")
    created = [row["command"][3] for row in raw
               if row["command"][:3] == ["ip", "netns", "add"] and row["returncode"] == 0]
    require(len(created) == len(set(created)) and set(created) ==
            {row["namespace"] for row in devices.values()}, "Namespace inventory differs from construction")
    used = []
    phases = []
    for filename in ["stable-before.json", "stable-after.json"]:
        phase = json.loads((path / filename).read_text())
        require(set(phase) == set(devices), "Incomplete observed device inventory")
        interfaces = {}
        for name, device in devices.items():
            for kind, suffix in COMMANDS.items():
                value = phase[name][kind]
                observation = commands[value["observation_id"]]
                require(observation["device_id"] == name and
                        observation["command"] == ["ip", "netns", "exec", device["namespace"]] + suffix and
                        observation["returncode"] == value["returncode"] == 0 and
                        observation["stdout"] == value["value"], "Raw observation correspondence failure")
                used.append(observation["id"])
            rows = json.loads(phase[name]["interfaces"]["value"])
            require(len({row["ifname"] for row in rows}) == len(rows), "Duplicate interface name")
            active = [row for row in rows if row["ifname"] != "lo" and "UP" in row["flags"]]
            require(all(row.get("linkinfo", {}).get("info_kind") == "veth" for row in active),
                    "Unrepresented active attachment")
            attached = [row for row in rows if row.get("linkinfo", {}).get("info_kind") == "veth"]
            interfaces.update({name + ":" + row["ifname"]: row for row in attached})
        require(len({row["ifindex"] for row in interfaces.values()}) == len(interfaces),
                "Ambiguous interface indexes require namespace-peer evidence")
        expected_ports = [endpoint for link in evidence["links"] for endpoint in link["endpoints"]]
        require(len(expected_ports) == len(set(expected_ports)) and set(expected_ports) == set(interfaces),
                "Declared links omit or duplicate an active attachment")
        for link in evidence["links"]:
            require(link["relation"] == "veth" and len(link["endpoints"]) == 2, "Unsupported attachment")
            left, right = [interfaces[e] for e in link["endpoints"]]
            require(left["link_index"] == right["ifindex"] and right["link_index"] == left["ifindex"],
                    "Observed reciprocal attachment differs from declared link")
            for endpoint, address in zip(link["endpoints"], link["addresses"], strict=True):
                require(address in [a["local"] + "/" + str(a["prefixlen"])
                                    for a in interfaces[endpoint]["addr_info"] if a["family"] == "inet"],
                        "Link address differs from raw interface")
            roles = {devices[e.split(":")[0]]["role"] for e in link["endpoints"]}
            expected_zone = "red" if "host" in roles else "gray" if "inner" in roles else "black"
            require(link["zone"] == expected_zone, "Zone differs from reviewed role placement")
        for name in ["FA", "FB"]:
            rules = phase[name]["filters4"]["value"]
            require(":FORWARD DROP " in rules and "-p esp -j ACCEPT" in rules,
                    "Observed screening filter missing")
            routes = json.loads(phase[name]["routes4"]["value"])
            require(any(row.get("gateway") and row.get("dev") == "outside" for row in routes),
                    "Observed router forwarding path missing")
        phases.append({endpoint: (row["ifindex"], row["link_index"],
                                 sorted((a["local"], a["prefixlen"]) for a in row["addr_info"]))
                       for endpoint, row in interfaces.items()})
    require(phases[0] == phases[1], "Attachment state changed across collection")
    boundary = {"IA", "IB", "OA", "OB"}
    controls = []
    for name in ["FA", "FB"]:
        zones = [link["zone"] for link in evidence["links"]
                 if any(e.startswith(name + ":") for e in link["endpoints"])]
        require(zones, "Screening router has no observed attachment")
        controls.append({"device": name, "screeningRouter": True,
                         "locatedOnBlack": all(zone == "black" for zone in zones),
                         "insideSolutionBoundary": name in boundary})
    return {"bundle": str(path), "manifest_sha256": manifest_hash, "controls": controls,
            "used_observations": sorted(set(used)), "source_hashes": SOURCE_HASHES,
            "declared_solution_components": sorted(boundary),
            "scope": [
                "Selected existing screening-router case, with complete veth inventory, including administratively down attachments and both retained phases.",
                "The MSC boundary is the declared Inner/Outer component boundary of this selected architecture. It is not a measured physical perimeter.",
                "Role and zone meanings follow the reviewed source construction. Raw commands bind interfaces, addresses, routing and filtering.",
                "Unique observed ifindexes make reciprocal peer binding unambiguous in this case. Inputs with collisions need explicit namespace-peer evidence.",
                "The added-screen case uses a filtering bridge and is not silently classified as the separate screening-router alternative.",
                "No whole-network packet claim, physical independence, product approval or selected key-management annex compliance follows from placement."]}


def generate(data):
    records = ["⟨" + ", ".join(str(row[k]).lower() for k in
               ["screeningRouter", "locatedOnBlack", "insideSolutionBoundary"]) + "⟩"
               for row in data["controls"]]
    return """import TDN.Requirements.Components

namespace TDN.Deployments.FreshOptionalScreening
open Requirements

def controls : List AdditionalControl := [""" + ", ".join(records) + """]
lemma black_placement : ∀ c ∈ controls, c.screeningRouter = true → c.locatedOnBlack = true := by native_decide
lemma boundary_placement : ∀ c ∈ controls, c.screeningRouter = true → c.insideSolutionBoundary = false := by native_decide

theorem selected_optional_control_placement : msc_additional_control_permissions controls :=
  additional_controls_from_black_screening_placement controls black_placement boundary_placement

theorem actual_screening_inventory : controls.length = 2 ∧
    ∀ c ∈ controls, c.screeningRouter = true := by native_decide

end TDN.Deployments.FreshOptionalScreening
"""


def main():
    parser = argparse.ArgumentParser()
    for name in ["bundle", "output", "report"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    data = parse(args.bundle)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"screening_routers": len(data["controls"]), "selected_scope_only": True}))


if __name__ == "__main__":
    main()
