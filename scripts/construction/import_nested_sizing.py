"""Import interface-specific budgets for the retained two-IPsec-layer size case."""
import argparse
import ipaddress
import json
from pathlib import Path
import re

from import_macsec_runtime import validate_files
from validate_evidence import require


PORTS = {
    "HA": {"red": "red"}, "HB": {"red": "red"},
    "IA": {"red": "red", "gray": "gray"}, "IB": {"red": "red", "gray": "gray"},
    "OA": {"gray": "gray", "black": "black"}, "OB": {"gray": "gray", "black": "black"},
    "FA": {"inside": "black", "outside": "black"}, "FB": {"inside": "black", "outside": "black"},
}
ROLES = {"HA": "host", "HB": "host", "IA": "inner", "IB": "inner",
         "OA": "outer", "OB": "outer", "FA": "outer-firewall", "FB": "outer-firewall"}


def encode(size):
    return ((size + 2 + 3) // 4) * 4 + 52


def parse(path):
    path = Path(path)
    digest = validate_files(path)
    evidence = json.loads((path / "evidence.json").read_text())
    require(evidence.get("error") is None, "Sizing collection failed")
    require(evidence["configuration_id"] == "layers-ipsec-ipsec-integrated" and
            evidence["runtime_backend"] == "supplemental-linux-netns-static-routes", "Wrong sizing case")
    devices = {d["id"]: d for d in evidence["devices"]}
    require(len(devices) == len(evidence["devices"]) and
            {n: d["role"] for n, d in devices.items()} == ROLES, "Incomplete sizing device inventory")
    commands = json.loads((path / "commands.json").read_text())
    indexed = {r["id"]: r for r in commands}
    require(len(indexed) == len(commands), "Duplicate sizing command")
    observations, phases = [], []
    for phase_name in ["configured-sizing", "stable-sized-after"]:
        phase = json.loads((path / (phase_name + ".json")).read_text())
        require(set(phase) == set(devices), "Incomplete sizing phase")
        entries = []
        for name in sorted(devices):
            def raw(kind, suffix):
                record = phase[name][kind]
                command = indexed[record["observation_id"]]
                require(command["command"] == ["ip", "netns", "exec", devices[name]["namespace"]] + suffix and
                        command["returncode"] == record["returncode"] == 0 and
                        command["stdout"] == record["value"], "Sizing observation differs from raw command")
                observations.append(command["id"])
                return record["value"]
            interfaces = json.loads(raw("interfaces", ["ip", "-j", "-d", "address"]))
            for port, stage in PORTS[name].items():
                selected = [i for i in interfaces if i["ifname"] == port]
                require(len(selected) == 1, "Missing or duplicate sizing interface")
                interface = selected[0]
                require(type(interface["mtu"]) is int and interface["mtu"] > 0 and
                        "UP" in interface["flags"], "Invalid sizing interface state")
                entries.append({"device": name, "port": port, "stage": stage, "mtu": interface["mtu"]})
            if name in {"IA", "IB", "OA", "OB"}:
                states = raw("xfrm", ["ip", "-s", "xfrm", "state", "list", "nokeys"])
                endpoints = re.findall(r"(?m)^src (\S+) dst (\S+)$", states)
                require(len(endpoints) == 2 and all(ipaddress.ip_address(a).version == 4 and
                        ipaddress.ip_address(b).version == 4 for a, b in endpoints), "Unexpected ESP outer family")
                require(states.count("aead rfc4106(gcm(aes)) <<Keys hidden>> 128") == 2 and
                        states.count(" mode tunnel") == 2 and states.count("proto esp ") == 2 and
                        not any(token in states for token in ["encap ", "tfcpad ", " auth ", " comp "]),
                        "Unsupported ESP length configuration")
        phases.append(entries)
    require(phases[0] == phases[1], "Interface sizing changed across observations")
    entries = phases[0]
    maximums = {e["mtu"] for e in entries if e["stage"] == "red"}
    require(len(maximums) == 1, "Red interfaces have inconsistent initial limits")
    maximum = maximums.pop()
    lengths = {"red": maximum, "gray": encode(maximum), "black": encode(encode(maximum))}
    require(all(lengths[e["stage"]] <= e["mtu"] for e in entries), "Nested length exceeds interface MTU")
    return {"bundle": str(path), "manifest_sha256": digest, "interfaces": entries,
            "maximum": maximum, "maximum_lengths": lengths, "observations": observations,
            "whole_RG033_established": False,
            "scope": [
                "Selected fixed two-IPsec-layer IPv4 geometry, with every declared data-path port represented in both directions.",
                "Each ESP encoding uses a20-byte outer IPv4 header,8-byte ESP header,8-byte explicit IV,16-byte ICV,2-byte trailer and minimal4-byte padding. No UDP encapsulation or TFC padding is recorded.",
                "The theorem assumes the modeled path and encodings, unchanged interface limits and enforcement of the initial Red IP limit. It does not infer all possible routes, arbitrary source sizes or fragmentation absence from an MTU value alone.",
                "Interface labels are selected from this case's recorded architecture. Complete packet-path correspondence and additional Gray encryption components require their own applications.",
                "Raw observations and manifest hashes bind the imported facts. Collector truth, Linux implementation behavior, minimal padding and no extra outer IPv4 options remain implementation assumptions.",
                "MACsec, other padding/frame variants, native FRR/OVS cases, future changes and all other applicable interfaces remain separate obligations.",
            ]}


def generate(data):
    entries = ",\n  ".join("⟨" + json.dumps(e["device"]) + ", " + json.dumps(e["port"]) +
                           ", ." + e["stage"] + ", " + str(e["mtu"]) + "⟩" for e in data["interfaces"])
    return '''import TDN.Requirements.DoubleEncapMtuCalculation

namespace TDN.Deployments.SnapshotNestedSizing
open TDN.Requirements.NestedSizing

def espLength := PacketLength.alignedWireLength 4 2 52

def interfaces : List InterfaceLimit := [
  ''' + entries + ''']

def redLimit : Nat := ''' + str(data["maximum"]) + '''

lemma every_maximum_fits : ∀ entry ∈ interfaces,
    lengthAt espLength espLength entry.stage redLimit ≤ entry.mtu := by decide

/-- The identical proof applies to every imported interface and every smaller
Red IP datagram under the fixed two-layer encoding contract. -/
theorem every_bounded_red_datagram_fits_each_stage :
    ∀ bytes, bytes ≤ redLimit → ∀ entry ∈ interfaces,
      lengthAt espLength espLength entry.stage bytes ≤ entry.mtu :=
  all_sizes_fit_each_interface espLength espLength
    (PacketLength.aligned_wire_length_monotone 4 2 52)
    (PacketLength.aligned_wire_length_monotone 4 2 52)
    interfaces redLimit every_maximum_fits

end TDN.Deployments.SnapshotNestedSizing
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.bundle)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"interfaces": len(data["interfaces"]), "lengths": data["maximum_lengths"]}))


if __name__ == "__main__":
    main()
