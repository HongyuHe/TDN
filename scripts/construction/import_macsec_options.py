"""Bind optional XPN and clear-VLAN choices to retained operational configurations."""
import argparse
import json
from pathlib import Path

from import_macsec_runtime import validate_files
from validate_evidence import require


def parse_case(path, tags):
    path = Path(path)
    digest = validate_files(path)
    evidence = json.loads((path / "evidence.json").read_text())
    require(evidence.get("error") is None and evidence["configuration_id"] == f"xpn256-clear-vlan-{tags}" and
            evidence["runtime_backend"] == "supplemental-linux-netns-static-routes", "Wrong option case")
    devices = {d["id"]: d for d in evidence["devices"]}
    require(len(evidence["devices"]) == 2 and set(devices) == {"A", "B"} and
            all(d["role"] == "macsec-peer" for d in devices.values()), "Incomplete option device inventory")
    commands = json.loads((path / "commands.json").read_text())
    indexed = {r["id"]: r for r in commands}
    require(len(indexed) == len(commands), "Duplicate option command")
    bindings = []
    for phase_name in ["before", "after"]:
        phase = json.loads((path / (phase_name + ".json")).read_text())
        require(set(phase) == set(devices), "Incomplete option phase")
        for device in sorted(devices):
            prefix = ["ip", "netns", "exec", devices[device]["namespace"]]
            raw = phase[device]["interfaces"]
            observation = indexed[raw["observation_id"]]
            require(observation["command"] == prefix + ["ip", "-j", "-d", "address"] and
                    observation["returncode"] == raw["returncode"] == 0 and
                    observation["stdout"] == raw["value"], "Option interface differs from raw command")
            rows = json.loads(raw["value"])
            by_name = {r["ifname"]: r for r in rows}
            require(len(by_name) == len(rows), "Duplicate interface name")
            macsec = [r for r in rows if r.get("linkinfo", {}).get("info_kind") == "macsec"]
            require(len(macsec) == 1 and macsec[0]["ifname"] == "macsec0", "Incomplete MACsec port inventory")
            port = macsec[0]
            config = port["linkinfo"]["info_data"]
            require(config["cipher_suite"] == "GCM-AES-XPN-256" and config["offload"] == "off" and
                    config["protect"] is True and config["encrypt"] is True and config["validation"] == "strict",
                    "Unsupported selected MACsec configuration")
            parent = port["link"]
            for index in reversed(range(tags)):
                require(parent == f"vlan{index}" and parent in by_name, "Clear VLAN parent chain differs")
                vlan = by_name[parent]
                info = vlan.get("linkinfo", {})
                expected_protocol = "802.1ad" if tags == 2 and index == 0 else "802.1Q"
                require(info.get("info_kind") == "vlan" and info["info_data"]["id"] == 100 + index and
                        info["info_data"]["protocol"] == expected_protocol, "Clear VLAN configuration differs")
                parent = vlan["link"]
            require(parent == "wire" and by_name[parent].get("linkinfo", {}).get("info_kind") == "veth",
                    "MACsec parent chain does not reach the recorded wire")
            require(len([r for r in rows if r.get("linkinfo", {}).get("info_kind") == "vlan"]) == tags,
                    "Unexpected VLAN interface inventory")
            command = prefix + ["ip", "link", "add", "link", port["link"], "name", "macsec0", "type", "macsec",
                                "port", "1", "encrypt", "on", "protect", "on", "validate", "strict", "replay", "on",
                                "window", "0", "cipher", "gcm-aes-xpn-256"]
            setup = [c for c in commands if c["command"] == command]
            require(len(setup) == 1 and setup[0]["returncode"] == 0, "Missing successful option installation")
            bindings.append({"phase": phase_name, "device": device, "observation_id": observation["id"],
                             "installation_observation": setup[0]["id"]})
    for device, peer in [("A", "10.93.0.2"), ("B", "10.93.0.1")]:
        probes = [p for p in evidence["probes"] if p["source_device"] == device and
                  p["expected_result"] == "delivered"]
        require(len(probes) == 1, "Missing positive option operation")
        probe = probes[0]
        raw = indexed[probe["observation_id"]]
        require(probe["observed_result"] == "delivered" and probe["destination"] == peer and
                raw["command"][:5] == ["ip", "netns", "exec", devices[device]["namespace"], "ping"] and
                raw["command"][-1] == peer and raw["returncode"] == 0 and
                "3 received" in raw["stdout"] and "0% packet loss" in raw["stdout"],
                "Positive option operation lacks a raw peer binding")
    return {"bundle": str(path), "manifest_sha256": digest, "tags": tags, "bindings": bindings,
            "devices": [{"device": d, "clearVlanEnabled": tags > 0,
                         "clearVlanSupported": tags > 0, "xpnEnabled": True, "xpnSupported": True}
                        for d in sorted(devices)]}


def parse(root):
    return {"cases": [parse_case(Path(root) / f"xpn256-clear-vlan-{tags}", tags) for tags in range(3)],
            "scope": [
                "Six selected software MACsec ports across zero, one and two clear VLAN tag cases.",
                "Supported means the recorded Linux implementation accepted the selected construction and carried ordinary traffic in both directions. Correct implementation of XPN and VLAN encapsulation remains an explicit implementation contract.",
                "VLAN placement is derived from actual interface parent chains below MACsec. No packet capture or arbitrary clear-payload visibility theorem is inferred from those records.",
                "Positive probes are finite observations. They do not establish every packet, packet-number exhaustion, rekey continuity, cipher security or complete MACsec compliance.",
                "Manual SAK provisioning does not establish PSK/CAK authentication or an approved key generator. Other RG027/028 duties remain separate.",
                "For the disabled clear-VLAN case, no supported capability is asserted. The optional-feature implication needs no such premise when the feature is disabled.",
            ]}


def generate(data):
    entries = []
    for case in data["cases"]:
        for d in case["devices"]:
            entries.append("⟨" + ", ".join(str(d[k]).lower() for k in
                            ["clearVlanEnabled", "clearVlanSupported", "xpnEnabled", "xpnSupported"]) + "⟩")
    return '''import TDN.Targets.Components

namespace TDN.Imported.FreshMACsecOptions
open TDN.Targets

/-- Capability facts describe observed operational support under the recorded
Linux implementation contract, with all other protection duties kept separate. -/
def options : List MACsecOptions := [''' + ", ".join(entries) + ''']

lemma all_selected_ports_present : options.length = 6 := by decide

theorem selected_options_use_supported_features :
    msc_macsec_optional_clear_vlan_and_xpn options := by
  apply macsec_options_of_supported_enablement
  · decide
  · decide

end TDN.Imported.FreshMACsecOptions
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle_root")
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.bundle_root)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"cases": len(data["cases"]), "ports": sum(len(c["devices"]) for c in data["cases"])}))


if __name__ == "__main__":
    main()
