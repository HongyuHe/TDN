"""Import actual PTB/socket observations and an alignment-aware ESP size budget."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from import_macsec_runtime import validate_files
from validate_evidence import require


def parse(path):
    digest = validate_files(path)
    evidence = json.loads((path / "evidence.json").read_text())
    require(evidence.get("error") is None, "PMTU experiment failed")
    commands = json.loads((path / "commands.json").read_text())
    indexed = {r["id"]: r for r in commands}
    require(len(indexed) == len(commands), "Duplicate PMTU command ID")
    namespaces = {d["id"]: d["namespace"] for d in evidence["devices"]}
    require(set(namespaces) == {"HA", "IA", "R", "IB", "HB"}, "Unexpected PMTU inventory")
    before = json.loads((path / "before.json").read_text())
    after = json.loads((path / "after.json").read_text())
    for phase in [before, after]:
        require(set(phase) == set(namespaces), "Incomplete PMTU raw phase")
        for device, observations in phase.items():
            for kind, record in observations.items():
                raw = indexed[record["observation_id"]]
                require(raw["command"][:4] == ["ip", "netns", "exec", namespaces[device]] and
                        raw["returncode"] == record["returncode"] == 0 and
                        raw["stdout"] == record["value"], "PMTU phase differs from raw command")
                if kind == "interfaces":
                    require(raw["command"][4:] == ["ip", "-j", "-d", "address"], "Wrong interface command")
                if kind == "xfrm":
                    require(raw["command"][4:] == ["ip", "-s", "xfrm", "state", "list", "nokeys"],
                            "Wrong XFRM state command")
    router = json.loads(before["R"]["interfaces"]["value"])
    egress = [r for r in router if r["ifname"] == "right"]
    require(len(egress) == 1, "Missing Black bottleneck interface")
    mtu = egress[0]["mtu"]
    for device in ["IA", "IB"]:
        states = before[device]["xfrm"]["value"]
        require(states.count("aead rfc4106(gcm(aes)) <<Keys hidden>> 128") == 2 and
                states.count("mode tunnel") == 2 and "encap " not in states and "tfcpad " not in states,
                "Unsupported ESP overhead configuration")
        endpoints = re.findall(r"^src (\S+) dst (\S+)", states, re.M)
        require(len(endpoints) == 2 and all(ipaddress.ip_address(a).version == 6 and
                ipaddress.ip_address(b).version == 6 for a, b in endpoints), "Wrong ESP outer family")
    sender = json.loads((path / "sender.json").read_text())
    receiver = json.loads((path / "receiver.json").read_text())
    black = json.loads((path / "sender-Black.json").read_text())["records"]
    red = json.loads((path / "Red-source.json").read_text())["records"]
    black_ptb = [r for r in black if r.get("icmpv6_type") == 2 and r.get("icmpv6_code") == 0]
    red_ptb = [r for r in red if r.get("icmpv6_type") == 2 and r.get("icmpv6_code") == 0]
    limit = sender["final_path_mtu"]
    def interface_address(device, name):
        rows = json.loads(before[device]["interfaces"]["value"])
        interfaces = [row for row in rows if row["ifname"] == name]
        require(len(interfaces) == 1, "Missing quoted-flow interface")
        addresses = [a["local"] for a in interfaces[0]["addr_info"]
                     if a["family"] == "inet6" and a.get("scope") == "global"]
        require(len(addresses) == 1, "Ambiguous quoted-flow address")
        return addresses[0]
    inner_quote = {"source": interface_address("HA", "red"),
                   "destination": interface_address("HB", "red"), "next_header": 17}
    outer_quote = {"source": interface_address("IA", "wire"),
                   "destination": interface_address("IB", "wire"), "next_header": 50}
    require(all(r.get("quoted_header") == outer_quote for r in black_ptb),
            "Black PTB quotes a different ESP flow")
    require(all(r.get("quoted_header") == inner_quote for r in red_ptb),
            "Translated PTB quotes a different source flow")
    require(black_ptb and all(r["advertised_mtu"] == mtu for r in black_ptb),
            "Black PTB differs from bottleneck MTU")
    require(red_ptb and all(r["advertised_mtu"] == limit for r in red_ptb),
            "Translated PTB differs from socket limit")
    require(any(error.get("errno") == 90 and error.get("origin") == 3 and error.get("type") == 2 and error.get("code") == 0 and error.get("info") == limit
                for event in sender["events"] for error in event.get("error_queue", [])),
            "No bound ICMPv6 socket error-queue event")
    size = sender["valid_send_bytes"]
    expected_hash = hashlib.sha256(bytes((29*i + 7) % 256 for i in range(size))).hexdigest()
    require(sender["valid_sha256"] == expected_hash and sender["ack"] == "owned-pmtu-ack" and
            any(r["bytes"] == size and r["sha256"] == expected_hash for r in receiver["received"]),
            "Successful public payload not bound to receiver")
    return {"manifest_sha256": digest, "bundle": str(path), "initial_mtu": sender["initial_path_mtu"],
            "effective_ip_limit": limit, "black_mtu": mtu, "successful_udp_payload": size,
            "encoding": {"alignment": 4, "trailer_bytes": 2, "fixed_bytes": 72},
            "scope": ["One observed IPv6 ESP path, not an invented Outer device or Gray-management path.",
                      "Sizes supplied to the budget are complete inner IP datagrams. UDP payload adds 40 IPv6 and 8 UDP bytes.",
                      "Encoding uses the declared minimal ESP padding contract, 40-byte IPv6 outer header, 8-byte ESP header, 8-byte explicit IV, 16-byte ICV and 2-byte trailer. No UDP encapsulation or TFC padding is selected.",
                      "Direct sender/receiver/capture JSON files are raw collector observations, authenticated by their manifest hashes. The collector and kernel behavior remain explicit implementation assumptions.",
                      "This is a finite observed PMTU transition and a universal numerical budget under that fixed limit, not every future PMTU condition or the whole RG033 interface inventory."]}


def generate(data):
    return f"""import TDN.Requirements.TunnelMtuAndFragmentationSpec

namespace TDN.Deployments.FreshPMTU

def initialIPLimit : Nat := {data["initial_mtu"]}
def effectiveIPLimit : Nat := {data["effective_ip_limit"]}
def blackMtu : Nat := {data["black_mtu"]}
def successfulUDPPayload : Nat := {data["successful_udp_payload"]}

/-- Complete inner IP length maps to outer IPv6 ESP length under minimal padding. -/
def encodedLength := PacketLength.alignedWireLength 4 2 72

lemma discovered_limit_is_smaller : effectiveIPLimit < initialIPLimit := by decide
lemma maximum_fits : encodedLength effectiveIPLimit ≤ blackMtu := by decide

theorem every_datagram_within_discovered_limit_fits (bytes : Nat)
    (bounded : bytes ≤ effectiveIPLimit) : encodedLength bytes ≤ blackMtu :=
  PacketLength.all_sizes_fit_from_maximum 4 2 72 effectiveIPLimit blackMtu maximum_fits bytes bounded

theorem observed_useful_payload_fits :
    encodedLength (successfulUDPPayload + 40 + 8) ≤ blackMtu :=
  every_datagram_within_discovered_limit_fits _ (by decide)

end TDN.Deployments.FreshPMTU
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    report = parse(Path(args.bundle))
    Path(args.output).write_text(generate(report))
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ["initial_mtu", "effective_ip_limit", "black_mtu"]}))


if __name__ == "__main__":
    main()
