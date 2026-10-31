"""Render raw-bound mixed-protocol configurations and unchanged local applications."""
import argparse
import json
from pathlib import Path

from import_pairing_execution import parse
from import_family_execution import encode_address, render_rules
from import_execution import association_list, tuple_list
from import_snapshot import quoted, lean_list
from validate_evidence import require


def mac_association(row, direction):
    return "{ tag := " + str(row["tag"]) + ", sci := " + str(row[direction + "_sci"]) + \
           ", associationNumber := " + str(row[direction + "_an"]) + ", keyGeneration := 0 }"


def render(report, namespace):
    data = report["operational"]
    device_ids = {name: i + 1 for i, name in enumerate(sorted(report["devices"]))}
    port_ids = {name: i + 1 for i, name in enumerate(sorted(data["interfaces"]))}
    devices, ports, routes = ["{}"], ["{}"], []
    for name, index in device_ids.items():
        hooks = {hook: sum([data["hooks"][name][family][hook]["parsed_rules"] for family in [4, 6]], [])
                 for hook in ["INPUT", "OUTPUT", "FORWARD"]}
        addresses = sorted({encode_address(a[1]) for key, interface in data["interfaces"].items()
                            if key.startswith(name + ":") for a in interface["addresses"]})
        devices.append("{ inputRules := " + render_rules(hooks["INPUT"]) +
                       ", outputRules := " + render_rules(hooks["OUTPUT"]) +
                       ", forwardRules := " + render_rules(hooks["FORWARD"]) +
                       ", outbound := " + association_list(data["policies"][name]["out"]) +
                       ", inbound := " + association_list(data["policies"][name]["in"]) +
                       ", states := " + tuple_list(data["states"][name]) +
                       ", localAddresses := " + lean_list([str(a) for a in addresses]) +
                       ", recipientDomain := " + ("some 1" if report["devices"][name]["role"] == "host" else "none") + " }")
    for key in port_ids:
        device, name = key.split(":")
        role = report["devices"][device]["role"]
        if role == "host":
            stack = []
        elif role == "inner":
            stack = [1] if name == "gray" else []
        elif role == "outer":
            stack = [2, 1] if name == "black" else [1]
        elif role in ["outer-firewall", "black-firewall"]:
            stack = [2, 1]
        elif device in ["EA", "EB"]:
            stack = [1]
        else:
            require(device == "BF", "Unclassified role stack")
            stack = [2, 1]
        ports.append("{ owner := " + str(device_ids[device]) + ", name := " + quoted(name) +
                     ", stack := " + lean_list([str(tag) for tag in stack]) + ", payloadOrigin := " + ("true" if report["devices"][device]["role"] == "host" else "false") + " }")
    for row in data["routes"]:
        for key, index in port_ids.items():
            if key.startswith(row["device"] + ":"):
                routes.append([index, port_ids[row["egress"]], row["low"], row["high"],
                               row["prefix"], row["metric"], row["priority"]])
    macs = []
    for row in data["mac_ports"]:
        macs.append("{ logicalPort := " + str(port_ids[row["device"] + ":" + row["logical"]]) +
                    ", physicalPort := " + str(port_ids[row["device"] + ":" + row["physical"]]) +
                    ", settings := ⟨true, true, true, 0⟩, transmitAssociation := some " +
                    mac_association(row, "tx") + ", receiveAssociations := [" +
                    mac_association(row, "rx") + "], validateStrict := true }")
    carriers = []
    for row in data["carriers"]:
        anchors = [key for key, interface in data["interfaces"].items() if key.startswith(row["device"] + ":")
                   and any(a[1] == row["source"] for a in interface["addresses"])]
        require(len(anchors) == 1, "Carrier source address lacks a unique local interface")
        carriers.append("{ virtualPort := " + str(port_ids[row["device"] + ":" + row["interface"]]) +
                        ", routingPort := " + str(port_ids[anchors[0]]) + ", transmit := { source := " +
                        str(encode_address(row["source"])) + ", destination := " +
                        str(encode_address(row["destination"])) + ", sourcePort := " + str(row["source_port"]) +
                        ", destinationPort := " + str(row["destination_port"]) + ", peerSession := " +
                        str(row["peer_session"]) + " }, localSession := " + str(row["local_session"]) + " }")
    links = [[port_ids[a], port_ids[b]] for a, b in data["links"]]
    bridges = [[port_ids[a], port_ids[b]] for a, b in data["bridges"]]
    sources = [index for key, index in port_ids.items() if key.endswith(":red") and
               report["devices"][key.split(":")[0]]["role"] == "host"]
    gray = sorted({port_ids[endpoint] for link in report["architecture_links"] if link["zone"] == "gray"
                   for endpoint in link["endpoints"]})
    black = sorted({port_ids[endpoint] for link in report["architecture_links"] if link["zone"] == "black"
                    for endpoint in link["endpoints"]})
    return "\n".join([
        "namespace TDN.Imported." + namespace,
        "open MultiProtocolExecution LayeredFrame", "set_option maxRecDepth 1000000",
        "set_option maxHeartbeats 0",
        "def devices : List Execution.DeviceData := " + lean_list(devices),
        "def ports : List Execution.PortData := " + lean_list(ports),
        "def routes : List Execution.Route := " + tuple_list(routes),
        "def links : List (Nat × Nat) := " + tuple_list(links),
        "def bridges : List (Nat × Nat) := " + tuple_list(bridges),
        "def macPorts : List MACPort := " + lean_list(macs),
        "def carriers : List CarrierPort := " + lean_list(carriers),
        "def config : Config := MultiProtocolExecution.finiteConfig devices ports routes links bridges macPorts carriers",
        "def layout := Execution.finiteLayout ports",
        "def redSources : List Nat := " + lean_list([str(n) for n in sources]),
        "def grayPorts : List Nat := " + lean_list([str(n) for n in gray]),
        "def blackPorts : List Nat := " + lean_list([str(n) for n in black]), "",
        "lemma mac_configuration_checked : ∀ port ∈ macPorts,",
        "    port.settings.controlledPortEnabled = true ∧ port.settings.protectFrames = true ∧",
        "    port.settings.encryptFrames = true ∧ port.settings.confidentialityOffset = 0 ∧",
        "    ∃ association, port.transmitAssociation = some association := by",
        "  simp [macPorts]", "",
        "lemma receive_peer_bindings : ∀ port ∈ macPorts, ∀ association ∈ port.receiveAssociations,",
        "    ∃ peer ∈ macPorts, peer.transmitAssociation = some association := by",
        "  unfold macPorts; decide", "",
        "theorem every_configured_mac_port_emits_full_encryption (port : MACPort)",
        "    (member : port ∈ macPorts) :",
        "    ∃ association, ∀ body, fullMACsecTransmit port association body := by",
        "  obtain ⟨enabled, protect, encrypt, zero, association, installed⟩ := mac_configuration_checked port member",
        "  refine ⟨association, fun body => ⟨installed, ?_⟩⟩",
        "  simpa [zero] using LinkProtection.enabled_sa_emits_encryption port.settings enabled protect encrypt",
        "    association.keyGeneration body", "",
        "theorem payload_preserved_by_every_mixed_execution {start finish : MultiProtocolExecution.State} {actions : List MultiProtocolExecution.Action}",
        "    (run : (lts config).MTr start actions finish) :",
        "    finish.frame.payload = start.frame.payload ∧ finish.frame.originDomain = start.frame.originDomain :=",
        "  all_executions_preserve_payload config run",
        "end TDN.Imported." + namespace, ""]), port_ids


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundles", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reports", type=Path, required=True)
    args = parser.parse_args()
    output = ["import TDN.Targets.MultiProtocolPackets", "import TDN.Semantics.FiniteMultiProtocol", ""]
    args.reports.mkdir(parents=True, exist_ok=True)
    for path in sorted(args.bundles.iterdir()):
        if not path.is_dir():
            continue
        report = parse(path)
        namespace = "Pairing" + "".join(piece.capitalize() for piece in path.name.split("-")[1:])
        text, port_ids = render(report, namespace)
        report["port_ids"] = port_ids
        report["namespace"] = namespace
        (args.reports / (path.name + ".json")).write_text(json.dumps(report, indent=2) + "\n")
        output.append(text)
    args.output.write_text("\n".join(output))
