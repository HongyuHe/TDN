"""Apply arbitrary-input boundary checks to all retained mixed mechanisms."""
import json
import os
from pathlib import Path

from validate_evidence import require

RUN = Path(os.environ["TDN_OUTPUT_DIR"])


def main():
    blocks = ["import TDN.Targets.MixedTunnelBoundaries",
              "import TDN.Semantics.FiniteMultiProtocolAuthentication",
              "import TDN.Evidence.FreshMixedDeliverySuite"]
    metadata = []
    reports = [(p, False) for p in sorted((RUN / "pairing-execution-v7").glob("*.json"))]
    reports += [(p, True) for p in sorted((RUN / "bridged-macsec-execution-v8").glob("*.json"))]
    for path, bridged in reports:
        report = json.loads(path.read_text())
        namespace = report["namespace"]
        port_ids = report["port_ids"]
        device_ids = {name: i + 1 for i, name in enumerate(sorted(report["devices"]))}
        blocks += ["namespace TDN.Imported." + namespace,
                   "open MultiProtocolExecution LayeredFrame",
                   "set_option maxRecDepth 1000000", "set_option maxHeartbeats 0"]
        for tag in [1, 2]:
            blocks.append(f"""lemma carrier_inbound_checks_{tag} :
    FiniteCarrierInputChecks devices ports carriers {tag} := by
  unfold FiniteCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_{tag} : CarrierInputCheck config layout {tag} :=
  finite_carrier_input_checks_sound devices ports routes links bridges macPorts carriers {tag}
    carrier_inbound_checks_{tag}
""")
        for device in ["IA", "IB", "OA", "OB"]:
            tag = 1 if device.startswith("I") else 2
            component = device_ids[device]
            def boundary_port(zone):
                endpoints = {endpoint for link in report["architecture_links"] if link["zone"] == zone
                             for endpoint in link["endpoints"] if endpoint.startswith(device + ":")}
                require(len(endpoints) == 1, "Boundary needs one observed external attachment per selected zone")
                return port_ids[next(iter(endpoints))]
            inside = boundary_port("red" if tag == 1 else "gray")
            outside = boundary_port("gray" if tag == 1 else "black")
            name = "mixedBoundary" + device
            blocks.append(f"""def {name} := Targets.mixedTunnelBoundary config layout
  [{inside}] [{outside}] {tag} {component}

lemma {name}_nonempty_attachments :
    ([{inside}] : List Nat) ≠ [] ∧ ([{outside}] : List Nat) ≠ [] := by decide

lemma {name}_ip_tags : ∀ entry, config.ip.owner entry = {component} →
    ∀ policy ∈ config.ip.inbound entry, policy.tag = {tag} := by
  have checked : ∀ policy ∈ (Execution.deviceAt devices {component}).inbound,
      policy.tag = {tag} := by decide
  intro entry owner policy member
  change (Execution.portAt ports entry).owner = {component} at owner
  change policy ∈ (Execution.deviceAt devices (Execution.portAt ports entry).owner).inbound at member
  rw [owner] at member
  exact checked policy member

lemma {name}_mac_tags : ∀ port ∈ config.macPorts,
    config.ip.owner port.physicalPort = {component} →
    ∀ association ∈ port.receiveAssociations, association.tag = {tag} := by
  change ∀ port ∈ macPorts, (Execution.portAt ports port.physicalPort).owner = {component} →
    ∀ association ∈ port.receiveAssociations, association.tag = {tag}
  decide

theorem {name}_no_bypass : Targets.BoundaryNoBypass {name} :=
  Targets.mixed_tunnel_boundary_from_local_checks config layout [{inside}] [{outside}] {tag} {component}
    mixed_local_conditions carrier_input_preserves_boundary_{tag}
    {name}_ip_tags {name}_mac_tags (by decide) (by decide)
""")
            direction = "Reverse" if device.endswith("A") else "Forward"
            label = direction + ("VLAN0" if bridged else "")
            trace_path = RUN / "mixed-traces" / ("Fresh" + namespace + label + ".json")
            trace = json.loads(trace_path.read_text())
            first = next(i for i, state in enumerate(trace["states"])
                         if state["phase"] == "received" and state["port"] == outside)
            last = next(i for i, state in enumerate(trace["states"])
                        if i > first and state["phase"] == "ready" and state["port"] == inside)
            inverse_ports = {value: key for key, value in port_ids.items()}
            require(all(inverse_ports[s["port"]].startswith(device + ":")
                        for s in trace["states"][first:last + 1]), "Positive segment leaves selected component")
            actions = "[" + ", ".join("." + action for action in trace["actions"][first:last]) + "]"
            proof = "Cslib.LTS.MTr.refl"
            for index in reversed(range(first, last)):
                proof = ("Cslib.LTS.MTr.stepL ⟨" + label + ".usefulStep" + str(index) +
                         ", by decide, by decide⟩ (" + proof + ")")
            blocks.append(f"""theorem {name}_positive_inbound :
    ∃ start actions finish, {name}.inboundEntry start ∧
      {name}.system.MTr start actions finish ∧ {name}.inboundExit finish := by
  refine ⟨{label}.usefulState{first}, {actions}, {label}.usefulState{last}, ?_, ?_, ?_⟩
  · simp only [{name}, Targets.mixedTunnelBoundary]
    decide
  · exact {proof}
  · simp only [{name}, Targets.mixedTunnelBoundary]
    decide
""")
            metadata.append({"configuration": namespace, "device": device, "component": component,
                             "tag": tag, "inside": inside, "outside": outside, "report": str(path),
                             "positive_trace": str(trace_path), "first": first, "last": last,
                             "proof": "TDN.Imported." + namespace + "." + name + "_no_bypass"})
        blocks.append("end TDN.Imported." + namespace)
    Path("TDN/Evidence/FreshMixedTunnelBoundaries.lean").write_text("\n\n".join(blocks) + "\n")
    (RUN / "mixed_tunnel_boundaries.json").write_text(json.dumps({
        "applications": metadata,
        "scope": [
            "Arbitrary received body and empty local authentication; no initial valid encryption stack or carrier provenance is assumed inward.",
            "Every inward crossing requires an actual receiving IPsec or MACsec operation at the selected component and on the same payload.",
            "MACsec receive uses SCI/AN. A local generation label or untrusted role annotation is not an additional wire guard.",
            "Outgoing input inherits the surrounding protected-payload invariant. Copied local responses and backend fragment composition remain separately active.",
            "All seven cases include actual positive inward component segments. Full RG029/030 optional configuration and global Outer Gray-origin accounting remain separate."
        ]}, indent=2) + "\n")
    print(json.dumps({"configurations": len(reports), "boundary_applications": len(metadata)}))


if __name__ == "__main__":
    main()
