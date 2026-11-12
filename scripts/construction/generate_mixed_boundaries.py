"""Apply arbitrary-input boundary checks to all retained mixed mechanisms."""
import json
import os
from pathlib import Path
from network_names import tunnel_matrix_module, forwarding_lean

from validate_evidence import require

RUN = Path(os.environ["TDN_OUTPUT_DIR"])


def main():
    blocks = ["import TDN.Requirements.HybridIpsecMacsecTunnelBoundaries",
              "import TDN.Models.TableDrivenMultiProtocolAuth",
              "import TDN.Deployments.SnapshotMixedDeliverySuite"]
    metadata = []
    reports = [(p, False) for p in sorted((RUN / "pairing-execution-v7").glob("*.json"))]
    reports += [(p, True) for p in sorted((RUN / "bridged-macsec-execution-v8").glob("*.json"))]
    for path, bridged in reports:
        report = json.loads(path.read_text())
        namespace = report["namespace"]
        port_ids = report["port_ids"]
        device_ids = {name: i + 1 for i, name in enumerate(sorted(report["devices"]))}
        blocks += ["namespace TDN.Deployments." + namespace,
                   "open MultiProtocolForwarding LayeredFrame",
                   "set_option maxRecDepth 1000000", "set_option maxHeartbeats 0"]
        for tag in [1, 2]:
            blocks.append(f"""lemma carrier_inbound_checks_{tag} :
    TableDrivenCarrierInputChecks devices ifaces carriers {tag} := by
  unfold TableDrivenCarrierInputChecks
  decide

lemma carrier_input_preserves_boundary_{tag} : CarrierInputCheck config expectedEncapStack {tag} :=
  table_driven_carrier_input_checks_sound devices ifaces routes links bridges macIfaces carriers {tag}
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
            blocks.append(f"""def {name} := Requirements.mixedTunnelBoundary config expectedEncapStack
  [{inside}] [{outside}] {tag} {component}

lemma {name}_nonempty_attachments :
    ([{inside}] : List Nat) ≠ [] ∧ ([{outside}] : List Nat) ≠ [] := by native_decide

lemma {name}_ip_tags : ∀ entry, config.ip.owner entry = {component} →
    ∀ policy ∈ config.ip.ingressPolicies entry, policy.tag = {tag} := by
  have checked : ∀ policy ∈ (DataPlaneForwarding.deviceAt devices {component}).ingressPolicies,
      policy.tag = {tag} := by native_decide
  intro entry owner policy member
  change (DataPlaneForwarding.ifaceAt ifaces entry).owner = {component} at owner
  change policy ∈ (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces entry).owner).ingressPolicies at member
  rw [owner] at member
  exact checked policy member

lemma {name}_mac_tags : ∀ iface ∈ config.macIfaces,
    config.ip.owner iface.physicalIface = {component} →
    ∀ association ∈ iface.receiveAssociations, association.tag = {tag} := by
  change ∀ iface ∈ macIfaces, (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).owner = {component} →
    ∀ association ∈ iface.receiveAssociations, association.tag = {tag}
  decide

theorem {name}_no_bypass : Requirements.BoundaryNoBypass {name} :=
  Requirements.mixed_tunnel_boundary_from_local_checks config expectedEncapStack [{inside}] [{outside}] {tag} {component}
    mixed_local_conditions carrier_input_preserves_boundary_{tag}
    {name}_ip_tags {name}_mac_tags (by native_decide) (by native_decide)
""")
            direction = "Reverse" if device.endswith("A") else "Forward"
            label = direction + ("VLAN0" if bridged else "")
            trace_path = RUN / "mixed-traces" / (tunnel_matrix_module(namespace, label) + ".json")
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
                         ", by native_decide, by native_decide⟩ (" + proof + ")")
            blocks.append(f"""theorem {name}_positive_inbound :
    ∃ start actions finish, {name}.inboundEntry start ∧
      {name}.system.MTr start actions finish ∧ {name}.inboundExit finish := by
  refine ⟨{label}.usefulState{first}, {actions}, {label}.usefulState{last}, ?_, ?_, ?_⟩
  · simp only [{name}, Requirements.mixedTunnelBoundary]
    decide
  · exact {proof}
  · simp only [{name}, Requirements.mixedTunnelBoundary]
    decide
""")
            metadata.append({"configuration": namespace, "device": device, "component": component,
                             "tag": tag, "inside": inside, "outside": outside, "report": str(path),
                             "positive_trace": str(trace_path), "first": first, "last": last,
                             "proof": "TDN.Deployments." + namespace + "." + name + "_no_bypass"})
        blocks.append("end TDN.Deployments." + namespace)
    Path("TDN/Deployments/SnapshotMixedTunnelBoundaries.lean").write_text(forwarding_lean("\n\n".join(blocks)) + "\n")
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
