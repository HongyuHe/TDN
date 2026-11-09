"""Apply unchanged boundary proofs to raw-bound family components and actual delivery segments."""
import json
import os
from pathlib import Path
from network_names import address_family_module, forwarding_lean

from import_snapshot import quoted
from validate_evidence import require

RUN = Path(os.environ["TDN_OUTPUT_DIR"])


def main():
    blocks = ["import TDN.Requirements.EncryptionComponentNoBypassSpec"]
    metadata = []
    for family in ["444", "446", "464", "466", "644", "646", "664", "666"]:
        blocks.append("import TDN.Deployments." + address_family_module(family) + "_SampleTrace")
    for family in ["444", "446", "464", "466", "644", "646", "664", "666"]:
        report = json.loads((RUN / ("fresh-family" + family + "-import.json")).read_text())
        trace = json.loads((RUN / ("family" + family + "-positive-trace.json")).read_text())
        namespace = "TDN.Deployments." + address_family_module(family)
        blocks += ["namespace " + namespace, "open DataPlaneForwarding", "set_option maxRecDepth 1000000",
                   "set_option maxHeartbeats 0"]
        for device in ["IA", "IB", "OA", "OB"]:
            inner = device[0] == "I"
            tag = 1 if inner else 2
            component = report["device_ids"][device]
            inside = report["port_ids"][device + (":red" if inner else ":gray")]
            outside = report["port_ids"][device + (":gray" if inner else ":black")]
            require(report["policies"][device]["in"] and report["policies"][device]["out"],
                    "Empty selected boundary policies")
            require(all(a[1] == tag for a in report["policies"][device]["in"]),
                    "Inbound policy tag differs")
            name = "boundary" + device
            blocks.append(f"def {name} := Requirements.operationalTunnelBoundary config expectedEncapStack [{inside}] [{outside}] {tag} {component}")
            blocks.append(f"""lemma {name}_inbound_tags : ∀ iface, config.owner iface = {component} →
    ∀ a ∈ config.ingressPolicies iface, a.tag = {tag} := by
  have checked : ∀ a ∈ (deviceAt devices {component}).ingressPolicies, a.tag = {tag} := by decide
  intro iface owner a member
  change (ifaceAt ifaces iface).owner = {component} at owner
  change a ∈ (deviceAt devices (ifaceAt ifaces iface).owner).ingressPolicies at member
  rw [owner] at member
  exact checked a member

theorem {name}_no_bypass : Requirements.BoundaryNoBypass {name} :=
  Requirements.tunnel_boundary_from_local_stack_checks config expectedEncapStack [{inside}] [{outside}] {tag} {component}
    local_stack_conditions {name}_inbound_tags (by decide) (by decide)
""")
            outbound = device[-1] == "A"
            first_port, last_port = (inside, outside) if outbound else (outside, inside)
            first = next(i for i, state in enumerate(trace["states"])
                         if state["phase"] == "received" and state["port"] == first_port)
            last = next(i for i, state in enumerate(trace["states"])
                        if i > first and state["phase"] == "ready" and state["port"] == last_port)
            actions = "[" + ", ".join("." + s["action"] for s in trace["steps"][first:last]) + "]"
            proof = "Cslib.LTS.MTr.refl"
            for index in reversed(range(first, last)):
                proof = ("Cslib.LTS.MTr.stepL ⟨witnessStep" + str(index) +
                         ", by decide, by decide⟩ (" + proof + ")")
            direction = "outbound" if outbound else "inbound"
            blocks.append(f"""theorem {name}_positive_{direction} :
    ∃ start actions finish, {name}.{direction}Entry start ∧
      {name}.system.MTr start actions finish ∧ {name}.{direction}Exit finish := by
  refine ⟨witnessState{first}, {actions}, witnessState{last}, ?_, ?_, ?_⟩
  · simp only [{name}, Requirements.operationalTunnelBoundary]
    decide
  · exact {proof}
  · simp only [{name}, Requirements.operationalTunnelBoundary]
    decide
""")
            metadata.append({"family": family, "device": device, "inside": inside, "outside": outside,
                             "component": component, "tag": tag, "positive_direction": direction,
                             "positive_first_state": first, "positive_last_state": last,
                             "input_report": "fresh-family" + family + "-import.json"})
        blocks.append("end " + namespace)
    Path("TDN/Deployments/SnapshotFamilyTunnelBoundaries.lean").write_text(forwarding_lean("\n\n".join(blocks)) + "\n")
    (RUN / "family_tunnel_boundaries.json").write_text(json.dumps({
        "applications": metadata,
        "scope": ["Inbound traversal starts with arbitrary encapLayers and empty local authentication.",
                  "Outbound input belongs to the surrounding protected-payload execution.",
                  "Every inbound decryption conclusion names this component, layer and original payload.",
                  "The current application proves boundary clauses. Full group settings and other mechanisms remain separately accounted."]
    }, indent=2) + "\n")
    print(json.dumps({"component_boundary_applications": len(metadata)}))


if __name__ == "__main__":
    main()
