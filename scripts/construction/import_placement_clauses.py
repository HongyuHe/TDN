"""Derive selected parallel, Red-egress and redundant placement facts from exact native graphs."""
import argparse
import json
import os
from pathlib import Path
from analyze_topology import validated_graph
from validate_evidence import require

RUN = Path(os.environ.get("TDN_OUTPUT_DIR", "data/construction/2026-10-24T014455Z"))
BASE = Path("data/snapshots/2026-10-24T014455Z")


def path_to_outer(graph, source):
    queue = [[source]]
    visited = {source}
    while queue:
        path = queue.pop(0)
        if path[-1] in graph["outer"]:
            return path
        for left, right in sorted(graph["gray_edges"]):
            if left == path[-1] and right not in visited and right not in graph["inner"]:
                visited.add(right)
                queue.append(path + [right])
    raise ValueError("An Inner has no branch to an Outer without another Inner")


def generate(shared, redundant):
    graph = validated_graph(shared)
    rg = validated_graph(redundant)
    require(len(graph["inner"]) > 1 and len(rg["outer"]) >= 4,
            "Nonempty parallel and redundant scopes are required")
    black = [i for i in rg["black"] if any(
        interface["device_id"] == rg["devices"][i]["id"] and interface["zone"] == "black"
        for interface in rg["snapshot"]["interfaces"])]
    require(black and all(
        interface["zone"] in {"black", "local", None}
        for interface in rg["snapshot"]["interfaces"]
        if interface["device_id"] in {rg["devices"][i]["id"] for i in black}),
        "Selected Black transports have conflicting zone declarations")
    paths = [path_to_outer(graph, i) for i in graph["inner"]]
    red = [i for i, device in enumerate(graph["devices"]) if device["role"] == "host"]
    require(red and all(graph["devices"][i]["security_level_id"] for i in red),
            "Actual selected Red hosts require security labels")
    require(all(a in graph["inner"] or b in graph["inner"] or ((a in red) == (b in red))
                for a, b in graph["edges"]), "Red attachment cut fails")
    text = """import TDN.Targets.PlacementClauses
import TDN.Evidence.FreshSharedTopology

namespace TDN.Imported.FreshSharedTopology
set_option maxRecDepth 100000
set_option maxHeartbeats 0
"""
    text += "def independentBranches : List (Node × Node × List Node) := [" + ", ".join(
        "(" + str(p[0]) + ", " + str(p[-1]) + ", " + str(p[1:]) + ")" for p in paths) + "]\n"
    text += """
lemma branch_checks : ∀ branch ∈ independentBranches,
    inner branch.1 ∧ outer branch.2.1 ∧
    List.IsChain (Waypointing.Avoiding grayEdge inner) (branch.1 :: branch.2.2) ∧
    (branch.1 :: branch.2.2).getLast (List.cons_ne_nil _ _) = branch.2.1 := by
  unfold independentBranches inner innerNodes outer outerNodes Waypointing.Avoiding grayEdge grayEdges
  decide

lemma branch_inventory_complete : ∀ node ∈ innerNodes,
    ∃ branch ∈ independentBranches, branch.1 = node := by
  unfold innerNodes independentBranches
  decide

theorem every_inner_has_an_independent_outer_branch (node : Node) (member : node ∈ innerNodes) :
    ∃ destination, outer destination ∧
      Relation.ReflTransGen (Waypointing.Avoiding grayEdge inner) node destination := by
  obtain ⟨branch, present, same⟩ := branch_inventory_complete node member
  obtain ⟨_, destination, chain, last⟩ := branch_checks branch present
  refine ⟨branch.2.1, destination, ?_⟩
  rw [← same]
  exact Targets.independent_inner_branch_from_chain grayEdge inner branch.2.2 chain last

"""
    text += "def redNodes : List Node := " + str(red) + "\n"
    text += """def isRed (node : Node) : Bool := node ∈ redNodes
lemma red_attachment_cut : ∀ a b, edge a b → ¬ inner a → ¬ inner b → isRed a = isRed b := by
  unfold edge edges inner innerNodes isRed redNodes
  decide
lemma red_start_clear : ∀ node ∈ redNodes, ¬ inner node := by
  unfold redNodes inner innerNodes
  decide
lemma actual_red_attachment_nonempty : redNodes ≠ [] ∧
    ∀ node ∈ redNodes, ∃ gateway, inner gateway ∧ edge node gateway := by
  unfold redNodes inner innerNodes edge edges
  decide

theorem every_virtual_red_egress_crosses_inner (source destination : Node)
    (start : source ∈ redNodes) (outside : isRed destination = false) :
    ¬ Relation.ReflTransGen (Waypointing.Avoiding edge inner) source destination :=
  Targets.red_egress_crosses_inner_from_attachment_cut edge inner isRed red_attachment_cut
    (red_start_clear source start) (by simpa [isRed] using start) outside

end TDN.Imported.FreshSharedTopology

namespace TDN.Imported.FreshRedundantPlacement
set_option maxRecDepth 100000
set_option maxHeartbeats 0
"""
    text += "abbrev Node := Fin " + str(len(rg["devices"])) + "\n"
    for name, values in [("edges", sorted(rg["edges"])), ("outerNodes", rg["outer"]),
                         ("firewallNodes", rg["firewall"]), ("blackNodes", black)]:
        text += "def " + name + " : List " + ("(Node × Node)" if name == "edges" else "Node") + " := " + str(values) + "\n"
    text += "def side (node : Node) : Nat := " + str(rg["outer_sides"]) + "[node.val]!\n"
    text += """def edge (a b : Node) : Prop := (a,b) ∈ edges
def firewall (node : Node) : Prop := node ∈ firewallNodes
lemma actual_redundant_inventory : outerNodes.length = 4 := by decide
lemma local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b := by
  unfold edge edges firewall firewallNodes side
  decide
lemma starts_clear : ∀ node ∈ outerNodes, ¬ firewall node := by
  unfold outerNodes firewall firewallNodes
  decide
lemma sides_differ : ∀ source ∈ outerNodes, ∀ destination ∈ blackNodes,
    side source ≠ side destination := by
  unfold outerNodes blackNodes side
  decide
lemma actual_firewall_connections : ∀ source ∈ outerNodes, ∃ f ∈ firewallNodes,
    ∃ destination ∈ blackNodes, edge source f ∧ edge f destination := by
  unfold outerNodes firewallNodes blackNodes edge edges
  decide
theorem redundant_outers_preserve_required_firewall_cut (source destination : Node)
    (start : source ∈ outerNodes) (finish : destination ∈ blackNodes) :
    ¬ Relation.ReflTransGen (Waypointing.Avoiding edge firewall) source destination :=
  Waypointing.waypointing_of_edge_invariant edge firewall side local_cut
    (starts_clear source start) (sides_differ source start destination finish)
end TDN.Imported.FreshRedundantPlacement
"""
    report = {"shared_bundle": str(shared), "redundant_bundle": str(redundant),
              "shared_validation": graph["validation"], "redundant_validation": rg["validation"],
              "independent_branches": [{"devices": [graph["devices"][i]["id"] for i in p], "indices": p} for p in paths],
              "red_hosts": [graph["devices"][i]["id"] for i in red],
              "black_transports": [rg["devices"][i]["id"] for i in black],
              "redundant_outers": [rg["devices"][i]["id"] for i in rg["outer"]],
              "scope": "SR16 actual parallel Inner-to-Outer branches, SR14 virtual Red attachment protection, and actual redundant Outers' retained firewall-placement clause. No physical NIC separation, product approval, full compliance or automatic failover claim.",
              "contracts": ["Complete truthful observed links and device roles under existing exact native graph importer.",
                            "Device contraction overapproximates internal paths.",
                            "NR is the declared redundant Outer example; untrusted Black branch from original CP placement context."]}
    return text, report


if __name__ == "__main__":
    text, report = generate(BASE / "native-shared-four-levels-20261024T015300Z-coverage-v1",
                            BASE / "native-redundant-20261024T020100Z")
    Path("TDN/Evidence/FreshPlacementClauses.lean").write_text(text)
    (RUN / "fresh-placement-clauses.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({"branches": len(report["independent_branches"]), "red_hosts": len(report["red_hosts"]),
                      "redundant_outers": len(report["redundant_outers"])}))
