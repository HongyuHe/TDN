import argparse
from collections import deque
import json
from pathlib import Path
from analyze_topology import validated_graph
from import_snapshot import identifier,lean_list


def shortest_path(edges,start,end,removed):
    queue=deque([[start]])
    visited={start}
    while queue:
        path=queue.popleft()
        if path[-1]==end:return path
        for left,right in sorted(edges):
            if left==path[-1] and right not in removed and right not in visited:
                visited.add(right)
                queue.append(path+[right])
    return None


def audit(bundle,output,report_path):
    graph=validated_graph(bundle)
    devices=graph["devices"]
    edges=graph["gray_edges"]
    inner=graph["inner"]
    firewalls=graph["gray_fw"]
    sides=graph["gray_sides"]
    failures=[]
    applicable_pairs=0
    for a in inner:
        for b in inner:
            if a>=b or devices[a]["security_level_id"]==devices[b]["security_level_id"]:continue
            applicable_pairs+=1
            path=shortest_path(edges,a,b,set(firewalls))
            if path is not None:
                failures.append({"nodes":path,"path":[devices[i]["id"] for i in path],"levels":[devices[a]["security_level_id"],devices[b]["security_level_id"]]})
    ns=identifier(graph["snapshot"]["snapshot_id"])+"_gray"
    levels=sorted({d["security_level_id"] for d in devices if d["security_level_id"] is not None})
    level_ids=[0 if d["security_level_id"] is None else levels.index(d["security_level_id"])+1 for d in devices]
    lines=["import TDN.Semantics.Waypointing","namespace TDN.Imported."+ns,"set_option maxRecDepth 100000","set_option maxHeartbeats 0","abbrev Node := Fin "+str(len(devices))]
    lines.append("def edges : List (Node × Node) := "+lean_list(["("+str(a)+", "+str(b)+")" for a,b in sorted(edges)]))
    lines.append("def innerNodes : List Node := "+lean_list([str(i) for i in inner]))
    lines.append("def firewallNodes : List Node := "+lean_list([str(i) for i in firewalls]))
    lines += ["def edge (a b : Node) : Prop := (a,b) ∈ edges","def firewall (a : Node) : Prop := a ∈ firewallNodes","def level (a : Node) : Nat := "+lean_list([str(i) for i in level_ids])+"[a.val]!","def side (a : Node) : Nat := "+lean_list([str(i) for i in sides])+"[a.val]!"]
    if failures:
        path=failures[0]["nodes"]
        def step(a,b):
            return "(show Waypointing.Avoiding edge firewall ("+str(a)+" : Node) "+str(b)+" from by unfold Waypointing.Avoiding edge edges firewall firewallNodes; decide)"
        proof="(Relation.ReflTransGen.single "+step(path[0],path[1])+")"
        for a,b in zip(path[1:-1],path[2:]):proof="("+proof+".tail "+step(a,b)+")"
        lines.append("theorem concrete_bypass : Relation.ReflTransGen (Waypointing.Avoiding edge firewall) ("+str(path[0])+" : Node) "+str(path[-1])+" := "+proof)
        lines.append("theorem bypass_crosses_distinct_levels : ("+str(path[0])+" : Node) ∈ innerNodes ∧ ("+str(path[-1])+" : Node) ∈ innerNodes ∧ level "+str(path[0])+" ≠ level "+str(path[-1])+" ∧ ¬ firewall "+str(path[0])+" := by unfold innerNodes level firewall firewallNodes; decide")
    elif applicable_pairs>0:
        lines += [
            "lemma local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → side a = side b := by unfold edge edges firewall firewallNodes side; decide",
            "lemma start_clear : ∀ a, a ∈ innerNodes → ¬ firewall a := by unfold innerNodes firewall firewallNodes; decide",
            "lemma sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → side a ≠ side b := by unfold innerNodes level side; decide",
            "theorem cross_level_waypointing (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Waypointing.Avoiding edge firewall) a b := Waypointing.waypointing_of_edge_invariant edge firewall side local_cut (start_clear a ha) (sides_differ a b ha hb different)"
        ]
    lines.append("end TDN.Imported."+ns)
    output.write_text("\n\n".join(lines)+"\n")
    probes=graph["snapshot"]["probes"]
    report={"snapshot_id":graph["snapshot"]["snapshot_id"],"manifest_sha256":graph["validation"]["source_manifest_sha256"],"snapshot_sha256":graph["validation"]["source_snapshot_sha256"],"device_order":[d["id"] for d in devices],"gray_edges":len(edges),"cross_level_cut_passed":not failures if applicable_pairs else None,"applicable_cross_level_pairs":applicable_pairs,"inactive_interfaces":graph["inactive_interfaces"],"native_runtime":graph["native_runtime"],"bypasses":failures,"sample_probe_count":len(probes),"sample_probe_expectations_match":all(p["expected_result"]==p["observed_result"] for p in probes),"theorem_namespace":"TDN.Imported."+ns,"scope":"All paths of conservative observed device-contracted Gray graph; bypass is structural reachability, not a claim that a filtered packet traversed it","assumptions":["Raw observation truth and collector inventory completeness","Declared roles, levels and zones","Veth namespace association and bridge membership verified against raw observations","Administratively down/unaddressed/unrouted/unattached GRE fallback interfaces contribute no live connectivity under the stated Linux interpretation","Collected states only; matching before/after observations do not prove uninterrupted constancy"]}
    report_path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"snapshot":report["snapshot_id"],"cut":not failures if applicable_pairs else None,"bypasses":len(failures),"first_bypass":failures[0] if failures else None}))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("bundle",type=Path)
    parser.add_argument("--lean-output",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    audit(args.bundle,args.lean_output,args.report)
