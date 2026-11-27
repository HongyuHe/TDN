"""Apply current TDN topology and packet-processing arguments to newly captured state."""
from collections import deque
import argparse
import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

from architecture_cases import complete_proof_input
from measure import typecheck
from observe_controls import HERE

ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/"mcp"))
from tdn_evidence.parsers.execution import parse_execution
from tdn_evidence.parsers.topology import validated_graph


def graph_input(native):
    g=validated_graph(native, ipv4_link_observations=True)
    gray={v:[] for v in range(len(g["devices"]))}
    for a,b in sorted(g["gray_edges"]):gray[a].append(b)
    security_levels={str(g["devices"][i]["security_level_id"]) for i in g["inner"]}
    if not security_levels:raise ValueError("Missing Inner security levels")
    gray_firewall_required=len(security_levels)>1
    destinations=g["gray_fw"] if gray_firewall_required else g["inner"]
    paths=[]
    for o in g["outer"]:
        pending=deque([(o,[])]);seen={o}
        while pending:
            current,path=pending.popleft()
            if current in destinations:
                paths.append([o,path])
                break
            for v in gray[current]:
                if v not in seen:
                    seen.add(v);pending.append((v,path+[v]))
    names=sorted({str(d["security_level_id"]) for d in g["devices"]})
    data={k:sorted(g[k]) for k in ("edges","gray_edges","inside","outside","outer","inner","black","firewall","gray_fw")}
    declared=json.loads((native/"spec.json").read_text())["devices"]
    black=[d["id"] for d in declared if d["role"]=="transport" and any(i["zone"]=="black" for i in d["interfaces"])]
    if not black: raise ValueError("No designated Black transport in the profile")
    data["black"]=[g["indices"][name] for name in black]
    data.update(count=len(g["devices"]),gray_paths=paths,gray_firewall_required=gray_firewall_required,levels=[names.index(str(d["security_level_id"])) for d in g["devices"]],
                outer_sides=g["outer_sides"],gray_sides=g["gray_sides"])
    return data


def prepare_template(spec,folder):
    text=(HERE/spec).read_text().replace('from "input.json"','from "evidence.json"')
    text=text.replace('set_option maxHeartbeats 0','set_option maxHeartbeats 10000000')
    lines=text.splitlines()
    first=next(i for i,l in enumerate(lines) if l.startswith("lemma "))
    lines.insert(first,'set_option Elab.async false\n\nrun_cmd do Lean.logInfo m!"TDN_BEGIN {← IO.monoNanosNow}"\n')
    pos=next(i for i,l in enumerate(lines) if l.startswith("end "))
    lines.insert(pos,'run_cmd do Lean.logInfo m!"TDN_END {← IO.monoNanosNow}"\n')
    result=folder/spec;result.write_text('\n'.join(lines)+'\n');return result


def suite(native,processing,out):
    out.mkdir(parents=True,exist_ok=False)
    summary={}
    sources=out/"fixed-sources";sources.mkdir()
    def check(key,file,fn):
        try:
            data=fn()
            lines=file.read_text().splitlines()
            expected=set(lines)
            result=typecheck(file,out/key,data,expected)
            summary[key]={k:result[k] for k in ("status","typecheck_ns","source_sha256","evidence_sha256","failed_obligations")}
        except Exception as err:
            summary[key]={"status":"import_error","message":str(err),"typecheck_ns":None}
    check("architecture", HERE/"MscArchitectureChecks.lean", lambda:complete_proof_input(native))
    check("topology", HERE/"TopologyChecks.lean",lambda:graph_input(native))
    parsed=None
    def packet_input():
        nonlocal parsed
        if parsed is None:
            parsed=parse_execution(native,processing,ipv4_link_observations=True)
            for device in parsed["devices"]:
                for hook in ("input", "forward", "output"):
                    rules = device[hook + "Rules"]
                    for i, rule in enumerate(rules):
                        if not rule["atoms"] and rule["verdict"] in {"allow", "deny"}:
                            device[hook + "Rules"] = rules[:i + 1]
                            device[hook + "Fallback"] = "deny"
                            break
            parsed["vpnIndices"]=[parsed["deviceIds"][d["id"]] for d in parsed["sourceDevices"] if d["role"] in ("inner","outer")]
            parsed["outerIndices"]=[parsed["deviceIds"][d["id"]] for d in parsed["sourceDevices"] if d["role"]=="outer"]
        return parsed
    for key,name in [("forwarding","SnapshotCompliance.lean"),("headers","HeaderCompliance.lean")]:
        check(key,prepare_template(name,sources),packet_input)
    def firewall_input():
        location=HERE/"perimeter/run.py"
        spec=spec_from_file_location("benchmark_perimeter_projection",location)
        mod=module_from_spec(spec);spec.loader.exec_module(mod)
        policy=json.loads((HERE/"perimeter/approved-control-policy.json").read_text())
        declaration=json.loads((native/"spec.json").read_text())
        return mod.project(packet_input(),mod.controls_from_intent(declaration,policy),declaration)
    check("firewall",HERE/"FirewallChecks.lean",firewall_input)
    (out/"summary.json").write_text(json.dumps(summary,indent=2)+'\n')
    return summary


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("snapshot",type=Path);p.add_argument("result",type=Path);a=p.parse_args()
    print({k:v['status'] for k,v in suite(a.snapshot/'native',a.snapshot/'processing',a.result).items()})
