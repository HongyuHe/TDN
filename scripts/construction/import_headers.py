import argparse
import json
from pathlib import Path
from validate_evidence import validate_bundle,require
from import_snapshot import identifier,quoted,lean_list,parse_rule
from source_paths import source_path


def ipv6_disabled(bundle,snapshot,device,inactive_ids=()):
    observations=[o for o in snapshot["observations"] if o.get("device_id")==device and "net.ipv6.conf.all.disable_ipv6" in o.get("command",[])]
    require(len(observations)==1 and observations[0]["returncode"]==0,"complete IPv6 disablement observation missing")
    raw=json.loads((bundle/observations[0]["raw_path"]).read_text())["stdout"]
    values=dict(line.split(" = ") for line in raw.splitlines())
    interfaces=[i for i in snapshot["interfaces"] if i["device_id"]==device]
    names=["all","default"]+[i["name"] for i in interfaces if i["id"] not in inactive_ids]
    require(all(values.get("net.ipv6.conf."+name+".disable_ipv6")=="1" and values.get("net.ipv6.conf."+name+".forwarding")=="0" for name in names),"IPv6 family is active or disablement is incomplete")
    require(not any(a.get("family")=="inet6" for i in interfaces for a in i["addresses"]),"IPv6 address present")
    require(not any(r["device_id"]==device and r["family"]==6 for r in snapshot["routes"]),"IPv6 route present")
    return {"device":device,"observation_id":observations[0]["id"],"disable_values":values}


def generate(bundle,output,report_path,chain_module="LoadedBaseline",namespace="Headers"):
    from analyze_topology import validated_graph
    graph=validated_graph(bundle)
    inactive_ids={i["interface_id"] for i in graph["inactive_interfaces"]}
    validation=validate_bundle(bundle)
    snapshot=json.loads((bundle/"snapshot.json").read_text())
    ns=identifier(snapshot["snapshot_id"])
    devices=[d for d in snapshot["devices"] if d["role"] in {"inner","outer"}]
    require(bool(devices),"empty VPN inventory")
    lines=["import TDN.Deployments."+chain_module,"import TDN.Requirements.Headers","namespace TDN.Deployments."+namespace,"open TDN.Deployments."+ns,"set_option maxRecDepth 100000","set_option maxHeartbeats 0"]
    definitions=[]
    observations=[]
    chain_ids=[]
    for device in devices:
        require(any(t["device_id"]==device["id"] and t["mechanism"]=="IPsec" for t in snapshot["tunnels"]),"header target currently supports inventoried IPsec gateways only")
        observations.append(ipv6_disabled(bundle,snapshot,device["id"],inactive_ids))
        chains=[c for c in snapshot["filters"] if c["device_id"]==device["id"] and c["family"]==4]
        require(len(chains)==3 and {c["chain"] for c in chains}=={"INPUT","FORWARD","OUTPUT"},"all IPv4 hooks must be inventoried exactly once")
        for chain in chains:
            require(chain["policy"]=="drop" and chain["table"]=="filter" and chain["status"]=="observed","header model needs observed default-deny filter chains")
            for rule in chain["ordered_rules"]:parse_rule(rule)
            chain_ids.append(chain["id"])
        all_chains=lean_list(["chain_"+identifier(c["id"]) for c in chains])
        receive=lean_list(["chain_"+identifier(c["id"]) for c in chains if c["chain"] in {"INPUT","FORWARD"}])
        outer=device["role"]=="outer"
        definitions.append("⟨"+", ".join([quoted(device["id"]),str(outer).lower(),quoted("black" if outer else "gray"),"true","false",str(outer).lower(),all_chains,"[]",receive,"[]"])+"⟩")
    lines.append("def gateways : List Requirements.GatewayHeaderPolicy := "+lean_list(definitions))
    lines.append("lemma all_header_certificates : ∀ g ∈ gateways, Requirements.HeaderCertificate g := by unfold gateways; decide")
    lines.append("theorem snapshot_RG038 : Requirements.msc_ip_header_and_multicast_filtering gateways := Requirements.header_certificates_suffice gateways (by unfold gateways; decide) all_header_certificates")
    lines.append("end TDN.Deployments."+namespace)
    output.write_text("\n\n".join(lines)+"\n")
    report={"snapshot_id":snapshot["snapshot_id"],"validation":validation,"devices":len(devices),"chain_ids":chain_ids,"ipv6_disabled":observations,"theorem":"TDN.Deployments."+namespace+".snapshot_RG038","inactive_interfaces":graph["inactive_interfaces"],"scope":"IPv4-only inventoried IPsec profile, ordered filter-table model with Outer IPv4-options objective; all modeled INPUT/FORWARD/OUTPUT packets quantified, not sampled probes","assumptions":["Raw collector truth and complete inventoried VPN/filter/interface state","iptables token semantics and decoded IP-header correspondence","Linux places applicable IP packets through the represented hooks with no alternative path or later override","Inactive IPv6 applicability follows observed data/loopback/all/default disablement, absent addresses/routes, and separately checked down/unaddressed/unrouted/unattached/unconfigured GRE fallback abstractions","Scope limited to this snapshot/profile; MACsec and active IPv6 profiles need independent instantiation"]}
    report_path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"devices":len(devices),"chains":len(chain_ids)}))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--lean-output",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    parser.add_argument("--source-key",default="loaded")
    parser.add_argument("--chain-module",default="LoadedBaseline")
    parser.add_argument("--namespace",default="Headers")
    args=parser.parse_args()
    generate(source_path(args.source_key),args.lean_output,args.report,args.chain_module,args.namespace)
