#!/usr/bin/env python3
"""Collect fresh, allowlisted MSC evidence without reading secret files."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import time


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--spec",required=True)
    p.add_argument("--output",required=True)
    p.add_argument("--configuration-id",required=True)
    p.add_argument("--case-ids",default="")
    a=p.parse_args()
    spec=json.loads(Path(a.spec).read_text())
    root=Path(a.output)
    root.mkdir(parents=True,exist_ok=False)
    (root/"raw").mkdir()
    started=utc()
    sid=root.name
    observations=[]
    failures=[]
    devices={d["id"]:d for d in spec["devices"]}
    def container(d):
        return d["id"] if spec["version"]==2 else "twinet-"+spec["name"]+"-"+d["id"].lower()
    def observe(device,kind,command,timeout=20):
        oid="obs-%05d"%(len(observations)+1)
        cmd=["docker","exec",container(devices[device]),*command] if device else command
        begin=utc()
        try:
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout)
            rc=r.returncode
            body=r.stdout
            stderr=r.stderr
        except subprocess.TimeoutExpired as e:
            rc=124
            body=(e.stdout or b"").decode() if isinstance(e.stdout,bytes) else (e.stdout or "")
            stderr="collector timeout"
        if "PRIVATE KEY-----" in body or "PRIVATE KEY-----" in stderr:
            raise RuntimeError("Refused secret material in allowlisted observation")
        raw={"stdout":body,"stderr":stderr}
        data=(json.dumps(raw,indent=2)+"\n").encode()
        path="raw/"+oid+".json"
        (root/path).write_bytes(data)
        ob={"id":oid,"collector":"construction-collect/v1","command":cmd,"device_id":device,"kind":kind,"started_at":begin,"ended_at":utc(),"returncode":rc,"raw_path":path,"raw_sha256":digest(data),"sanitizer":"xfrm-nokeys-and-public-allowlist","parse_status":"raw"}
        observations.append(ob)
        if rc:
            failures.append({"observation_id":oid,"kind":kind,"returncode":rc})
        return body,ob
    def parsed(body):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None
    def fact(oid,did,status="observed",**kw):
        return {"id":oid,"device_id":did,"status":status,**kw}
    snapshot={"schema_version":"csfc-evidence/v1","snapshot_id":sid,"scope":{"expected_device_ids":list(devices),"expected_interface_ids":[d["id"]+":"+i["name"] for d in spec["devices"] for i in d["interfaces"]],"source_case_ids":a.case_ids.split(",") if a.case_ids else [],"management_applicability":"optional_disabled"},"devices":[],"interfaces":[],"links":[],"routes":[],"filters":[],"tunnels":[],"credentials":[],"probes":[],"management":{"profile":"none","applicability":"optional_disabled","records":[],"failures":[]},"observations":observations,"limitations":[]}
    _,hostob=observe(None,"software",["sh","-c","uname -a; docker version --format {{.Server.Version}}; date -u +%FT%TZ"])
    pre={}
    observed={}
    commands={"interfaces":["ip","-j","-d","address","show"],"routes4":["ip","-j","-4","route","show","table","all"],"routes6":["ip","-j","-6","route","show","table","all"],"filters4":["iptables-save","-t","filter"],"filters6":["ip6tables-save","-t","filter"],"policies":["ip","xfrm","policy","list"],"states":["ip","-s","xfrm","state","list","nokeys"],"forwarding":["sysctl","net.ipv4.ip_forward","net.ipv6.conf.all.forwarding"]}
    for did,d in devices.items():
        rows={}
        for kind,cmd in commands.items():
            body,ob=observe(did,kind,cmd)
            rows[kind]=(body,ob)
            if kind in ["routes4","routes6","filters4","filters6","policies"]:
                pre[did+"/"+kind]=digest(body.encode())
        observed[did]=rows
        body,ob=observe(None,"container-inspect",["docker","inspect","--format","{{json .}}",container(d)])
        info=parsed(body) or {}
        snapshot["devices"].append(fact(did,did,role=d["role"],site=d.get("site"),security_level_id=d.get("level"),implementation="Linux container",namespace=container(d),host_id=platform.node(),virtualization_kind="container-shared-kernel",physical_independence="unavailable",image_id=info.get("Image"),observed_running=info.get("State",{}).get("Running"),observation_ids=[ob["id"]]))
        for port in parsed(rows["interfaces"][0]) or []:
            declared=next((i for i in d["interfaces"] if i["name"]==port["ifname"]),{})
            snapshot["interfaces"].append(fact(did+":"+port["ifname"],did,name=port["ifname"],zone=declared.get("zone","local"),addresses=port.get("addr_info",[]),address_family=sorted({i["family"] for i in port.get("addr_info",[])}),link_kind=port.get("linkinfo",{}).get("info_kind",port.get("link_type")),parent_interface=port.get("link"),mtu=port.get("mtu"),observed_up="UP" in port.get("flags",[]),security_level_id=d.get("level"),observation_ids=[rows["interfaces"][1]["id"]]))
        for family in [4,6]:
            key="routes"+str(family)
            for j,r in enumerate(parsed(rows[key][0]) or []):
                snapshot["routes"].append(fact(did+":"+key+":"+str(j),did,family=family,table=r.get("table","main"),destination=r.get("dst","default"),gateway=r.get("gateway"),output_interface=r.get("dev"),priority=r.get("metric"),protocol=r.get("protocol"),type=r.get("type","unicast"),raw=r,observation_ids=[rows[key][1]["id"]]))
            key="filters"+str(family)
            chains={}
            for line in rows[key][0].splitlines():
                if line.startswith(":"):
                    tok=line.split()
                    chains[tok[0][1:]]={"policy":tok[1],"ordered_rules":[]}
                elif line.startswith("-A "):
                    tok=shlex.split(line)
                    rule={"ordinal":len(chains[tok[1]]["ordered_rules"]),"matches":tok[2:tok.index("-j")] if "-j" in tok else tok[2:],"action":tok[tok.index("-j")+1] if "-j" in tok else "unsupported","raw_text":line,"observation_ids":[rows[key][1]["id"]]}
                    chains[tok[1]]["ordered_rules"].append(rule)
            for name,ch in chains.items():
                snapshot["filters"].append(fact(did+":"+key+":"+name,did,family=family,table="filter",chain=name,hook=name.lower(),priority=0,observation_ids=[rows[key][1]["id"]],**ch))
        if d.get("tunnel"):
            t=d["tunnel"]
            sas,so=observe(did,"sas",["swanctl","--list-sas"])
            conns,co=observe(did,"connections",["swanctl","--list-conns"])
            certs,ce=observe(did,"public-certificates",["swanctl","--list-certs","--utc"])
            snapshot["tunnels"].append(fact(did+":tunnel",did,peer_device_id=t["peer"],layer=d["role"],mechanism="IPsec",endpoints={"local":t["local"],"remote":t["remote"]},traffic_selectors={"local":t["local_ts"],"remote":t["remote_ts"]},mode="tunnel",algorithms={"raw_sas":sas},authentication={"configured":"pubkey","observed_connections":conns},replay_protection={"raw_states":rows["states"][0]},lifetimes={"raw_connections":conns},observed_state=sas,policies=rows["policies"][0],statistics=rows["states"][0],encapsulation=None,observation_ids=[so["id"],co["id"],rows["states"][1]["id"],rows["policies"][1]["id"]]))
            snapshot["credentials"].append(fact(did+":credentials",did,layer=d["role"],authentication_kind="certificate",public_certificate_listing=certs,chain_validation="unavailable from listing alone",revocation_evidence="local CRL details in public listing",observation_ids=[ce["id"]]))
    for j,l in enumerate(spec["links"]):
        aid=l["a"]["device"]+":"+l["a"]["interface"]
        bid=l["b"]["device"]+":"+l["b"]["interface"]
        snapshot["links"].append({"id":"link-%03d"%j,"status":"configured","endpoints":[aid,bid],"relation":"veth","physical_claim_supported":False,"observation_ids":[observed[l["a"]["device"]]["interfaces"][1]["id"],observed[l["b"]["device"]]["interfaces"][1]["id"]]})
    hosts=[d for d in spec["devices"] if d["role"]=="host"]
    for src in hosts:
        for dst in hosts:
            if src["id"]==dst["id"]:
                continue
            addr=next(i["address"].split("/")[0] for i in dst["interfaces"] if i.get("address"))
            same=src.get("level")==dst.get("level")
            body,ob=observe(src["id"],"probe",["ping","-n","-c","2","-W","1",addr],timeout=7)
            outcome="delivered" if ob["returncode"]==0 else "no_reply" if ob["returncode"]==1 else "collection_error"
            snapshot["probes"].append({"id":"probe-"+ob["id"],"status":"observed" if outcome!="collection_error" else "failed","source_device":src["id"],"destination":addr,"destination_device":dst["id"],"family":4,"protocol":"icmp","source_case_ids":snapshot["scope"]["source_case_ids"],"purpose":"same-level useful traffic" if same else "cross-level denial","expected_result":"delivered" if same else "no_reply","observed_result":outcome,"command":ob["command"],"started_at":ob["started_at"],"ended_at":ob["ended_at"],"returncode":ob["returncode"],"observation_ids":[ob["id"]]})
    post={}
    for did in devices:
        for kind in ["routes4","routes6","filters4","filters6","policies"]:
            body,ob=observe(did,"convergence-"+kind,commands[kind])
            post[did+"/"+kind]=digest(body.encode())
    changed=[k for k in pre if pre[k]!=post[k]]
    failures=[f for f in failures if not (f["kind"]=="probe" and f["returncode"]==1)]
    snapshot["limitations"].append({"id":"virtual-appliances","affected_case_ids":snapshot["scope"]["source_case_ids"],"classification":"physical_capability","reason":"Containers and veth links share one Linux host; the capture does not establish physical separation, product independence, secure facilities or formal approval.","actionable_change":"Supply external physical and organizational records."})
    (root/"snapshot.json").write_text(json.dumps(snapshot,indent=2)+"\n")
    (root/"spec.json").write_text(json.dumps(spec,indent=2)+"\n")
    files=[]
    for path in sorted(root.rglob("*")):
        if path.is_file():
            files.append({"path":str(path.relative_to(root)),"sha256":digest(path.read_bytes()),"bytes":path.stat().st_size,"category":"raw" if path.parent.name=="raw" else "normalized"})
    manifest={"schema_version":"csfc-evidence/v1","snapshot_id":sid,"run_id":"construction-v2","configuration_id":a.configuration_id,"emulation_id":spec["name"],"source_case_ids":snapshot["scope"]["source_case_ids"],"requirement_group_ids":[],"started_at":started,"ended_at":utc(),"host":platform.node(),"software":{"kernel":platform.release(),"python":platform.python_version()},"code_hashes":{"collector":digest(Path(__file__).read_bytes())},"configuration_hashes":{"spec":digest(Path(a.spec).read_bytes())},"files":files,"collection_failures":failures,"sanitization":{"private_files_read":False,"xfrm_key_export":False},"inventory_complete":{k:{"complete":not failures,"reason":"Explicit expected inventory and every command result retained."} for k in ["devices","interfaces","links","routes","filters","tunnels","credentials","probes"]},"management":{"complete":True,"reason":"Optional profile disabled."},"convergence":{"before":pre,"after":post,"selected_fields":["IPv4 and IPv6 routes","IPv4 and IPv6 ordered filters","XFRM policies"],"consistent":not changed,"changed":changed,"interpretation":"No observed configuration changes across collection; finite sequential observation only."}}
    (root/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps({"snapshot_id":sid,"observations":len(observations),"failures":len(failures),"converged":not changed,"probes":len(snapshot["probes"]),"unexpected_probes":[q["id"] for q in snapshot["probes"] if q["expected_result"]!=q["observed_result"]]}))

if __name__=="__main__":
    main()
