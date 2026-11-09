import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
from import_provenance import verified_files
from import_snapshot import quoted,lean_list
from source_paths import source_path
from validate_evidence import require,unique_records,utc

NATIVE_KEYS=["native_baseline","native_same_level","native_shared","native_redundant","native_management"]
ROUTING_NAMES=["zebra","ospfd","ospf6d","bgpd","ripd","ripngd","isisd","pimd","pim6d","eigrpd","babeld","staticd","ldpd","nhrpd","bird","bird6","routed","gated"]


def dns_servers(content):
    rows=[line.split() for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    servers=[]
    for row in rows:
        if row[0]=="nameserver":
            require(len(row)==2,"malformed resolver nameserver")
            servers.append(ipaddress.ip_address(row[1]))
    require(servers,"resolver has no explicit literal server")
    return servers


def inventory(root):
    manifest,files=verified_files(root)
    require(manifest["schema_version"]=="csfc-component-inventory/v1","wrong component inventory schema")
    data=json.loads((root/"observations.json").read_text())
    namespaces=json.loads((root/"namespace-processes.json").read_text())
    observations=unique_records(data["records"],"inventory observation")
    require(utc(data["started_at"])<=utc(namespaces["observed_at"])<=utc(data["ended_at"]),"namespace scan outside inventory interval")
    snapshots={}
    for key in NATIVE_KEYS:
        bundle=source_path(key)
        m=json.loads((bundle/"manifest.json").read_text())
        snapshots[m["configuration_id"]]=(bundle,m,json.loads((bundle/"snapshot.json").read_text()))
    require({s["configuration_id"] for s in data["scopes"]}==set(snapshots),"native inventory configuration coverage incomplete")
    rows=[];owners={};unavailable=[]
    for scope in data["scopes"]:
        bundle,sm,snapshot=snapshots[scope["configuration_id"]]
        require(scope["spec_sha256"]==sm["configuration_hashes"]["spec"],"inventory spec differs from bound native snapshot")
        devices={d["id"]:d for d in snapshot["devices"]}
        require(set(scope["expected_device_ids"])==set(devices)=={d["device_id"] for d in scope["devices"]} and len(scope["devices"])==len(devices),"inventory device coverage mismatch")
        for device in scope["devices"]:
            did=device["device_id"];name=device["container"];record=observations[device["inventory_observation_id"]]
            require(name==devices[did]["namespace"] and record["command"]==["docker","exec",name,"python3","[hashed inventory script]"],"inventory observer/device association mismatch")
            require(record["returncode"]==0 and not record["stderr"].strip() and json.loads(record["stdout"])==device["inventory"],"normalized inventory differs from successful raw observer")
            before=[r for r in observations.values() if r["command"]==["docker","inspect","--format","{{json .}}",name]]
            after=[r for r in observations.values() if r["command"]==["docker","inspect","--format","{{.Id}} {{.State.Pid}} {{.State.StartedAt}}",name]]
            require(len(before)==len(after)==1 and before[0]["returncode"]==after[0]["returncode"]==0,"identity collection incomplete")
            raw=json.loads(before[0]["stdout"]);identity=device["identity_before"]
            require(raw["Id"]==identity["id"] and raw["Image"]==identity["image"] and raw["State"]["Running"] and raw["State"]["Pid"]==identity["state"]["Pid"] and raw["State"]["StartedAt"]==identity["state"]["StartedAt"],"normalized before identity differs")
            expected=" ".join([raw["Id"],str(raw["State"]["Pid"]),raw["State"]["StartedAt"]])
            require(after[0]["stdout"].strip()==device["identity_after"]==expected,"device identity changed during inventory")
            require(utc(before[0]["ended_at"])<=utc(record["started_at"])<=utc(record["ended_at"])<=utc(after[0]["started_at"]),"identity/observer ordering mismatch")
            scope_id=scope["configuration_id"]+":"+did;net=device["network_namespace_identity"]
            require(namespaces["namespace_owners"].get(net)==[scope_id],"network namespace ownership mismatch")
            owners[scope_id]=net
            associations=[a for a in namespaces["docker_associations"] if a["id"]==identity["id"]]
            require(len(associations)==1 and associations[0]["host_pid"]==raw["State"]["Pid"] and associations[0]["network_namespace"]==net and associations[0]["device_scopes"]==[scope_id],"host namespace scan identity mismatch")
            snap_inspects=[o for o in snapshot["observations"] if o.get("command",[])[:2]==["docker","inspect"] and o["command"][-1]==name]
            snap_identities=[json.loads(json.loads((bundle/o["raw_path"]).read_text())["stdout"]) for o in snap_inspects if o["returncode"]==0]
            require(any(i.get("Id")==identity["id"] and i.get("State",{}).get("Pid")==raw["State"]["Pid"] for i in snap_identities),"inventory container differs from topology snapshot")
            inv=device["inventory"];public=inv["public_files"]["/etc/resolv.conf"]
            require(public["exists"],"resolver file absent")
            servers=dns_servers(public["content"])
            root_users=[a for a in inv["access"] if a["user"]=="root"]
            require(len(root_users)==1 and root_users[0]["uid"]==0,"root account inventory missing/ambiguous")
            root_user=root_users[0]
            require(root_user.get("hash_exported") is False,"password hash exported or status missing")
            processes=[p for p in namespaces["processes"] if scope_id in p["device_scopes"]]
            require(processes and all(p["network_namespace"]==net for p in processes),"host process namespace association inconsistent")
            unavailable.extend({"device":scope_id,"command":c["argv"],"reason":c.get("unavailable",c.get("stderr"))} for c in inv["commands"] if c.get("returncode")!=0)
            rows.append({"scope":scope_id,"device_id":did,"configuration_id":scope["configuration_id"],"role":devices[did]["role"],"dns_servers":[str(a) for a in servers],"dns_lookup_configuration":inv["public_files"]["/etc/nsswitch.conf"],"root_password_locked":root_user.get("password_locked"),"root_empty_password":root_user.get("empty_password"),"process_names":sorted(set(p["name"] for p in processes)),"process_ids":[p["host_pid"] for p in processes],"observation_id":record["id"],"identity_observations":[before[0]["id"],after[0]["id"]],"snapshot_id":snapshot["snapshot_id"]})
    for process in namespaces["processes"]:
        require(process["device_scopes"]==namespaces["namespace_owners"].get(process["network_namespace"]),"process scopes differ from namespace ownership")
    sidecars=[]
    for association in namespaces["docker_associations"]:
        scopes=association["device_scopes"]
        require(scopes==namespaces["namespace_owners"].get(association["network_namespace"]),"container scopes differ from namespace ownership")
        if association["name"].endswith("-frr"):
            base=next(a for a in namespaces["docker_associations"] if a["name"]==association["name"].removesuffix("-frr"))
            require(association["network_mode"]=="container:"+base["id"] and association["network_namespace"]==base["network_namespace"],"FRR sidecar uses different namespace")
            sidecars.append(association)
    return {"bundle":str(root),"manifest_sha256":hashlib.sha256((root/"manifest.json").read_bytes()).hexdigest(),"collection_interval":[data["started_at"],data["ended_at"]],"rows":rows,"sidecars":sidecars,"observation_ids":list(observations),"unavailable_commands":unavailable,"routing_name_dictionary":ROUTING_NAMES,"assumptions":["Collector completeness and truth; normalized hash-script marker identifies the bundled collector by collector convention, not a raw shell command byte match","Known routing process names are a finite syntactic inventory, not exhaustive semantic detection of all routing implementations","Container/spec association binds distinct collection intervals without asserting unchanged intervening state"],"remaining_obligations":["Complete vendor-default inventory and historical changed/removed comparison","Automatic remote boot semantics","Full protocol/routing-function and all-interface behavior refinement","DNS lookup objective applicability; current inherited DNS use is explicit"]}


def generate(output,report_path):
    report=inventory(source_path("native_process_inventory"))
    lines=["import TDN.Requirements.Operations","namespace TDN.Deployments.NativeInventory","set_option maxRecDepth 100000"]
    dns=[]
    for row in report["rows"]:
        addresses=[]
        for value in row["dns_servers"]:
            address=ipaddress.ip_address(value)
            addresses.append(("Sum.inl" if address.version==4 else "Sum.inr")+" ⟨"+str(int(address))+", by decide⟩")
        dns.append("("+quoted(row["scope"])+", "+lean_list(addresses)+")")
    lines.append("def resolverConfigurations : List (String × List Requirements.DNSAddress) := "+lean_list(dns))
    lines.append("theorem every_recorded_component_has_specified_dns_server : resolverConfigurations ≠ [] ∧ ∀ c ∈ resolverConfigurations, c.2 ≠ [] := by unfold resolverConfigurations; decide")
    lines.append("def rootAccess : List (String × Bool × Bool) := "+lean_list(["("+quoted(r["scope"])+", "+str(r["root_password_locked"]).lower()+", "+str(r["root_empty_password"]).lower()+")" for r in report["rows"]]))
    lines.append("theorem recorded_root_passwords_locked : rootAccess ≠ [] ∧ ∀ r ∈ rootAccess, r.2.1 = true ∧ r.2.2 = false := by unfold rootAccess; decide")
    lines.append("def routingNames : List String := "+lean_list([quoted(s) for s in ROUTING_NAMES]))
    lines.append("def encryptorProcesses : List (String × List String) := "+lean_list(["("+quoted(r["scope"])+", "+lean_list([quoted(s) for s in r["process_names"]])+")" for r in report["rows"] if r["role"] in {"inner","outer"}]))
    lines.append("theorem no_recorded_encryptor_process_has_known_routing_name : encryptorProcesses ≠ [] ∧ ∀ c ∈ encryptorProcesses, ∀ name ∈ c.2, name ∉ routingNames := by unfold encryptorProcesses routingNames; decide")
    lines.append("end TDN.Deployments.NativeInventory")
    output.write_text("\n\n".join(lines)+"\n")
    report_path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"components":len(report["rows"]),"frr_sidecars":len(report["sidecars"]),"unavailable_commands":len(report["unavailable_commands"])}))

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--lean-output",required=True,type=Path);parser.add_argument("--report",required=True,type=Path);args=parser.parse_args();generate(args.lean_output,args.report)
