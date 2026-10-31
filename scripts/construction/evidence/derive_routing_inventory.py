"""Derive routing-process and attachment evidence from retained local observations."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze_topology import validated_graph
from import_macsec_runtime import validate_files
from validate_evidence import require


def derive(inventory, bundles):
    inventory = Path(inventory)
    inventory_hash = validate_files(inventory)
    manifest = json.loads((inventory / "manifest.json").read_text())
    collector = Path(__file__).with_name("native_inventory.py")
    require(hashlib.sha256(collector.read_bytes()).hexdigest() == manifest["code_hashes"][collector.name],
            "Inventory collector source differs from captured version")
    data = json.loads((inventory / "observations.json").read_text())
    processes = json.loads((inventory / "namespace-processes.json").read_text())
    records = {r["id"]: r for r in data["records"]}
    require(len(records) == len(data["records"]), "Duplicate inventory observation ID")
    require(len({p["host_pid"] for p in processes["processes"]}) == len(processes["processes"]),
            "Duplicate recorded host PID")
    for process in processes["processes"]:
        require(process["device_scopes"] == processes["namespace_owners"].get(process["network_namespace"]),
                "Host process namespace attribution differs")
    for association in processes["docker_associations"]:
        require(association["device_scopes"] == processes["namespace_owners"].get(association["network_namespace"]),
                "Container namespace attribution differs")
    result = []
    for bundle in map(Path, bundles):
        graph = validated_graph(bundle)
        snap = graph["snapshot"]
        configuration = json.loads((bundle / "manifest.json").read_text())["configuration_id"]
        scopes = [s for s in data["scopes"] if s["configuration_id"] == configuration]
        require(len(scopes) == 1, "Missing or duplicate process scope")
        scope = scopes[0]
        devices = {d["id"]: d for d in snap["devices"]}
        observed = {d["device_id"]: d for d in scope["devices"]}
        require(len(observed) == len(scope["devices"]) and set(devices) == set(observed) == set(scope["expected_device_ids"]),
                "Process scope and complete topology device inventories differ")
        entries = []
        for name, device in devices.items():
            if device["role"] not in {"inner", "outer"}:
                continue
            entry = observed[name]
            identity = entry["identity_before"]
            namespace = entry["network_namespace_identity"]
            owner = configuration + ":" + name
            require(processes["namespace_owners"].get(namespace) == [owner], "Namespace ownership differs")
            raw = records[entry["inventory_observation_id"]]
            require(raw["command"] == ["docker", "exec", device["namespace"], "python3", "[hashed inventory script]"] and
                    raw["returncode"] == 0 and json.loads(raw["stdout"]) == entry["inventory"],
                    "Container inventory differs from raw observation")
            inspect = [r for r in records.values() if r["command"] ==
                       ["docker", "inspect", "--format", "{{json .}}", device["namespace"]]]
            require(len(inspect) == 1 and inspect[0]["returncode"] == 0, "Missing identity observation")
            actual = json.loads(inspect[0]["stdout"])
            require(actual["Id"] == identity["id"] and actual["Image"] == identity["image"] == device["image_id"] and
                    actual["State"]["Pid"] == identity["state"]["Pid"] and actual["State"]["Running"] is True,
                    "Process container identity differs")
            end_command = ["docker", "inspect", "--format", "{{.Id}} {{.State.Pid}} {{.State.StartedAt}}", device["namespace"]]
            end = [r for r in records.values() if r["command"] == end_command]
            expected_end = f'{actual["Id"]} {actual["State"]["Pid"]} {actual["State"]["StartedAt"]}'
            require(len(end) == 1 and end[0]["returncode"] == 0 and
                    end[0]["stdout"].strip() == entry["identity_after"] == expected_end, "Container changed during inventory")
            snapshot_inspect = [o for o in snap["observations"] if o["command"][:2] == ["docker", "inspect"] and
                                o["command"][-1] == device["namespace"] and o["returncode"] == 0]
            require(snapshot_inspect, "Missing snapshot identity binding")
            for o in snapshot_inspect:
                value = json.loads(json.loads((bundle / o["raw_path"]).read_text())["stdout"])
                require(value["Id"] == actual["Id"] and value["State"]["Pid"] == actual["State"]["Pid"] and
                        value["State"]["StartedAt"] == actual["State"]["StartedAt"], "Snapshot and process collection identity differ")
            running = [p for p in processes["processes"] if p["network_namespace"] == namespace]
            require(running and all(p["device_scopes"] == [owner] for p in running), "Process namespace attribution differs")
            associations = [a for a in processes["docker_associations"] if a["network_namespace"] == namespace]
            main = [a for a in associations if a["id"] == actual["Id"]]
            require(len(main) == 1 and main[0]["host_pid"] == actual["State"]["Pid"] and
                    main[0]["image"] == actual["Image"], "Missing main container namespace association")
            known = {("sleep", "sleep infinity"), ("charon", "/usr/lib/ipsec/charon")}
            process_rows = [{"host_pid": p["host_pid"], "name": p["name"], "command": p["command"].strip(),
                             "state": p["process_state"], "recognized_fixed_program": (p["name"],p["command"].strip()) in known}
                            for p in running]
            attachments = []
            for link in snap["links"]:
                ids = link["endpoint_interface_ids"]
                if any(i.split(":",1)[0] == name for i in ids):
                    attachments.append({"endpoints": ids, "observation_ids": link["observation_ids"]})
            interfaces = [{k: i[k] for k in ["id", "name", "zone", "addresses", "link_kind", "observed_up", "observation_ids"]}
                          for i in snap["interfaces"] if i["device_id"] == name]
            entries.append({"device_id":name,"role":device["role"],"namespace":namespace,
                            "container_id":actual["Id"],"image_id":actual["Image"],"container_pid":actual["State"]["Pid"],
                            "identity_observation_ids":[inspect[0]["id"],entry["inventory_observation_id"],end[0]["id"]],
                            "snapshot_identity_observation_ids":[o["id"] for o in snapshot_inspect],
                            "recorded_host_processes":process_rows,"all_recorded_programs_recognized":all(p["recognized_fixed_program"] for p in process_rows),
                            "same_namespace_containers":[{k:a[k] for k in ['id','name','host_pid','image','network_mode']} for a in associations],
                            "startup_directories":entry["inventory"]["startup_files"],
                            "service_manager_observations":[r for r in entry["inventory"]["commands"] if r["argv"][0]=='systemctl'],
                            "interfaces":interfaces,"attachments":attachments})
        result.append({"configuration_id":configuration,"snapshot":str(bundle),
                       "snapshot_manifest_sha256":graph["validation"]["source_manifest_sha256"],
                       "complete_device_count":len(devices),"encryption_devices":entries,
                       "validated_edges":sorted(graph["edges"]),"device_indices":graph["indices"],
                       "snapshot_filter_records":snap["filters"],
                       "topology_scope":"Validated reciprocal virtual attachments. Potential graph paths do not establish actual packet forwarding or physical separation."})
    return {"schema_version":"csfc-derived-routing-evidence/v1","request_id":"C-ROUTING-010",
            "derived_at":datetime.now(timezone.utc).isoformat(),"inventory_bundle":str(inventory),
            "inventory_manifest_sha256":inventory_hash,"inventory_interval":[data["started_at"],data["ended_at"]],
            "host_process_observed_at":processes["observed_at"],"collector_sha256":manifest['code_hashes'][collector.name],
            "configurations":result,
            "assumptions_and_missing_fields":[
                "The host collector enumerates /proc and selects processes by network namespace, including sidecars. It silently skips vanished or unreadable processes; no per-process read-error ledger is exported. Complete observation therefore requires a collector/access/no-relevant-race assumption.",
                "The host process list and namespace associations are direct collector JSON observations, not individual recorded shell readlink commands. Main container identities separately bind to raw Docker observations.",
                "Program names and commands identify recorded sleep and charon programs under an image/runtime correspondence assumption. They are not an executable attestation or a proof against hidden or modified software.",
                "Successful inventory enumeration covers an observation interval. Future process launches, injected execution or configuration changes are not excluded.",
                "The retained public-file inventory does not include complete FRR configuration files or arbitrary charon plugin code. A missing FRR row alone is not used as proof of absence.",
                "Inner forwarding-for-other-encryptors and parallel placement require applying graph/filter semantics to the supplied attachment and raw rule records. Optional management is not required for the selected data-path analysis.",
            ]}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--inventory',required=True)
    parser.add_argument('--bundles',nargs='+',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    output=Path(args.output)
    require(not output.exists(),'Refusing to overwrite a derived evidence version')
    data=derive(args.inventory,args.bundles)
    output.mkdir(parents=True)
    body=output/'routing-evidence.json';body.write_text(json.dumps(data,indent=2)+'\n')
    manifest={'request_id':'C-ROUTING-010','derived_at':data['derived_at'],
              'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'files':[{'path':body.name,'bytes':body.stat().st_size,'sha256':hashlib.sha256(body.read_bytes()).hexdigest()}]}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'output':str(output),'configurations':len(data['configurations']),
                      'encryption_devices':sum(len(c['encryption_devices']) for c in data['configurations'])}))


if __name__=='__main__':
    main()
