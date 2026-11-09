import argparse
import hashlib
import json
from pathlib import Path
from analyze_topology import validated_graph
from import_domains import validate_declaration,level_lean,has_figure_six,bind_native_declaration
from import_mechanisms import probe_outcome
from import_snapshot import quoted,lean_list
from source_paths import source_path,verified_source
from validate_evidence import require


def bind_configuration(config,bundle,snapshot,manifest):
    require(config["configuration_id"]==manifest["configuration_id"] and config["emulation_id"]==manifest["emulation_id"],"declaration configuration/emulation mismatch")
    digest=hashlib.sha256((bundle/"spec.json").read_bytes()).hexdigest()
    require(digest==manifest["configuration_hashes"]["spec"]==config["spec_sha256"],"declaration does not bind this exact specification")
    levels={l["id"]:l for l in config["security_levels"]}
    devices={d["id"]:d for d in snapshot["devices"]}
    interfaces={i["id"]:i for i in snapshot["interfaces"]}
    networks={n["id"]:n for n in config["red_networks"]}
    inner_map={i:n for n in networks.values() for i in n["inner_device_ids"]}
    require(set(inner_map)=={d["id"] for d in devices.values() if d["role"]=="inner"},"declared Inner coverage differs from runtime inventory")
    host_map={}
    for binding in config["device_port_bindings"]:
        device=devices[binding["device_id"]]
        interface=interfaces[binding["interface_id"]]
        network=networks[binding["red_network_id"]]
        require(device["site"]==network["site"] and device["security_level_id"]==network["security_level_id"],"device level/site declaration does not match captured configuration metadata")
        if device.get("network_id") is not None:
            require(device["network_id"]==network["logical_network_id"],"device network declaration differs from captured configuration metadata")
        require(interface["device_id"]==device["id"] and interface["zone"]=="red" and interface["status"]=="observed","declared Red port not observed")
        if device["role"]=="inner":
            require(device.get("trust_domain_id")==network["trust_domain_id"],"declared trust domain differs from captured configuration metadata")
        elif device["role"]=="host":host_map[device["id"]]=network
        else:raise ValueError("unexpected Red port role")
    for network in networks.values():
        ports=[b["interface_id"] for b in config["device_port_bindings"] if b["red_network_id"]==network["id"]]
        require(any(set(l["endpoint_interface_ids"])==set(ports) for l in snapshot["links"] if l["relation"]=="veth"),"declared local Red host/Inner attachment lacks observed adjacency")
    return levels,inner_map,host_map


def parsed_wrapped_ping(probe,observation,bundle,devices):
    command=observation["command"]
    require(command[:3]==["docker","exec",devices[probe["source_device"]]["namespace"]] and command[-1]==probe["destination"],"wrapped probe namespace/destination mismatch")
    require("python3" in command and any('subprocess.run(["ping"' in arg for arg in command),"unsupported ping observer wrapper")
    raw=json.loads((bundle/observation["raw_path"]).read_text())
    require(observation["returncode"]==0 and not raw["stderr"].strip(),"ping observer collection failed")
    tested=json.loads(raw["stdout"])
    result,tx,rx=probe_outcome({**tested,"command":["ping",probe["destination"]]})
    require(tested["returncode"]==probe["returncode"] and result==probe["observed_result"],"normalized ping outcome differs from raw tested-program result")
    return result,tx,rx


def generate(output,report_path,source_key="coherent_same_level",namespace="SameLevelBinding",declaration_key="domain_declaration"):
    declaration_path=verified_source(declaration_key)
    configs=validate_declaration(json.loads(declaration_path.read_text()))
    bundle=source_path(source_key)
    graph=validated_graph(bundle)
    snapshot=graph["snapshot"]
    manifest=json.loads((bundle/"manifest.json").read_text())
    config=next(c for c in configs if c["configuration_id"]==manifest["configuration_id"])
    if declaration_key=="native_declaration":bind_native_declaration(config,bundle,manifest,snapshot)
    levels,inner_map,host_map=bind_configuration(config,bundle,snapshot,manifest)
    bindings=[]
    for tunnel in snapshot["tunnels"]:
        if tunnel["layer"]!="inner":continue
        local=inner_map[tunnel["device_id"]];remote=inner_map[tunnel["peer_device_id"]]
        bindings.append({"tunnel_id":tunnel["id"],"left":levels[local["security_level_id"]],"right":levels[remote["security_level_id"]],"logical_left":local["logical_network_id"],"logical_right":remote["logical_network_id"]})
    require(bindings,"no Inner tunnel binding")
    observations={o["id"]:o for o in snapshot["observations"]}
    devices={d["id"]:d for d in snapshot["devices"]}
    probes=[]
    for probe in snapshot["probes"]:
        require(probe["source_device"] in host_map and probe["destination_device"] in host_map and len(probe["observation_ids"])==1,"unexpected same-level probe endpoints")
        left=host_map[probe["source_device"]]["logical_network_id"];right=host_map[probe["destination_device"]]["logical_network_id"]
        result,tx,rx=parsed_wrapped_ping(probe,observations[probe["observation_ids"][0]],bundle,devices)
        probes.append({"id":probe["id"],"source":probe["source_device"],"destination":probe["destination_device"],"logical_left":left,"logical_right":right,"result":result,"transmitted":tx,"received":rx,"source_purpose_annotation":probe["purpose"],"derived_purpose":"same-logical-network delivery" if left==right else ("same-level cross-network refusal" if levels[host_map[probe["source_device"]]["security_level_id"]]==levels[host_map[probe["destination_device"]]["security_level_id"]] else "cross-level cross-network refusal")})
    require({(p["source"],p["destination"]) for p in probes}=={(a,b) for a in host_map for b in host_map if a!=b},"ordered Red host probe-pair coverage incomplete")
    lines=["import TDN.Deployments.DomainTypes","namespace TDN.Deployments."+namespace,"set_option maxRecDepth 100000"]
    lines.append("def peerLevels : List (SecurityLevel × SecurityLevel) := "+lean_list(["("+level_lean(b["left"])+", "+level_lean(b["right"])+")" for b in bindings]))
    lines.append("theorem observed_inner_peers_have_same_full_declared_level : peerLevels ≠ [] ∧ ∀ p ∈ peerLevels, p.1 = p.2 := by unfold peerLevels; decide")
    captured_levels=[levels[n["security_level_id"]] for n in host_map.values()]
    lines.append("def capturedLevels : List SecurityLevel := "+lean_list([level_lean(level) for level in captured_levels]))
    if has_figure_six(captured_levels):
        lines.append("theorem captured_source_figure_six_levels : Evidence.HasSourceFigureSixLevels capturedLevels := by unfold Evidence.HasSourceFigureSixLevels capturedLevels; decide")
    lines.append("def logicalProbes : List (String × String × String) := "+lean_list(["("+quoted(p["logical_left"])+", "+quoted(p["logical_right"])+", "+quoted(p["result"])+")" for p in probes]))
    lines.append("theorem recorded_logical_domain_outcomes : ∀ p ∈ logicalProbes, p.2.2 = (if p.1 = p.2.1 then \"delivered\" else \"no_reply\") := by unfold logicalProbes; decide")
    lines.append("theorem positive_and_negative_witnesses : (∃ p ∈ logicalProbes, p.2.2 = \"delivered\") ∧ (∃ p ∈ logicalProbes, p.1 ≠ p.2.1 ∧ p.2.2 = \"no_reply\") := by unfold logicalProbes; decide")
    lines.append("end TDN.Deployments."+namespace)
    output.write_text("\n\n".join(lines)+"\n")
    report_path.write_text(json.dumps({"snapshot_id":snapshot["snapshot_id"],"manifest_sha256":graph["validation"]["source_manifest_sha256"],"declaration_sha256":hashlib.sha256(declaration_path.read_bytes()).hexdigest(),"spec_sha256":config["spec_sha256"],"identity_scope":"Logical network identities come from the hash-bound scenario declaration; present captured metadata must agree, and absent optional network_id fields are not treated as observed identities","bindings":bindings,"probes":probes,"inactive_interfaces":graph["inactive_interfaces"],"scope":"Hash-bound declared level/network meaning and finite runtime peer/probe records; no universal cross-network authentication exclusion or physical port claim","unbound_declarations":[c["configuration_id"] for c in configs if c!=config]},indent=2)+"\n")
    print(json.dumps({"peer_bindings":len(bindings),"probes":len(probes)}))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--lean-output",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    parser.add_argument("--source-key",default="coherent_same_level")
    parser.add_argument("--namespace",default="SameLevelBinding")
    parser.add_argument("--declaration-key",default="domain_declaration")
    args=parser.parse_args()
    generate(args.lean_output,args.report,args.source_key,args.namespace,args.declaration_key)
