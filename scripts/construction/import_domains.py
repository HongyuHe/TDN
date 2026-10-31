import argparse
import hashlib
import json
from pathlib import Path
from import_snapshot import identifier,quoted,lean_list
from source_paths import verified_source
from validate_evidence import require,unique_records,safe_path,utc


def validate_declaration(data):
    require(data["schema_version"] in {"csfc-security-declarations/v1","csfc-native-profile-declarations/v1"},"wrong declaration schema")
    utc(data["created_at"])
    configs=data["configurations"]
    require(configs and len({c["configuration_id"] for c in configs})==len(configs),"empty/duplicate configurations")
    for config in configs:
        require(config["status"]=="declared","semantic labels must retain declared status")
        levels=unique_records(config["security_levels"],"security level")
        networks=unique_records(config["red_networks"],"Red network")
        require(levels and networks,"empty security-domain declaration")
        used_inner=set()
        for level in levels.values():
            require(isinstance(level["classification"],str) and bool(level["classification"]),"classification label missing")
            for field in ["compartments","dissemination_controls","other_controls"]:
                values=level[field]
                require(isinstance(values,list) and all(isinstance(v,str) and v for v in values) and len(set(values))==len(values),"controls must be explicit duplicate-free string sets")
        for network in networks.values():
            require(network["security_level_id"] in levels and network["site"] and network["logical_network_id"] and network["trust_domain_id"],"network domain association incomplete")
            inners=network["inner_device_ids"]
            require(inners and len(inners)==len(set(inners)) and not used_inner.intersection(inners),"Inner component shared across distinct declared Red networks")
            used_inner.update(inners)
            require(network["source_case_ids"],"network has no source case")
        bindings=config["device_port_bindings"]
        require(len({b["interface_id"] for b in bindings})==len(bindings),"duplicate declared interface binding")
        bound_inner=set()
        for binding in bindings:
            network=networks[binding["red_network_id"]]
            require(binding["security_level_id"]==network["security_level_id"],"port label differs from Red network")
            require(binding["interface_id"].startswith(binding["device_id"]+":"),"port does not identify its device")
            if binding["binding_role"]=="inner-red-attachment":
                require(binding["device_id"] in network["inner_device_ids"],"Inner binding crosses Red-network identity")
                bound_inner.add(binding["device_id"])
            else:require(binding["binding_role"]=="red-host-attachment","unknown declared port role")
        require(bound_inner==used_inner,"Inner Red port bindings incomplete")
    return configs


def has_figure_six(levels):
    return any(l["classification"]=="TOP_SECRET" for l in levels) and all(any(l["classification"]=="SECRET" and control in l["dissemination_controls"] for l in levels) for control in ["US_ONLY","COALITION"])


def bind_native_declaration(config,bundle,manifest,snapshot):
    require(config["snapshot_id"]==snapshot["snapshot_id"],"native declaration snapshot identity mismatch")
    require(config["snapshot_manifest_sha256"]==hashlib.sha256((bundle/"manifest.json").read_bytes()).hexdigest(),"native declaration manifest binding mismatch")
    require(config["spec_sha256"]==hashlib.sha256((bundle/"spec.json").read_bytes()).hexdigest()==manifest["configuration_hashes"]["spec"],"native declaration specification mismatch")
    require(config["configuration_id"]==manifest["configuration_id"] and config["emulation_id"]==manifest["emulation_id"],"native declaration configuration mismatch")
    require(set(config["source_case_ids"])==set(manifest["source_case_ids"]),"native declaration source-case scope mismatch")


def level_lean(level):
    fields=[quoted(level["classification"])]+["{"+", ".join(quoted(v) for v in level[key])+"}" for key in ["compartments","dissemination_controls","other_controls"]]
    return "⟨"+", ".join(fields)+"⟩"


def generate(output,report_path):
    path=verified_source("domain_declaration")
    root=path.parent
    manifest=json.loads(safe_path(root,"manifest.json").read_text())
    require(manifest["schema_version"]=="csfc-security-declarations/v1","declaration manifest schema mismatch")
    for entry in manifest["files"]:
        content=safe_path(root,entry["path"]).read_bytes()
        require(hashlib.sha256(content).hexdigest()==entry["sha256"] and len(content)==entry["bytes"],"declaration hash/size mismatch")
    configs=validate_declaration(json.loads(path.read_text()))
    lines=["import TDN.Evidence.DomainTypes","namespace TDN.Imported.Domains","set_option maxRecDepth 100000","set_option maxHeartbeats 0"]
    reports=[]
    for config in configs:
        ns=identifier(config["configuration_id"])
        lines.append("namespace "+ns)
        levels={l["id"]:l for l in config["security_levels"]}
        lines.append("def levels : List SecurityLevel := "+lean_list([level_lean(l) for l in levels.values()]))
        values=[]
        for network in config["red_networks"]:
            identity="⟨"+", ".join([quoted(network["id"]),quoted(network["site"]),level_lean(levels[network["security_level_id"]]),"{"+", ".join(quoted(i) for i in network["inner_device_ids"])+"}"])+"⟩"
            values.append("⟨"+", ".join([identity,quoted(network["logical_network_id"]),quoted(network["trust_domain_id"]),lean_list([quoted(c) for c in network["source_case_ids"]])])+"⟩")
        lines.append("def networks : List Evidence.DeclaredRedNetwork := "+lean_list(values))
        lines.append("theorem declared_dedicated_inner_assignments : DedicatedInnerAssignments (networks.map Evidence.DeclaredRedNetwork.identity) := by unfold DedicatedInnerAssignments networks; decide")
        if config["configuration_id"]=="shared-same-level":
            lines.append("theorem declared_distinct_domains_same_full_level : Evidence.DifferentDomainsAtSameLevel networks := by unfold Evidence.DifferentDomainsAtSameLevel networks; decide")
        else:
            lines.append("theorem declared_figure_six_levels : Evidence.HasSourceFigureSixLevels levels := by unfold Evidence.HasSourceFigureSixLevels levels; decide")
            lines.append("theorem declared_additional_unclassified : ∃ l ∈ levels, l.classification = \"UNCLASSIFIED\" := by unfold levels; decide")
        lines.append("end "+ns)
        reports.append({"configuration_id":config["configuration_id"],"spec_sha256":config["spec_sha256"],"network_count":len(config["red_networks"]),"level_count":len(levels),"qualifications":config["qualifications"],"runtime_binding":"pending matching immutable snapshot/spec hash and observed interface inventory"})
    lines.append("end TDN.Imported.Domains")
    output.write_text("\n\n".join(lines)+"\n")
    report_path.write_text(json.dumps({"declaration_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"configurations":reports,"status":"declared semantic/configuration facts only","full_groups_established":[]},indent=2)+"\n")
    print(json.dumps({"declared_configurations":len(configs)}))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--lean-output",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    generate(args.lean_output,args.report)
