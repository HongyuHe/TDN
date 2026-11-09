import hashlib
import json
from pathlib import Path
from source_paths import source_path,source_collection,output_path


def reconcile(register):
    successes=[]
    for path in output_path().glob("*-validation.json"):
        try:rows=json.loads(path.read_text())
        except (ValueError,OSError):continue
        if isinstance(rows,list) and rows and all(isinstance(r,dict) and r.get("returncode")==0 and "ended_at" in r for r in rows):
            successes.append((max(r["ended_at"] for r in rows),str(path)))
    validation={"kind":"historical_successful_check","path":max(successes)[1],"completed_at":max(successes)[0]} if successes else {"kind":"unvalidated"}
    catalog={}
    prefixes={}
    reports={}
    for name,filename in [("baseline","baseline-import.json"),("adjacency","adjacency-import.json"),("loaded","loaded-baseline-import.json"),("shared_before","shared_before-policies.json"),("shared_after","shared_after-policies.json"),("redundant_after","redundant_after-policies.json")]+[(name,name+"-import.json") for name in ["coherent_baseline","coherent_same_level","coherent_shared","coherent_redundant","coherent_management","four_shared","four_redundant","native_baseline","native_same_level","native_shared","native_redundant","native_management"]]:
        report=json.loads(output_path(filename).read_text())
        snapshot=json.loads((source_path(name)/"snapshot.json").read_text())
        key="snapshot:"+snapshot["snapshot_id"]
        catalog[key]={"kind":"observed_snapshot","bundle":str(source_path(name)),"manifest_sha256":report["validation"]["source_manifest_sha256"],"snapshot_sha256":report["validation"]["source_snapshot_sha256"],"report":str(output_path(filename)),"observation_ids":[o["id"] for o in snapshot["observations"]],"observation_scope":"Complete recorded snapshot dependency; narrower per-fact references remain in snapshot.json and import report","validation":validation}
        ns=snapshot["snapshot_id"].replace("-","_")
        prefixes["TDN.Deployments."+ns+"."]=[key]
        prefixes["TDN.Deployments."+ns+"_gray."]=[key]
        reports[name]=key
    scenario=source_path("scenario")
    catalog["declaration:transport"]={"kind":"declared_configuration_intent","path":str(scenario),"sha256":hashlib.sha256(scenario.read_bytes()).hexdigest(),"observation_ids":[],"validation":validation}
    prefixes["TDN.Deployments.baseline_adjacency_ipv6_20261017T2112Z_topology."]=[reports["adjacency"],"declaration:transport"]
    prefixes["TDN.Deployments.Headers."]=[reports["loaded"]]
    mechanisms=json.loads(output_path("mechanism-import.json").read_text())
    mechanism_keys=[]
    for case in mechanisms["cases"]:
        key="mechanism:"+case["id"]
        commands=json.loads((Path(case["bundle"])/"commands.json").read_text())
        catalog[key]={"kind":"finite_mechanism_experiment","bundle":case["bundle"],"manifest_sha256":case["manifest_sha256"],"report":str(output_path("mechanism-import.json")),"observation_ids":[o["id"] for o in commands],"validation":validation}
        mechanism_keys.append(key)
    prefixes["TDN.Deployments.Mechanisms."]=mechanism_keys
    for name in ["ikev2","ikev2_headers","mka_matching","mka_mismatched"]:
        bundle=source_path(name)
        events=json.loads((bundle/"events.json").read_text())
        catalog["events:"+name]={"kind":"finite_event_experiment","bundle":str(bundle),"manifest_sha256":hashlib.sha256((bundle/"manifest.json").read_bytes()).hexdigest(),"observation_ids":[r["id"] for r in events["records"]],"validation":validation}
    prefixes["TDN.Deployments.Events.observed_objective_exchange_sequence"]=["events:ikev2"]
    prefixes["TDN.Deployments.Events.matching_mka_outcome"]=["events:mka_matching"]
    prefixes["TDN.Deployments.Events.mismatched_mka_outcome"]=["events:mka_mismatched"]
    prefixes["TDN.Deployments.IKEHeaders."]=["events:ikev2_headers"]
    domain=source_path("domain_declaration")
    catalog["declaration:domains"]={"kind":"declared_configuration_intent","path":str(domain),"sha256":hashlib.sha256(domain.read_bytes()).hexdigest(),"observation_ids":[],"validation":validation}
    prefixes["TDN.Deployments.Domains."]=["declaration:domains"]
    prefixes["TDN.Deployments.SameLevelBinding."]=[reports["coherent_same_level"],"declaration:domains"]
    prefixes["TDN.Deployments.FourSharedBinding."]=[reports["four_shared"],"declaration:domains"]
    prefixes["TDN.Deployments.FourRedundantBinding."]=[reports["four_redundant"],"declaration:domains"]
    prefixes["TDN.Deployments.Management."]=[reports["coherent_management"]]
    mka_audit=source_path("mka_audit")
    catalog["source:mka-audit"]={"kind":"pinned_implementation_source","bundle":str(mka_audit),"manifest_sha256":hashlib.sha256((mka_audit/"manifest.json").read_bytes()).hexdigest(),"report":str(output_path("mka-source-import.json")),"observation_ids":[],"validation":validation}
    prefixes["TDN.Deployments.MKASource."]=["source:mka-audit","events:mka_matching"]
    native_declaration=source_path("native_declaration")
    catalog["declaration:native"]={"kind":"declared_configuration_intent","path":str(native_declaration),"sha256":hashlib.sha256(native_declaration.read_bytes()).hexdigest(),"observation_ids":[],"validation":validation}
    for name,ns in [("native_baseline","NativeBaseline"),("native_same_level","NativeSameLevel"),("native_shared","NativeShared"),("native_redundant","NativeRedundant"),("native_management","NativeManagement")]:
        snapshot=json.loads((source_path(name)/"snapshot.json").read_text())
        prefixes["TDN.Deployments."+snapshot["snapshot_id"].replace("-","_")+"_topology."]=[reports[name],"declaration:native"]
        prefixes["TDN.Deployments."+ns+"Binding."]=[reports[name],"declaration:native"]
        prefixes["TDN.Deployments."+ns+"Headers."]=[reports[name]]
    prefixes["TDN.Deployments.NativeManagementTLS."]=[reports["native_management"]]
    for name,filename,ns in [("native_process_inventory","native_inventory-import.json","NativeInventory"),("native_redundancy_events","native_redundancy-import.json","NativeRedundancy")]:
        report=json.loads(output_path(filename).read_text())
        key="events:"+name
        catalog[key]={"kind":"finite_native_inventory_or_event","bundle":str(source_path(name)),"manifest_sha256":report["manifest_sha256"],"report":str(output_path(filename)),"observation_ids":report["observation_ids"],"validation":validation}
        prefixes["TDN.Deployments."+ns+"."]=[key]+([reports[n] for n in ["native_baseline","native_same_level","native_shared","native_redundant","native_management"]] if name=="native_process_inventory" else [reports["native_redundant"]])
    supplemental=json.loads(output_path("supplemental-import.json").read_text())
    supplemental_keys={}
    for case in supplemental["cases"]+supplemental["ca"]:
        key="supplemental:"+case["id"]
        catalog[key]={"kind":"finite_supplemental_experiment","bundle":case["bundle"],"manifest_sha256":case["manifest_sha256"],"report":str(output_path("supplemental-import.json")),"observation_ids":case["observation_ids"],"source_case_ids":case["source_case_ids"],"validation":validation}
        supplemental_keys[case["id"]]=key
    for theorem,ids in {
        "recorded_probe_expectations":[c["id"] for c in supplemental["cases"] if c["probes"]],
        "useful_and_negative_probe_witnesses":[c["id"] for c in supplemental["cases"] if c["probes"]],
        "observed_ntp_replies_without_clock_adjustment":["time-red","time-gray"],
        "supplemental_tls_recorded_outcomes":["central-management","alternative-egress","management-vlan"],
        "observed_good_crl_authentication_exchanges":["ca-local","ca-enterprise","ca-central"],
        "recorded_ospf_neighbors_and_routes":["routing-ospf-black","routing-ospf-red"],
        "recorded_relay_both_branches":["cds-log"]}.items():
        prefixes["TDN.Deployments.Supplemental."+theorem]=[supplemental_keys[i] for i in ids]
    for name in ["auth_before","auth_after","auth_negative"]:
        bundle=source_path(name)
        events=json.loads((bundle/"events.json").read_text())
        catalog["events:"+name]={"kind":"finite_authentication_configuration_experiment","bundle":str(bundle),"manifest_sha256":hashlib.sha256((bundle/"manifest.json").read_bytes()).hexdigest(),"observation_ids":[r["id"] for r in events["records"]],"validation":validation}
    prefixes["TDN.Deployments.Authentication.recorded_sha256_refusal_and_sha384_recovery"]=["events:auth_negative"]
    prefixes["TDN.Deployments.Authentication."]=["events:auth_before","events:auth_after"]
    extensions=json.loads(output_path("extensions-import.json").read_text())
    extension_keys={}
    for case in extensions["http"]+extensions["eap"]+[dict(extensions["aw"],id="aw-placement"),dict(extensions["redundancy"],id="redundancy-events")]:
        key="extension:"+case["id"]
        catalog[key]={"kind":"finite_extension_experiment","bundle":case["bundle"],"manifest_sha256":case["manifest_sha256"],"report":str(output_path("extensions-import.json")),"observation_ids":case["observation_ids"],"source_case_ids":case["source_case_ids"],"validation":validation}
        extension_keys[case["id"]]=key
    for theorem,ids in {"http_exception_0_bounded":["http-crl-v1"],"http_exception_1_bounded":["http-ocsp-v1"],"observed_revocation_status_pairs":["http-crl-v1","http-ocsp-v1"],"eap_authentication_without_successful_data_probe":[e["id"] for e in extensions["eap"]],"recorded_host_and_guest_tls_use":["aw-placement"],"recorded_manual_redundancy_probe_outcomes":["redundancy-events"],"outage_and_restoration_witnesses":["redundancy-events"]}.items():
        prefixes["TDN.Deployments.Extensions."+theorem]=[extension_keys[i] for i in ids]
    provenance=source_path("provenance")
    catalog["provenance:experiment-code"]={"kind":"source_hash_association","bundle":str(provenance),"manifest_sha256":hashlib.sha256((provenance/"manifest.json").read_bytes()).hexdigest(),"report":str(output_path("provenance-import.json")),"observation_ids":[],"validation":validation}
    for prefix,keys in prefixes.items():
        if prefix.startswith("TDN.Deployments.Extensions.") or prefix.startswith("TDN.Deployments.Supplemental."):
            keys.append("provenance:experiment-code")
    historical=[]
    for bundle in source_collection("utility_historical"):
        manifest=json.loads((bundle/"manifest.json").read_text())
        key="historical:utility-v1:"+manifest["configuration_id"]
        catalog[key]={"kind":"historical_finite_experiment","bundle":str(bundle),"manifest_sha256":hashlib.sha256((bundle/"manifest.json").read_bytes()).hexdigest(),"status":"Superseded by fresh utility-v3 observations for active generated facts","provenance_limit":"Entrypoint and matrix helper were hash-bound; the indirect routing-helper runtime version was not bound","observation_ids":[],"validation":{"kind":"historical_successful_check","reference":"Prior construction checkpoints preserve utility-v1 generated facts and reports"}}
        historical.append(key)
    register["historical_evidence_dependencies"]=historical
    for group in register["groups"]:
        claimed=set(group["lean_theorems"])
        for clause in group["clause_progress"]:claimed.update(clause.get("lean_theorems",[]))
        for scope in group.get("established_scopes",[]):claimed.add(scope["theorem"])
        claims=[]
        used=set()
        for theorem in sorted(claimed):
            keys=next((keys for prefix,keys in sorted(prefixes.items(),key=lambda item:-len(item[0])) if theorem.startswith(prefix)),None)
            if theorem.startswith("TDN.Deployments.") and keys is None:raise ValueError("Unmapped imported theorem dependency: "+theorem)
            keys=keys or []
            used.update(keys)
            claims.append({"theorem":theorem,"evidence_keys":keys,"kind":"concrete_parsed_data_result" if keys else "generic_conditional_result_without_snapshot_instance","validation":validation})
        group["claim_dependencies"]=claims
        group["evidence_dependencies"]=[{"evidence_key":key,**{k:v for k,v in catalog[key].items() if k!="observation_ids"}} for key in sorted(used)]
        for scope in group.get("established_scopes",[]):
            scope["evidence_keys"]=next(c["evidence_keys"] for c in claims if c["theorem"]==scope["theorem"])
            scope["validation_reference_kind"]="historical_successful_check"
            scope["validation"]=validation
    register["evidence_catalog"]=catalog
    register["dependency_validation_reference"]=validation
    return register
