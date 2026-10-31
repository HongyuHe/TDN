import argparse
import hashlib
import json
from pathlib import Path
from source_paths import source_path,source_collection
from validate_evidence import require,safe_path


def verified_files(root):
    manifest=json.loads((root/"manifest.json").read_text())
    names=set()
    for entry in manifest["files"]:
        require(entry["path"] not in names,"duplicate provenance file")
        names.add(entry["path"])
        data=safe_path(root,entry["path"]).read_bytes()
        require(len(data)==entry["bytes"] and hashlib.sha256(data).hexdigest()==entry["sha256"],"provenance artifact hash/size mismatch")
    return manifest,names


def provenance_report():
    root=source_path("provenance")
    supplement,names=verified_files(root)
    require(supplement["schema_version"]=="csfc-code-provenance-supplement/v1" and "provenance.json" in names,"wrong provenance supplement")
    provenance=json.loads((root/"provenance.json").read_text())
    bundles=[]
    for key in ["utility","utility_historical","routing_v2","routing_v4"]:bundles+=source_collection(key)
    for key in ["ca_local","ca_enterprise","ca_central","http_crl","http_ocsp","aw_placement","redundancy_events"]+["eap_"+d+"_v"+str(v) for d in ["forward","reverse"] for v in [3,4,5]]:bundles.append(source_path(key))
    indexed={hashlib.sha256((p/"manifest.json").read_bytes()).hexdigest():p for p in bundles}
    require(len(indexed)==len(bundles)==39,"provenance bundle inventory mismatch")
    require({a["manifest_sha256"] for a in provenance["associations"]}==set(indexed),"provenance association manifests do not cover supplied bundles")
    records=[]
    for association in provenance["associations"]:
        bundle=indexed[association["manifest_sha256"]]
        manifest,files=verified_files(bundle)
        checked=[]
        for binding in association["bindings"]:
            field=binding["recorded_field"]
            if field.startswith("manifest."):
                actual=manifest[field.removeprefix("manifest.")]
            elif field.startswith("case.json.") or field.startswith("variant.json."):
                name,key=field.split(".json.")
                require(name+".json" in files,"bound metadata not in manifest")
                actual=json.loads((bundle/(name+".json")).read_text())[key]
            else:
                hashes=manifest.get("code_hashes",{})
                if not hashes and "placement.json" in files:hashes=json.loads((bundle/"placement.json").read_text())["code_hashes"]
                actual=hashes[field]
            require(actual==binding["sha256"],"provenance field digest mismatch")
            source=binding["matching_source"]
            require(source in names and hashlib.sha256(safe_path(root,source).read_bytes()).hexdigest()==actual,"bound source digest mismatch")
            checked.append({"field":field,"sha256":actual,"source":source})
        records.append({"bundle":str(bundle),"manifest_sha256":association["manifest_sha256"],"bindings":checked,"collector_declared_complete_runtime_helper_hashes":association["complete_runtime_helper_hashes"],"qualification":association["qualification"]})
    return {"manifest_sha256":hashlib.sha256((root/"manifest.json").read_bytes()).hexdigest(),"assembled_at":provenance["assembled_at"],"records":records,"scope":"Content-addressed source association, not a proof of execution, collector truth or dependency completeness beyond the recorded fields"}

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--report",type=Path,required=True);args=parser.parse_args()
    report=provenance_report();args.report.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"source_associations":len(report["records"])}))
