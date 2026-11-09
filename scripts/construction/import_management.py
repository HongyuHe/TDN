import argparse
import json
from pathlib import Path
from analyze_topology import validated_graph
from import_snapshot import quoted,lean_list
from source_paths import source_path
from validate_evidence import require


def tls_sample(result,case,source,target,certificate_field="client_certificate",version_field="tls_version",outcome_field="result"):
    certificate=result[certificate_field]
    require(type(certificate) is bool,"TLS certificate input is not Boolean")
    require(result.get(version_field)=="TLSv1.3" and result.get("cipher")==["TLS_AES_256_GCM_SHA384","TLSv1.3",256],"TLS negotiated suite missing or different")
    outcome=result[outcome_field]
    required="TLSV13_ALERT_CERTIFICATE_REQUIRED" in result.get("error","")
    if certificate:
        require(outcome=="delivered" and result.get("response","").startswith("HTTP/1.0 200 OK"),"credentialed TLS attempt lacks successful application response")
    else:
        require(outcome=="rejected" and required,"negative TLS test is not an explicit certificate-required refusal")
    return {"case_id":case,"source":source,"target":target,"certificate":certificate,"version":result[version_field],"cipher":result["cipher"][0],"outcome":outcome,"certificate_required":required}


def tls_lean(sample):
    return "⟨"+", ".join([quoted(sample["case_id"]),quoted(sample["source"]),quoted(sample["target"]),str(sample["certificate"]).lower(),quoted(sample["version"]),quoted(sample["cipher"]),quoted(sample["outcome"]),str(sample["certificate_required"]).lower()])+"⟩"


def import_management(root):
    graph=validated_graph(root)
    snapshot=graph["snapshot"]
    management=snapshot["management"]
    require(management["profile"]=="independent_management" and management["applicability"]=="optional_enabled" and not management["failures"],"unexpected or failed management profile")
    devices={d["id"]:d for d in snapshot["devices"]}
    observations={o["id"]:o for o in snapshot["observations"]}
    samples=[]
    for record in management["records"]:
        require(record["status"]=="observed" and record["profile"]=="mutual_tls" and len(record["observation_ids"])==1,"management record is not one observed TLS attempt")
        obs=observations[record["observation_ids"][0]]
        source=record["source_device_id"];target=record["target_device_id"]
        cmd=obs["command"]
        require(obs["kind"]=="management-tls-probe" and obs["device_id"]==source and cmd[:3]==["docker","exec",devices[source]["namespace"]],"TLS source namespace mismatch")
        require(cmd[3:5]==["python3","-c"] and "ssl.create_default_context" in cmd[5] and "ss.getpeercert()" in cmd[5],"unexpected TLS observer")
        require(cmd[-1]==("yes" if record["client_certificate"] else "no"),"TLS certificate argument differs")
        target_interfaces=[i for i in snapshot["interfaces"] if i["device_id"]==target and i["zone"]=="management"]
        require(len(target_interfaces)==1,"management interface binding ambiguous")
        interface=target_interfaces[0]
        require(any(a["local"]==cmd[-2] for a in interface["addresses"]),"TLS destination differs from declared management address")
        for oid in interface["observation_ids"]:
            raw=json.loads((root/observations[oid]["raw_path"]).read_text())
            rows=json.loads(raw["stdout"])
            require(any(r["ifname"]==interface["name"] and any(a["local"]==cmd[-2] for a in r["addr_info"]) for r in rows),"TLS destination absent from observed interface")
        raw=json.loads((root/obs["raw_path"]).read_text())
        require(obs["returncode"]==0 and not raw["stderr"].strip(),"TLS observer failed")
        result=json.loads(raw["stdout"])
        require(result==record["result"] and result["client_certificate"]==record["client_certificate"],"normalized TLS record differs from raw result")
        require(["IP Address",cmd[-2]] in result["peer"]["subjectAltName"],"TLS peer certificate lacks target address")
        sample=tls_sample(result,snapshot["snapshot_id"],source,target)
        samples.append({**sample,"observation_id":obs["id"]})
    expected={d["id"] for d in devices.values() if d["role"] in {"inner","outer","firewall","gray-firewall"}}
    require(expected and {(s["target"],s["certificate"]) for s in samples}=={(d,c) for d in expected for c in [True,False]} and len(samples)==2*len(expected),"TLS positive/negative coverage of managed components incomplete")
    return {"snapshot_id":snapshot["snapshot_id"],"manifest_sha256":graph["validation"]["source_manifest_sha256"],"samples":samples,"scope":"Recorded mutual-TLS application attempts from named management workstations; no human identity, authorization, physical segregation or all-traffic guarantee"}


def generate(output,report_path,source_key="coherent_management",namespace="Management"):
    report=import_management(source_path(source_key))
    lines=["import TDN.Deployments.SupplementalTypes","namespace TDN.Deployments."+namespace,"def samples : List Evidence.TLSSample := "+lean_list([tls_lean(s) for s in report["samples"]]),"theorem recorded_tls_outcomes : Evidence.TLSRecordedOutcomes samples := by unfold Evidence.TLSRecordedOutcomes samples; decide","theorem both_test_branches_present : (∃ s ∈ samples, s.clientCertificate = true) ∧ (∃ s ∈ samples, s.clientCertificate = false) := by unfold samples; decide","end TDN.Deployments."+namespace]
    output.write_text("\n\n".join(lines)+"\n")
    report_path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"tls_samples":len(report["samples"])}))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--lean-output",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    parser.add_argument("--source-key",default="coherent_management")
    parser.add_argument("--namespace",default="Management")
    args=parser.parse_args()
    generate(args.lean_output,args.report,args.source_key,args.namespace)
