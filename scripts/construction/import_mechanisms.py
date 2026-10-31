import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from import_snapshot import identifier, quoted, lean_list
from validate_evidence import EvidenceError, require, safe_path, utc, unique_records


def validate_manifest(root):
    manifest=json.loads(safe_path(root,"manifest.json").read_text())
    require(manifest["schema_version"]=="csfc-mechanism-evidence/v1","wrong mechanism schema")
    require(utc(manifest["started_at"])<=utc(manifest["ended_at"]),"reversed mechanism interval")
    paths=set()
    for entry in manifest["files"]:
        require(entry["path"] not in paths,"duplicate mechanism path")
        paths.add(entry["path"])
        content=safe_path(root,entry["path"]).read_bytes()
        require(len(content)==entry["bytes"] and hashlib.sha256(content).hexdigest()==entry["sha256"],"mechanism artifact hash/size mismatch")
    require({"evidence.json","commands.json","stable-before.json","stable-after.json"}<=paths,"mechanism evidence files missing")
    return manifest


def probe_outcome(command):
    require("ping" in command["command"],"probe does not identify ping")
    match=re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received",command["stdout"])
    require(match is not None,"probe packet-count output missing")
    tx,rx=int(match[1]),int(match[2])
    require(tx>0 and 0<=rx<=tx,"invalid probe packet counts")
    if command["returncode"]==0 and rx>0:
        return "delivered",tx,rx
    if command["returncode"]==1 and rx==0 and not command["stderr"].strip():
        return "no_reply",tx,rx
    raise EvidenceError("probe runtime error or ambiguous outcome")


def import_case(root):
    manifest=validate_manifest(root)
    evidence=json.loads((root/"evidence.json").read_text())
    require(evidence["configuration_id"]==manifest["configuration_id"],"mechanism configuration mismatch")
    require(manifest.get("error") is None and evidence.get("error") is None,"mechanism run reports error")
    commands=unique_records(json.loads((root/"commands.json").read_text()),"command")
    devices=unique_records(evidence["devices"],"device")
    phases={name:json.loads((root/("stable-"+name+".json")).read_text()) for name in ["before","after"]}
    for phase in phases.values():
        require(set(phase)==set(devices),"stable inventory differs from declared devices")
        for device,records in phase.items():
            for kind,record in records.items():
                command=commands.get(record["observation_id"])
                require(command is not None and command["device_id"]==device,"stable observation reference mismatch")
                require(command["returncode"]==record["returncode"]==0 and command["stdout"]==record["value"],"stable observation differs from raw command")
    probes=[]
    for probe in evidence["probes"]:
        command=commands.get(probe["observation_id"])
        require(command is not None and command["device_id"]==probe["source_device"],"probe source binding missing")
        require(command["command"][-1]==probe["destination"],"probe destination binding mismatch")
        result,tx,rx=probe_outcome(command)
        require(result==probe["observed_result"],"normalized probe outcome differs from raw evidence")
        probes.append({**probe,"transmitted":tx,"received":rx})
    layers={}
    settings=[]
    for tunnel in evidence["tunnels"]:
        if tunnel["layer"] not in {"inner","outer"}:continue
        require(tunnel["layer"] not in layers,"duplicate mechanism layer")
        layers[tunnel["layer"]]=tunnel["mechanism"]
        require(len(tunnel["endpoints"])==2 and all(endpoint in devices for endpoint in tunnel["endpoints"]),"invalid mechanism endpoint pair")
        for phase_name,phase in phases.items():
            for endpoint_index,endpoint in enumerate(tunnel["endpoints"]):
                records=phase[endpoint]
                if tunnel["mechanism"]=="IPsec":
                    raw=records["xfrm"]["value"]
                    local=tunnel["local"] if endpoint_index==0 else tunnel["remote"]
                    remote=tunnel["remote"] if endpoint_index==0 else tunnel["local"]
                    require("src "+local+" dst "+remote in raw and "src "+remote+" dst "+local in raw and "mode tunnel" in raw and "aead rfc4106(gcm(aes))" in raw,"observed IPsec states do not bind layer endpoints")
                elif tunnel["mechanism"]=="MACsec":
                    address=str(ipaddress.ip_interface(tunnel["local"] if endpoint_index==0 else tunnel["remote"]).ip)
                    interfaces=json.loads(records["interfaces"]["value"])
                    matches=[i for i in interfaces if i.get("linkinfo",{}).get("info_kind")=="macsec" and any(a.get("local")==address for a in i.get("addr_info",[]))]
                    require(len(matches)==1,"MACsec layer interface binding ambiguous")
                    interface=matches[0];data=interface["linkinfo"]["info_data"]
                    settings.append({"case_id":evidence["configuration_id"],"device":endpoint,"phase":phase_name,"interface":interface["ifname"],"cipher":data["cipher_suite"],"protect":data["protect"],"encrypt":data["encrypt"],"validation":data["validation"],"replay_protect":data["replay_protect"],"replay_window":data["window"]})
                else:
                    raise EvidenceError("unknown protection mechanism")
    require(set(layers)=={"inner","outer"},"both protection layer records required")
    families=None
    match=re.fullmatch(r"families-([46])([46])([46])",evidence["configuration_id"])
    if match:
        families=[int(x) for x in match.groups()]
        for zone,family in zip(["red","gray","black"],families):
            links=[link for link in evidence["links"] if link["zone"]==zone]
            require(bool(links),"declared family zone has no links")
            for link in links:
                for identity,address in zip(link["endpoints"],link["addresses"]):
                    require(ipaddress.ip_interface(address).version==family,"declared zone family mismatch")
                    device,name=identity.split(":",1)
                    for phase in phases.values():
                        rows=json.loads(phase[device]["interfaces"]["value"])
                        expected=str(ipaddress.ip_interface(address).ip)
                        require(any(i["ifname"]==name and any(a.get("local")==expected for a in i.get("addr_info",[])) for i in rows),"declared address absent from observed zone interface")
    return {"id":evidence["configuration_id"],"inner":layers["inner"],"outer":layers["outer"],"families":families,"probes":probes,"macsec_settings":settings,"bundle":str(root),"manifest_sha256":hashlib.sha256((root/"manifest.json").read_bytes()).hexdigest(),"limitations":evidence["limitations"],"scope":"Bounded channel/settings/probe evidence; no IKE/MKA, KGS, independence, all-packet or complete CP claim"}


def generate(roots,output,report_path):
    cases=[import_case(p.parent) for root in roots for p in sorted(root.glob("*/manifest.json"))]
    require(cases and len({c["id"] for c in cases})==len(cases),"empty/duplicate mechanism cases")
    lines=["import TDN.Evidence.MechanismTypes","namespace TDN.Imported.Mechanisms","set_option maxRecDepth 100000","set_option maxHeartbeats 0"]
    values=[]
    for case in cases:
        family="none" if case["families"] is None else "some ("+", ".join(map(str,case["families"]))+")"
        probes=["⟨"+", ".join([quoted(p["id"]),quoted(p["expected_result"]),quoted(p["observed_result"]),str(p["transmitted"]),str(p["received"])])+"⟩" for p in case["probes"]]
        values.append("⟨"+", ".join([quoted(case["id"]),quoted(case["inner"]),quoted(case["outer"]),family,lean_list(probes)])+"⟩")
    lines.append("def cases : List Evidence.MechanismCase := "+lean_list(values))
    if all(p["expected_result"]==p["observed_result"] for c in cases for p in c["probes"]):
        lines.append("theorem recorded_probe_expectations : Evidence.ExpectedProbeOutcomes cases := by unfold Evidence.ExpectedProbeOutcomes cases; decide")
    lines.append("theorem each_case_has_positive_traffic : Evidence.EachCaseHasUsefulTraffic cases := by unfold Evidence.EachCaseHasUsefulTraffic cases; decide")
    lines.append("theorem all_eight_declared_family_choices : ∀ r ∈ [4,6], ∀ g ∈ [4,6], ∀ b ∈ [4,6], ∃ c ∈ cases, c.families = some (r,g,b) := by unfold cases; decide")
    lines.append("theorem all_four_declared_layer_pairings : ∀ i ∈ [\"IPsec\",\"MACsec\"], ∀ o ∈ [\"IPsec\",\"MACsec\"], ∃ c ∈ cases, c.inner = i ∧ c.outer = o := by unfold cases; decide")
    settings=[s for c in cases for s in c["macsec_settings"]]
    values=["⟨"+", ".join([quoted(s["case_id"]),quoted(s["device"]),quoted(s["phase"]),quoted(s["interface"]),quoted(s["cipher"]),str(s["protect"]).lower(),str(s["encrypt"]).lower(),quoted(s["validation"]),str(s["replay_protect"]).lower(),str(s["replay_window"])])+"⟩" for s in settings]
    lines.append("def macsecSettings : List Evidence.MACsecChannelSetting := "+lean_list(values))
    lines.append("theorem recorded_macsec_selected_flags : Evidence.MACsecSelectedFlags macsecSettings := by unfold Evidence.MACsecSelectedFlags macsecSettings; decide")
    lines.append("end TDN.Imported.Mechanisms")
    output.write_text("\n\n".join(lines)+"\n")
    report={"case_count":len(cases),"probe_count":sum(len(c["probes"]) for c in cases),"macsec_setting_count":len(settings),"cases":cases,"full_groups_established":[],"authentication_claim":False,"universal_forwarding_claim":False}
    report_path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:report[k] for k in ["case_count","probe_count","macsec_setting_count"]}))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("roots",nargs="+",type=Path)
    parser.add_argument("--lean-output",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    generate(args.roots,args.lean_output,args.report)
