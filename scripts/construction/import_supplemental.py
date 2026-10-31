import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from import_events import event_bundle,one
from import_management import tls_sample,tls_lean
from import_mechanisms import probe_outcome
from import_snapshot import quoted,lean_list
from source_paths import source_path,source_collection
from validate_evidence import require,safe_path,utc,unique_records


def mechanism_bundle(root):
    manifest=json.loads((root/"manifest.json").read_text())
    require(manifest["schema_version"]=="csfc-mechanism-evidence/v1" and manifest.get("error") is None,"failed or wrong supplemental mechanism bundle")
    paths=set()
    for entry in manifest["files"]:
        require(entry["path"] not in paths,"duplicate supplemental file")
        paths.add(entry["path"])
        content=safe_path(root,entry["path"]).read_bytes()
        require(len(content)==entry["bytes"] and hashlib.sha256(content).hexdigest()==entry["sha256"],"supplemental file hash/size mismatch")
    require({"evidence.json","commands.json","stable-after.json"}<=paths,"supplemental observations missing")
    evidence=json.loads((root/"evidence.json").read_text())
    require(evidence["schema_version"]==manifest["schema_version"] and evidence["configuration_id"]==manifest["configuration_id"] and evidence["error"] is None,"supplemental configuration/error mismatch")
    commands=unique_records(json.loads((root/"commands.json").read_text()),"command")
    devices=unique_records(evidence["devices"],"device")
    start,end=utc(manifest["started_at"]),utc(manifest["ended_at"])
    require(start<=end,"supplemental interval reversed")
    for command in commands.values():
        require(start<=utc(command["started_at"])<=utc(command["ended_at"])<=end,"supplemental command outside collection interval")
        if command.get("device_id"):
            require(command["device_id"] in devices and command["command"][:4]==["ip","netns","exec",devices[command["device_id"]]["namespace"]],"supplemental command namespace mismatch")
    for phase in ["before","after"]:
        name="stable-"+phase+".json"
        if name not in paths:continue
        inventory=json.loads((root/name).read_text())
        require(set(inventory)==set(devices),"supplemental stable device coverage mismatch")
        for device,records in inventory.items():
            for record in records.values():
                obs=commands[record["observation_id"]]
                require(obs["device_id"]==device and obs["returncode"]==record["returncode"]==0 and obs["stdout"]==record["value"],"supplemental normalized stable observation differs")
    if "case.json" in paths:
        metadata=json.loads((root/"case.json").read_text())
        code={"entrypoint_sha256":metadata["script_sha256"],"base_helper_sha256":manifest["code_sha256"],**manifest.get("code_hashes",{})}
        cases=metadata["source_case_ids"]
    else:
        require("variant.json" in paths,"supplemental source-case binding missing")
        metadata=json.loads((root/"variant.json").read_text())
        require(metadata["base_sha256"]==manifest["code_sha256"],"routing base helper hash mismatch")
        code={"entrypoint_sha256":metadata["extension_sha256"],"base_helper_sha256":metadata["base_sha256"]}
        cases=[metadata["source_case_id"]]
    require(all(re.fullmatch(r"[0-9a-f]{64}",v) for v in code.values()),"source-code binding malformed")
    probes=[];tls=[]
    for probe in evidence["probes"]:
        obs=commands[probe["observation_id"]]
        require(obs["device_id"]==probe["source_device"],"supplemental probe source mismatch")
        if "ping" not in obs["command"]:
            require("python3" in obs["command"] and obs["command"][-2]==probe["destination"] and "ssl.create_default_context" in " ".join(obs["command"]),"unsupported supplemental test program")
            require(obs["returncode"]==0 and not obs["stderr"].strip(),"supplemental TLS observer failed")
            result=json.loads(obs["stdout"])
            require(obs["command"][-1]==("yes" if result["authenticated_client"] else "no"),"supplemental TLS input differs")
            sample=tls_sample(result,evidence["configuration_id"],probe["source_device"],probe["destination"],"authenticated_client","version","outcome")
            require(sample["outcome"]==probe["observed_result"]==probe["expected_result"],"supplemental TLS outcome differs")
            tls.append({**sample,"observation_id":obs["id"]})
            continue
        require(obs["command"][-1]==probe["destination"],"supplemental ping destination mismatch")
        result,tx,rx=probe_outcome(obs)
        require(result==probe["observed_result"],"supplemental normalized probe differs")
        probes.append({**probe,"transmitted":tx,"received":rx})
    return {"id":evidence["configuration_id"],"bundle":str(root),"manifest_sha256":hashlib.sha256((root/"manifest.json").read_bytes()).hexdigest(),"code_bindings":code,"source_case_ids":cases,"probes":probes,"tls":tls,"limitations":metadata.get("source_specific_limits",metadata.get("limitations",[]))+evidence["limitations"],"observation_ids":list(commands)},evidence,commands


def parse_ntp(record,case,evidence):
    require(record["returncode"]==0 and not record["stderr"].strip() and "python3" in record["command"],"NTP observer failed")
    value=json.loads(record["stdout"])
    require(value["port"]==123 if "port" in value else value["server"][1]==123,"NTP server port differs")
    server=value["server"][0]
    require(any(str(ipaddress.ip_interface(a).ip)==server for link in evidence["links"] for endpoint,a in zip(link["endpoints"],link["addresses"]) if endpoint.split(":")[0]=="TIME"),"NTP server differs from declared time endpoint")
    require(value["mode"]==4 and 0<value["stratum"]<16 and value["origin_matches"] is True and value["system_clock_adjusted"] is False,"NTP response fields do not describe an unadjusted correlated reply")
    require(0<=value["round_trip_seconds"]<3,"NTP sample timed out")
    return {"case_id":case,"observation_id":record["id"],**value}


def parse_ospf(records,evidence,case):
    neighbors=[r for r in records.values() if r["command"][-1]=="show ip ospf neighbor json"]
    routes=[r for r in records.values() if r["command"][-1]=="show ip route json"]
    require(len(neighbors)==len(routes)==2,"OSPF endpoint observations missing")
    values=[]
    roles={d["id"]:d["role"] for d in evidence["devices"]}
    for neighbor in neighbors:
        require(neighbor["returncode"]==0 and roles[neighbor["device_id"]]!="outer","OSPF observation failed or on Outer")
        rows=[row for rows in json.loads(neighbor["stdout"])["neighbors"].values() for row in rows]
        require(rows and all(r["converged"]=="Full" for r in rows),"OSPF neighbor not Full")
        route=one([r for r in routes if r["device_id"]==neighbor["device_id"]],"OSPF route device mismatch")
        require(route["returncode"]==0,"OSPF route observation failed")
        selected=[r for rows in json.loads(route["stdout"]).values() for r in rows if r.get("protocol")=="ospf" and r.get("selected") and r.get("installed")]
        require(selected,"no selected installed OSPF route")
        values.append({"case_id":case,"device":neighbor["device_id"],"role":roles[neighbor["device_id"]],"full_neighbors":len(rows),"selected_installed_routes":len(selected),"observation_ids":[neighbor["id"],route["id"]]})
    return values


def checked_certificate_statuses(text):
    blocks=re.split(r'\[CFG\] checking certificate status of "CN=([^"\n]+)"\n',text)
    require(len(blocks)>1,"CA status check missing")
    checked=[]
    for identity,body in zip(blocks[1::2],blocks[2::2]):
        require(body.count("certificate status is good")==1 and "certificate status is not available" not in body and "crl correctly signed by" in body and "crl is valid:" in body,"CA successful exchange lacks valid CRL status")
        checked.append(identity)
    require(len(checked)==len(set(checked)),"CA status checks repeat identity")
    return checked


def parse_ca(root):
    events,records,digest=event_bundle(root,"csfc-authentication-events/v1")
    mode=events["mode"]
    exchanges=[]
    initiations=[r for r in records.values() if "--initiate" in r["command"]]
    require(len(initiations)==2,"CA experiment needs two layer endpoint exchanges")
    for initiation in initiations:
        text=initiation["stdout"]
        local=one(re.findall(r"authentication of '([^']+)' \(myself\) with (\w+) successful",text),"CA local auth missing/ambiguous")
        peer=one(re.findall(r"authentication of '([^']+)' with (\w+) successful",text),"CA peer auth missing/ambiguous")
        require(local[0]!=peer[0],"CA endpoints have same identity")
        require(local[1]==peer[1]=="ECDSA_WITH_SHA384_DER","CA selected authentication signature differs")
        checked=checked_certificate_statuses(text)
        require(peer[0] in checked,"peer certificate status not checked")
        require("reached self-signed root ca with a path length of" in text and "initiate completed successfully" in text,"CA trust path or establishment missing")
        remote=peer[0].removesuffix(".msc.test")
        mapping=events["peer_issuer_mapping"][remote]
        require('CN='+mapping["issuer"]+'"' in text and 'CN='+mapping["root"]+'"' in text,"CA trace differs from declared issuer/root")
        probe=one([r for r in records.values() if "ping" in r["command"] and r["command"][:3]==initiation["command"][:3]],"CA useful probe binding missing")
        outcome,tx,rx=probe_outcome(probe)
        require(outcome=="delivered","CA endpoint exchange lacks useful traffic")
        exchanges.append({"case_id":"ca-"+mode,"local":local[0],"peer":peer[0],"local_signature":local[1],"peer_signature":peer[1],"peer_status":"good","reached_root":True,"replies":rx,"transmitted":tx,"trace_observation":initiation["id"],"probe_observation":probe["id"],"issuer":mapping["issuer"],"root":mapping["root"],"checked_certificates":checked})
    return {"id":"ca-"+mode,"bundle":str(root),"manifest_sha256":digest,"source_case_ids":events["case_ids"],"exchanges":exchanges,"peer_issuer_mapping":events["peer_issuer_mapping"],"limitations":events["limitations"],"observation_ids":list(records)}


def generate(output,report_path):
    cases=[];ntp=[];tls=[];ospf=[];channels=[];cds=[]
    for key in ["utility","routing_v2","routing_v4"]:
        for root in source_collection(key):
            case,evidence,commands=mechanism_bundle(root)
            cases.append(case)
            tls+=case["tls"]
            if {t["layer"] for t in evidence["tunnels"]}>={"inner","outer"}:
                states=[]
                for phase in ["before","after"]:
                    inventory=json.loads((root/("stable-"+phase+".json")).read_text())
                    for tunnel in evidence["tunnels"]:
                        if tunnel["layer"] not in {"inner","outer"}:continue
                        require(tunnel["mechanism"]=="IPsec" and len(tunnel["endpoints"])==2,"unsupported supplemental channel")
                        for endpoint in tunnel["endpoints"]:
                            raw=inventory[endpoint]["xfrm"]["value"]
                            require("src "+tunnel["local"]+" dst "+tunnel["remote"] in raw and "src "+tunnel["remote"]+" dst "+tunnel["local"] in raw and "mode tunnel" in raw and "aead rfc4106(gcm(aes))" in raw,"supplemental channel endpoint state missing")
                            states.append({"phase":phase,"device":endpoint,"layer":tunnel["layer"],"observation_id":inventory[endpoint]["xfrm"]["observation_id"]})
                channels.append({"case_id":case["id"],"states":states,"scope":"Recorded bidirectional IPsec state endpoints; no packet-to-SA refinement"})
            if case["id"].startswith("time-"):
                selected=[r for r in commands.values() if r["stdout"].strip().startswith('{"server":')]
                require(len(selected)==3,"three NTP reply samples required")
                ntp += [parse_ntp(r,case["id"],evidence) for r in selected]
            if case["id"].startswith("routing-ospf-"):ospf+=parse_ospf(commands,evidence,case["id"])
            if case["id"]=="cds-log":
                relay=[json.loads(line) for line in (root/"CDS-service.log").read_text().splitlines()]
                received=[json.loads(line) for line in (root/"SIEM-service.log").read_text().splitlines()]
                sends=[r for r in commands.values() if r["device_id"]=="GRAY" and "s.sendto(sys.argv[1].encode()" in " ".join(r["command"])]
                require(len(sends)==2 and all(r["returncode"]==0 for r in sends),"CDS test sends missing")
                valid=json.loads(sends[0]["command"][-1]);invalid=json.loads(sends[1]["command"][-1])
                require(set(valid)=={"device","severity","event"} and set(invalid)=={"command"},"CDS test payloads changed")
                require([r["accepted"] for r in relay]==[True,False] and len(received)==1 and received[0]["event"]==valid,"CDS relay/receiver event correspondence failed")
                cds.append({"case_id":case["id"],"accepted":1,"rejected":1,"received":1,"event":valid,"observation_ids":[r["id"] for r in sends],"log_files":["CDS-service.log","SIEM-service.log"],"scope":"Finite software relay filter event; no approved CDS or complete SIEM claim"})
    require(len(cases)==16 and len({c["id"] for c in cases})==16,"supplemental case inventory differs")
    ca=[parse_ca(source_path("ca_"+mode)) for mode in ["local","enterprise","central"]]
    lines=["import TDN.Evidence.SupplementalTypes","namespace TDN.Imported.Supplemental","set_option maxRecDepth 100000","set_option maxHeartbeats 0"]
    probes=[p for c in cases for p in c["probes"]]
    lines.append("def probes : List Evidence.MechanismProbe := "+lean_list(["⟨"+", ".join([quoted(p["id"]),quoted(p["expected_result"]),quoted(p["observed_result"]),str(p["transmitted"]),str(p["received"])])+"⟩" for p in probes]))
    lines.append("theorem recorded_probe_expectations : probes ≠ [] ∧ ∀ p ∈ probes, p.expected = p.observed := by unfold probes; decide")
    lines.append("theorem useful_and_negative_probe_witnesses : (∃ p ∈ probes, 0 < p.received) ∧ (∃ p ∈ probes, p.observed = \"no_reply\") := by unfold probes; decide")
    lines.append("def ntpReplies : List Evidence.NTPReply := "+lean_list(["⟨"+", ".join([quoted(s["case_id"]),quoted(s["server"][0]),str(s["server"][1]),str(s["mode"]),str(s["stratum"]),str(s["origin_matches"]).lower(),str(s["system_clock_adjusted"]).lower()])+"⟩" for s in ntp]))
    lines.append("theorem observed_ntp_replies_without_clock_adjustment : Evidence.RecordedNTPReplies ntpReplies := by unfold Evidence.RecordedNTPReplies ntpReplies; decide")
    lines.append("def tlsSamples : List Evidence.TLSSample := "+lean_list([tls_lean(s) for s in tls]))
    lines.append("theorem supplemental_tls_recorded_outcomes : Evidence.TLSRecordedOutcomes tlsSamples := by unfold Evidence.TLSRecordedOutcomes tlsSamples; decide")
    exchanges=[e for c in ca for e in c["exchanges"]]
    lines.append("def caExchanges : List Evidence.CAExchange := "+lean_list(["⟨"+", ".join([quoted(e["case_id"]),quoted(e["local"]),quoted(e["peer"]),quoted(e["local_signature"]),quoted(e["peer_signature"]),quoted(e["peer_status"]),str(e["reached_root"]).lower(),str(e["replies"])])+"⟩" for e in exchanges]))
    lines.append("theorem observed_good_crl_authentication_exchanges : Evidence.RecordedCertificateExchanges caExchanges := by unfold Evidence.RecordedCertificateExchanges caExchanges; decide")
    lines.append("def ospfCounts : List (String × String × Nat × Nat) := "+lean_list(["("+", ".join([quoted(s["case_id"]),quoted(s["device"]),str(s["full_neighbors"]),str(s["selected_installed_routes"])])+")" for s in ospf]))
    lines.append("theorem recorded_ospf_neighbors_and_routes : ospfCounts ≠ [] ∧ ∀ s ∈ ospfCounts, 0 < s.2.2.1 ∧ 0 < s.2.2.2 := by unfold ospfCounts; decide")
    lines.append("def relayCounts : List (Nat × Nat × Nat) := "+lean_list(["("+", ".join(str(s[k]) for k in ["accepted","rejected","received"])+")" for s in cds]))
    lines.append("theorem recorded_relay_both_branches : relayCounts ≠ [] ∧ ∀ s ∈ relayCounts, 0 < s.1 ∧ 0 < s.2.1 ∧ s.2.2 = s.1 := by unfold relayCounts; decide")
    lines.append("end TDN.Imported.Supplemental")
    output.write_text("\n\n".join(lines)+"\n")
    report={"cases":cases,"channels":channels,"ntp":ntp,"tls":tls,"ospf":ospf,"cds":cds,"ca":ca,"scope":"Finite supplemental endpoint/mechanism records. Case metadata and executed-code digests are declared provenance; no integrated complete MSC compliance or external approval inferred."}
    report_path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"cases":len(cases),"probes":len(probes),"ntp_replies":len(ntp),"tls":len(tls),"ospf":len(ospf),"ca_exchanges":len(exchanges)}))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--lean-output",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    generate(args.lean_output,args.report)
