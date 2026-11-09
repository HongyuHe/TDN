import argparse
import hashlib
import json
from pathlib import Path
import re
from import_events import one
from import_mechanisms import probe_outcome
from import_snapshot import quoted,lean_list
from loaded_policy import parse_configuration,brace_content,immediate_sections
from source_paths import source_path
from validate_evidence import require,safe_path,utc,unique_records


def read_bundle(root,schema):
    manifest=json.loads((root/"manifest.json").read_text())
    require(manifest["schema_version"]==schema,"authentication schema mismatch")
    names=set()
    for entry in manifest["files"]:
        require(entry["path"] not in names,"duplicate auth file")
        names.add(entry["path"])
        content=safe_path(root,entry["path"]).read_bytes()
        require(hashlib.sha256(content).hexdigest()==entry["sha256"] and len(content)==entry["bytes"],"authentication hash/size mismatch")
    require("events.json" in names,"authentication events missing")
    events=json.loads((root/"events.json").read_text())
    require(events["schema_version"]==schema and events.get("error") is None,"authentication run failed")
    start,end=utc(events["started_at"]),utc(events["ended_at"])
    require(start<=end,"authentication interval reversed")
    records=unique_records(events["records"],"auth event")
    for record in records.values():
        require(start<=utc(record["started_at"])<=utc(record["ended_at"])<=end,"auth event outside interval")
        if record["returncode"]!=0:
            absent=(record["returncode"]==1 and "--terminate" in record["command"] and "no matching SAs to terminate found" in record["stderr"])
            trial=(schema=="csfc-auth-negative/v1" and record["returncode"]==1 and "--initiate" in record["command"] and "received AUTHENTICATION_FAILED notify error" in record["stdout"])
            require(absent or trial,"unclassified authentication command failure")
    return events,records,hashlib.sha256((root/"manifest.json").read_bytes()).hexdigest()


def certificate_parameters(text,identity):
    require(re.findall(r"Subject: CN = ([^\n]+)",text)==[identity],"public certificate subject mismatch")
    curves=re.findall(r"ASN1 OID: ([^\s]+)",text)
    require(curves==["secp384r1"] and "Public-Key: (384 bit)" in text,"certificate is not the observed P384 credential")
    signatures=re.findall(r"Signature Algorithm: ([^\s]+)",text)
    require(signatures==["ecdsa-with-SHA384","ecdsa-with-SHA384"],"certificate signature algorithm differs")
    fingerprint=one(re.findall(r"sha256 Fingerprint=([0-9A-F:]+)",text),"certificate fingerprint missing")
    require(len(fingerprint.split(":"))==32,"malformed SHA256 certificate fingerprint")
    return {"curve":curves[0],"certificate_signature":signatures[0],"fingerprint_sha256":fingerprint}


def selected_exchange(text):
    local=one(re.findall(r"authentication of '([^']+)' \(myself\) with (\w+) successful",text),"selected local authentication ambiguous")
    remote=one(re.findall(r"authentication of '([^']+)' with (\w+) successful",text),"selected remote authentication ambiguous")
    require(local[0]!=remote[0] and local[1]==remote[1]=="ECDSA_WITH_SHA384_DER","selected authentication differs")
    ike=one(re.findall(r"selected proposal: IKE:([^\n]+)",text),"IKE proposal ambiguous")
    esp=one(re.findall(r"selected proposal: ESP:([^\n]+)",text),"ESP proposal ambiguous")
    require(ike=="AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384" and esp=="AES_GCM_16_256/NO_EXT_SEQ","selected cryptographic suite differs")
    require("initiate completed successfully" in text or "IKE_SA" in text and "established between" in text,"exchange establishment missing")
    return {"local_identity":local[0],"remote_identity":remote[0],"local_signature":local[1],"remote_signature":remote[1],"ike":ike,"esp":esp}


def import_phase(root,expected_auth):
    events,records,digest=read_bundle(root,"csfc-auth-events/v1")
    configurations=sorted(root.glob("*.loaded.conf"))
    require(len(configurations)==8,"complete eight-gateway authentication inventory required")
    devices=[]
    for file in configurations:
        device=file.name.removesuffix(".loaded.conf")
        config=file.read_text()
        connections=parse_configuration(config)
        require(set(connections)=={"msc"},"unexpected auth connection inventory")
        c=connections["msc"]
        require(c["local"]["auth"]==c["remote"]["auth"]==expected_auth,"authentication policy differs from selected phase")
        local=c["local"]["id"];remote=c["remote"]["id"]
        namespace="twinet-csfc-v2-"+device.lower()
        own=[r for r in records.values() if r["command"][:3]==["docker","exec",namespace]]
        load=one([r for r in own if r["command"][3:]==["swanctl","--load-conns","--file","/etc/swanctl/swanctl.conf"]],"exact-file auth load missing")
        reads=[r for r in own if r["command"][3:]==["cat","/etc/swanctl/swanctl.conf"] and r["stdout"]==config]
        require(any(utc(r["ended_at"])<=utc(load["started_at"]) for r in reads) and any(utc(load["ended_at"])<=utc(r["started_at"]) for r in reads),"auth file read/load/read binding absent")
        require(re.findall(r"loaded connection '([^']+)'",load["stdout"])==["msc"],"loaded auth connection differs")
        runtime=one([r for r in own if r["command"][-2:]==["--list-conns","--raw"]],"auth runtime inventory missing")
        require(utc(load["ended_at"])<=utc(runtime["started_at"]) and runtime["stdout"].count("list-conn event {")==1,"auth runtime association invalid")
        body=runtime["stdout"]
        for field,value in [("local_addrs","["+c["local_addrs"]+"]"),("remote_addrs","["+c["remote_addrs"]+"]"),("version","IKEv2")]:
            require(field+"="+value in body,"auth runtime endpoint/version differs")
        require("id="+local in body and "id="+remote in body,"auth runtime peer identity differs")
        cert=one([r for r in own if r["command"][3:5]==["openssl","x509"]],"public certificate record missing")
        parameters=certificate_parameters(cert["stdout"],local)
        devices.append({"device":device,"namespace":namespace,"local_address":c["local_addrs"],"remote_address":c["remote_addrs"],"local_identity":local,"remote_identity":remote,"local_constraint":c["local"]["auth"],"remote_constraint":c["remote"]["auth"],"loaded_configuration_sha256":hashlib.sha256(config.encode()).hexdigest(),**parameters,"observation_ids":[r["id"] for r in reads]+[load["id"],runtime["id"],cert["id"]]})
    exchanges=[]
    if expected_auth!="pubkey":
        initiations=[r for r in records.values() if "--initiate" in r["command"]]
        require(len(initiations)==4,"fresh authentication exchange inventory differs")
        for record in initiations:
            exchange=selected_exchange(record["stdout"])
            configured=one([d for d in devices if d["local_identity"]==exchange["local_identity"]],"selected exchange local binding missing")
            require(configured["remote_identity"]==exchange["remote_identity"],"selected exchange peer differs from loaded policy")
            exchanges.append({**exchange,"observation_id":record["id"]})
    advertisements=[];other_headers=[]
    for record in records.values():
        if record["command"][-1].endswith(".jsonl"):
            configured=one([d for d in devices if d["namespace"]==record["command"][2]],"header observer namespace is not an inventoried gateway")
            for line in record["stdout"].splitlines():
                packet=json.loads(line)
                require(utc(events["started_at"])<=utc(packet["timestamp"])<=utc(events["ended_at"]),"auth header outside collection interval")
                if not packet.get("signature_hash_notifies"):
                    other_headers.append({"observation_id":record["id"],"observer":configured["device"],"source":packet["source"],"destination":packet["destination"],"exchange_type":packet["ike_exchange_type"],"scope":"No signature-hash advertisement; retained outside this finite capability claim"})
                for notify in packet.get("signature_hash_notifies",[]):
                    owners=[d for d in devices if d["local_address"]==packet["source"] and d["remote_address"]==packet["destination"]]
                    require(len(owners)==1 and packet["ike_version"]==32,"auth advertisement peer/version binding mismatch")
                    require(notify["notify_type"]==16431 and packet["ike_exchange_type"]==34,"signature-hash advertisement not INIT")
                    advertisements.append({"observer":record["command"][2],"connection_source_device":owners[0]["device"],"observation_id":record["id"],"source":packet["source"],"destination":packet["destination"],"initiator_spi":packet["ike_initiator_spi"],"responder_spi":packet["ike_responder_spi"],"response":bool(packet["ike_flags"]&32),"algorithm_ids":notify["signature_hash_algorithm_ids"]})
    require(advertisements,"signature-hash advertisements missing")
    probes=[]
    for record in records.values():
        if "ping" in record["command"]:
            outcome,tx,rx=probe_outcome(record)
            require(outcome=="delivered","auth phase has failed useful probe")
            probes.append({"observation_id":record["id"],"transmitted":tx,"received":rx})
    require(len(probes)==4,"four useful auth phase probes required")
    return {"bundle":str(root),"manifest_sha256":digest,"phase":events["phase"],"devices":devices,"exchanges":exchanges,"advertisements":advertisements,"other_headers":other_headers,"probes":probes,"observation_ids":list(records),"scope":"Exact-file loader association and selected public credentials/exchanges. Minimum key-strength policy is not an exact allowed-curve restriction; responder capability advertisements are not effective per-peer policy."}


def negative_trial(records):
    initiations=[r for r in records.values() if "--initiate" in r["command"]]
    failed=one([r for r in initiations if r["returncode"]==1],"one negative initiation required")
    restored=one([r for r in initiations if r["returncode"]==0],"restored positive initiation required")
    require(utc(failed["ended_at"])<utc(restored["started_at"]),"negative/restored order wrong")
    signature=one(re.findall(r"authentication of '([^']+)' \(myself\) with (\w+) successful",failed["stdout"]),"negative local signature missing")
    require(signature==("I_A1.msc.test","ECDSA_WITH_SHA256_DER") and "received AUTHENTICATION_FAILED notify error" in failed["stdout"] and "initiate completed successfully" not in failed["stdout"],"negative initiation lacks explicit auth failure")
    logs=[r for r in records.values() if r["command"][2]=="twinet-csfc-v2-i_b1" and "tail" in r["command"] and utc(failed["ended_at"])<=utc(r["started_at"])<utc(restored["started_at"])]
    require(len(logs)==1,"negative responder log association ambiguous")
    text=logs[0]["stdout"]
    require("authentication of 'I_A1.msc.test' with ECDSA_WITH_SHA256_DER successful" in text and "IKE signature scheme ECDSA_WITH_SHA256_DER not acceptable" in text and "selected peer config 'msc' unacceptable: non-matching authentication done" in text,"negative responder lacks signature-policy rejection cause")
    positive=selected_exchange(restored["stdout"])
    require(positive["local_identity"]==signature[0] and positive["remote_identity"]=="I_B1.msc.test","restored pair differs")
    probe=one([r for r in records.values() if "ping" in r["command"]],"restored useful probe missing")
    require(utc(restored["ended_at"])<=utc(probe["started_at"]),"useful probe precedes restoration")
    outcome,tx,rx=probe_outcome(probe)
    require(outcome=="delivered","restored path not useful")
    return {"negative_signature":signature[1],"rejection_cause":"signature scheme not acceptable","restored_signature":positive["local_signature"],"restored_replies":rx,"observation_ids":[failed["id"],logs[0]["id"],restored["id"],probe["id"]]}


def generate(output,report_path):
    before=import_phase(source_path("auth_before"),"pubkey")
    after=import_phase(source_path("auth_after"),"ecdsa-384-sha384")
    require({d["device"]:d["fingerprint_sha256"] for d in before["devices"]}=={d["device"]:d["fingerprint_sha256"] for d in after["devices"]},"public credentials changed between auth phases")
    events,records,digest=read_bundle(source_path("auth_negative"),"csfc-auth-negative/v1")
    trial=negative_trial(records)
    trial.update({"bundle":str(source_path("auth_negative")),"manifest_sha256":digest})
    lines=["import TDN.Deployments.SupplementalTypes","namespace TDN.Deployments.Authentication","set_option maxRecDepth 100000"]
    lines.append("def credentials : List (String × String × String × String) := "+lean_list(["("+", ".join(quoted(d[k]) for k in ["device","curve","local_constraint","remote_constraint"])+")" for d in after["devices"]]))
    lines.append('theorem observed_credentials_and_configured_hash_constraints : credentials ≠ [] ∧ ∀ c ∈ credentials, c.2.1 = "secp384r1" ∧ c.2.2.1 = "ecdsa-384-sha384" ∧ c.2.2.2 = "ecdsa-384-sha384" := by unfold credentials; decide')
    lines.append("def selectedSignatures : List (String × String) := "+lean_list(["("+quoted(e["local_signature"])+", "+quoted(e["remote_signature"])+")" for e in after["exchanges"]]))
    lines.append('theorem selected_authentication_uses_sha384 : selectedSignatures ≠ [] ∧ ∀ s ∈ selectedSignatures, s.1 = "ECDSA_WITH_SHA384_DER" ∧ s.2 = "ECDSA_WITH_SHA384_DER" := by unfold selectedSignatures; decide')
    lines.append("def advertisedCapabilities : List (Bool × List Nat) := "+lean_list(["("+str(a["response"]).lower()+", "+lean_list([str(x) for x in a["algorithm_ids"]])+")" for a in after["advertisements"]]))
    lines.append('theorem observed_capabilities_distinguish_request_and_response : advertisedCapabilities ≠ [] ∧ ∀ a ∈ advertisedCapabilities, a.2 = (if a.1 then [2,3,4,5] else [3]) := by unfold advertisedCapabilities; decide')
    lines.append("def trial : String × String × String × Nat := ("+", ".join([quoted(trial["negative_signature"]),quoted(trial["rejection_cause"]),quoted(trial["restored_signature"]),str(trial["restored_replies"])])+")")
    lines.append('theorem recorded_sha256_refusal_and_sha384_recovery : trial.1 = "ECDSA_WITH_SHA256_DER" ∧ trial.2.1 = "signature scheme not acceptable" ∧ trial.2.2.1 = "ECDSA_WITH_SHA384_DER" ∧ 0 < trial.2.2.2 := by unfold trial; decide')
    lines.append("end TDN.Deployments.Authentication")
    output.write_text("\n\n".join(lines)+"\n")
    report_path.write_text(json.dumps({"before":before,"after":after,"negative_trial":trial,"scope":"Partial RG-017/019/020 algorithm/authentication contributions; no complete CNSA profile or all-curve enforcement claim","assumptions":["Truth and completeness of supplied public records","Exact-file loader association; VICI does not expose full signature constraints","Negative tail-log event association within the isolated test interval"]},indent=2)+"\n")
    print(json.dumps({"credentials":len(after["devices"]),"selected_exchanges":len(after["exchanges"]),"negative_trial":"cause_checked"}))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--lean-output",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    generate(args.lean_output,args.report)
