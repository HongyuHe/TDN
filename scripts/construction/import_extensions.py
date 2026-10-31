import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from import_events import one
from import_management import tls_sample,tls_lean
from import_mechanisms import probe_outcome
from import_provenance import verified_files
from import_snapshot import quoted,lean_list
from source_paths import source_path
from validate_evidence import require,utc,unique_records


def manifest_report(root):
    manifest,files=verified_files(root)
    return manifest,files,{"bundle":str(root),"manifest_sha256":hashlib.sha256((root/"manifest.json").read_bytes()).hexdigest()}


def decode_bridge_http(text):
    header=re.search(r"Bridge chain: FORWARD, entries: (\d+), policy: (\w+)\n(.*?)(?=\nBridge chain:|\Z)",text,re.S)
    require(header is not None and header[1]=="4" and header[2]=="DROP","HTTP bridge inventory/default differs")
    lines=[line.split(" , pcnt")[0] for line in header[3].splitlines() if line.strip()]
    require(len(lines)==4 and lines[:2]==["-p ARP -j ACCEPT","-p IPv4 --ip-proto esp -j ACCEPT"],"HTTP bridge base rules differ")
    request=re.fullmatch(r"-p IPv4 --ip-src ([0-9.]+) --ip-dst ([0-9.]+) --ip-proto tcp --ip-dport 80 -j ACCEPT",lines[2])
    response=re.fullmatch(r"-p IPv4 --ip-src ([0-9.]+) --ip-dst ([0-9.]+) --ip-proto tcp --ip-sport 80 -j ACCEPT",lines[3])
    require(request is not None and response is not None,"HTTP bridge exception is broader or unsupported")
    require(request[1]==response[2] and request[2]==response[1],"HTTP bridge response endpoint mismatch")
    return int(ipaddress.IPv4Address(request[1])),int(ipaddress.IPv4Address(request[2]))


def import_http(key):
    root=source_path(key);manifest,files,report=manifest_report(root)
    evidence=json.loads((root/"evidence.json").read_text());commands=unique_records(json.loads((root/"commands.json").read_text()),"HTTP command")
    require(evidence["error"] is None,"HTTP experiment failed")
    filters=[r for r in commands.values() if r["command"][-3:]==["ebtables","-L","--Lc"]]
    require(len(filters)==2 and all(r["returncode"]==0 for r in filters),"HTTP bridge before/after observations missing")
    bounds=[decode_bridge_http(r["stdout"]) for r in filters]
    require(bounds[0]==bounds[1],"HTTP bridge bounds changed")
    checks=[]
    if key=="http_crl":
        verifications=[r for r in commands.values() if "verify" in r["command"] and "-crl_check" in r["command"]]
        require(len(verifications)==2,"CRL validation event pair missing")
        good,bad=verifications
        require(good["returncode"]==0 and good["stdout"].strip().endswith("client.pem: OK"),"good CRL verification failed")
        require(bad["returncode"]==2 and "error 23 at 0 depth lookup: certificate revoked" in bad["stderr"],"CRL negative result is not certificate revoked")
        require(good["command"][-1]==bad["command"][-1],"CRL checked certificate differs")
        downloads=[r for r in commands.values() if "curl" in r["command"] and "-o" in r["command"]]
        require(len(downloads)==2 and all(r["returncode"]==0 for r in downloads),"CRL HTTP retrieval missing")
        require(all("http://10.12.0.2/current.crl" in r["command"] for r in downloads),"CRL retrieval endpoint changed")
        for retrieval,verification in zip(downloads,verifications):
            require(retrieval["command"][retrieval["command"].index("-o")+1]==verification["command"][verification["command"].index("-CRLfile")+1] and utc(retrieval["ended_at"])<=utc(verification["started_at"]),"downloaded CRL not bound to verification")
        checks=[{"status":"good","observation_id":good["id"]},{"status":"revoked","observation_id":bad["id"]}]
        signature="ecdsa-with-SHA384"
    else:
        responses=[r for r in commands.values() if "ocsp" in r["command"] and "-url" in r["command"]]
        require(len(responses)==2,"OCSP response pair missing")
        signatures=[]
        for record,status in zip(responses,["good","revoked"]):
            require(record["returncode"]==0 and "Response verify OK" in record["stderr"],"OCSP response signature verification failed")
            require(re.findall(r"Cert Status: (\w+)",record["stdout"])==[status],"OCSP certificate status differs")
            require(record["command"][record["command"].index("-url")+1]=="http://10.12.0.2","OCSP HTTP endpoint differs")
            signatures.append(re.findall(r"Signature Algorithm: ([^\s]+)",record["stdout"])[0])
            checks.append({"status":status,"observation_id":record["id"]})
        require(len(set(signatures))==1,"OCSP response signature algorithms differ")
        signature=signatures[0]
    probes=[r for r in commands.values() if "ping" in r["command"]]
    require(len(probes)==1,"HTTP useful probe missing")
    outcome,tx,rx=probe_outcome(probes[0]);require(outcome=="delivered","HTTP experiment disabled useful data traffic")
    timeout=one([r for r in commands.values() if "curl" in r["command"] and r["returncode"]==28],"negative HTTP timeout record missing")
    return {**report,"id":evidence["configuration_id"],"source_case_ids":json.loads((root/"case.json").read_text())["source_case_ids"],"bounds":{"client":bounds[0][0],"server":bounds[0][1]},"checks":checks,"response_signature":signature,"useful_replies":rx,"filter_observations":[r["id"] for r in filters],"timeout_observation":timeout["id"],"timeout_scope":"Observed timeout only; no causal blocking result inferred from unchanged printed ACCEPT counters","observation_ids":list(commands),"scope":"Finite OpenSSL revocation checks and modeled IPv4 TCP bridge exception; no VPN revocation enforcement or full cryptographic-profile claim"}


def import_eap(key):
    root=source_path(key);manifest,files,report=manifest_report(root)
    evidence=json.loads((root/"evidence.json").read_text());metadata=json.loads((root/"case.json").read_text())
    commands=unique_records(json.loads((root/"commands.json").read_text()),"EAP command")
    logs={Path(r["command"][-1]).name:r for r in commands.values() if r["command"][0]=="cat" and r["command"][-1].endswith(".log")}
    require(set(logs)=={"P0.log","P1.log","AS.log"} and all(r["returncode"]==0 for r in logs.values()),"EAP endpoint/AS logs missing")
    supp=logs[metadata["supplicant"]+".log"];auth=logs[metadata["authenticator"]+".log"];server=logs["AS.log"]
    require("CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully" in supp["stdout"] and "CTRL-EVENT-EAP-SUCCESS2" in auth["stdout"] and "CTRL-EVENT-EAP-SUCCESS" in server["stdout"],"EAP success events missing")
    require("remote certificate verification (param=success)" in supp["stdout"] and "remote certificate verification success" in server["stdout"],"mutual EAP certificate verification not recorded")
    versions=set(re.findall(r"SSL: Using TLS version (\S+)",supp["stdout"]+server["stdout"]))
    require(versions=={"TLSv1.2"},"EAP TLS version missing/different")
    links=[r for r in commands.values() if r["command"][-4:]==["ip","-j","-d","link"]]
    p0=[r for r in links if "tcv2e-P0" in r["command"]]
    require(p0 and all(r["returncode"]==0 for r in p0),"failed EAP data-channel interface observation missing")
    interface_samples=[{"observation_id":r["id"],"macsec_interfaces":[{"name":i["ifname"],"operstate":i["operstate"]} for i in json.loads(r["stdout"]) if i.get("linkinfo",{}).get("info_kind")=="macsec"]} for r in p0]
    data_state="not_attempted"
    data_observations=[]
    for probe in evidence["probes"]:
        raw=commands[probe["observation_id"]]
        require("ping" in raw["command"] and raw["returncode"]==2 and raw["stdout"]=="" and "Network is unreachable" in raw["stderr"] and probe["observed_result"]=="collection_error","EAP data probe needs a separately classified outcome")
        data_state="runtime_error"
        data_observations.append(raw["id"])
    if data_state=="not_attempted":
        require(evidence["error"]=="No MACsec interface at P0" and not interface_samples[-1]["macsec_interfaces"],"EAP missing-interface report differs from final observation")
    return {**report,"id":evidence["configuration_id"],"source_case_ids":[metadata["source_case_id"]],"supplicant":metadata["supplicant"],"authenticator":metadata["authenticator"],"tls_version":"TLSv1.2","authentication_success":True,"interface_observations":interface_samples,"data_probe_status":data_state,"data_observations":data_observations,"experiment_error":evidence["error"],"observation_ids":list(commands),"event_observations":[supp["id"],auth["id"],server["id"]]+[r["id"] for r in p0],"scope":"Finite reversed-role EAP authentication; no successful data probe is recorded. Transient MACsec interfaces and runtime probe errors remain explicit. No simultaneous dual-role or complete Table10 suite claim"}


def import_aw():
    root=source_path("aw_placement");manifest,files,report=manifest_report(root)
    placement=json.loads((root/"placement.json").read_text())
    records=[(name,json.loads((root/name).read_text())) for name in files if name.endswith("physical-and-vm-aw-use.json")]
    name,record=one(records,"AW raw use record missing")
    require(record["returncode"]==0,"AW collection failed")
    samples=[]
    for line in record["output"].splitlines():
        if not line.startswith('{"started_at"'):continue
        value=json.loads(line)
        require(utc(record["started_at"])<=utc(value["started_at"])<=utc(value["ended_at"])<=utc(record["ended_at"]),"AW subevent outside raw command interval")
        sample=tls_sample(value,"aw-placement",value["hostname"],"management-test-listener",outcome_field="outcome")
        samples.append({**sample,"virtualization":value["virtualization"],"kernel":value["kernel"],"identity":value["identity"]})
    require(len(samples)==4 and {(s["virtualization"],s["certificate"]) for s in samples}=={(v,c) for v in ["none","kvm"] for c in [True,False]},"AW host/guest positive/negative coverage missing")
    require(len({s["source"] for s in samples})==2 and len({s["kernel"] for s in samples})==2,"AW distinct observed host/guest environments missing")
    return {**report,"source_case_ids":placement["source_case_ids"],"assembled_at":placement["assembled_at"],"observed_interval":[record["started_at"],record["ended_at"]],"samples":samples,"observation_ids":[name],"scope":"Observed host and KVM guest client environments with finite TLS use; no dedicated-use, hardware approval, protected-facility or physical-cable claim"}


def import_redundancy(source_key="redundancy_events"):

    root=source_path(source_key);manifest,files,report=manifest_report(root)
    events=json.loads((root/"events.json").read_text());require(events["error"] is None,"redundancy event experiment failed")
    records=unique_records(events["records"],"redundancy event")
    probes=[]
    for probe in events["probes"]:
        r=records[probe["observation_id"]];outcome,tx,rx=probe_outcome(r)
        require(outcome==probe["observed"]==probe["expected"],"redundancy probe outcome differs")
        probes.append({**probe,"transmitted":tx,"received":rx,"started_at":r["started_at"],"ended_at":r["ended_at"]})
    insertion=one([r for r in records.values() if "csfc-v2-forwarding-outage" in r["command"] and "-I" in r["command"]],"tagged primary outage insertion missing")
    removal=one([r for r in records.values() if "csfc-v2-forwarding-outage" in r["command"] and "-D" in r["command"]],"tagged primary outage removal missing")
    require(insertion["returncode"]==removal["returncode"]==0,"outage operation failed")
    denied=one([p for p in probes if p["observed"]=="no_reply"],"one recorded outage refusal required")
    standby=[p for p in probes if p["id"].startswith("standby-restored-")]
    require(len(standby)==4 and utc(insertion["ended_at"])<utc(denied["started_at"])<min(utc(p["started_at"]) for p in standby) and max(utc(p["ended_at"]) for p in standby)<utc(removal["started_at"]),"outage/manual restoration event order differs")
    require(len(probes)==17,"redundancy phase probe coverage differs")
    return {**report,"source_case_ids":events["source_case_ids"],"configuration_id":events["configuration_id"],"probes":probes,"operation_observations":[insertion["id"],removal["id"]],"observation_ids":list(records),"scope":"Finite tagged primary DROP and manual standby route selection outcomes; no automatic HA, physical fault or universal availability claim"}


def generate(output,report_path):
    http=[import_http(key) for key in ["http_crl","http_ocsp"]]
    eap=[import_eap("eap_"+direction+"_v"+str(version)) for direction in ["forward","reverse"] for version in [3,4,5]]
    aw=import_aw();redundancy=import_redundancy()
    lines=["import TDN.Evidence.SupplementalTypes","import TDN.Semantics.BridgePolicy","namespace TDN.Imported.Extensions","set_option maxRecDepth 100000"]
    for index,case in enumerate(http):
        client,server=case["bounds"]["client"],case["bounds"]["server"]
        lines.append(f"def httpChain{index} := BridgePolicy.chain {client} {server}")
        lines.append(f"theorem http_exception_{index}_bounded (p : BridgePolicy.Frame) (h4 : p.etherType = 2048) (ht : p.ipProtocol = 6) (ha : Filter.evaluate httpChain{index} .deny p = .allow) : BridgePolicy.HTTPRequest {client} {server} p ∨ BridgePolicy.HTTPResponse {client} {server} p := BridgePolicy.accepted_tcp_is_bounded _ _ p h4 ht ha")
    lines.append("def revocationStatuses : List (String × List String) := "+lean_list(["("+quoted(c["id"])+", "+lean_list([quoted(v["status"]) for v in c["checks"]])+")" for c in http]))
    lines.append('theorem observed_revocation_status_pairs : revocationStatuses ≠ [] ∧ ∀ c ∈ revocationStatuses, c.2 = ["good","revoked"] := by unfold revocationStatuses; decide')
    lines.append("def eapResults : List (String × String × Bool × String) := "+lean_list(["("+", ".join([quoted(e["id"]),quoted(e["tls_version"]),str(e["authentication_success"]).lower(),quoted(e["data_probe_status"])])+")" for e in eap]))
    lines.append('theorem eap_authentication_without_successful_data_probe : eapResults ≠ [] ∧ ∀ e ∈ eapResults, e.2.1 = "TLSv1.2" ∧ e.2.2.1 = true ∧ e.2.2.2 ∈ ["not_attempted","runtime_error"] := by unfold eapResults; decide')
    lines.append("def awSamples : List Evidence.TLSSample := "+lean_list([tls_lean(s) for s in aw["samples"]]))
    lines.append("theorem recorded_host_and_guest_tls_use : Evidence.TLSRecordedOutcomes awSamples := by unfold Evidence.TLSRecordedOutcomes awSamples; decide")
    lines.append("def redundancyProbes : List Evidence.MechanismProbe := "+lean_list(["⟨"+", ".join([quoted(p["id"]),quoted(p["expected"]),quoted(p["observed"]),str(p["transmitted"]),str(p["received"])])+"⟩" for p in redundancy["probes"]]))
    lines.append("theorem recorded_manual_redundancy_probe_outcomes : redundancyProbes ≠ [] ∧ ∀ p ∈ redundancyProbes, p.expected = p.observed := by unfold redundancyProbes; decide")
    lines.append('theorem outage_and_restoration_witnesses : (∃ p ∈ redundancyProbes, p.observed = "no_reply") ∧ (∃ p ∈ redundancyProbes, p.id = "standby-restored-1" ∧ 0 < p.received) := by unfold redundancyProbes; decide')
    lines.append("end TDN.Imported.Extensions")
    output.write_text("\n\n".join(lines)+"\n")
    report_path.write_text(json.dumps({"http":http,"eap":eap,"aw":aw,"redundancy":redundancy},indent=2)+"\n")
    print(json.dumps({"http":len(http),"eap_partial":len(eap),"aw_samples":len(aw["samples"]),"redundancy_probes":len(redundancy["probes"])}))

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--lean-output",type=Path,required=True);parser.add_argument("--report",type=Path,required=True);args=parser.parse_args();generate(args.lean_output,args.report)
