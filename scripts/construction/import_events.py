import argparse
import hashlib
import json
from pathlib import Path
import re
from import_mechanisms import probe_outcome
from import_snapshot import quoted,lean_list
from validate_evidence import require,EvidenceError,safe_path,utc,unique_records
from source_paths import source_path


def event_bundle(root,schema):
    manifest=json.loads(safe_path(root,"manifest.json").read_text())
    require(manifest["schema_version"]==schema,"unexpected event schema")
    paths=set()
    for entry in manifest["files"]:
        require(entry["path"] not in paths,"duplicate event file")
        paths.add(entry["path"])
        content=safe_path(root,entry["path"]).read_bytes()
        require(hashlib.sha256(content).hexdigest()==entry["sha256"] and len(content)==entry["bytes"],"event manifest hash/size mismatch")
    require("events.json" in paths,"event file missing")
    events=json.loads((root/"events.json").read_text())
    require(events["schema_version"]==schema and events["error"] is None,"event run reports error")
    start,end=utc(events["started_at"]),utc(events["ended_at"])
    require(start<=end,"reversed event interval")
    records=unique_records(events["records"],"event")
    for record in records.values():
        require(start<=utc(record["started_at"])<=utc(record["ended_at"])<=end,"event outside recorded interval")
        if record["returncode"]!=0:
            require("ping" in record["command"] and probe_outcome(record)[0]=="no_reply","event command failed")
    return events,records,hashlib.sha256((root/"manifest.json").read_bytes()).hexdigest()


def one(items,message):
    require(len(items)==1,message)
    return items[0]


def parse_ike_trace(text):
    lines=text.splitlines()
    def line(pattern):
        return one([i for i,value in enumerate(lines) if re.search(pattern,value)],"missing/ambiguous IKE phase "+pattern)
    positions=[line(r"generating IKE_SA_INIT request 0 "),line(r"parsed IKE_SA_INIT response 0 "),line(r"generating IKE_INTERMEDIATE request 1 \[ KE \]"),line(r"parsed IKE_INTERMEDIATE response 1 \[ KE \]"),line(r"generating IKE_AUTH request 2 \[ IDi "),line(r"parsed IKE_AUTH response 2 \[ IDr ")]
    require(positions==sorted(set(positions)),"IKE phases are out of order")
    ike=one(re.findall(r"selected proposal: IKE:([^\n]+)",text),"ambiguous IKE proposal").split("/")
    require(ike==["AES_GCM_16_256","PRF_HMAC_SHA2_384","ECP_384","KE1_ML_KEM_1024"],"unexpected objective negotiated proposal")
    initial=[int(x) for x in re.findall(r"\((\d+) bytes\)","\n".join(lines[positions[0]:positions[1]]))]
    require(len(initial)==2,"initial exchange message-size observations incomplete")
    auth=re.findall(r"authentication of '([^']+)'(?: \(myself\))? with (\w+) successful",text)
    require(len(auth)==2 and len({identity for identity,algorithm in auth})==2,"two distinct authentication endpoints missing")
    esp=one(re.findall(r"selected proposal: ESP:([^/\n]+)",text),"ambiguous ESP proposal")
    fragments=[]
    for exchange,direction in [("IKE_INTERMEDIATE","request"),("IKE_INTERMEDIATE","response"),("IKE_AUTH","request"),("IKE_AUTH","response")]:
        found=[(int(a),int(b)) for a,b in re.findall(exchange+r" "+direction+r" [12] \[ EF\((\d+)/(\d+)\) \]",text)]
        require(found and len({b for a,b in found})==1 and sorted(a for a,b in found)==list(range(1,found[0][1]+1)),"incomplete/repeated IKE encrypted-fragment sequence")
        fragments.append(found[0][1])
    return {"positions":positions,"initial_key_exchange":ike[2],"additional_key_exchange":ike[3].removeprefix("KE1_"),"signature_algorithms":[a for i,a in auth],"authentication_identities":[i for i,a in auth],"esp_cipher":esp,"initial_message_bytes":initial,"fragment_counts":fragments,"revocation_status_available":"certificate status is not available" not in text}


def import_ike(root):
    events,records,digest=event_bundle(root,"csfc-protocol-events/v1")
    initiate=one([r for r in records.values() if "--initiate" in r["command"]],"one initiated exchange required")
    trace=parse_ike_trace(initiate["stdout"])
    states=[r for r in records.values() if r["command"][-1:]==["--list-sas"]]
    require(len(states)==2,"both IKE peer states required")
    for state in states:
        require(state["stdout"].count("ESTABLISHED, IKEv2")==1 and "AES_GCM_16-256/PRF_HMAC_SHA2_384/ECP_384/KE1_ML_KEM_1024" in state["stdout"],"ambiguous/mismatched peer SA suite")
        require(all(identity in state["stdout"] for identity in trace["authentication_identities"]),"peer identities differ across trace and SA inventory")
    probe=one([r for r in records.values() if "ping" in r["command"]],"one useful protocol probe required")
    outcome,tx,rx=probe_outcome(probe)
    require(outcome=="delivered","objective exchange has no useful traffic")
    return {**trace,"ike_version":2,"useful_replies":rx,"transmitted":tx,"manifest_sha256":digest,"trace_observation":initiate["id"],"sa_observations":[r["id"] for r in states],"probe_observation":probe["id"],"limitations":events["limitations"],"pmtu_evidence":"ER-015 pending; message sizes are application observations, not complete datagram lengths"}


def import_mka(root):
    events,records,digest=event_bundle(root,"csfc-authentication-events/v1")
    require(events["authentication"]=="MKA PSK" and events["mode"] in {"matching","mismatched"},"unsupported authentication case")
    statuses=[r for r in records.values() if "wpa_cli" in r["command"] and r["command"][-1]=="status"]
    require(len(statuses)==2,"two MKA peer statuses required")
    peers=[]
    for status in statuses:
        fields=dict(line.split("=",1) for line in status["stdout"].splitlines() if "=" in line)
        control=status["command"][status["command"].index("-p")+1]
        suffix=re.search(r"ctrl([01])$",control)
        require(suffix is not None,"MKA peer control binding missing")
        peer=suffix[1]
        namespace="tcv2k-"+("a" if peer=="0" else "b")
        states=[r for r in records.values() if namespace in r["command"] and r["command"][-4:]==["-s","macsec","show"]]
        if not states:
            states=[r for r in records.values() if namespace in r["command"] and r["command"][-3:]==["-s","macsec","show"]]
        require(states,"MKA peer kernel state missing")
        raw=states[-1]["stdout"]
        require(raw.count("cipher suite:")==1,"ambiguous MACsec interface state")
        cipher=one(re.findall(r"cipher suite: ([^,]+),",raw),"MACsec cipher missing")
        txpart=raw.split("RXSC:")[0]
        rxpart="RXSC:".join(raw.split("RXSC:")[1:])
        active=lambda text:len(re.findall(r"\d+: PN \d+, state on,",text))
        logs=[r for r in records.values() if r["command"][-1].endswith("peer"+peer+".log") and "cat" in r["command"]]
        require(logs,"MKA peer log missing")
        peers.append({"peer":namespace,"secured":fields.get("Secured")=="Yes","live_peers":int(fields["live_peers"]),"hello_ms":int(fields["MKA Hello Time"]),"active_tx_sas":active(txpart),"active_rx_sas":active(rxpart),"cipher":cipher,"icv_rejections":logs[-1]["stdout"].count("Computed ICV is not equal to Received ICV"),"status_observation":status["id"],"state_observation":states[-1]["id"],"log_observation":logs[-1]["id"]})
    probe=one([r for r in records.values() if "ping" in r["command"]],"one MKA probe required")
    outcome,tx,rx=probe_outcome(probe)
    return {"mode":events["mode"],"peers":peers,"transmitted":tx,"received":rx,"outcome":outcome,"manifest_sha256":digest,"public_settings":events["public_settings"],"public_settings_status":"declared configuration, not independently observed secret provenance","limitations":events["limitations"]}


def generate(output,report_path):
    ike=import_ike(source_path("ikev2"))
    mka=[import_mka(source_path(name)) for name in ["mka_matching","mka_mismatched"]]
    lines=["import TDN.Evidence.EventTypes","namespace TDN.Imported.Events","set_option maxRecDepth 100000"]
    fields=[str(i) for i in ike["positions"]]+[quoted(ike["initial_key_exchange"]),quoted(ike["additional_key_exchange"]),lean_list([quoted(a) for a in ike["signature_algorithms"]]),quoted(ike["esp_cipher"]),lean_list([str(i) for i in ike["initial_message_bytes"]])]+[str(i) for i in ike["fragment_counts"]]+["2",str(ike["useful_replies"])]
    lines.append("def objectiveExchange : Evidence.IKEExchangeObservation := ⟨"+", ".join(fields)+"⟩")
    lines.append("theorem observed_objective_exchange_sequence : Evidence.ObservedObjectiveSequence objectiveExchange := by unfold Evidence.ObservedObjectiveSequence objectiveExchange; decide")
    for case in mka:
        peer_values=["⟨"+", ".join([quoted(p["peer"]),str(p["secured"]).lower(),str(p["live_peers"]),str(p["hello_ms"]),str(p["active_tx_sas"]),str(p["active_rx_sas"]),quoted(p["cipher"]),str(p["icv_rejections"])])+"⟩" for p in case["peers"]]
        name=case["mode"]+"MKA"
        lines.append("def "+name+" : Evidence.MKAExperiment := ⟨"+str(case["mode"]=="matching").lower()+", "+lean_list(peer_values)+", "+str(case["transmitted"])+", "+str(case["received"])+"⟩")
        prop="ObservedMatchingMKASuccess" if case["mode"]=="matching" else "ObservedMismatchedMKARefusal"
        lines.append("theorem "+case["mode"]+"_mka_outcome : Evidence."+prop+" "+name+" := by unfold Evidence."+prop+" "+name+"; decide")
    lines.append("end TDN.Imported.Events")
    output.write_text("\n\n".join(lines)+"\n")
    report_path.write_text(json.dumps({"ike":ike,"mka":mka,"full_groups_established":[],"trust":"Collector truth, complete selected records, and log/kernel-state semantics; finite selected experiments only"},indent=2)+"\n")
    print(json.dumps({"ike_exchange":True,"mka_cases":len(mka)}))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--lean-output",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    generate(args.lean_output,args.report)
