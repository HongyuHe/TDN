"""Translate normalized fresh evidence into literal Lean data and narrow checkable claims."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from validate_evidence import validate_bundle, EvidenceError
from loaded_policy import loaded_policies

class Unsupported(ValueError):
    pass


def quoted(value):
    return json.dumps(value, ensure_ascii=False)


def lean_list(values):
    return "[" + ", ".join(values) + "]"


def optional(value):
    return "none" if value is None else "some " + quoted(value)


def identifier(value):
    value = re.sub(r"[^A-Za-z0-9_]", "_", value)
    return "x_" + value if not value or value[0].isdigit() else value


def parse_rule(rule):
    matches = rule["matches"]
    if set(matches) != {"iptables_tokens"}:
        raise Unsupported("only literal iptables_tokens currently supported")
    tokens = matches["iptables_tokens"]
    atoms = []
    modules = []
    policy = {}
    index = 0
    while index < len(tokens):
        key=tokens[index]
        if index+1 >= len(tokens):
            raise Unsupported("missing argument for " + key)
        value=tokens[index+1]
        index += 2
        if key in {"-s","-d"}:
            prefix=ipaddress.ip_network(value,strict=True)
            atoms.append({"kind":"sourceRange" if key=="-s" else "destinationRange","low":int(prefix.network_address),"high":int(prefix.broadcast_address),"family":prefix.version})
        elif key in {"-i","-o","-p"}:
            if key in {"-i","-o"} and "+" in value:
                raise Unsupported("interface wildcard")
            atoms.append({"kind":{"-i":"ingress","-o":"egress","-p":"protocol"}[key],"value":value})
        elif key == "-m":
            if value not in {"policy","multiport","u32","conntrack","tcp","udp"}:
                raise Unsupported("unknown module " + value)
            modules.append(value)
        elif key in {"--dir","--pol","--reqid","--mode"}:
            if key in policy:
                raise Unsupported("duplicate policy field")
            policy[key]=value
        elif key in {"--dports","--dport","--sports","--sport"}:
            values=value.split(",")
            if not all(v.isdigit() and 0 <= int(v) <= 65535 for v in values):
                raise Unsupported("unsupported port syntax")
            atoms.append({"kind":"sourcePorts" if key in {"--sport","--sports"} else "destinationPorts","values":[int(v) for v in values]})
        elif key == "--u32":
            if value != "0x0>>0x18&0xf=0x5":
                raise Unsupported("unsupported u32 expression")
            atoms.append({"kind":"ipv4HeaderWords","value":5})
        elif key == "--ctstate":
            states=value.split(",")
            if not set(states) <= {"NEW","ESTABLISHED","RELATED","INVALID","UNTRACKED"}:
                raise Unsupported("unknown connection state")
            atoms.append({"kind":"connectionStates","values":states})
        else:
            raise Unsupported("unsupported token " + key)
    if policy:
        if "policy" not in modules or set(policy)!={"--dir","--pol","--reqid","--mode"} or policy["--pol"]!="ipsec" or policy["--mode"]!="tunnel" or policy["--dir"] not in {"in","out"} or not policy["--reqid"].isdigit():
            raise Unsupported("incomplete/unsupported policy guard")
        atoms.append({"kind":"inboundPolicy" if policy["--dir"]=="in" else "outboundPolicy","value":int(policy["--reqid"])})
    elif "policy" in modules:
        raise Unsupported("policy module lacks constraints")
    action=rule["action"]
    if action not in {"accept","drop","reject"}:
        raise Unsupported("unsupported verdict")
    return {"atoms":atoms,"verdict":"allow" if action=="accept" else "deny","ordinal":rule["ordinal"],"raw_text":rule["raw_text"]}


def lean_atom(atom):
    kind=atom["kind"]
    if kind in {"sourceRange","destinationRange"}:
        return "." + kind + " " + str(atom["low"]) + " " + str(atom["high"])
    if kind in {"sourcePorts","destinationPorts","connectionStates"}:
        values=lean_list([str(v) if type(v) is int else quoted(v) for v in atom["values"]])
        return f".{kind} {values}"
    value=atom["value"]
    return f".{kind} " + (str(value) if type(value) is int else quoted(value))


def guarded(rule,inside,outside):
    if rule["verdict"]=="deny":
        return True
    atoms=rule["atoms"]
    pairs={(a["kind"],a.get("value")) for a in atoms if "value" in a}
    return (("ingress",inside) in pairs and ("egress",outside) in pairs and any(a["kind"]=="outboundPolicy" for a in atoms)) or (("ingress",outside) in pairs and ("egress",inside) in pairs and any(a["kind"]=="inboundPolicy" for a in atoms))


def parse_xfrm_policies(raw):
    policies=[]
    for block in re.split(r"(?m)(?=^src )",raw):
        if not block.strip():
            continue
        lines=[line.strip() for line in block.splitlines() if line.strip()]
        if any(line.startswith("socket ") for line in lines):
            continue
        if len(lines)!=4:
            raise Unsupported("unrecognized XFRM policy block")
        selector=re.fullmatch(r"src (\S+) dst (\S+)",lines[0])
        direction=re.fullmatch(r"dir (in|out|fwd) priority (\d+)",lines[1])
        endpoints=re.fullmatch(r"tmpl src (\S+) dst (\S+)",lines[2])
        template=re.fullmatch(r"proto esp(?: spi 0x[0-9a-fA-F]+)? reqid (\d+) mode tunnel",lines[3])
        if not all((selector,direction,endpoints,template)):
            raise Unsupported("unrecognized XFRM selector/template")
        policies.append({"source":str(ipaddress.ip_network(selector[1],strict=True)),"destination":str(ipaddress.ip_network(selector[2],strict=True)),"direction":direction[1],"priority":int(direction[2]),"local":endpoints[1],"remote":endpoints[2],"request_id":int(template[1]),"mode":"tunnel"})
    return policies


def check_installed_policy(tunnel):
    policies=parse_xfrm_policies(tunnel["policies"])
    selectors=tunnel["traffic_selectors"]
    endpoints=tunnel["endpoints"]
    expected=[]
    for direction in ("out","in","fwd"):
        reverse=direction!="out"
        expected.append({"direction":direction,"source":str(ipaddress.ip_network(selectors["remote" if reverse else "local"],strict=True)),"destination":str(ipaddress.ip_network(selectors["local" if reverse else "remote"],strict=True)),"local":endpoints["remote" if reverse else "local"],"remote":endpoints["local" if reverse else "remote"]})
    found=[]
    for item in expected:
        candidates=[p for p in policies if all(p[k]==v for k,v in item.items())]
        if len(candidates)!=1:
            return {"passed":False,"reason":"Missing/ambiguous installed directional policy matching selectors and peer endpoints","expected":item,"policies":policies}
        found.extend(candidates)
    if len({p["request_id"] for p in found})!=1:
        return {"passed":False,"reason":"Directional request IDs disagree","policies":policies}
    return {"passed":True,"request_id":found[0]["request_id"],"policies":policies,"scope":"Matched supplied tunnel selectors and endpoints in three installed directional policies; socket policies are retained in raw input and do not establish global absence of bypass."}


def parse_observed_modes(tunnel):
    raw=tunnel.get("observed_state", "")
    if tunnel.get("status") != "observed" or "ESTABLISHED, IKEv2," not in raw:
        raise Unsupported("no established IKEv2 state")
    if len(re.findall(r"(?m)^\S+: #\d+, ESTABLISHED, IKEv2,",raw)) != 1 or len(re.findall(r"INSTALLED, TUNNEL, ESP:",raw)) != 1:
        raise Unsupported("ambiguous multiple IKE/CHILD SAs; tunnel binding required")
    endpoints=tunnel.get("endpoints",{})
    local_rows=re.findall(r"(?m)^  local  .* @ ([^\[\n]+)\[",raw)
    remote_rows=re.findall(r"(?m)^  remote .* @ ([^\[\n]+)\[",raw)
    if local_rows != [endpoints.get("local")] or remote_rows != [endpoints.get("remote")]:
        raise Unsupported("observed SA endpoints do not bind to target tunnel")
    suite=re.search(r"(?m)^  (AES_[^\n]+)$",raw)
    esp=re.search(r"INSTALLED, TUNNEL, ESP:([^\n]+)",raw)
    if suite is None or esp is None:
        raise Unsupported("unrecognized observed cipher suite")
    def mode(text):
        if text.startswith("AES_GCM_"):
            return "gcm"
        if text.startswith("AES_CBC_"):
            return "cbc"
        raise Unsupported("unsupported observed cipher mode")
    return {"device_id":tunnel["device_id"],"ike_version":2,"ike_mode":mode(suite[1]),"esp_mode":mode(esp[1]),"esp_hmac": "HMAC" in esp[1],"observation_ids":tunnel["observation_ids"],"scope":"Negotiated mode in collected established tunnel, not all offered proposals or future negotiations"}


def rule_policy_covered(rule, policy_checks):
    if rule["verdict"] == "deny":
        return True
    atoms = rule["atoms"]
    policy_atoms = [a for a in atoms if a["kind"] in {"inboundPolicy", "outboundPolicy"}]
    source = next((a for a in atoms if a["kind"] == "sourceRange"), None)
    destination = next((a for a in atoms if a["kind"] == "destinationRange"), None)
    if not policy_atoms or source is None or destination is None:
        return False
    for atom in policy_atoms:
        direction = "out" if atom["kind"] == "outboundPolicy" else "in"
        candidates = [p for check in policy_checks if check.get("passed") for p in check["policies"] if p["direction"] == direction and p["request_id"] == atom["value"]]
        if not any(int(ipaddress.ip_network(p["source"]).network_address) <= source["low"] <= source["high"] <= int(ipaddress.ip_network(p["source"]).broadcast_address) and int(ipaddress.ip_network(p["destination"]).network_address) <= destination["low"] <= destination["high"] <= int(ipaddress.ip_network(p["destination"]).broadcast_address) for p in candidates):
            return False
    return True


def generate(bundle, output, report_path):
    validation=validate_bundle(bundle)
    snapshot=json.loads((bundle/"snapshot.json").read_text())
    ns=identifier(snapshot["snapshot_id"])
    lines=["import TDN.Evidence.Types","import TDN.Semantics.PacketPolicy",f"namespace TDN.Imported.{ns}","set_option maxRecDepth 100000","set_option maxHeartbeats 0"]
    devices=[]
    for d in snapshot["devices"]:
        status={"not_applicable":"notApplicable"}.get(d["status"],d["status"])
        devices.append("⟨"+", ".join([quoted(d["id"]),quoted(d["role"]),optional(d.get("site")),optional(d.get("security_level_id")),"."+status,lean_list([quoted(v) for v in d["observation_ids"]])])+"⟩")
    tunnels=[]
    for t in snapshot["tunnels"]:
        status={"not_applicable":"notApplicable"}.get(t["status"],t["status"])
        tunnels.append("⟨"+", ".join([quoted(t["id"]),quoted(t["device_id"]),quoted(t["peer_device_id"]),quoted(t["layer"]),quoted(t["mechanism"]),quoted(t.get("mode") or ""),"."+status,lean_list([quoted(v) for v in t["observation_ids"]])])+"⟩")
    probes=[]
    for p in snapshot["probes"]:
        status={"not_applicable":"notApplicable"}.get(p["status"],p["status"])
        probes.append("⟨"+", ".join([quoted(p["id"]),quoted(p["source_device"]),quoted(p["destination"]),quoted(p["purpose"]),quoted(p["observed_result"]),"."+status,lean_list([quoted(v) for v in p["observation_ids"]])])+"⟩")
    lines.extend(["def snapshot : Evidence.Snapshot where", "  id := "+quoted(snapshot["snapshot_id"]),"  manifestSha256 := "+quoted(validation["source_manifest_sha256"]),"  snapshotSha256 := "+quoted(validation["source_snapshot_sha256"]),"  devices := "+lean_list(devices),"  tunnels := "+lean_list(tunnels),"  probes := "+lean_list(probes)])
    lines.append("theorem observed_provenance : Evidence.HasProvenance snapshot := by unfold Evidence.HasProvenance snapshot; decide")
    if any(p["status"]=="observed" and p["observed_result"]=="delivered" for p in snapshot["probes"]):
        lines.append("theorem useful_observed_traffic : Evidence.HasObservedSuccess snapshot := by unfold Evidence.HasObservedSuccess snapshot; decide")
    if any(t["mechanism"] == "IPsec" for t in snapshot["tunnels"]) and all(t["mechanism"] != "IPsec" or t.get("mode") == "tunnel" for t in snapshot["tunnels"]):
        lines.append("theorem observed_ipsec_tunnel_modes : Evidence.IPsecTunnelModes snapshot := by unfold Evidence.IPsecTunnelModes snapshot; decide")
    level_by_device={d["id"]:d.get("security_level_id") for d in snapshot["devices"]}
    inner_peers=[t for t in snapshot["tunnels"] if t["layer"]=="inner"]
    if inner_peers and all(level_by_device[t["device_id"]] is not None and level_by_device[t["device_id"]]==level_by_device[t["peer_device_id"]] for t in inner_peers):
        lines.append("theorem observed_inner_peers_same_declared_level : Evidence.InnerPeersSameDeclaredLevel snapshot := by unfold Evidence.InnerPeersSameDeclaredLevel snapshot; decide")
    report={"snapshot_id":snapshot["snapshot_id"],"validation":validation,"translated_chains":[],"unsupported":[],"forwarding_certificates":[],"installed_policy_checks":[],"claims":{"whole_groups_established":[],"linux_refinement_established":False}}
    device_index={d["id"]:d for d in snapshot["devices"]}
    for chain in snapshot["filters"]:
        try:
            rules=[parse_rule(r) for r in chain["ordered_rules"]]
        except Unsupported as exc:
            report["unsupported"].append({"chain_id":chain["id"],"reason":str(exc)})
            continue
        chain_name="chain_"+identifier(chain["id"])
        emitted=["⟨"+lean_list([lean_atom(a) for a in r["atoms"]])+", ."+r["verdict"]+"⟩" for r in rules]
        lines.append("def "+chain_name+" : List PacketPolicy.Rule := "+lean_list(emitted))
        report["translated_chains"].append({"chain_id":chain["id"],"definition":chain_name,"rule_count":len(rules),"source_status":chain["status"]})
        role=device_index[chain["device_id"]]["role"]
        if chain["chain"]=="FORWARD" and role in {"inner","outer","inner-encryption","outer-encryption","inner-vpn","outer-vpn"}:
            inside,outside=("red","gray") if role.startswith("inner") else ("gray","black")
            passed=chain["policy"]=="drop" and all(guarded(r,inside,outside) for r in rules)
            checks=[]
            for tunnel in snapshot["tunnels"]:
                if tunnel["device_id"] == chain["device_id"] and tunnel["mechanism"] == "IPsec":
                    try:
                        checks.append(check_installed_policy(tunnel))
                    except (Unsupported, ValueError):
                        checks.append({"passed":False})
            installed_coverage = bool(checks) and all(rule_policy_covered(r,checks) for r in rules)
            record={"installed_policy_coverage":installed_coverage,"chain_id":chain["id"],"passed":passed,"inside":inside,"outside":outside,"nonempty_allow":any(r["verdict"]=="allow" for r in rules),"scope":"Every accepted packet in translated first-match FORWARD chain has a direction-appropriate tunnel-policy match; local/input/output traffic and Linux refinement remain separate."}
            if passed:
                theorem=chain_name+"_guarded"
                lines.append("theorem "+theorem+" : ∀ r ∈ "+chain_name+", r.verdict = .allow → PacketPolicy.Guarded r "+quoted(inside)+" "+quoted(outside)+" := by unfold "+chain_name+"; decide")
                lines.append("theorem "+chain_name+"_protects (p : PacketPolicy.Packet) (accepted : Filter.evaluate ("+chain_name+".map PacketPolicy.Rule.toFilter) .deny p = .allow) : PacketPolicy.ProtectedForward "+quoted(inside)+" "+quoted(outside)+" p := PacketPolicy.forwarding_policy_protects "+chain_name+" "+quoted(inside)+" "+quoted(outside)+" "+theorem+" p accepted")
                record["theorem"]="TDN.Imported."+ns+"."+chain_name+"_protects"
            report["forwarding_certificates"].append(record)
    for tunnel in snapshot["tunnels"]:
        if tunnel["mechanism"]=="IPsec" and isinstance(tunnel.get("policies"),str):
            try:
                check=check_installed_policy(tunnel)
            except (Unsupported,ValueError) as exc:
                check={"passed":False,"reason":str(exc)}
            report["installed_policy_checks"].append({"tunnel_id":tunnel["id"],**check})
    hard_lifetimes=[]
    for tunnel in snapshot["tunnels"]:
        if tunnel["mechanism"]!="IPsec" or tunnel["status"]!="observed":
            continue
        raw=tunnel.get("replay_protection",{}).get("raw_states", "")
        states=len(re.findall(r"(?m)^src ",raw))
        limits=re.findall(r"expire add: soft (?:[0-9]+|INF)\(sec\), hard ([0-9]+)\(sec\)",raw)
        if states and len(limits)==states and all(int(value)>0 for value in limits):
            hard_lifetimes.extend({"device":tunnel["device_id"],"state_index":index,"seconds":int(value)} for index,value in enumerate(limits))
        else:
            report["unsupported"].append({"tunnel_id":tunnel["id"],"reason":"ESP hard lifetime is unbounded (kernel zero) or not completely parsed"})
    report["esp_hard_lifetimes"]=hard_lifetimes
    if hard_lifetimes and all(f["seconds"]<=28800 for f in hard_lifetimes):
        facts=["⟨"+quoted(f["device"])+", "+str(f["state_index"])+", "+str(f["seconds"])+"⟩" for f in hard_lifetimes]
        lines.append("def observedESPHardLifetimes : List Evidence.HardLifetimeFact := "+lean_list(facts))
        lines.append("theorem observed_esp_hard_lifetimes_within_bound : Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes := by unfold Evidence.ESPHardLifetimesWithinBound observedESPHardLifetimes; decide")
    mode_records=[]
    for tunnel in snapshot["tunnels"]:
        if tunnel["mechanism"]=="IPsec":
            try:
                mode_records.append(parse_observed_modes(tunnel))
            except Unsupported as exc:
                report["unsupported"].append({"tunnel_id":tunnel["id"],"reason":str(exc)})
    report["observed_modes"]=mode_records
    if mode_records:
        configs=[]
        for index,mode in enumerate(mode_records):
            configs.append("⟨"+str(index)+", 2, ."+mode["ike_mode"]+", ."+mode["esp_mode"]+", "+str(mode["esp_hmac"]).lower()+"⟩")
        lines.append("def observedVPNModes : List Targets.VPNConfig := "+lean_list(configs))
        lines.append("theorem observed_vpn_modes_conform : Targets.NegotiatedModesConform observedVPNModes := by unfold Targets.NegotiatedModesConform observedVPNModes; decide")
    if any("loaded_public_configuration" in t for t in snapshot["tunnels"]):
        try:
            loaded,bindings=loaded_policies(bundle,snapshot)
            report["loaded_mode_policy"]={"records":loaded,"bindings":bindings,"configuration_target":"TDN.Imported."+ns+".snapshot_loaded_configuration_RG022","scope":"Complete inventoried VPN gateway connection/CHILD mode configuration after successful exact-file load and reconciled runtime inventory; loader/parser/collector correspondence is explicit trust."}
            values=[]
            for policy in loaded:
                esp=lean_list(["⟨."+p["mode"]+", "+str(p["hmac"]).lower()+"⟩" for p in policy["esp_proposals"]])
                values.append("⟨"+quoted(policy["device"]+"/"+policy["connection"])+", [2], "+lean_list(["."+m for m in policy["ike_modes"]])+", "+esp+"⟩")
            lines.append("def loadedVPNModePolicies : List Targets.VPNModePolicy := "+lean_list(values))
            lines.append("theorem snapshot_loaded_configuration_RG022 : Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies := by unfold Targets.msc_ike_version_and_encryption_modes loadedVPNModePolicies; decide")
        except EvidenceError as exc:
            report["loaded_mode_policy"]={"error":str(exc),"configuration_target":None}
    lines.append("end TDN.Imported."+ns)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text("\n\n".join(lines)+"\n")
    report["generated_lean_sha256"]=hashlib.sha256(output.read_bytes()).hexdigest()
    report_path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"snapshot_id":snapshot["snapshot_id"],"translated_chains":len(report["translated_chains"]),"unsupported":report["unsupported"],"forwarding_certificates":report["forwarding_certificates"],"installed_policy_passed":sum(x["passed"] for x in report["installed_policy_checks"])},indent=2))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("bundle",type=Path)
    parser.add_argument("--lean-output",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    generate(args.bundle,args.lean_output,args.report)

if __name__=="__main__":
    main()
