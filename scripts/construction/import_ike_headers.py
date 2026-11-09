import argparse
from collections import Counter
import json
from pathlib import Path
from import_events import event_bundle,one,import_ike
from import_snapshot import quoted,lean_list
from source_paths import source_path
from validate_evidence import require,utc


def header_identity(row):
    return tuple((k,v) for k,v in sorted(row.items()) if k not in {"timestamp","packet_type"})


def validate_headers(rows,mtu,peers):
    require(bool(rows),"header capture is empty")
    for row in rows:
        require({row["source"],row["destination"]}==set(peers),"header endpoint differs from exchange peers")
        require(row["ike_version"]==32,"unexpected IKE version in capture")
        require(row["ip_total_length"]==row["ip_header_length"]+row["udp_length"],"IP/UDP length inconsistency")
        marker=4 if row["udp_destination"]==4500 else 0
        require(row["udp_length"]==8+marker+row["ike_length"],"UDP/IKE length inconsistency")
        require(row["ip_total_length"]<=mtu and not row["more_fragments"] and row["fragment_offset_bytes"]==0,"captured packet exceeds path bound or uses IP fragmentation")
    initiator_spis={r["ike_initiator_spi"] for r in rows}
    responder_spis={r["ike_responder_spi"] for r in rows if r["ike_responder_spi"]!="0000000000000000"}
    require(len(initiator_spis)==len(responder_spis)==1,"capture mixes distinct IKE SAs")
    for source in peers:
        for exchange,message in [(34,0),(43,1),(35,2)]:
            selected=[r for r in rows if r["source"]==source and r["ike_exchange_type"]==exchange]
            require(selected and all(r["ike_message_id"]==message for r in selected),"missing exchange direction or wrong message ID")
            if exchange==34:
                require(len(selected)==1 and selected[0]["ike_next_payload"]==33,"initial exchange capture ambiguous")
            else:
                require(all(r["ike_next_payload"]==53 for r in selected),"encrypted IKE fragment payload missing")
                total=selected[0]["ef_total_fragments"]
                require(all(r["ef_total_fragments"]==total for r in selected) and sorted(r["ef_fragment_number"] for r in selected)==list(range(1,total+1)),"incomplete or duplicate encrypted fragments")
    return True


def generate(output,report_path):
    root=source_path("ikev2_headers")
    events,records,digest=event_bundle(root,"csfc-protocol-events/v1")
    exchange=import_ike(root)
    addresses=[r for r in records.values() if r["command"][-4:]==["-j","-d","address"]]
    if not addresses:addresses=[r for r in records.values() if r["command"][-3:]==["-j","-d","address"]]
    require(len(addresses)==2,"two endpoint interface inventories required")
    host=one([r for r in records.values() if r["command"]==["ip","-j","-d","link","show"]],"host link inventory missing")
    host_links=json.loads(host["stdout"])
    network=one([r for r in records.values() if r["command"][:3]==["docker","network","inspect"]],"bridge network inventory missing")
    network=json.loads(network["stdout"])[0]
    require(network["Driver"]=="bridge","direct bridge path required")
    identities={v["Name"]:v for v in network["Containers"].values()}
    peers=[]
    path_links=[]
    for address in addresses:
        namespace=address["command"][2]
        interface=one([i for i in json.loads(address["stdout"]) if i["ifname"]=="eth0"],"unique endpoint eth0 missing")
        peer=identities[namespace]
        ip=peer["IPv4Address"].split("/")[0]
        require(interface["address"]==peer["MacAddress"] and any(a.get("local")==ip for a in interface["addr_info"]),"endpoint identity differs from bridge inventory")
        peers.append(ip)
        host_peer=one([i for i in host_links if i["ifindex"]==interface["link_index"]],"host veth peer missing")
        require(host_peer["link_index"]==interface["ifindex"] and host_peer["linkinfo"]["info_kind"]=="veth","reciprocal host veth indices mismatch")
        bridge=one([i for i in host_links if i["ifname"]==host_peer["master"]],"host bridge missing")
        require(bridge["linkinfo"]["info_kind"]=="bridge","peer master is not a bridge")
        path_links += [{"namespace":namespace,"interface":"eth0","mtu":interface["mtu"]},{"namespace":"host","interface":host_peer["ifname"],"mtu":host_peer["mtu"]},{"namespace":"host","interface":bridge["ifname"],"mtu":bridge["mtu"]}]
        route=one([r for r in records.values() if r["command"][:3]==["docker","exec",namespace] and r["command"][-3:-1]==["route","get"]],"endpoint peer route missing")
        selected=json.loads(route["stdout"])[0]
        require(selected["dev"]=="eth0" and selected["prefsrc"]==ip and "gateway" not in selected,"peer route is not direct on observed interface")
    require(path_links[2]["interface"]==path_links[5]["interface"],"peers do not attach to the same bridge")
    mtu=min(link["mtu"] for link in path_links)
    captures=[r for r in records.values() if r["command"][-1:]==["/tmp/ike-headers.jsonl"] and "cat" in r["command"]]
    require(len(captures)==2,"two endpoint header captures required")
    sets=[[json.loads(line) for line in r["stdout"].splitlines()] for r in captures]
    for rows in sets:
        validate_headers(rows,mtu,peers)
        require(all(utc(events["started_at"])<=utc(r["timestamp"])<=utc(events["ended_at"]) for r in rows),"capture timestamp outside interval")
    require(Counter(header_identity(r) for r in sets[0])==Counter(header_identity(r) for r in sets[1]),"endpoint capture contents disagree")
    rows=[r for group in sets for r in group]
    values=[]
    for row in rows:
        fields=[quoted(row["source"]),quoted(row["destination"]),str(row["ip_total_length"]),str(row["more_fragments"]).lower(),str(row["fragment_offset_bytes"]),str(row["ike_exchange_type"]),str(row["ike_message_id"]),str(row["ike_next_payload"]),str(row.get("ef_fragment_number",0)),str(row.get("ef_total_fragments",0))]
        values.append("⟨"+", ".join(fields)+"⟩")
    lines=["import TDN.Deployments.EventTypes","namespace TDN.Deployments.IKEHeaders","set_option maxRecDepth 100000","def pathMTU : Nat := "+str(mtu),"def headers : List Evidence.IKEHeaderObservation := "+lean_list(values),"theorem recorded_headers_fit_without_ip_fragmentation : Evidence.RecordedHeadersFitWithoutIPFragmentation headers pathMTU := by unfold Evidence.RecordedHeadersFitWithoutIPFragmentation headers pathMTU; decide","theorem recorded_exchange_message_kinds : Evidence.RecordedExchangeMessageKinds headers := by unfold Evidence.RecordedExchangeMessageKinds headers; decide","end TDN.Deployments.IKEHeaders"]
    output.write_text("\n\n".join(lines)+"\n")
    report={"manifest_sha256":digest,"exchange":exchange,"path_links":path_links,"path_mtu_bound":mtu,"header_records":len(rows),"unique_packets":len(sets[0]),"max_ip_total_length":max(r["ip_total_length"] for r in rows),"encrypted_fragment_records":sum(r["ike_next_payload"]==53 for r in rows),"capture_observations":[r["id"] for r in captures],"scope":"Recorded headers in one finite IKE exchange, with equal endpoint captures","assumptions":["Header collector truth and correct decoding; payloads are deliberately absent","Direct same-bridge namespace route and veth association faithfully represent the path during capture","Capture completeness is a separate assumption; equality of endpoint records does not establish that no packet was omitted by both collectors","No future-exchange, all-path PMTU or complete RFC-conformance claim"]}
    report_path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"headers":len(rows),"path_mtu":mtu,"maximum":report["max_ip_total_length"]}))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--lean-output",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    generate(args.lean_output,args.report)
