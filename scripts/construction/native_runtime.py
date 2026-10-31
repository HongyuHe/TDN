import json
import re
from validate_evidence import require


def uuid_set(value):
    if isinstance(value,list) and len(value)==2 and value[0]=="uuid" and isinstance(value[1],str):return [value[1]]
    require(isinstance(value,list) and len(value)==2 and value[0]=="set","malformed OVS UUID set")
    result=[]
    for item in value[1]:
        require(isinstance(item,list) and len(item)==2 and item[0]=="uuid" and isinstance(item[1],str),"malformed OVS UUID member")
        result.append(item[1])
    require(len(result)==len(set(result)),"duplicate OVS UUID relation")
    return result


def ovs_rows(value):
    require(isinstance(value,dict) and set(value)=={"data","headings"},"unsupported OVS table encoding")
    headings=value["headings"]
    require(len(headings)==len(set(headings)) and "_uuid" in headings,"duplicate/missing OVS heading")
    result={}
    for cells in value["data"]:
        require(len(cells)==len(headings),"OVS table row length differs")
        row=dict(zip(headings,cells));identity=uuid_set(row["_uuid"])
        require(len(identity)==1 and identity[0] not in result,"duplicate OVS row UUID")
        result[identity[0]]=row
    return result


def validate_native(bundle,snapshot):
    runtime=snapshot.get("native_runtime",[])
    if not runtime:return {"openvswitch_ids":set(),"membership_ids":set(),"report":None}
    observations={o["id"]:o for o in snapshot["observations"]}
    devices={d["id"]:d for d in snapshot["devices"]}
    interfaces={i["id"]:i for i in snapshot["interfaces"]}
    def raw(o):return json.loads((bundle/o["raw_path"]).read_text())["stdout"]
    def observed(record):
        require(record["observation_ids"],"native observation references missing")
        values=[]
        for oid in record["observation_ids"]:
            o=observations[oid];require(o["returncode"]==0,"native CLI observation failed")
            value=raw(o)
            if isinstance(record.get("raw_value"),dict):value=json.loads(value)
            require(value==record["raw_value"],"normalized native CLI value differs from raw")
            values.append((o,value))
        return values
    def inspect(namespace):
        found=[json.loads(raw(o)) for o in observations.values() if o["command"][:2]==["docker","inspect"] and o["command"][-1]==namespace and o["returncode"]==0]
        require(found and all(f["Name"].lstrip("/")==namespace and f["State"]["Running"] for f in found),"native container identity/running state missing")
        require(len({(f["Id"],f["State"]["Pid"]) for f in found})==1,"native container identity changed")
        return found[0]
    associations={r["device_id"]:r for r in runtime if r["kind"]=="FRR control namespace association"}
    require(len(associations)==sum(r["kind"]=="FRR control namespace association" for r in runtime),"duplicate native FRR association")
    expected_frr={d["id"] for d in devices.values() if d["role"] in {"transport","firewall","gray-firewall"}}
    require(set(associations)==expected_frr,"native FRR role coverage incomplete")
    frr=[]
    control_names={}
    for device,record in associations.items():
        base=inspect(devices[device]["namespace"])
        entries=[observations[i] for i in record["observation_ids"]]
        inspections=[o for o in entries if o["command"][:2]==["docker","inspect"]]
        require(len(inspections)==1,"native FRR control inspect ambiguous")
        control_name=inspections[0]["command"][-1];control=inspect(control_name)
        require(control["Id"]==record["control_container_id"] and control["HostConfig"]["NetworkMode"]=="container:"+base["Id"],"FRR control does not join declared forwarding container")
        expected=["readlink",f'/proc/{base["State"]["Pid"]}/ns/net',f'/proc/{control["State"]["Pid"]}/ns/net']
        links=[o for o in entries if o["command"]==expected and o["returncode"]==0]
        require(len(links)==1,"native FRR raw PID namespace query missing")
        names=raw(links[0]).splitlines()
        require(len(names)==2 and names[0]==names[1] and re.fullmatch(r"net:\[\d+\]",names[0]) and names==record["network_namespace_identities"],"native FRR namespace identity mismatch")
        control_names[device]={control_name,devices[device]["namespace"]}
        frr.append({"device":device,"forwarding_pid":base["State"]["Pid"],"control_pid":control["State"]["Pid"],"namespace_identity":names[0],"observation_ids":record["observation_ids"]})
    ovs_devices={r["device_id"] for r in runtime if r["kind"].startswith("native-ovs-")}
    require(ovs_devices=={d["id"] for d in devices.values() if d["role"]=="switch"},"native OVS switch coverage differs")
    tables={}
    for record in runtime:
        if record["kind"]=="FRR control namespace association":continue
        values=observed(record)
        device=record["device_id"]
        if record["kind"].startswith("native-frr-"):
            require(device in control_names and all(o["command"][:2]==["docker","exec"] and o["command"][2] in control_names[device] for o,_ in values),"FRR CLI queried wrong namespace")
            suffixes={"native-frr-running":["vtysh","-c","show running-config"],"native-frr-routes":["vtysh","-c","show ip route json"],"native-frr-ospf-neighbors":["vtysh","-c","show ip ospf neighbor json"],"native-frr-ospf-interfaces":["vtysh","-c","show ip ospf interface json"],"native-frr-daemons":["vtysh","-c","show daemons"]}
            require(record["kind"] in suffixes and all(o["command"][3:]==suffixes[record["kind"]] for o,_ in values),"unsupported FRR observation command")
        elif record["kind"].startswith("native-ovs-"):
            require(all(o["command"][:3]==["docker","exec",devices[device]["namespace"]] for o,_ in values),"OVS CLI queried wrong namespace")
            table_names={"native-ovs-bridge":"Bridge","native-ovs-port":"Port","native-ovs-interface":"Interface","native-ovs-controller":"Controller"}
            if record["kind"] in table_names:
                require(all(o["command"][3:5]==["ovs-vsctl","--format=json"] and o["command"][-2:]==["list",table_names[record["kind"]]] for o,_ in values),"OVS table query command mismatch")
            key=(device,record["kind"])
            require(key not in tables,"duplicate OVS table observation")
            tables[key]=record
        else:raise ValueError("unsupported native runtime kind")
    memberships=[];openvswitch_ids=set();switches=[]
    for device in sorted(ovs_devices):
        kinds=["bridge","port","interface","controller","flows","groups","meters"]
        require(all((device,"native-ovs-"+kind) in tables for kind in kinds),"OVS table/flow inventory incomplete")
        bridge,ports,ifaces,controllers=[ovs_rows(tables[(device,"native-ovs-"+kind)]["raw_value"]) for kind in kinds[:4]]
        require(len(bridge)==1 and ports and ifaces and not controllers,"unsupported empty or externally controlled OVS profile")
        arrays=[json.loads(raw(o)) for o in observations.values() if o.get("device_id")==device and o["command"][-5:]==["ip","-j","-d","address","show"] and o["returncode"]==0]
        require(arrays,"native switch raw interfaces absent")
        inventory={i["ifname"]:i for i in arrays[0]}
        referenced_ports=[p for b in bridge.values() for p in uuid_set(b["ports"])]
        require(set(referenced_ports)==set(ports) and len(referenced_ports)==len(set(referenced_ports)),"OVS Bridge/Port coverage incomplete or shared")
        referenced_ifaces=[i for port in ports.values() for i in uuid_set(port["interfaces"])]
        require(set(referenced_ifaces)==set(ifaces) and len(referenced_ifaces)==len(set(referenced_ifaces)),"OVS Port/Interface coverage incomplete or shared")
        require(len({i["name"] for i in ifaces.values()})==len(ifaces) and len({i["ofport"] for i in ifaces.values()})==len(ifaces),"duplicate OVS interface name/ofport")
        for bid,b in bridge.items():
            require(not uuid_set(b["controller"]) and b["datapath_type"] in {"","system"},"unsupported OVS controller/datapath")
            for pid in uuid_set(b["ports"]):
                port=ports[pid];ids=uuid_set(port["interfaces"])
                require(len(ids)==1 and port["bond_mode"]==["set",[]] and port["other_config"]==["map",[]],"unsupported OVS bond/port options")
                iid=ids[0];interface=ifaces[iid];name=interface["name"]
                require(port["name"]==name and name in inventory,"OVS port does not bind raw interface")
                actual=inventory[name]
                require(interface["ifindex"]==actual["ifindex"] and interface["mac_in_use"]==actual["address"] and interface["options"]==["map",[]] and interface["error"]==["set",[]] and isinstance(interface["ofport"],int) and interface["ofport"]>0,"OVS interface identity/options/error mismatch")
                if name==b["name"]:
                    require(interface["type"]=="internal" and actual.get("linkinfo",{}).get("info_kind")=="openvswitch","OVS internal interface mismatch")
                    openvswitch_ids.add(device+":"+name)
                else:
                    require(interface["type"]=="" and actual.get("linkinfo",{}).get("info_kind")=="veth","unsupported OVS patch/tunnel/system interface")
                    memberships.append({"endpoints":[device+":"+name,device+":"+b["name"]],"bridge_uuid":bid,"port_uuid":pid,"interface_uuid":iid})
        system=inventory.get("ovs-system")
        require(system is not None and system.get("linkinfo",{}).get("info_kind")=="openvswitch" and "UP" not in system["flags"] and system["operstate"]=="DOWN" and not system["addr_info"] and not system.get("master") and not system.get("link") and not system.get("link_index"),"OVS system interface unsupported active attachment")
        for o in observations.values():
            if o.get("device_id")==device and o["command"][-7:] in [["ip","-j",f,"route","show","table","all"] for f in ["-4","-6"]]:
                require(o["returncode"]==0 and not any(r.get("dev")=="ovs-system" or any(h.get("dev")=="ovs-system" for h in r.get("nexthops",[])) for r in json.loads(raw(o))),"OVS system interface has raw route")
        require(not any(device+":ovs-system" in l["endpoint_interface_ids"] for l in snapshot["links"]),"OVS system interface has declared attachment")
        openvswitch_ids.add(device+":ovs-system")
        switches.append({"device":device,"bridges":len(bridge),"ports":len(ports),"interfaces":len(ifaces),"observation_ids":[o for k in kinds for o in tables[(device,"native-ovs-"+k)]["observation_ids"]]})
    normalized=[l for l in snapshot["links"] if l["relation"]=="ovs_bridge_membership"]
    require(len(normalized)==len(memberships),"normalized OVS membership count differs")
    for membership in memberships:
        matches=[l for l in normalized if l["endpoint_interface_ids"]==membership["endpoints"] and l.get("ovs_bridge_uuid")==membership["bridge_uuid"] and l.get("ovs_port_uuid")==membership["port_uuid"] and l.get("ovs_interface_uuid")==membership["interface_uuid"]]
        require(len(matches)==1 and matches[0]["status"]=="observed","normalized OVS membership UUID/endpoints differ")
    raw_ovs={d+":"+r["ifname"] for d in ovs_devices for o in observations.values() if o.get("device_id")==d and o["command"][-5:]==["ip","-j","-d","address","show"] for r in json.loads(raw(o)) if r.get("linkinfo",{}).get("info_kind")=="openvswitch"}
    require(raw_ovs==openvswitch_ids,"unmodeled raw OVS internal interface")
    return {"openvswitch_ids":openvswitch_ids,"membership_ids":{l["id"] for l in normalized},"report":{"frr_associations":frr,"ovs_switches":switches,"ovs_memberships":memberships,"scope":"Native CLI/namespace/UUID correspondence. Graph conservatively contracts all listed switch ports; flow correctness and physical separation are not inferred."}}
