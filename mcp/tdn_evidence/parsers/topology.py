"""Validate observed adjacency and calculate candidate firewall-region labels."""
import json
from .snapshot import validate_bundle, EvidenceError, require
from .native import validate_native


def components(count,edges,removed):
    labels=list(range(count))
    def root(x):
        while labels[x]!=x:
            x=labels[x]
        return x
    for a,b in edges:
        if a not in removed and b not in removed:
            labels[root(b)]=root(a)
    return [root(i) for i in range(count)]


def inactive_fallback(record):
    kind=record.get("linkinfo",{}).get("info_kind")
    data=record.get("linkinfo",{}).get("info_data",{})
    if kind not in {"gre","gretap","erspan"}:
        raise EvidenceError("unsupported inactive interface kind")
    if "UP" in record.get("flags",[]) or record.get("operstate")!="DOWN" or record.get("addr_info") or record.get("master") or record.get("link") or record.get("link_index"):
        raise EvidenceError("fallback tunnel is active, addressed or attached")
    if data.get("local") not in {"any","0.0.0.0","::"} or data.get("remote") not in {"any","0.0.0.0","::"}:
        raise EvidenceError("fallback tunnel has configured endpoints")
    return kind


def raw_interface_kind(record,allow_inactive_fallback=False,allow_openvswitch=False):
    if record.get("link_type")=="loopback" or "LOOPBACK" in record.get("flags",[]):
        return "loopback"
    kind=record.get("linkinfo",{}).get("info_kind")
    if allow_inactive_fallback and kind in {"gre","gretap","erspan"}:
        return inactive_fallback(record)
    if allow_openvswitch and kind=="openvswitch":return kind
    if kind not in {"veth","bridge"}:
        raise EvidenceError("unsupported raw interface kind: "+str(kind))
    return kind


def verify_peer_namespace(raw_left,raw_right,left_device,right_device,pids,aliases,peer_maps):
    left_alias=peer_maps[left_device].get(raw_left.get("link_netnsid"))
    right_alias=peer_maps[right_device].get(raw_right.get("link_netnsid"))
    if aliases.get(left_alias)!=pids[right_device] or aliases.get(right_alias)!=pids[left_device]:
        raise EvidenceError("raw reciprocal peer namespace does not match named devices")


def adjacency_projection(rows):
    projected=json.loads(json.dumps(rows))
    for row in projected:
        info=row.get("linkinfo",{})
        if info.get("info_kind")=="bridge":
            info.get("info_data",{}).pop("gc_timer",None)
    return projected


def validated_graph(bundle):
    validation=validate_bundle(bundle)
    snapshot=json.loads((bundle/"snapshot.json").read_text())
    require(all(validation["inventory_complete"][kind] for kind in ["devices","interfaces","links"]),
            "complete observed topology inventory required")
    require(all(row["status"]=="observed" for kind in ["devices","interfaces","links"] for row in snapshot[kind]),
            "complete observed topology records required")
    native=validate_native(bundle,snapshot)
    devices=snapshot["devices"]
    indices={d["id"]:i for i,d in enumerate(devices)}
    interfaces={i["id"]:i for i in snapshot["interfaces"]}
    observation_by_id={o["id"]:o for o in snapshot["observations"]}
    def stdout(observation):
        require(observation["returncode"]==0 and observation["parse_status"]=="parsed",
                "topology raw observation failed or unparsed")
        return json.loads((bundle/observation["raw_path"]).read_text())["stdout"]
    pids={}
    aliases={}
    peer_maps={}
    for device in devices:
        inspect=[o for o in snapshot["observations"] if o.get("command",[])[:2]==["docker","inspect"] and o["command"][-1]==device["namespace"]]
        identities=[json.loads(stdout(o)) for o in inspect if o["returncode"]==0]
        valid={identity["State"]["Pid"] for identity in identities if identity.get("Name","").lstrip("/")==device["namespace"] and identity["State"]["Running"]}
        if len(valid)!=1:
            raise EvidenceError("device namespace PID association is ambiguous")
        pids[device["id"]]=valid.pop()
    if len(set(pids.values()))!=len(pids):
        raise EvidenceError("distinct modeled devices share one namespace PID")
    for obs in snapshot["observations"]:
        command=obs.get("command",[])
        if command[:3]==["ip","netns","attach"] and len(command)==5 and obs["returncode"]==0:
            alias,pid=command[3],int(command[4])
            if alias in aliases and aliases[alias]!=pid:
                raise EvidenceError("namespace alias reassigned")
            aliases[alias]=pid
    inactive_interfaces=[]
    for device,pid in pids.items():
        expected=["nsenter","-t",str(pid),"-n","ip","-j","netns","list-id"]
        matches=[o for o in snapshot["observations"] if o.get("command")==expected and o["returncode"]==0]
        if not matches:
            raise EvidenceError("missing raw peer namespace map")
        maps=[{row["nsid"]:row.get("name") for row in json.loads(stdout(obs))} for obs in matches]
        if any(mapping!=maps[0] for mapping in maps):
            raise EvidenceError("peer namespace map changed between observations")
        peer_maps[device]=maps[0]
    for device in devices:
        observed=[o for o in snapshot["observations"] if o.get("device_id")==device["id"] and o.get("command",[])[-5:]==["ip","-j","-d","address","show"]]
        if not observed or any(o["returncode"]!=0 for o in observed):
            raise EvidenceError("missing/failed complete interface observation")
        require(all(o["command"]==["docker","exec",device["namespace"],"ip","-j","-d","address","show"]
                    for o in observed), "complete interface command target mismatch")
        inventories=[json.loads(stdout(o)) for o in observed]
        if any(adjacency_projection(rows)!=adjacency_projection(inventories[0]) for rows in inventories):
            raise EvidenceError("raw interface inventory changed between observations")
        raw_interfaces=inventories[0]
        names={r["ifname"] for r in raw_interfaces}
        for raw_interface in raw_interfaces:
            identity=device["id"]+":"+raw_interface["ifname"]
            if identity not in interfaces or interfaces[identity]["link_kind"]!=raw_interface_kind(raw_interface,allow_inactive_fallback=True,allow_openvswitch=identity in native["openvswitch_ids"]):
                raise EvidenceError("normalized interface kind differs from raw observation")
            if raw_interface.get("linkinfo",{}).get("info_kind") in {"gre","gretap","erspan"}:
                routes=[r for r in snapshot["routes"] if r["device_id"]==device["id"] and r.get("output_interface")==raw_interface["ifname"]]
                attachments=[l for l in snapshot["links"] if identity in l["endpoint_interface_ids"]]
                if routes or attachments:
                    raise EvidenceError("inactive fallback tunnel has a route or declared link")
                for family in ["-4","-6"]:
                    route_obs=[o for o in snapshot["observations"] if o.get("device_id")==device["id"] and o.get("command",[])[-7:]==["ip","-j",family,"route","show","table","all"]]
                    if not route_obs or any(o["returncode"]!=0 for o in route_obs):
                        raise EvidenceError("inactive fallback requires complete raw route inventories")
                    for route_observation in route_obs:
                        require(route_observation["command"]==["docker","exec",device["namespace"],
                                "ip","-j",family,"route","show","table","all"],
                                "fallback route command target mismatch")
                        raw_routes=json.loads(stdout(route_observation))
                        if any(r.get("dev")==raw_interface["ifname"] or any(hop.get("dev")==raw_interface["ifname"] for hop in r.get("nexthops",[])) for r in raw_routes):
                            raise EvidenceError("inactive fallback has a raw route reference")
                bridge_obs=[o for o in snapshot["observations"] if o.get("device_id")==device["id"] and o.get("command",[])[-4:]==["bridge","-j","link","show"]]
                if not bridge_obs or any(o["returncode"]!=0 for o in bridge_obs):
                    raise EvidenceError("inactive fallback requires raw bridge inventory")
                require(all(o["command"]==["docker","exec",device["namespace"],"bridge","-j","link","show"]
                            for o in bridge_obs), "bridge command target mismatch")
                if any(row.get("ifname")==raw_interface["ifname"] for o in bridge_obs for row in json.loads(stdout(o))):
                    raise EvidenceError("inactive fallback has raw bridge membership")
                inactive_interfaces.append({"interface_id":identity,"kind":raw_interface["linkinfo"]["info_kind"],"observation_ids":[o["id"] for o in observed],"admin_up":False,"addresses":0,"routes":0,"attachments":0,"configured_local_remote":False,"abstraction":"administratively down, unaddressed, unconfigured fallback contributes no live connectivity at collected states"})
        normalized={i["name"] for i in snapshot["interfaces"] if i["device_id"]==device["id"]}
        if names!=normalized:
            raise EvidenceError("normalized interface inventory does not equal raw observation")
    veth_ids={i["id"] for i in snapshot["interfaces"] if i["link_kind"]=="veth"}
    veth_endpoints=[endpoint for link in snapshot["links"] if link["relation"]=="veth" for endpoint in link["endpoint_interface_ids"]]
    if set(veth_endpoints)!=veth_ids or len(veth_endpoints)!=len(set(veth_endpoints)):
        raise EvidenceError("veth adjacency does not cover every observed veth interface exactly once")
    edges=set()
    gray_edges=set()
    inside=[]
    outside=[]
    for link in snapshot["links"]:
        if link["status"]!="observed":
            raise EvidenceError("all-path model needs observed adjacency")
        left,right=[interfaces[x] for x in link["endpoint_interface_ids"]]
        if link["relation"]=="veth":
            raw_arrays=[]
            for oid in link["observation_ids"]:
                obs=observation_by_id[oid]
                if obs.get("device_id") in {left["device_id"],right["device_id"]}:
                    peer_device=next(d for d in devices if d["id"]==obs["device_id"])
                    require(obs["command"]==["docker","exec",peer_device["namespace"],
                            "ip","-j","-d","address","show"], "link interface observation target mismatch")
                    array=json.loads(stdout(obs))
                    raw_arrays.append((obs["device_id"],array))
            def raw_interface(interface):
                found=[r for device,rows in raw_arrays if device==interface["device_id"] for r in rows if r.get("ifname")==interface["name"]]
                if len(found)!=1:
                    raise EvidenceError("raw link interface identity ambiguous")
                return found[0]
            a,b=raw_interface(left),raw_interface(right)
            verify_peer_namespace(a,b,left["device_id"],right["device_id"],pids,aliases,peer_maps)
            if a.get("link_index")!=b.get("ifindex") or b.get("link_index")!=a.get("ifindex"):
                raise EvidenceError("reciprocal raw ifindex mismatch")
        elif link["relation"]=="ovs_bridge_membership":
            if link["id"] not in native["membership_ids"] or left["device_id"]!=right["device_id"]:
                raise EvidenceError("unverified OVS membership")
        elif link["relation"]=="bridge_attachment":
            rows=[r for oid in link["observation_ids"] for r in json.loads(stdout(observation_by_id[oid]))]
            if not any(r.get("ifname")==left["name"] and r.get("master")==right["name"] for r in rows):
                raise EvidenceError("raw bridge attachment mismatch")
        else:
            raise EvidenceError("unsupported topology relation")
        a,b=indices[left["device_id"]],indices[right["device_id"]]
        if a!=b:
            edges.update({(a,b),(b,a)})
            if left["zone"]==right["zone"]=="gray":
                gray_edges.update({(a,b),(b,a)})
        for first,second in ((left,right),(right,left)):
            a,b=indices[first["device_id"]],indices[second["device_id"]]
            if devices[a]["role"]=="outer" and devices[b]["role"]=="firewall" and first["name"]=="black" and second["name"]=="inside":
                inside.append((a,b))
            if devices[a]["role"]=="firewall" and devices[b]["role"]=="transport" and first["name"]=="outside":
                outside.append((a,b))
    roles={role:[i for i,d in enumerate(devices) if d["role"]==role] for role in {d["role"] for d in devices}}
    outer=roles.get("outer",[])
    firewall=roles.get("firewall",[])
    black=roles.get("transport",[])
    gray_fw=roles.get("gray-firewall",[])
    inner=roles.get("inner",[])
    outer_sides=components(len(devices),edges,set(firewall))
    gray_sides=components(len(devices),gray_edges,set(gray_fw))
    return {"validation":validation,"native_runtime":native["report"],"inactive_interfaces":inactive_interfaces,"snapshot":snapshot,"devices":devices,"indices":indices,"interfaces":interfaces,"edges":edges,"gray_edges":gray_edges,"inside":inside,"outside":outside,"roles":roles,"outer":outer,"firewall":firewall,"black":black,"gray_fw":gray_fw,"inner":inner,"outer_sides":outer_sides,"gray_sides":gray_sides}
