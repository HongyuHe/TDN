import argparse
import hashlib
import json
from pathlib import Path
from import_snapshot import identifier, quoted, lean_list
from validate_evidence import validate_bundle, EvidenceError, require
from source_paths import verified_source
from native_runtime import validate_native
from import_domains import validate_declaration,bind_native_declaration


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


def analyze(bundle,output,report_path,scenario_key="scenario",scenario_declaration=None,namespace=None):
    graph=validated_graph(bundle)
    validation=graph["validation"]
    snapshot=json.loads((bundle/"snapshot.json").read_text())
    manifest=json.loads((bundle/"manifest.json").read_text())
    scenario_path=Path(scenario_declaration) if scenario_declaration else verified_source(scenario_key)
    scenario_digest=hashlib.sha256(scenario_path.read_bytes()).hexdigest()
    data=json.loads(scenario_path.read_text())
    if scenario_declaration:
        require(data["schema_version"]=="csfc-topology-scenario/v1", "unsupported topology scenario declaration")
        scenario=next(row for row in data["configurations"] if row["configuration_id"]==manifest["configuration_id"])
        require(scenario["snapshot_id"]==snapshot["snapshot_id"] and
                scenario["snapshot_manifest_sha256"]==validation["source_manifest_sha256"] and
                scenario["spec_sha256"]==hashlib.sha256((bundle/"spec.json").read_bytes()).hexdigest()==
                manifest["configuration_hashes"]["spec"],
                "current topology declaration snapshot/spec binding differs")
        require(scenario["untrusted_black"] is True and scenario["gray_firewall_required"] is True,
                "selected topology scenario applicability differs")
    elif scenario_key=="native_declaration":
        config=next(c for c in validate_declaration(data) if c["configuration_id"]==manifest["configuration_id"])
        bind_native_declaration(config,bundle,manifest,snapshot)
        scenario={**config["transport_scenario"],"configuration_id":config["configuration_id"],"case_ids":config["source_case_ids"]}
    else:scenario=data["baseline"]
    if scenario["configuration_id"]!=manifest["configuration_id"] or scenario["transport_kind"]!="emulated_public_internet" or scenario["status"]!="declared" or not set(scenario["case_ids"])<=set(manifest["source_case_ids"]):
        raise EvidenceError("scenario declaration does not bind this configuration and source cases")
    specification=json.loads((bundle/"spec.json").read_text())
    intended={device["id"]:device for device in specification["devices"]}
    require(set(intended)=={device["id"] for device in snapshot["devices"]},
            "topology role specification inventory differs")
    for device in snapshot["devices"]:
        require(device["role"]==intended[device["id"]]["role"],
                "topology role differs from declared specification")
        declared_interfaces={row["name"]:row for row in intended[device["id"]]["interfaces"]}
        for interface in snapshot["interfaces"]:
            if interface["device_id"]!=device["id"]:
                continue
            if interface["link_kind"]=="veth":
                require(interface["name"] in declared_interfaces and
                        interface["zone"]==declared_interfaces[interface["name"]]["zone"],
                        "topology interface zone differs from declared specification")

    snapshot=graph["snapshot"]
    devices=graph["devices"]
    indices=graph["indices"]
    interfaces=graph["interfaces"]
    edges=graph["edges"]
    gray_edges=graph["gray_edges"]
    inside=graph["inside"]
    outside=graph["outside"]
    roles=graph["roles"]
    outer=graph["outer"]
    firewall=graph["firewall"]
    black=[indices[x] for x in scenario["transport_device_ids"]] if scenario_key=="native_declaration" or scenario_declaration else graph["black"]
    if not all(devices[x]["role"]=="transport" and any(i["device_id"]==devices[x]["id"] and i["zone"]=="black" for i in interfaces.values()) for x in black):raise EvidenceError("Black transport declaration lacks matching role and zone")
    gray_fw=graph["gray_fw"]
    inner=graph["inner"]
    outer_sides=graph["outer_sides"]
    gray_sides=graph["gray_sides"]
    def stdout(observation):
        require(observation["returncode"]==0 and observation["parse_status"]=="parsed",
                "topology raw observation failed or unparsed")
        return json.loads((bundle/observation["raw_path"]).read_text())["stdout"]
    if not outer or not black or not all(any((o,f) in inside and (f,b) in outside for f in firewall for b in black) for o in outer):
        raise EvidenceError("missing oriented Outer-Firewall-Black placement")
    if not all(outer_sides[o]!=outer_sides[b] for o in outer for b in black):
        raise EvidenceError("Outer firewall-free path found")
    if not all(gray_sides[a]!=gray_sides[b] for a in inner for b in inner if devices[a]["security_level_id"]!=devices[b]["security_level_id"]):
        raise EvidenceError("cross-level Gray firewall-free path found")
    count=len(devices)
    ns=identifier(snapshot["snapshot_id"])+"_topology" if namespace is None else namespace
    require(identifier(ns)==ns, "invalid topology namespace")
    lines=["import TDN.Targets.Topology",f"namespace TDN.Imported.{ns}","set_option maxRecDepth 100000", "set_option maxHeartbeats 0",f"abbrev Node := Fin {count}"]
    def nodes(name,values):
        lines.append("def "+name+" : List Node := "+lean_list([str(v) for v in values]))
    def pairs(name,values):
        lines.append("def "+name+" : List (Node × Node) := "+lean_list(["("+str(a)+", "+str(b)+")" for a,b in sorted(values)]))
    pairs("edges",edges);pairs("grayEdges",gray_edges);pairs("insideAttachments",inside);pairs("outsideAttachments",outside)
    for name,values in (("outerNodes",outer),("firewallNodes",firewall),("blackNodes",black),("grayFirewallNodes",gray_fw),("innerNodes",inner)):
        nodes(name,values)
    levels=sorted({d["security_level_id"] for d in devices if d["security_level_id"] is not None})
    level_ids=[0 if d["security_level_id"] is None else levels.index(d["security_level_id"])+1 for d in devices]
    for name,values in (("outerSide",outer_sides),("graySide",gray_sides),("level",level_ids)):
        lines.append("def "+name+" (node : Node) : Nat := "+lean_list([str(v) for v in values])+"[node.val]!")
    lines += [
        "def edge (a b : Node) : Prop := (a,b) ∈ edges",
        "def grayEdge (a b : Node) : Prop := (a,b) ∈ grayEdges",
        "def firewall (a : Node) : Prop := a ∈ firewallNodes",
        "def grayFirewall (a : Node) : Prop := a ∈ grayFirewallNodes",
        "def untrustedBlack : Bool := true",
        "def publicInternet : Bool := true",
        "def grayRequired : Bool := true",
        "def grayConnection : Node → Node → Prop := Relation.ReflTransGen grayEdge",
        "def outer (a : Node) : Prop := a ∈ outerNodes",
        "def black (a : Node) : Prop := a ∈ blackNodes",
        "def inner (a : Node) : Prop := a ∈ innerNodes",
        "def insideAttachment (a b : Node) : Prop := (a,b) ∈ insideAttachments",
        "def outsideAttachment (a b : Node) : Prop := (a,b) ∈ outsideAttachments",
        "def externalConnection (_ _ : Node) : Prop := False",
        "lemma nonempty_outer_inventory : outerNodes ≠ [] := by decide",
        "lemma nonempty_black_inventory : blackNodes ≠ [] := by decide",
        "lemma outer_local_cut : ∀ a b, edge a b → ¬ firewall a → ¬ firewall b → outerSide a = outerSide b := by unfold edge edges firewall firewallNodes outerSide; decide",
        "lemma outer_start_clear : ∀ a, a ∈ outerNodes → ¬ firewall a := by unfold outerNodes firewall firewallNodes; decide",
        "lemma outer_sides_differ : ∀ a b, a ∈ outerNodes → b ∈ blackNodes → outerSide a ≠ outerSide b := by unfold outerNodes blackNodes outerSide; decide",
        "theorem all_outer_paths_cross_firewall (a b : Node) (ha : a ∈ outerNodes) (hb : b ∈ blackNodes) : ¬ Relation.ReflTransGen (Paths.Avoiding edge firewall) a b := Paths.no_firewall_free_crossing edge firewall outerSide outer_local_cut (outer_start_clear a ha) (outer_sides_differ a b ha hb)",
        "lemma inside_outside_placement : ∀ o, o ∈ outerNodes → ∃ f b, f ∈ firewallNodes ∧ b ∈ blackNodes ∧ (o,f) ∈ insideAttachments ∧ (f,b) ∈ outsideAttachments := by unfold outerNodes firewallNodes blackNodes insideAttachments outsideAttachments; decide",
        "theorem snapshot_public_internet_RG034 : Targets.msc_outer_firewall_placement untrustedBlack publicInternet grayRequired edge grayConnection outer firewall black grayFirewall inner insideAttachment outsideAttachment externalConnection := Targets.outer_firewall_placement_from_local_checks outerSide (fun _ => rfl) (by intro a b h; apply Relation.ReflTransGen.single; have checked : ∀ a b : Node, (a,b) ∈ insideAttachments ∨ (a,b) ∈ outsideAttachments ∨ False → edge a b := (by unfold insideAttachments outsideAttachments edge edges; decide); exact checked a b h) inside_outside_placement gray_internal_connected (fun _ => outer_local_cut) (fun _ => outer_start_clear) (fun _ => outer_sides_differ)",
        "lemma gray_local_cut : ∀ a b, grayEdge a b → ¬ grayFirewall a → ¬ grayFirewall b → graySide a = graySide b := by unfold grayEdge grayEdges grayFirewall grayFirewallNodes graySide; decide",
        "lemma inner_start_clear : ∀ a, a ∈ innerNodes → ¬ grayFirewall a := by unfold innerNodes grayFirewall grayFirewallNodes; decide",
        "lemma gray_sides_differ : ∀ a b, a ∈ innerNodes → b ∈ innerNodes → level a ≠ level b → graySide a ≠ graySide b := by unfold innerNodes level graySide; decide",
        "theorem cross_level_gray_paths_cross_firewall (a b : Node) (ha : a ∈ innerNodes) (hb : b ∈ innerNodes) (different : level a ≠ level b) : ¬ Relation.ReflTransGen (Paths.Avoiding grayEdge grayFirewall) a b := Paths.no_firewall_free_crossing grayEdge grayFirewall graySide gray_local_cut (inner_start_clear a ha) (gray_sides_differ a b ha hb different)",
    ]
    connection_proofs=[]
    connection_paths=[]
    for origin in outer:
        queue=[[origin]]
        visited={origin}
        found=None
        while queue and found is None:
            path=queue.pop(0)
            if path[-1] in gray_fw:
                found=path
                break
            for left,right in sorted(gray_edges):
                if left==path[-1] and right not in visited:
                    visited.add(right)
                    queue.append(path+[right])
        if found is None:raise EvidenceError("Outer lacks Gray-side path to Gray Firewall")
        connection_paths.append(found)
        proof="Relation.ReflTransGen.refl"
        for left,right in zip(found,found[1:]):
            proof="("+proof+").tail (by unfold grayEdge grayEdges; decide : grayEdge "+str(left)+" "+str(right)+")"
        connection_proofs.append("  · exact ⟨"+str(found[-1])+", by unfold grayFirewall grayFirewallNodes; decide, "+proof+"⟩")
    connected="lemma gray_internal_connected (o : Node) (ho : o ∈ outerNodes) : ∃ f, grayFirewall f ∧ Relation.ReflTransGen grayEdge o f := by\n  simp only [outerNodes, List.mem_cons, List.not_mem_nil, or_false] at ho\n  rcases ho with "+" | ".join(["rfl"]*len(outer))+"\n"+"\n".join(connection_proofs)
    index=next(i for i,line in enumerate(lines) if line.startswith("theorem snapshot_public_internet_RG034"))
    lines.insert(index,connected)
    ipv6=[]
    for device in devices:
        if device["role"] not in {"inner","outer"}:
            continue
        observations=[o for o in snapshot["observations"] if o.get("device_id")==device["id"] and "net.ipv6.conf.all.disable_ipv6" in o.get("command",[])]
        if len(observations)!=1:
            raise EvidenceError("missing/ambiguous IPv6 disablement observation")
        values={}
        for line in stdout(observations[0]).splitlines():
            key,value=line.split(" = ")
            values[key]=int(value)
        inactive_ids={i["interface_id"] for i in graph["inactive_interfaces"]}
        names=["all","default"]+[i["name"] for i in snapshot["interfaces"] if i["device_id"]==device["id"] and i["id"] not in inactive_ids]
        for name in names:
            if values.get("net.ipv6.conf."+name+".disable_ipv6")!=1 or values.get("net.ipv6.conf."+name+".forwarding")!=0:
                raise EvidenceError("IPv6 path remains enabled")
        addresses=[a for i in snapshot["interfaces"] if i["device_id"]==device["id"] for a in i["addresses"] if a.get("family")=="inet6"]
        routes=[r for r in snapshot["routes"] if r["device_id"]==device["id"] and r["family"]==6]
        if addresses or routes:
            raise EvidenceError("IPv6 addresses/routes remain")
        ipv6.append({"device":device["id"],"observation_id":observations[0]["id"],"values":values,"addresses":0,"routes":0})
    lines.append("def ipv6Disablement : List (Nat × Nat) := "+lean_list(["("+str(item["values"][key])+", "+str(item["values"][key.replace(".disable_ipv6",".forwarding")])+")" for item in ipv6 for key in item["values"] if key.endswith(".disable_ipv6")]))
    lines.append("theorem all_recorded_ipv6_interfaces_disabled : ∀ setting ∈ ipv6Disablement, setting.1 = 1 ∧ setting.2 = 0 := by unfold ipv6Disablement; decide")
    lines.append("end TDN.Imported."+ns)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text("\n\n".join(lines)+"\n")
    report={"gray_connection_paths":connection_paths,"native_runtime":graph["native_runtime"],"scenario_declaration_path":str(scenario_path),"scenario_declaration_sha256":scenario_digest,"scenario_declaration":scenario,"snapshot_id":snapshot["snapshot_id"],"manifest_sha256":validation["source_manifest_sha256"],"snapshot_sha256":validation["source_snapshot_sha256"],"device_order":[d["id"] for d in devices],"observed_links":len(snapshot["links"]),"directed_device_edges":len(edges),"gray_directed_edges":len(gray_edges),"inactive_interfaces":graph["inactive_interfaces"],"outer_topology_target":"TDN.Imported."+ns+".snapshot_public_internet_RG034","gray_path_clause":"TDN.Imported."+ns+".cross_level_gray_paths_cross_firewall","ipv6_disablement":ipv6,"assumptions":["Raw observation truth and collector completeness","Declared device roles, untrusted Public-Internet representative case and required Gray Firewalls; The separately hashed scenario declaration binds the selected current snapshot and source cases","Device contraction overapproximates internal physical connectivity","Known GRE-family fallback interfaces contribute no live connectivity only after explicit admin-down, no-address, no-route, no-attachment and unconfigured-endpoint checks; Linux down-interface correspondence is an assumption","Snapshot interval only; no physical appliance independence or future invariant"]}
    report_path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"links":len(snapshot["links"]),"outer_placement":True,"gray_cut":True,"ipv6_disabled_devices":len(ipv6)}))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("bundle",type=Path)
    parser.add_argument("--lean-output",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    parser.add_argument("--scenario-key",default="scenario")
    parser.add_argument("--scenario-declaration",type=Path)
    parser.add_argument("--namespace")
    args=parser.parse_args()
    analyze(args.bundle,args.lean_output,args.report,args.scenario_key,args.scenario_declaration,args.namespace)
