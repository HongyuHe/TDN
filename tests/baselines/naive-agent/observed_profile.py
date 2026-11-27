"""Add observed virtual links, preserving independent administrative zone assignments."""

from collections import defaultdict
from copy import deepcopy
from ipaddress import ip_interface


def capture_topology(topology, interfaces, zone_assignments=None):
    result = deepcopy(topology)
    devices = {d["id"]: d for d in result["devices"]}
    if set(devices) != set(interfaces) or len(devices) != len(result["devices"]):
        raise ValueError("Observed device inventory does not match the declared devices")
    declared = {(d["id"], p["name"]): p for d in devices.values() for p in d["interfaces"]}
    zones = {k: p["zone"] for k, p in declared.items()}
    for key, zone in (zone_assignments or {}).items():
        if zone not in {"red", "gray", "black", "management"} or zones.get(key, zone) != zone:
            raise ValueError(f"Conflicting or invalid zone assignment for {key}")
        zones[key] = zone
    subnets = defaultdict(set)
    for port in declared.values():
        if port.get("address"):
            subnets[ip_interface(port["address"]).network].add(port["zone"])

    def endpoint(item):
        return item["device"], item["interface"]

    peers = {}
    for link in result["links"]:
        left, right = endpoint(link["a"]), endpoint(link["b"])
        if left in peers or right in peers or left == right:
            raise ValueError("Nonunique declared link endpoint")
        peers[left], peers[right] = right, left

    ports = {}
    by_index = defaultdict(list)
    for device, rows in interfaces.items():
        for port in rows:
            key = device, port["ifname"]
            kind = port.get("linkinfo", {}).get("info_kind")
            if kind == "dummy" and key not in declared:
                devices[device]["interfaces"].append({"name": key[1], "zone": "local", "mtu": port["mtu"]})
            if kind != "veth":
                continue
            if key in ports:
                raise ValueError(f"Duplicate observed endpoint {key}")
            ports[key] = port
            by_index[port["ifindex"], port["link_index"]].append(key)

    changed = set()
    additions = []
    for key, port in sorted(ports.items()):
        candidates = [p for p in by_index[port["link_index"], port["ifindex"]] if p[0] != key[0]]
        if not candidates and key in declared and "LOWER_UP" not in port.get("flags", []):
            continue
        if len(candidates) != 1:
            raise ValueError(f"Missing or ambiguous reciprocal endpoint for {key}")
        other, = candidates
        if key >= other or peers.get(key) == other:
            continue
        ends = (key, other)
        memberships = {zones[k] for k in ends if k in zones}
        for k in ends:
            declared_zones = {p["zone"] for p in devices[k[0]]["interfaces"] if (k[0], p["name"]) in declared}
            if len(declared_zones) == 1:
                memberships.update(declared_zones)
            for address in ports[k].get("addr_info", []):
                if address.get("family") in {"inet", "inet6"}:
                    ip = ip_interface(f"{address['local']}/{address['prefixlen']}").ip
                    matching = [s for s in subnets if ip.version == s.version and ip in s]
                    if matching:
                        best = max(s.prefixlen for s in matching)
                        for s in matching:
                            if s.prefixlen == best:
                                memberships.update(subnets[s])
        assigned = next(iter(memberships)) if len(memberships) == 1 else "unknown"
        for k in ends:
            if k in declared:
                changed.add(k)
                continue
            record = {"name": k[1], "mtu": ports[k]["mtu"], "zone": zones.get(k, assigned)}
            ipv4 = [a for a in ports[k].get("addr_info", []) if a["family"] == "inet"]
            if ipv4:
                record["address"] = f"{ipv4[0]['local']}/{ipv4[0]['prefixlen']}"
            devices[k[0]]["interfaces"].append(record)
        additions.append(dict(zip(("a", "b"), ({"device": k[0], "interface": k[1]} for k in ends))))
    result["links"] = [link for link in result["links"] if not any(endpoint(p) in changed for p in link.values())]
    result["links"].extend(additions)
    return result
