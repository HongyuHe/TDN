"""Attach the observed endpoints of an extra benchmark Ethernet link to the capture inventory."""

from copy import deepcopy


def capture_topology(topology, interfaces):
    result = deepcopy(topology)
    devices = {d["id"]: d for d in result["devices"]}
    extra = []
    for name, rows in interfaces.items():
        declared = {p["name"] for p in devices[name]["interfaces"]}
        for p in rows:
            if p["ifname"] in declared:
                continue
            kind = p.get("linkinfo", {}).get("info_kind")
            if kind == "dummy":
                devices[name]["interfaces"].append(
                    {"name": p["ifname"], "zone": "local", "mtu": p["mtu"]}
                )
            elif kind == "veth":
                extra.append((name, p))
    if not extra:
        return result
    if len(extra) != 2:
        raise ValueError("Additional link needs exactly two observed endpoints")
    (a, pa), (b, pb) = extra
    if (
        a == b
        or pa["ifname"] != "lan2"
        or pb["ifname"] != "lan2"
        or pa["link_index"] != pb["ifindex"]
        or pb["link_index"] != pa["ifindex"]
    ):
        raise ValueError("Unexpected link outside the registered benchmark profiles")
    roles = {devices[a]["role"], devices[b]["role"]}
    if roles == {"inner"}:
        zone = "gray"
    elif roles == {"host", "inner"}:
        zone = "red"
    elif roles == {"outer", "transport"} and any(n.endswith("_BLACK") for n in (a, b)):
        zone = "black"
    else:
        raise ValueError("Unknown zone on the additional link")
    for name, p in extra:
        entry = {"name": p["ifname"], "zone": zone, "mtu": p["mtu"]}
        addresses = [x for x in p["addr_info"] if x["family"] == "inet"]
        if addresses:
            (ip,) = addresses
            entry["address"] = f"{ip['local']}/{ip['prefixlen']}"
        devices[name]["interfaces"].append(entry)
    result["links"].append(
        {
            "a": {"device": a, "interface": pa["ifname"]},
            "b": {"device": b, "interface": pb["ifname"]},
        }
    )
    return result
