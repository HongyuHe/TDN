"""Load the three registered Twinet topologies or regenerate them from net-05."""

from collections import Counter
from pathlib import Path
import argparse
import json
import sys


PROFILE_DIR = Path(__file__).resolve().parent.parent / "profiles"
NATIVE_BASE = PROFILE_DIR / "native" / "net-05.json"
NETWORKS = {
    "Base": ("XB", 2, 1, "clnode176.clemson.cloudlab.us"),
    "10xLevels": ("XL", 20, 1, "clnode159.clemson.cloudlab.us"),
    "10xDevices": ("XD", 2, 10, "clnode163.clemson.cloudlab.us"),
}
STATE_ROOT = "/var/tmp/tdn-scale-study"


def generate_topology(name):
    prefix, levels, branches, _ = NETWORKS[name]
    original = json.loads(NATIVE_BASE.read_text())
    spec = {
        k: v for k, v in original["topology"].items() if k not in ("devices", "links")
    }
    spec.update(name="baseline-" + prefix.lower(), devices=[], links=[])
    devices = {}

    def add(suffix, role, site="", level=""):
        device = {"id": prefix + "_" + suffix, "role": role, "interfaces": []}
        if site:
            device["site"] = site
        if level:
            device["level"] = level
        spec["devices"].append(device)
        devices[suffix] = device
        return device

    def connect(a, ai, ip_a, b, bi, ip_b, zone, mtu):
        endpoints = []
        for suffix, iface, address in ((a, ai, ip_a), (b, bi, ip_b)):
            node = devices[suffix]
            port = {"name": iface, "zone": zone, "mtu": mtu}
            if address:
                port["address"] = address
            if node["role"] == "switch":
                port["bridge"] = True
            node["interfaces"].append(port)
            endpoints.append({"device": node["id"], "interface": iface})
        spec["links"].append(dict(zip(("a", "b"), endpoints)))

    def route(node, destination, via):
        devices[node].setdefault("routes", []).append(
            {"prefix": destination, "via": via}
        )

    def management(site, suffix, octet, targets):
        switch = "M_" + site + suffix
        aw = "AW_" + site + suffix
        add(switch, "switch", site, "management")
        add(aw, "admin", site, "management")
        addr = f"172.30.{octet}"
        connect(aw, "mgmt", addr + ".10/24", switch, "admin", "", "management", 1400)
        for index, target in enumerate(targets):
            devices[target]["admin"] = addr + ".10"
            connect(
                target,
                "mgmt",
                f"{addr}.{20 + index}/24",
                switch,
                f"d{index}",
                "",
                "management",
                1400,
            )

    add("BLACK", "transport")
    for site, other, near, far in (("A", "B", 1, 2), ("B", "A", 2, 1)):
        for branch in range(1, branches + 1):
            suffix = site if branch == 1 else site + str(branch)
            gf, gr = "GF_" + suffix, "GR_" + suffix
            o, fw = f"O_{site}{branch}", f"OF_{site}{branch}"
            add(gf, "gray-firewall", site)["boundary_flows"] = []
            add(gr, "transport", site)
            outer = add(o, "outer", site, "shared")
            add(fw, "firewall", site)
            wan = f"172.20.{near * 10 + branch}"
            remote_wan = f"172.20.{far * 10 + branch}"
            black = f"172.21.{near * 10 + branch}"
            connect(
                o, "black", wan + ".1/30", fw, "inside", wan + ".2/30", "black", 1500
            )
            connect(
                fw,
                "outside",
                black + ".1/30",
                "BLACK",
                f"p{near}_{branch}",
                black + ".2/30",
                "black",
                1500,
            )
            outer["tunnel"] = {
                "peer": f"{prefix}_O_{other}{branch}",
                "local": wan + ".1",
                "remote": remote_wan + ".1",
                "local_ts": f"10.{100 * near}.0.0/16",
                "remote_ts": f"10.{100 * far}.0.0/16",
                "trust": "outer",
                "reqid": 200 + branch,
                "inside": "gray",
                "outside": "black",
                "flows": [],
            }
            route(o, f"10.{100 * far}.0.0/16", wan + ".2")
            route(o, remote_wan + ".1/32", wan + ".2")
            for level in range(1, levels + 1):
                k = (branch - 1) * levels + level
                label = "S" + str(level)
                red, inner, switch = (f"{r}_{site}{k}" for r in ("R", "I", "G"))
                add(red, "host", site, label)["network"] = f"red-{k}"
                gateway = add(inner, "inner", site, label)
                gateway["network"] = f"red-{k}"
                add(switch, "switch", site, label)
                local, remote = f"10.{near}.{k}", f"10.{far}.{k}"
                gray, remote_gray = f"10.{100 * near}.{k}", f"10.{100 * far}.{k}"
                outer_lan, router_lan = (
                    f"10.{100 * near + 10}.{k}",
                    f"10.{100 * near + 20}.{k}",
                )
                iface = "gray" if level == 1 else f"gray{level}"
                connect(
                    red,
                    "red",
                    local + ".10/24",
                    inner,
                    "red",
                    local + ".1/24",
                    "red",
                    1320,
                )
                connect(
                    inner,
                    "gray",
                    gray + ".2/24",
                    gf,
                    f"s{level}",
                    gray + ".254/24",
                    "gray",
                    1400,
                )
                connect(
                    gf,
                    f"g{level}",
                    router_lan + ".254/24",
                    gr,
                    f"g{level}",
                    router_lan + ".1/24",
                    "gray",
                    1400,
                )
                connect(
                    gr,
                    f"o{level}",
                    outer_lan + ".254/24",
                    switch,
                    "filter",
                    "",
                    "gray",
                    1400,
                )
                connect(
                    o, iface, outer_lan + ".1/24", switch, "outer", "", "gray", 1400
                )
                gateway["tunnel"] = {
                    "peer": f"{prefix}_I_{other}{k}",
                    "local": gray + ".2",
                    "remote": remote_gray + ".2",
                    "local_ts": local + ".0/24",
                    "remote_ts": remote + ".0/24",
                    "trust": f"inner-s{level}",
                    "reqid": 100 + k,
                    "inside": "red",
                    "outside": "gray",
                }
                route(red, "0.0.0.0/0", local + ".1")
                route(inner, remote + ".0/24", gray + ".254")
                route(inner, remote_gray + ".2/32", gray + ".254")
                for j in range(1, levels + 1):
                    if j != level:
                        route(
                            inner,
                            f"10.{100 * near}.{(branch - 1) * levels + j}.0/24",
                            gray + ".254",
                        )
                route(gf, remote_gray + ".2/32", router_lan + ".1")
                route(gr, gray + ".2/32", router_lan + ".254")
                route(gr, remote_gray + ".2/32", outer_lan + ".1")
                route(o, gray + ".2/32", outer_lan + ".254")
                outer["tunnel"]["flows"].append(
                    {
                        "inside": iface,
                        "local": gray + ".2/32",
                        "remote": remote_gray + ".2/32",
                    }
                )
                for incoming, outgoing, source, destination in (
                    (f"s{level}", f"g{level}", gray, remote_gray),
                    (f"g{level}", f"s{level}", remote_gray, gray),
                ):
                    devices[gf]["boundary_flows"].append(
                        {
                            "ingress": incoming,
                            "egress": outgoing,
                            "source": source + ".2/32",
                            "destination": destination + ".2/32",
                        }
                    )
                octet = near * 10 + k if k <= 2 else 30 * near + k
                management(site, str(k), octet, [inner])
            gray_id = "99" if branch == 1 else f"99_{branch}"
            management(site, gray_id, 99 + near * 10 + branch - 1, [gf, o, fw])
    return spec


def profile(name):
    _, _, _, host = NETWORKS[name]
    original = json.loads(NATIVE_BASE.read_text())
    spec_path = PROFILE_DIR / "scale" / f"{name}.json"
    return {
        "network": name,
        "worker": "hy@" + host,
        "deployment_directory": f"{STATE_ROOT}/{name}/state",
        "black_transport_interpretation": original["black_transport_interpretation"],
        "topology": json.loads(spec_path.read_text()),
    }


def inventory(name):
    spec = profile(name)["topology"]
    return {
        "devices": len(spec["devices"]),
        "links": len(spec["links"]),
        "roles": dict(Counter(d["role"] for d in spec["devices"])),
        "levels": sorted({d["level"] for d in spec["devices"] if d["role"] == "inner"}),
    }


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("name", choices=NETWORKS)
    mode = cli.add_mutually_exclusive_group()
    mode.add_argument(
        "--topology", action="store_true", help="regenerate the Twinet topology and print its JSON"
    )
    sys.path.insert(0, str(PROFILE_DIR.parent))
    from scale.design import CONTROLS, control_topology
    mode.add_argument("--control-topology", choices=CONTROLS, help="print a healthy topology for the registered study")
    args = cli.parse_args()
    if args.control_topology:
        result = control_topology(args.name,args.control_topology)
    elif args.topology:
        result = generate_topology(args.name)
    else:
        result = inventory(args.name)
    print(json.dumps(result, indent=2))
