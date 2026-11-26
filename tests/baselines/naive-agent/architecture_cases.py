"""Read the Red attachments, Gray links and ordered IPv4 ESP rules used by the three cases."""

from collections import defaultdict
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
import json
import re
import sys

from cohort import HERE
from gray_connectivity import paths_from
from measure import typecheck

sys.path.insert(0, str(HERE.parents[2] / "mcp"))
from tdn_evidence.parsers.correspondence import parse_iptables_save

FAMILIES = ("shared-inner-gateway", "gray-cross-level-path", "gray-cross-level-forward")
SPI = 0x54444E31
ANY = (0, 2**32 - 1)
OBLIGATION = dict(
    zip(
        FAMILIES,
        (
            "dedicated_inner_gateways",
            "different_levels_have_different_regions",
            "protected_gray_forwarding_respects_levels",
        ),
    )
)


def devices_for(topology):
    devices = {d["id"]: d for d in topology["devices"]}
    if len(devices) != len(topology["devices"]):
        raise ValueError("Duplicate device identity")
    return devices


def site_a_pair(topology):
    devices = devices_for(topology)

    def choose(role, suffix):
        matches = [
            n
            for n, d in devices.items()
            if d["role"] == role and d.get("site") == "A" and n.endswith(suffix)
        ]
        if len(matches) != 1:
            raise ValueError(f"Expected one Site A {role} ending in {suffix}")
        return matches[0]

    a, b, fw = (
        choose("inner", "_A1"),
        choose("inner", "_A2"),
        choose("gray-firewall", "_GF_A"),
    )
    if devices[a]["level"] == devices[b]["level"]:
        raise ValueError("Two distinct Red security levels are required")
    return a, b, fw


def raw_observations(native):
    snapshot = json.loads((native / "snapshot.json").read_text())
    manifest = json.loads((native / "manifest.json").read_text())
    hashes = {f["path"]: f["sha256"] for f in manifest["files"]}
    for name in ("spec.json", "snapshot.json"):
        if sha256((native / name).read_bytes()).hexdigest() != hashes[name]:
            raise ValueError(f"{name} hash differs from the collection manifest")
    if not manifest["convergence"]["consistent"]:
        raise ValueError("The device observations changed during collection")
    records = {}
    for obs in snapshot["observations"]:
        if obs["kind"] not in {"interfaces", "sas", "filters4"}:
            continue
        key = obs["device_id"], obs["kind"]
        relative = obs["raw_path"]
        if key in records or not re.fullmatch(r"raw/obs-\d+\.json", relative):
            raise ValueError(f"Ambiguous observation {key}")
        data = (native / relative).read_bytes()
        if (
            sha256(data).hexdigest() != obs["raw_sha256"]
            or hashes[relative] != obs["raw_sha256"]
        ):
            raise ValueError(f"Observation hash differs for {key}")
        raw = json.loads(data)
        if obs["returncode"] != 0:
            raise ValueError(f"Failed observation {key}")
        records[key] = raw["stdout"]
    return records


def installed_subnets(text):
    prefixes = set()
    established = installed = False
    for line in text.splitlines():
        if line and not line.startswith(" "):
            established = bool(re.search(r", ESTABLISHED, IKEv2,", line))
            installed = False
        elif re.match(r"^  \S+: #", line):
            installed = established and ", INSTALLED, TUNNEL, ESP:" in line
        elif installed and line.startswith("    local "):
            for word in line.split()[1:]:
                prefixes.add(str(IPv4Network(word.rstrip(","))))
    return prefixes


def prefix_range(value):
    net = IPv4Network(value)
    return (int(net.network_address), int(net.broadcast_address))


def esp_rules(text):
    chain = parse_iptables_save(text)["FORWARD"]
    if chain["policy"] not in ("accept", "drop"):
        raise ValueError("Unknown FORWARD policy")
    rules = []
    for source in chain["rules"]:
        tokens = source["tokens"]
        if "!" in tokens or len(tokens) % 2:
            raise ValueError(f"Unsupported match in {source['raw']}")
        args = dict(zip(tokens[::2], tokens[1::2]))
        if args.get("-p", "all") not in {"esp", "50", "all", "0"}:
            continue
        if (
            len(args) != len(tokens) // 2
            or set(args) - {"-s", "-d", "-i", "-o", "-p", "-m", "--espspi"}
            or args.get("-m", "esp") != "esp"
            or source["action"] not in {"accept", "drop"}
            or any("+" in args.get(k, "") for k in ("-i", "-o"))
        ):
            raise ValueError(f"Unsupported ESP rule {source['raw']}")
        spi = ANY
        if "--espspi" in args:
            values = [int(x, 0) for x in args["--espspi"].split(":")]
            if len(values) not in (1, 2) or not 0 <= values[0] <= values[-1] <= ANY[1]:
                raise ValueError("Invalid ESP SPI range")
            spi = values[0], values[-1]
        rules.append(
            {
                "source": prefix_range(args.get("-s", "0.0.0.0/0")),
                "destination": prefix_range(args.get("-d", "0.0.0.0/0")),
                "ingress": args.get("-i"),
                "egress": args.get("-o"),
                "spi": spi,
                "permit": source["action"] == "accept",
            }
        )
    return rules, chain["policy"] == "accept"


def observed_links(devices, raw):
    ports = {}
    zones = {}
    for name, device in devices.items():
        zones.update({(name, p["name"]): p["zone"] for p in device["interfaces"]})
        for p in json.loads(raw[name, "interfaces"]):
            if p.get("linkinfo", {}).get("info_kind") == "veth":
                ports[name, p["ifname"]] = p
    by_index = defaultdict(list)
    for key, p in ports.items():
        by_index[p["ifindex"], p["link_index"]].append(key)
    pairs = []
    for key, p in ports.items():
        if "UP" not in p["flags"] or "LOWER_UP" not in p["flags"]:
            continue
        peers = [k for k in by_index[p["link_index"], p["ifindex"]] if k[0] != key[0]]
        if len(peers) != 1:
            raise ValueError(f"Missing or ambiguous live veth peer for {key}")
        peer = peers[0]
        if not {"UP", "LOWER_UP"} <= set(ports[peer]["flags"]):
            raise ValueError(f"Inconsistent carrier observations {key}, {peer}")
        if key < peer:
            if key not in zones or peer not in zones:
                raise ValueError(
                    f"An observed link has no declared zone: {key}, {peer}"
                )
            pairs.append((key, peer))
    return ports, zones, pairs


def network_facts(topology, raw):
    devices = devices_for(topology)
    names = sorted(devices)
    ids = {n: i for i, n in enumerate(names)}
    inners = [n for n in names if devices[n]["role"] == "inner"]
    firewalls = [n for n in names if devices[n]["role"] == "gray-firewall"]
    ports, zones, pairs = observed_links(devices, raw)
    attachments = defaultdict(set)
    edges = set()
    selectors = {n: installed_subnets(raw[n, "sas"]) for n in inners}
    for left, right in pairs:
        for host, gateway in ((left, right), (right, left)):
            if zones[host] == zones[gateway] == "gray":
                edges.add((host[0], gateway[0]))
            elif (
                zones[host] == zones[gateway] == "red"
                and devices[host[0]]["role"] == "host"
                and gateway[0] in selectors
            ):
                attachments[host[0]].add((gateway[0], gateway[1], host[1]))

    reds = {}
    for host, d in devices.items():
        if d["role"] != "host" or not any(p["zone"] == "red" for p in d["interfaces"]):
            continue
        original = next(
            p for p in d["interfaces"] if p["name"] == "red" and p["zone"] == "red"
        )
        subnet = IPv4Interface(original["address"]).network
        identity = d["site"] + "/" + str(d.get("network") or subnet)
        components = set()
        for gateway, gi, hi in attachments[host]:

            def has_address(port):
                return any(
                    i["family"] == "inet" and IPv4Address(i["local"]) in subnet
                    for i in port.get("addr_info", [])
                )

            if (
                has_address(ports[host, hi])
                and has_address(ports[gateway, gi])
                and str(subnet) in selectors[gateway]
            ):
                components.add(gateway)
        if not components:
            raise ValueError(
                f"Could not bind {host}'s Red subnet to a linked Inner with an installed traffic selector"
            )
        row = reds.setdefault(
            identity,
            {
                "id": identity,
                "site": d["site"],
                "level": {
                    "classification": d["level"],
                    "compartments": [],
                    "dissemination": [],
                    "otherControls": [],
                },
                "innerComponents": [],
            },
        )
        if row["level"]["classification"] != d["level"]:
            raise ValueError(f"Inconsistent levels for {identity}")
        row["innerComponents"] = sorted(set(row["innerComponents"]) | components)
    if len(reds) < 2:
        raise ValueError(
            "At least two independently identified Red networks are required"
        )

    cut = [(x, y) for x, y in edges if x not in firewalls and y not in firewalls]
    regions = {}
    for n in names:
        if n not in regions:
            regions.update(dict.fromkeys(paths_from(n, cut), ids[n]))
    core = {
        "reds": list(reds.values()),
        "nodeCount": len(names),
        "edges": sorted((ids[x], ids[y]) for x, y in edges),
        "inners": [ids[x] for x in inners],
        "firewalls": [ids[x] for x in firewalls],
        "levels": [devices[x].get("level", "") for x in names],
        "regions": [regions[x] for x in names],
    }
    return core, ports, zones


def proof_input(topology, raw):
    core, ports, zones = network_facts(topology, raw)
    devices = devices_for(topology)
    addresses, policies = {}, []
    for name in sorted(devices):
        d = devices[name]
        live = {
            iface: port
            for (node, iface), port in ports.items()
            if node == name
            and zones.get((node, iface)) == "gray"
            and {"UP", "LOWER_UP"} <= set(port["flags"])
        }
        if d["role"] == "gray-firewall":
            if not live:
                raise ValueError(f"No connected Gray interfaces on {name}")
            rules, default = esp_rules(raw[name, "filters4"])
            policies.append(
                {"ifaces": sorted(live), "rules": rules, "defaultAllow": default}
            )
        if d["role"] == "inner":
            values = {
                int(IPv4Address(a["local"]))
                for port in live.values()
                for a in port.get("addr_info", [])
                if a["family"] == "inet"
            }
            if not values or not d.get("level"):
                raise ValueError(
                    f"Missing Gray address or Red security level on {name}"
                )
            for address in values:
                if address in addresses:
                    raise ValueError(
                        f"Multiple Inner gateways own {IPv4Address(address)}"
                    )
                addresses[address] = d["level"]
    if not policies or len(set(addresses.values())) < 2:
        raise ValueError(
            "The multi-level experiment needs a Gray Firewall and two different Inner levels"
        )
    return {
        **core,
        "grayAcls": policies,
        "innerAddresses": [
            {"address": a, "level": level} for a, level in sorted(addresses.items())
        ],
    }


def complete_proof_input(native):
    return proof_input(
        json.loads((native / "spec.json").read_text()), raw_observations(native)
    )


def project(topology, raw):
    core, ports, zones = network_facts(topology, raw)
    devices = devices_for(topology)
    a, b, firewall = site_a_pair(topology)
    names = sorted(devices)
    ids = {n: i for i, n in enumerate(names)}
    inners = [names[i] for i in core["inners"]]
    cut = [
        (names[i], names[j])
        for i, j in core["edges"]
        if i not in core["firewalls"] and j not in core["firewalls"]
    ]
    addrs = {}
    for owner, iface in ((a, "gray"), (b, "gray"), (firewall, "s1"), (firewall, "s2")):
        if zones.get((owner, iface)) != "gray":
            raise ValueError(f"Expected a Gray interface on {owner}/{iface}")
        (local,) = [
            IPv4Interface(f"{i['local']}/{i['prefixlen']}")
            for i in ports[owner, iface]["addr_info"]
            if i["family"] == "inet"
        ]
        addrs[owner, iface] = local
    for owner in (a, b):
        address = addrs[owner, "gray"].ip
        owners = {
            n
            for (n, iface), port in ports.items()
            if n in inners
            and zones.get((n, iface)) == "gray"
            and any(
                i["family"] == "inet" and IPv4Address(i["local"]) == address
                for i in port.get("addr_info", [])
            )
        }
        if owners != {owner}:
            raise ValueError(f"Ambiguous Gray endpoint address {address}")
    for owner, iface in ((a, "s1"), (b, "s2")):
        if addrs[owner, "gray"].network != addrs[firewall, iface].network:
            raise ValueError(f"Gray address does not match {firewall}/{iface}")
    rules, default = esp_rules(raw[firewall, "filters4"])
    evidence = {
        **core,
        "endpoints": [ids[a], ids[b]],
        "packet": {
            "source": int(addrs[a, "gray"].ip),
            "destination": int(addrs[b, "gray"].ip),
            "ingress": "s1",
            "egress": "s2",
            "spi": SPI,
        },
        "espRules": rules,
        "defaultAllow": default,
    }
    witnesses = {
        "assignments": {row["id"]: row["innerComponents"] for row in core["reds"]},
        "gray_path": paths_from(a, cut).get(b),
        "gateways": [a, b],
        "firewall": firewall,
    }
    return evidence, witnesses


def captured(native):
    topo = json.loads((native / "spec.json").read_text())
    return project(topo, raw_observations(native))


def check(native, dest):
    evidence = complete_proof_input(native)
    source = HERE / "MscArchitectureChecks.lean"
    return typecheck(source, dest, evidence, {"  native_decide"})
