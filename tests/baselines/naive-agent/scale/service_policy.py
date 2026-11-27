"""Bind independent IPv4 service authorizations to ordered, observed firewall rules."""

from collections import defaultdict
from ipaddress import IPv4Address, IPv4Network
from itertools import product
import json
from pathlib import Path
import socket

from architecture_cases import raw_observations
from tdn_evidence.parsers.correspondence import parse_iptables_save
from tdn_evidence.parsers.packet_policy import parse_rule
from measure import typecheck

FIELDS = (
    "source",
    "destination",
    "sport",
    "dport",
    "protocol",
    "ingress",
    "egress",
    "ihl",
    "length",
)
LIMITS = (2**32 - 1, 2**32 - 1, 65535, 65535, 255, None, None, 15, 65535)
SOURCE = Path(__file__).resolve().parents[1] / "ServicePolicyChecks.lean"


def host(value):
    return int(IPv4Address(value))


def region(ifaces, **values):
    bounds = [(0, v if v is not None else len(ifaces) - 1) for v in LIMITS]
    for key, val in values.items():
        if key in ("ingress", "egress") and isinstance(val, str):
            val = ifaces.index(val)
        low, high = val if isinstance(val, tuple) else (val, val)
        i = FIELDS.index(key)
        if not 0 <= low <= high <= bounds[i][1]:
            raise ValueError(f"Invalid {key} range")
        bounds[i] = (low, high)
    return bounds


def ordered_regions(chain, names):
    parsed_rules = [
        parse_rule({**raw, "matches": {"iptables_tokens": raw["tokens"]}, "ordinal": i, "raw_text": raw["raw"]})
        for i, raw in enumerate(chain["rules"])
    ]
    policy_matches = sorted({(a["kind"], a["value"]) for rule in parsed_rules for a in rule["atoms"]
                             if a["kind"] in {"inboundPolicy", "outboundPolicy"}})
    rules = []
    for parsed in parsed_rules:
        pieces = [region(names) + [(0, 1)] * len(policy_matches)]
        for atom in parsed["atoms"]:
            kind = atom["kind"]
            if kind in ("inboundPolicy", "outboundPolicy"):
                index = len(FIELDS) + policy_matches.index((kind, atom["value"]))
                for piece in pieces:
                    piece[index] = (1, 1)
                continue
            if kind in ("sourceRange", "destinationRange"):
                key, vals = kind.removesuffix("Range"), [(atom["low"], atom["high"])]
            elif kind in ("ingress", "egress"):
                key, vals = kind, [names.index(atom["value"])]
            elif kind == "protocol":
                val = atom["value"]
                key, vals = (
                    "protocol",
                    [int(val) if val.isdecimal() else socket.getprotobyname(val)],
                )
            elif kind in ("sourcePorts", "destinationPorts"):
                key, vals = (
                    ("sport" if kind == "sourcePorts" else "dport"),
                    atom["values"],
                )
            elif kind == "ipv4HeaderWords":
                key, vals = "ihl", [atom["value"]]
            elif kind == "networkBytesRange":
                key, vals = "length", [(atom["low"], atom["high"])]
            else:
                raise ValueError(f"Unsupported service-policy match {kind}")
            index = FIELDS.index(key)
            updated = []
            for box, value in product(pieces, vals):
                lo, hi = value if isinstance(value, tuple) else (value, value)
                lo, hi = max(box[index][0], lo), min(box[index][1], hi)
                if lo <= hi:
                    updated.append(box[:index] + [(lo, hi)] + box[index + 1 :])
            pieces = updated
        rules.extend(
            {"region": b, "permit": parsed["verdict"] == "allow"} for b in pieces
        )
    if chain["policy"] not in ("accept", "drop"):
        raise ValueError("Unknown chain policy")
    return rules, chain["policy"] == "accept"


def reverse_sources(routes, iface):
    boundaries = sorted({v for _, _, low, high, *_ in routes for v in (low, high + 1)})
    result = []
    for low, end in zip(boundaries, boundaries[1:]):
        candidates = [r for r in routes if r[2] <= low <= r[3]]
        if not candidates:
            continue
        priority = min((r[6], -r[4], r[5]) for r in candidates)
        if any(r[1] == iface and (r[6], -r[4], r[5]) == priority for r in candidates):
            if result and result[-1][1] + 1 == low:
                result[-1] = (result[-1][0], end - 1)
            else:
                result.append((low, end - 1))
    return result


def outer_gray_allowances(device, iface, inner_by_ip, active, services):
    incoming, outgoing = [], []
    for flow in device["tunnel"]["flows"]:
        if flow["inside"] != iface:
            continue
        networks = [IPv4Network(flow[k]) for k in ("local", "remote")]
        if any(network.num_addresses != 1 for network in networks):
            raise ValueError("Outer Gray peer authorizations require individual Inner addresses")
        src, dst = (int(network.network_address) for network in networks)
        left, right = inner_by_ip[src], inner_by_ip[dst]
        if (left["tunnel"]["peer"] != right["id"] or right["tunnel"]["peer"] != left["id"]
                or active[left["id"]]["level"] != active[right["id"]]["level"]):
            continue
        for allowed, a, b in ((incoming, src, dst), (outgoing, dst, src)):
            for traffic in ({"protocol": 50}, {"protocol": 17, "dport": 500}, {"protocol": 17, "dport": 4500}):
                allowed.append(dict(source=a, destination=b, **traffic))
    for service in services:
        if service["device"] == device["id"] and service["interface"] == iface:
            allowed = {"in": incoming, "out": outgoing}[service["direction"]]
            allowed.append(dict(source=host(service["source"]), destination=host(service["destination"]),
                                protocol=service["protocol"], dport=service["destinationPort"]))
    return incoming, outgoing


def proof_input(native, intended, forwarding, policy, *, registered=False):
    active = {
        d["id"]: d for d in json.loads((native / "spec.json").read_text())["devices"]
    }
    devices = {d["id"]: d for d in intended["devices"]}
    if devices.keys() != active.keys():
        raise ValueError("Device inventory differs between design and capture")
    raw = raw_observations(native)
    by_ingress = defaultdict(list)
    for route in forwarding["routes"]:
        fields = (
            "ingress",
            "egress",
            "destPrefixLow",
            "destPrefixHigh",
            "prefixLength",
            "metric",
            "tablePriority",
        )
        by_ingress[route["ingress"]].append(tuple(route[k] for k in fields))
    inner_by_ip = {
        host(d["tunnel"]["local"]): d for d in devices.values() if d["role"] == "inner"
    }
    answers = []
    for name, d in devices.items():
        if d["role"] not in {"gray-firewall", "inner", "outer"}:
            continue
        chains = parse_iptables_save(raw[name, "filters4"])
        observed = json.loads(raw[name, "interfaces"])
        observed_names = {p["ifname"] for p in observed}
        if registered and not {p["name"] for p in d["interfaces"]} <= observed_names:
            raise ValueError(f"Missing registered interface in the capture of {name}")
        if registered:
            zones = {(p["name"], p["zone"]) for p in d["interfaces"]}
            if not zones <= {(p["name"], p["zone"]) for p in active[name]["interfaces"]}:
                raise ValueError(f"Captured interface zones disagree with the registered design on {name}")
        names = sorted(
            {""}
            | {p["ifname"] for p in observed}
            | {p["name"] for p in active[name]["interfaces"]}
            | {
                r["tokens"][i + 1]
                for c in chains.values()
                for r in c["rules"]
                for i, t in enumerate(r["tokens"])
                if t in ("-i", "-o")
            }
        )
        if registered:
            names = ["", *sorted(observed_names), *sorted(set(names) - observed_names - {""})]
        queries = defaultdict(list)

        def add(hook, clause, required, scope, exceptions=()):
            if registered:
                ports = (1, len(observed_names))
                scope = {"ingress": "" if hook == "OUTPUT" else ports,
                         "egress": "" if hook == "INPUT" else ports, **scope}
            queries[hook].append(
                {
                    "clause": clause,
                    "mustPermit": required,
                    "scope": region(names, **scope),
                    "exceptions": [region(names, **e) for e in exceptions],
                }
            )

        if d["role"] == "gray-firewall":
            if registered:
                for p in d["interfaces"]:
                    if p["zone"] == "gray":
                        for service in policy["grayManagementServices"]:
                            add("INPUT", "MSC-PF-27", False, dict(ingress=p["name"], egress="",
                                protocol=service["protocol"], dport=service["destinationPort"]))
            approved = []
            http_ports = set(policy["httpServicePorts"])
            for service in policy["innerRevocationHttp"]:
                if service["firewall"] != name:
                    continue
                gateway = devices[service["inner"]]
                if gateway["role"] != "inner":
                    raise ValueError("Revocation client must be an Inner gateway")
                a, b = host(gateway["tunnel"]["local"]), host(service["responder"])
                port = service["port"]
                http_ports.add(port)
                for allowance in (
                    dict(
                        source=a,
                        destination=b,
                        dport=port,
                        ingress=service["ingress"],
                        egress=service["egress"],
                    ),
                    dict(
                        source=b,
                        destination=a,
                        sport=port,
                        ingress=service["egress"],
                        egress=service["ingress"],
                    ),
                ):
                    approved.append(allowance)
                    add("FORWARD", "MSC-PF-25", True, dict(protocol=6, **allowance))
            for http_port in sorted(http_ports):
                for field in ("sport", "dport"):
                    add(
                        "FORWARD",
                        "MSC-PF-25",
                        False,
                        {"protocol": 6, field: http_port},
                        approved,
                    )
            for f in d["boundary_flows"]:
                src, dst = (IPv4Network(f[k]) for k in ("source", "destination"))
                if src.num_addresses != 1 or dst.num_addresses != 1:
                    raise ValueError(
                        "IKE authorization requires individual peer addresses"
                    )
                a, b = host(src.network_address), host(dst.network_address)
                left, right = inner_by_ip[a], inner_by_ip[b]
                if (
                    left["tunnel"]["peer"] != right["id"]
                    or right["tunnel"]["peer"] != left["id"]
                ):
                    raise ValueError(
                        "Declared IKE authorization is not a reciprocal peer pair"
                    )
                if active[left["id"]]["level"] != active[right["id"]]["level"]:
                    continue
                for port in (500, 4500):
                    add(
                        "FORWARD",
                        "MSC-PF-23",
                        True,
                        dict(
                            source=a,
                            destination=b,
                            ingress=f["ingress"],
                            egress=f["egress"],
                            protocol=17,
                            sport=port,
                            dport=port,
                            ihl=5,
                            length=(56, 65535),
                        ),
                    )
        else:
            tunnel = d["tunnel"]
            if registered and d["role"] == "outer" and "MSC-PF-10" in policy["selected_objectives"]:
                for hook in ("INPUT", "FORWARD", "OUTPUT"):
                    for words in range(6, 16):
                        add(hook, "MSC-PF-10", False, dict(ihl=words, length=(4 * words, 65535)))
            for iface in active[name]["interfaces"]:
                port = iface["name"]
                if port not in observed_names:
                    continue
                if d["role"] == "inner" and iface["zone"] == "gray":
                    ends = dict(
                        source=host(tunnel["remote"]), destination=host(tunnel["local"])
                    )
                    allowances = [{**ends, "protocol": 50}] + [
                        {**ends, "protocol": 17, "dport": p} for p in (500, 4500)
                    ]
                    for item in policy["innerGrayControl"]:
                        if item["device"] == name:
                            allowances.append(
                                dict(
                                    source=host(item["source"]),
                                    destination=host(item["destination"]),
                                    protocol=item["protocol"],
                                    dport=item["destinationPort"],
                                )
                            )
                    add(
                        "INPUT",
                        "MSC-PF-5",
                        False,
                        dict(ingress=port, egress=""),
                        allowances,
                    )
                if d["role"] == "outer" and iface["zone"] == "black":
                    allowed = [host(tunnel["remote"])] + [
                        host(x["address"])
                        for x in policy["outerBlackPeers"]
                        if x["device"] == name
                    ]
                    add(
                        "OUTPUT",
                        "MSC-OR-10",
                        False,
                        dict(ingress="", egress=port),
                        [dict(destination=ip) for ip in allowed],
                    )
                if d["role"] == "outer" and iface["zone"] == "gray":
                    idx = forwarding["portIds"][name + ":" + port]
                    if not by_ingress[idx]:
                        raise ValueError(
                            f"No captured forwarding entries on {name}:{port}"
                        )
                    reachable = [dict(source=b) for b in reverse_sources(by_ingress[idx], idx)]
                    add("INPUT", "MSC-PF-18", False, dict(ingress=port, egress=""), reachable)
                    if registered:
                        add("FORWARD", "MSC-PF-18", False, dict(ingress=port), reachable)
                        incoming, outgoing = outer_gray_allowances(d, port, inner_by_ip, active, policy["outerGrayServices"])
                        for hook, scope, allowed in (
                            ("INPUT", dict(ingress=port, egress=""), incoming),
                            ("FORWARD", dict(ingress=port), incoming),
                            ("FORWARD", dict(egress=port), outgoing),
                            ("OUTPUT", dict(ingress="", egress=port), outgoing),
                        ):
                            add(hook, "MSC-PF-20", False, scope, allowed)
        for hook, items in queries.items():
            rules, fallback = ordered_regions(chains[hook], names)
            extra_dimensions = len(rules[0]["region"]) - len(FIELDS) if rules else 0
            for query in items:
                for box in (query["scope"], *query["exceptions"]):
                    box.extend([(0, 1)] * extra_dimensions)
            answers.append(
                dict(
                    device=name,
                    hook=hook,
                    rules=rules,
                    fallback=fallback,
                    queries=items,
                )
            )
    return {"chains": answers, "registeredPanel": registered,
            "checkIPv4Options": registered and "MSC-PF-10" in policy["selected_objectives"]}


def check(native, intent, forwarding, dest, *, registered_policy=None):
    policy = registered_policy if registered_policy is not None else json.loads(
        Path(__file__).with_name("service-policy.json").read_text())
    evidence = proof_input(native, intent, forwarding, policy, registered=registered_policy is not None)
    return typecheck(SOURCE, dest, evidence, set(SOURCE.read_text().splitlines()))
