"""Translate retained early source guards with exact raw table correspondence."""
import ipaddress
import json

from validate_evidence import require

IPV6_OFFSET = 2 ** 128
TABLE = "EVA_SOURCE_V13"


def clean(value):
    if isinstance(value, list):
        return [clean(item) for item in value]
    if isinstance(value, dict):
        return {key: clean(item) for key, item in value.items()
                if key not in {"handle", "packets", "bytes"}}
    return value


def prefix_atom(protocol, field, right):
    family = 4 if protocol == "ip" else 6
    if isinstance(right, str):
        network = ipaddress.ip_network(right, strict=True)
    else:
        require(set(right) == {"prefix"} and set(right["prefix"]) == {"addr", "len"},
                "Unsupported nft address expression")
        network = ipaddress.ip_network(str(right["prefix"]["addr"]) + "/" + str(right["prefix"]["len"]), strict=True)
    require(network.version == family, "nft payload address family mismatch")
    offset = IPV6_OFFSET if family == 6 else 0
    return {"kind": "sourceRange" if field == "saddr" else "destinationRange",
            "low": int(network.network_address) + offset,
            "high": int(network.broadcast_address) + offset}


def alternatives(expression):
    require(set(expression) == {"match"}, "Source guard contains a nonmatching operation")
    match = expression["match"]
    require(set(match) == {"op", "left", "right"} and match["op"] == "==",
            "Unsupported source guard comparison")
    left, right = match["left"], match["right"]
    if left == {"meta": {"key": "iifname"}}:
        require(isinstance(right, str) and right and "*" not in right, "Unsupported input interface")
        return [[{"kind": "ingress", "value": right}]]
    if left == {"meta": {"key": "nfproto"}}:
        require(right == {"set": ["ipv4", "ipv6"]}, "Unexpected network-family guard")
        return [[{"kind": "sourceRange", "low": 0, "high": 2 ** 32 - 1}],
                [{"kind": "sourceRange", "low": IPV6_OFFSET, "high": 2 * IPV6_OFFSET - 1}]]
    if "payload" in left:
        require(set(left) == {"payload"} and set(left["payload"]) == {"protocol", "field"},
                "Unsupported payload expression")
        protocol, field = left["payload"]["protocol"], left["payload"]["field"]
        if protocol in {"ip", "ip6"} and field in {"saddr", "daddr"}:
            return [[prefix_atom(protocol, field, right)]]
        if protocol == "ip6" and field == "hoplimit":
            require(type(right) is int and 0 <= right <= 255, "Invalid IPv6 hop limit")
            return [[{"kind": "hopLimit", "value": right}]]
        if protocol == "icmpv6" and field == "type":
            values = right.get("set") if isinstance(right, dict) else [right]
            names = {"nd-neighbor-solicit": 135, "nd-neighbor-advert": 136}
            require(values and all(value in names for value in values), "Unexpected ND type")
            return [[{"kind": "protocol", "value": "ipv6-icmp"},
                     {"kind": "icmpType", "value": names[value]}] for value in values]
    if left == {"ipsec": {"key": "reqid", "dir": "in", "spnum": 0}}:
        require(type(right) is int and right >= 0, "Invalid inbound reqid")
        return [[{"kind": "inboundPolicy", "value": right}]]
    raise ValueError("Unsupported nft source expression")


def parse_table(objects):
    require(objects and list(objects[0]) == ["table"] and
            clean(objects[0]["table"]) == {"family": "inet", "name": TABLE},
            "Wrong source-policy table")
    require(len(objects) >= 3 and list(objects[1]) == ["chain"] and
            clean(objects[1]["chain"]) == {"family": "inet", "table": TABLE, "name": "ingress",
                "type": "filter", "hook": "prerouting", "prio": -460, "policy": "accept"},
            "Source guard must precede routing and defragmentation")
    translated = []
    for item in objects[2:]:
        require(list(item) == ["rule"], "Unexpected object in source table")
        rule = clean(item["rule"])
        require(set(rule) == {"family", "table", "chain", "expr"} and
                rule["family"] == "inet" and rule["table"] == TABLE and rule["chain"] == "ingress",
                "Wrong source rule placement")
        expressions = rule["expr"]
        require(len(expressions) >= 3 and expressions[-2] == {"counter": {}} and
                expressions[-1] in [{"accept": None}, {"drop": None}],
                "Unsupported source rule action or counter")
        rows = [[]]
        for expression in expressions[:-2]:
            rows = [prefix + atoms for prefix in rows for atoms in alternatives(expression)]
        verdict = "allow" if expressions[-1] == {"accept": None} else "deny"
        translated.extend({"atoms": atoms, "verdict": verdict} for atoms in rows)
    return translated


def selected_table(raw):
    objects = json.loads(raw)["nftables"]
    return [item for item in objects if
            any(isinstance(value, dict) and value.get("family") == "inet" and
                (value.get("name") == TABLE or value.get("table") == TABLE)
                for value in item.values())]


def parse_source_guards(path, evidence, commands, phases):
    source = path / "source-policy-scope.json"
    if not source.exists():
        require(all("nft" not in device or not selected_table(device["nft"]["value"])
                    for phase in phases for device in phase.values()),
                "Unreported early source policy")
        return {}
    supplied = json.loads(source.read_text())
    expected = {d["id"]: d["namespace"] for d in evidence["devices"]
                if d["role"] in {"inner", "outer"}}
    require(set(supplied["rules"]) == set(expected) and supplied["priority"] == -460,
            "Source guard device or priority summary mismatch")
    indexed = {row["id"]: row for row in commands}
    result = {}
    for device, namespace in expected.items():
        record = supplied["rules"][device]
        raw = indexed[record["observation_id"]]
        require(raw["command"] == ["ip", "netns", "exec", namespace, "nft", "-a", "-j",
                                    "list", "table", "inet", TABLE] and
                raw["device_id"] == device and raw["returncode"] == 0 and
                json.loads(raw["stdout"]) == record["ruleset"],
                "Source guard summary differs from raw table command")
        originals = [item for item in record["ruleset"]["nftables"] if "metainfo" not in item]
        rules = parse_table(originals)
        observations = [raw["id"]]
        for phase in phases:
            require("nft" in phase[device], "Missing complete nft ruleset")
            captured = selected_table(phase[device]["nft"]["value"])
            require(clean(captured) == clean(originals),
                    "Stable full ruleset differs from source table export")
            observations.append(phase[device]["nft"]["observation_id"])
        result[device] = {"priority": -460, "fallback": "allow", "rules": rules,
                          "observations": observations,
                          "translation_scope": "Exact ordered matches except first inbound reqid is represented by membership. This is a safety overapproximation for longer security paths; one-entry paths coincide. Model packets use disjoint encoded IPv4/IPv6 address ranges."}
    return result
