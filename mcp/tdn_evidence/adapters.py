"""Adapters declare read commands and preserve unsupported syntax explicitly."""
from dataclasses import dataclass
from typing import Callable
import ipaddress
import json
import re


class Unsupported(ValueError):
    pass


def json_records(text):
    value = json.loads(text)
    if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
        raise Unsupported("Expected an array of objects")
    return value


def raw_config(text):
    return [{"text": text, "interpretation": "uninterpreted configuration"}]


def linux_routes(text):
    rows = json_records(text)
    result = []
    allowed = {"dst", "gateway", "dev", "protocol", "scope", "prefsrc", "metric", "table", "type", "flags", "nhid", "nexthops", "pref"}
    tables = {"local": 255, "main": 254, "default": 253}
    for row in rows:
        unknown = set(row) - allowed
        if unknown:
            raise Unsupported("Unmodeled route fields: " + ", ".join(sorted(unknown)))
        if row.get("flags"):
            raise Unsupported("Route flags need explicit semantics")
        if row.get("nexthops") or row.get("nhid"):
            raise Unsupported("Multipath/next-hop objects require expansion before a forwarding proof")
        table = row.get("table", 254)
        table = tables.get(table, table)
        if not isinstance(table, int):
            raise Unsupported("Unknown routing table: " + str(table))
        result.append({"destination": row.get("dst", "default"), "gateway": row.get("gateway"),
                       "output": row.get("dev"), "table": table, "kind": row.get("type", "unicast"),
                       "protocol": str(row.get("protocol", "")), "metric": row.get("metric", 0),
                       "preferred_source": row.get("prefsrc"), "scope": row.get("scope", "global"),
                       "raw": row})
    return result


def frr_routes(text):
    tables = json.loads(text)
    if not isinstance(tables, dict):
        raise Unsupported("Expected FRR route dictionary")
    result = []
    for prefix, routes in tables.items():
        ipaddress.ip_network(prefix, strict=False)
        if not isinstance(routes, list):
            raise Unsupported("Unexpected FRR route group")
        for route in routes:
            result.append({"destination": prefix, "protocol": route.get("protocol"),
                           "selected": route.get("selected", False), "installed": route.get("installed", False),
                           "metric": route.get("metric"), "next_hops": route.get("nexthops", []), "raw": route})
    return result


def bird_routes(text):
    result = []
    table = None
    current = None
    prefix = None
    for line in text.splitlines():
        if not line.strip() or line == "Access restricted" or re.match(r"BIRD [0-9.]+ ready\.", line):
            continue
        match = re.fullmatch(r"Table ([^:]+):", line)
        if match:
            table = match[1]
            continue
        match = re.match(r"^(\S+/\d+)?\s+(\S+) \[([^]]+)\]\s*(\*)?\s*\(([^)]+)\)(.*)$", line)
        if match:
            if match[1]:
                prefix = str(ipaddress.ip_network(match[1], strict=False))
            if prefix is None or table is None:
                raise Unsupported("BIRD route lacks table or prefix context")
            current = {"destination": prefix, "kind": match[2], "protocol": match[3].split()[0],
                       "table": table, "selected": bool(match[4]), "preference": match[5],
                       "next_hops": [], "attributes": []}
            result.append(current)
            continue
        if line[:1].isspace() and current is not None:
            match = re.fullmatch(r"\s+via (\S+) on (\S+)(?: weight (\d+))?", line)
            direct = re.fullmatch(r"\s+dev (\S+)", line)
            if match:
                current["next_hops"].append({"gateway": str(ipaddress.ip_address(match[1])), "interface": match[2], "weight": int(match[3] or 1)})
            elif direct:
                current["next_hops"].append({"gateway": None, "interface": direct[1], "weight": 1})
            else:
                current["attributes"].append(line.strip())
            continue
        raise Unsupported("Unrecognized BIRD route line: " + line)
    return result


@dataclass(frozen=True)
class Capability:
    argv: tuple[str, ...]
    parse: Callable
    meaning: str
    recheck: bool = False


@dataclass(frozen=True)
class Adapter:
    version: str
    capabilities: dict[str, Capability]



#* Strip key bytes inside the device before any output crosses the SSH boundary.
_XFRM_STATES = (
    "python3", "-c",
    "import json,subprocess,sys; r=subprocess.run(['ip','-j','xfrm','state'],capture_output=True,text=True); "
    "sys.stderr.write(r.stderr); "
    "rows=json.loads(r.stdout) if r.returncode==0 else []; "
    "[(algorithm.update({'key_bits':len(algorithm['key'].removeprefix('0x'))*4}),algorithm.pop('key')) "
    "for row in rows for algorithm in row.values() if isinstance(algorithm,dict) and 'key' in algorithm]; "
    "print(json.dumps(rows)); sys.exit(r.returncode)"
)

ADAPTERS = {
    "linux": Adapter("linux-iproute2-v1", {
        "interfaces": Capability(("ip", "-j", "-d", "link", "show"), json_records, "Observed links and interface identities", True),
        "addresses": Capability(("ip", "-j", "addr", "show"), json_records, "Observed addresses"),
        "fib4": Capability(("ip", "-j", "-4", "route", "show", "table", "all"), linux_routes, "Installed IPv4 forwarding entries", True),
        "fib6": Capability(("ip", "-j", "-6", "route", "show", "table", "all"), linux_routes, "Installed IPv6 forwarding entries", True),
        "rules4": Capability(("ip", "-j", "-4", "rule", "show"), json_records, "Ordered IPv4 policy routing rules", True),
        "rules6": Capability(("ip", "-j", "-6", "rule", "show"), json_records, "Ordered IPv6 policy routing rules", True),
        "firewall4": Capability(("iptables-save",), raw_config, "Ordered IPv4 firewall text; proof interpretation requires the packet-policy parser", True),
        "firewall6": Capability(("ip6tables-save",), raw_config, "Ordered IPv6 firewall text", True),
        "version": Capability(("uname", "-r"), raw_config, "Worker kernel version"),
    }),
    "bird": Adapter("bird2-v1", {
        "routes": Capability(("birdc", "-r", "show", "route", "all"), bird_routes, "BIRD candidate routes with selected-route markers; kernel FIB is collected separately"),
        "protocols": Capability(("birdc", "-r", "show", "protocols", "all"), raw_config, "BIRD protocol state"),
        "config": Capability(("cat", "/etc/bird/bird.conf"), raw_config, "BIRD configured behavior", True),
        "version": Capability(("bird", "--version"), raw_config, "BIRD version"),
    }),
    "frr": Adapter("frr-json-v1", {
        "routes": Capability(("vtysh", "-c", "show ip route json"), frr_routes, "FRR candidate routes and installed/selected flags"),
        "config": Capability(("vtysh", "-c", "show running-config"), raw_config, "FRR running configuration", True),
        "version": Capability(("vtysh", "-c", "show version"), raw_config, "FRR version"),
    }),
    "ovs": Adapter("ovs-json-v1", {
        "bridges": Capability(("ovs-vsctl", "--format=json", "list", "Bridge"), lambda t: [json.loads(t)], "OVS Bridge table including UUIDs", True),
        "ports": Capability(("ovs-vsctl", "--format=json", "list", "Port"), lambda t: [json.loads(t)], "OVS Port table including UUIDs", True),
        "interfaces": Capability(("ovs-vsctl", "--format=json", "list", "Interface"), lambda t: [json.loads(t)], "OVS Interface table including UUIDs"),
    }),
    "ipsec": Adapter("strongswan-xfrm-v1", {
        "states": Capability(_XFRM_STATES, json_records, "Installed XFRM associations and local reqids/wire SPIs; key bytes removed on device"),
        "policies": Capability(("ip", "-j", "xfrm", "policy"), json_records, "Installed IPsec policy selectors and local reqids", True),
        "connections": Capability(("swanctl", "--list-conns"), raw_config, "Loaded strongSwan connections"),
        "sas": Capability(("swanctl", "--list-sas"), raw_config, "Observed negotiated associations; no secret key export"),
    }),
    "macsec": Adapter("linux-macsec-v1", {
        "channels": Capability(("ip", "-j", "macsec", "show"), json_records, "MACsec channels and packet counters; no key export"),
    }),
}


def register_adapter(name, adapter):
    if name in ADAPTERS:
        raise ValueError("Adapter already registered: " + name)
    ADAPTERS[name] = adapter
