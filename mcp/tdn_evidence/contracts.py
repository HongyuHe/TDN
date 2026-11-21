"""Evidence needed by the installed-route, topology, filter, and IPsec execution views."""
from .adapters import ADAPTERS

ROUTE_FIELDS = {"destination": "string", "gateway": "string or null", "output": "string or null",
                "table": "natural number", "kind": "string", "protocol": "string",
                "metric": "natural number", "scope": "string"}
FAMILIES = {"installed-ipv4-routes": 4, "installed-ipv6-routes": 6}
TOPOLOGY = {
    "devices": ("id", "role", "namespace"),
    "interfaces": ("id", "device_id", "name", "zone", "link_kind", "observation_ids"),
    "links": ("id", "relation", "endpoint_interface_ids", "observation_ids"),
}
FILTERS = {"filters": ("device_id", "family", "table", "chain", "policy", "ordered_rules", "observation_ids")}
EXECUTION = {
    **TOPOLOGY, **FILTERS,
    "routes": ("device_id", "family", "table", "destination", "output_interface", "observation_ids"),
    "tunnels": ("id", "layer", "mechanism", "observation_ids"),
}
SAVED = {
    "topology": (TOPOLOGY, "Bind declared and observed interfaces and both ends of links before checking firewall paths."),
    "packet_filters": (FILTERS, "Match ordered rules and default decisions to the captured filter chains."),
    "multi_protocol_execution": (EXECUTION, "Join installed routes, policy routing, filter hooks, links, XFRM policies and directional SAs at matching interfaces."),
}
EXECUTION_OBSERVATIONS = ("interfaces", "routes4", "policies", "states")

def describe(source, view):
    if source == "live" and view == "inventory":
        return {"source": source, "view": view, "claim": "Installed forwarding entries at collection time",
                "required_per_device": list(FAMILIES), "fields": ROUTE_FIELDS.copy(),
                "providers": {key: [f"{vendor}.{name}" for vendor, adapter in sorted(ADAPTERS.items())
                    for name, cap in adapter.capabilities.items() if cap.provides == key] for key in FAMILIES},
                "checks": ["One successful observation per device and family", "Stable recheck", "Matching IP address families"],
                "empty_table": "An observed empty list covers the family and contributes zero routes.",
                "lean_conditions": "The export records installed entries. Route lookup also needs ordered policy tables and the input packet."}
    if source == "saved" and view in SAVED:
        fields, claim = SAVED[view]
        result = {"source": source, "view": view, "claim": claim, "required_fields": fields,
                  "checks": ["Bind each source to the snapshot manifest", "Run the view’s correspondence checks before export"]}
        if view == "multi_protocol_execution":
            result.update(required_per_device=list(EXECUTION_OBSERVATIONS),
                          supplement=["policy-routing4", "routes4", "all-tables4"],
                          local_conditions="Match source and egress interfaces, ordered filtering, selected policies and installed SAs. Match OVS membership on switched paths. Validate additional XFRM epochs when requested.",
                          scope="Native IPv4 IPsec and OVS with a hash-bound processing supplement.")
        return result
    raise ValueError(f"No evidence contract for {source}.{view}. Available: live.inventory, " +
                     ", ".join("saved." + name for name in SAVED))

def check_fields(records, required, subject):
    if not isinstance(records, list):
        raise ValueError(f"{subject}: expected an observed list of records")
    for index, row in enumerate(records):
        if not isinstance(row, dict):
            raise ValueError(f"{subject}[{index}]: expected a record")
        for field in required:
            if field not in row:
                raise ValueError(f"{subject}[{index}]: missing field {field}")

def check_route_rows(records, subject):
    check_fields(records, ROUTE_FIELDS, subject)
    for index, row in enumerate(records):
        for field, expected in ROUTE_FIELDS.items():
            value = row[field]
            if expected == "natural number":
                valid = type(value) is int and value >= 0
            else:
                valid = isinstance(value, str) or (value is None and expected == "string or null")
            if not valid:
                raise ValueError(f"{subject}[{index}].{field}: expected {expected}")


def check_saved(view, snapshot):
    if view not in SAVED:
        return
    for table, fields in SAVED[view][0].items():
        if table not in snapshot:
            raise ValueError(f"{view}: missing observation table {table}")
        check_fields(snapshot[table], fields, f"{view}.{table}")
    if view == "multi_protocol_execution":
        check_fields(snapshot.get("observations"), ("device_id", "kind", "returncode", "parse_status"), "execution.observations")
        observed = {(o["device_id"], o["kind"]) for o in snapshot["observations"]
                    if o["returncode"] == 0 and o["parse_status"] == "parsed"}
        for device in snapshot["devices"]:
            for kind in EXECUTION_OBSERVATIONS:
                if (device["id"], kind) not in observed:
                    raise ValueError(f"{view}: missing successful {kind} observation on {device['id']}")

def installed_route_observations(manifest):
    if manifest["consistency"] != "stable-during-recheck":
        raise ValueError("A Lean bundle requires unchanged rechecked state")
    devices = {d["id"] for d in manifest["devices"]}
    rechecks = {o["capability"]: o for o in manifest["observations"] if o["adapter"] == "recheck"}
    covered = set()
    result = {}
    for o in manifest["observations"]:
        if o["adapter"] == "recheck":
            continue
        supplies = o.get("provides")
        if supplies is None:
            adapter = ADAPTERS.get(o["adapter"])
            cap = adapter.capabilities.get(o["capability"]) if adapter and adapter.version == o["parser_version"] else None
            supplies = cap.provides if cap else None
        if supplies not in FAMILIES:
            continue
        family = FAMILIES[supplies]
        key = o["device"], family
        if o["device"] not in devices or key in covered:
            raise ValueError(f"Ambiguous device or duplicate IPv{family} forwarding observation: {o['id']}")
        if o["status"] != "observed":
            raise ValueError("Cannot export unsupported or failed forwarding observations: " + o["id"])
        recheck = rechecks.get(o["id"])
        if not recheck or recheck["device"] != o["device"] or recheck["status"] != "observed" or recheck["records"] != [{"unchanged": True}] or recheck["sha256"] != o["sha256"]:
            raise ValueError(f"{o['id']}: missing unchanged recheck for installed IPv{family} routes")
        check_route_rows(o["records"], f"{o['device']}.IPv{family}.{o['id']}")
        result[o["id"]] = family
        covered.add(key)
    for device in sorted(devices):
        for family in FAMILIES.values():
            if (device, family) not in covered:
                raise ValueError(f"Missing forwarding coverage for {device}: fib{family} (installed IPv{family} routes)")
    return result
