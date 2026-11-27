"""Prospective study design. Archived runs keep their original catalogue."""

from hashlib import sha256
from dataclasses import replace
from ipaddress import ip_network
import json
from pathlib import Path
import shlex

from scale.catalog import CASES as HISTORICAL_CASES, Case
from scale.control_filters import filter_rotations, healthy_rule_order

VERSION = 3
CONTROLS = ("healthy-control", "healthy-route-variant-a", "healthy-route-variant-b")
BASE_CONTROL = CONTROLS[0]
PANEL_REVISION = 2
HERE = Path(__file__).resolve().parent

# Each replacement occupies the same slot in the 20-case design.
REPLACEMENTS = {
    "firewall-outside-disconnected": Case(
        "outer-outbound-protection",
        "MSC-OR-2",
        "RG-030.02 / RG-007.06",
        "Red payload crosses Black with only Inner protection",
        "Independent observations identify the same non-control Red payload at Gray ingress and Black egress. The Inner layer remains and the Outer layer is absent.",
    ),
    "inner-gray-application": Case(
        "inner-outbound-protection",
        "MSC-IR-3",
        "RG-029.02 / RG-007.05",
        "Red payload appears on Gray without Inner protection",
        "The same non-control Red payload reaches Gray egress without the required Inner protection.",
    ),
    "inner-peer-loopback": Case(
        "shared-layer-key-context",
        "MSC §4",
        "RG-007.01",
        "Inner and Outer protection use the same key context",
        "Independently collected records tie both active protection layers to the same key origin and context. Issuer names alone are insufficient.",
    ),
    "outer-black-multicast": Case(
        "outer-gray-default-admission",
        "MSC-PF-20",
        "RG-039.07",
        "Outer gateway admits unapproved Gray traffic through its default policy",
        "An unapproved packet reaches the default decision and is admitted at the Outer Gray interface.",
    ),
    "firewall-local-empty-udp": Case(
        "gray-management-data-interface",
        "MSC-PF-27",
        "RG-040.04",
        "Gray Firewall accepts local management on a data interface",
        "A management service on the Gray Firewall accepts a request received on a Gray data interface.",
    ),
    "inner-empty-ipv4-header": Case(
        "outer-ipv4-options",
        "MSC-PF-10 (selected objective)",
        "RG-038.02",
        "Outer VPN gateway admits an IPv4 packet with header options",
        "A deployment that selected PF-10 admits an IPv4 packet whose measured header length exceeds five words.",
    ),
    "outer-gray-wrong-ingress": Case(
        "outer-gray-source-reachability",
        "MSC-PF-18",
        "RG-039.05",
        "Outer gateway accepts a source unreachable on its Gray ingress",
        "The observed ingress and accepted source disagree with the independently recorded reachable prefixes.",
    ),
}
PATH_CASES = {
    "gray-cross-level-path": "Observed interfaces form a continuous Gray path between different-level Inner gateways. The path contains no Gray Firewall.",
    "outer-firewall-alternate-path": "Observed interfaces form a continuous path from the Outer gateway to Black transport. The path contains no Outer Firewall.",
}
CASES = tuple(
    REPLACEMENTS.get(c.key, replace(c, observation=PATH_CASES.get(c.key, c.observation)))
    for c in HISTORICAL_CASES
)
ALL_BY_NAME = {c.key: c for c in (*HISTORICAL_CASES, *CASES)}
NEW_KEYS = frozenset(c.key for c in REPLACEMENTS.values())


def cases_for(protocol):
    version = protocol.get("method_version", 1)
    if version not in (1, 2, VERSION):
        raise ValueError(f"Unknown study method version {version}")
    return CASES if version == VERSION else HISTORICAL_CASES


def controls_for(protocol):
    return CONTROLS if protocol.get("method_version") == VERSION else (BASE_CONTROL,)


def control_run_root(folder, network, variant):
    if variant not in CONTROLS:
        raise ValueError("Unknown matched control variant")
    if variant == BASE_CONTROL:
        return folder
    return folder / "measurements" / network / variant / "control-run"


def clause_coverage(cases):
    guide = json.loads((HERE.parents[3] / "specs/requirement_clause_map.json").read_bytes())
    groups = {clause.split(".")[0] for c in cases for clause in c.clause.split(" / ")}
    clauses = {
        f"{rg}.{i:02d}": [] for rg in sorted(groups) for i in range(1, len(guide[rg]["clauses"]) + 1)
    }
    for case in cases:
        for clause in case.clause.split(" / "):
            clauses[clause].append(case.key)
    return clauses


def additional_routes(spec, control):
    """More-specific routes use the same next hop as the existing authorized subnet."""
    rotation = CONTROLS.index(control)
    gateways = sorted((d for d in spec["devices"] if d["role"] == "inner"), key=lambda d: d["id"])
    for i, dev in enumerate(gateways):
        prefix = ip_network(dev["tunnel"]["remote_ts"])
        (route,) = (r for r in dev["routes"] if r["prefix"] == str(prefix))
        halves = list(prefix.subnets(prefixlen_diff=1))
        for sub in halves[: (i + rotation) % 3]:
            yield dev["id"], {"prefix": str(sub), "via": route["via"]}


def control_topology(name, control=BASE_CONTROL):
    from scale.profiles import profile

    spec = profile(name)["topology"]
    devices = {d["id"]: d for d in spec["devices"]}
    for device, route in additional_routes(spec, control):
        devices[device]["routes"].append(route)
    for i, fw in enumerate(d for d in spec["devices"] if d["role"] == "gray-firewall"):
        allowed = fw["boundary_flows"]
        offset = (i + CONTROLS.index(control)) % len(allowed)
        fw["boundary_flows"] = allowed[offset:] + allowed[:offset]
    return spec


def control_profile(name, control=BASE_CONTROL):
    from scale.profiles import profile

    registered = profile(name)
    topology = control_topology(name, control)
    return {**registered, "topology": topology, "control_variant": control,
            "filter_rotations": filter_rotations(topology["devices"], CONTROLS.index(control))}


def deployment_policy(spec):
    services = json.loads((HERE / "service-policy.json").read_bytes())
    outer_pairs = {
        tuple(sorted((d["id"], d["tunnel"]["peer"]))) for d in spec["devices"] if d["role"] == "outer"
    }
    return {
        "selected_objectives": ["MSC-PF-10"],
        "authorized_outer_pairs": sorted(map(list, outer_pairs)),
        **{k: v for k, v in services.items() if k != "scope"},
    }


def validate_control_shape(name, control, snapshot, declared, *, healthy):
    from scale.profiles import profile

    base = profile(name)["topology"]
    designated = control_topology(name, control)
    if healthy and declared != designated:
        raise ValueError(f"Declared control topology differs from the registered {control} design")
    if declared is not None:
        if {d["id"]: d["role"] for d in declared["devices"]} != {
            d["id"]: d["role"] for d in designated["devices"]
        }:
            raise ValueError("The topology's device roles differ from the registered study")
    installed = {
        (r["device_id"], r["destination"], r.get("gateway"))
        for r in snapshot["routes"]
        if r.get("status") == "observed" and r.get("family") == 4 and r.get("table") in ("main", 254)
    }

    def routes(k):
        return {(device, r["prefix"], r["via"]) for device, r in additional_routes(base, k)}

    possible = set.union(*(routes(k) for k in CONTROLS))
    if installed & possible != routes(control):
        raise ValueError(
            "The observed forwarding entries do not match the registered harmless route variation"
        )
    if healthy:
        ordered = {(c["device_id"], c["chain"]): [r["raw_text"] for r in c["ordered_rules"]]
                   for c in snapshot["filters"] if c["family"] == 4 and c["table"] == "filter"}
        for device, rotation in filter_rotations(designated["devices"], CONTROLS.index(control)).items():
            for hook in ("INPUT", "FORWARD"):
                rows = ordered.get((device, hook))
                if not rows or rows != healthy_rule_order(rows, rotation):
                    raise ValueError(f"{device} {hook} differs from the registered healthy rule order")
        chains = {
            c["device_id"]: c
            for c in snapshot["filters"]
            if c["family"] == 4 and c["table"] == "filter" and c["chain"] == "FORWARD"
        }
        for fw in (d for d in designated["devices"] if d["role"] == "gray-firewall"):
            order = [
                (f["ingress"], f["egress"], f["source"], f["destination"]) for f in fw["boundary_flows"]
            ]
            observed = []
            for row in chains[fw["id"]]["ordered_rules"]:
                words = shlex.split(row["raw_text"])
                fields = dict(zip(words, words[1:]))
                if fields.get("-p") in ("esp", "50") and fields.get("-j") == "ACCEPT":
                    key = tuple(fields.get(k) for k in ("-i", "-o", "-s", "-d"))
                    if key in order:
                        observed.append(key)
            if observed != order:
                raise ValueError(
                    f"Gray Firewall {fw['id']} does not show the registered order of the authorized peers"
                )


def topology_digest(spec):
    return sha256(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def key_attestations(native, snapshot, *, healthy=False, require_complete=False):
    records = {}
    for observation in snapshot["observations"]:
        if observation["kind"] != "public-key-context":
            continue
        device = observation["device_id"]
        raw = Path(observation["raw_path"])
        if (
            device in records
            or observation["returncode"] != 0
            or raw.parent != Path("raw")
            or not raw.name.startswith("obs-")
            or raw.suffix != ".json"
            or not raw.stem.removeprefix("obs-").isdigit()
        ):
            raise ValueError("Invalid or duplicate public key-origin observation")
        contents = (native / raw).read_bytes()
        if sha256(contents).hexdigest() != observation.get("raw_sha256"):
            raise ValueError("Public key-origin observation digest mismatch on " + device)
        record = json.loads(json.loads(contents)["stdout"])
        if (
            not isinstance(record, dict)
            or set(record) != {"device", "active", "origin", "key_context"}
            or record["device"] != device
            or type(record["active"]) is not bool
            or not all(
                isinstance(record[k], str) and record[k].strip() for k in ("origin", "key_context")
            )
        ):
            raise ValueError("Invalid public key-origin attestation")
        records[device] = record
    if require_complete:
        gateways = {d["id"] for d in snapshot["devices"] if d["role"] in {"inner", "outer"}}
        if set(records) != gateways or not gateways:
            raise ValueError("Expected a public key-origin observation for every Inner and Outer gateway")
        if healthy and not all(r["active"] for r in records.values()):
            raise ValueError("The healthy control has a gateway without an active key context")
    if healthy and records:
        roles = {d["id"]: d["role"] for d in snapshot["devices"]}
        active = {
            role: {
                (r["origin"], r["key_context"])
                for device, r in records.items()
                if roles[device] == role and r["active"]
            }
            for role in ("inner", "outer")
        }
        if active["inner"] & active["outer"]:
            raise ValueError("The healthy control already shares a key context between layers")
    return records


def validate_health(name, report):
    from delivery_lab import intended_pairs
    from scale.profiles import profile

    config = profile(name)
    expected = {tuple(row[:2]) for row in intended_pairs(config)}
    sessions = {d["id"] for d in config["topology"]["devices"] if d["role"] in ("inner", "outer")}
    receipts = report["delivery"]
    tunnels = report["tunnels"]
    if (
        report.get("ready") is not True
        or tunnels["attempted"]
        or not all(r["delivered"] is True for r in receipts)
        or {(r["source"], r["destination"]) for r in receipts} != expected
    ):
        raise ValueError(
            "The control lacks successful independent deliveries for all intended Red pairs"
        )
    for instant in ("before", "after"):
        observed = tunnels[instant]
        if {r["device"] for r in observed} != sessions or not all(
            r["established"] is True and r["installed"] is True for r in observed
        ):
            raise ValueError("The control has unconfirmed tunnel state")


def validate_path_observation(case, anchor, body, native):
    snapshot = json.loads((native / "snapshot.json").read_bytes())
    devices = {d["id"]: d for d in snapshot["devices"]}
    interfaces = {
        i["id"]: i for i in snapshot["interfaces"] if i["status"] == "observed" and i["observed_up"]
    }
    edges = {
        frozenset(e["endpoint_interface_ids"])
        for e in snapshot["links"]
        if e["status"] == "observed"
        and e["relation"] == "veth"
        and e.get("runtime_peer_check", {}).get("verified") is True
    }
    path = json.loads(body)["path"]
    cur = anchor
    if not isinstance(path, list) or not path:
        raise ValueError("Expected a nonempty observed interface path")
    gray = case == "gray-cross-level-path"
    for a, b in path:
        if a not in interfaces or b not in interfaces or frozenset((a, b)) not in edges:
            raise ValueError("The path uses an unobserved or down link")
        left, right = interfaces[a], interfaces[b]
        if left["device_id"] != cur or (gray and (left["zone"], right["zone"]) != ("gray", "gray")):
            raise ValueError("Discontinuous path or unsupported Gray interface")
        cur = right["device_id"]
        if devices[cur]["role"] == ("gray-firewall" if gray else "firewall"):
            raise ValueError("The recorded path traverses the required firewall")
    if gray:
        levels = [devices[d].get("security_level_id") for d in (anchor, cur)]
        valid = (
            devices[anchor]["role"] == devices[cur]["role"] == "inner"
            and all(levels)
            and levels[0] != levels[1]
        )
    else:
        valid = (
            devices[anchor]["role"] == "outer"
            and devices[cur]["role"] == "transport"
            and right["zone"] == "black"
        )
    if not valid:
        raise ValueError("The path endpoints do not establish the registered placement violation")


def validate_case_observation(case, anchor, level, body, operator, native):
    """Check a supervisor's interpretation against the case and bind it to retained recordings."""
    if case in PATH_CASES:
        validate_path_observation(case, anchor, body, native)
        return
    if case not in NEW_KEYS:
        return
    r = json.loads(body)
    if r.get("anchor") != anchor or r.get("case") != case:
        raise ValueError("The confirmation must identify the registered device and case")
    readings = r["readings"]
    hashes = set()
    for stage in ("before", "during", "restored"):
        receipt = readings[stage]
        path = (operator / receipt["file"]).resolve()
        if not path.is_relative_to(operator.resolve()) or not path.is_file() or not path.stat().st_size:
            raise ValueError(f"Missing {stage} device recording")
        digest = sha256(path.read_bytes()).hexdigest()
        if (
            digest != receipt["sha256"]
            or digest in hashes
            or receipt["violated"] is not (stage == "during")
        ):
            raise ValueError(f"Invalid or reused {stage} recording")
        hashes.add(digest)
    f = r["facts"]
    if case in ("inner-outbound-protection", "outer-outbound-protection"):
        zones, layers = (
            (("Red", "Gray"), [])
            if case == "inner-outbound-protection"
            else (("Gray", "Black"), ["Inner"])
        )
        ok = (
            (f["ingress_zone"], f["egress_zone"]) == zones
            and f["egress_layers"] == layers
            and f["ingress_layers"] == layers
            and f["source_level"] == level
        )
        ok = (
            ok
            and f["red_origin"] is True
            and f["control_traffic"] is False
            and bool(f["ingress_payload_id"])
            and f["ingress_payload_id"] == f["egress_payload_id"]
            and f["forwarded"] is True
        )
    elif case == "shared-layer-key-context":
        inner, outer = f["inner"], f["outer"]
        ok = (
            inner["device"] == anchor
            and inner["device"] != outer["device"]
            and inner["active"] is True
            and outer["active"] is True
            and bool(inner["origin"])
            and bool(inner["key_context"])
            and (inner["origin"], inner["key_context"]) == (outer["origin"], outer["key_context"])
        )
        snap = json.loads((native / "snapshot.json").read_bytes())
        roles = {d["id"]: d["role"] for d in snap["devices"]}
        records = key_attestations(native, snap)
        for label, layer in (("inner", inner), ("outer", outer)):
            record = records.get(layer["device"])
            if record is None or roles.get(layer["device"]) != label:
                raise ValueError(f"Missing routine public key-origin evidence for the {label} gateway")
            ok = ok and all(record[k] == layer[k] for k in record)
    elif case == "outer-ipv4-options":
        length = f["ipv4_header_words"]
        ok = (
            f["pf10_selected"] is True
            and type(length) is int
            and 5 < length <= 15
            and f["accepted"] is True
        )
    elif case == "outer-gray-default-admission":
        ok = (
            f["zone"] == "Gray"
            and f["matched_explicit_rule"] is False
            and f["default_policy"] == "ACCEPT"
            and f["approved"] is False
            and f["accepted"] is True
        )
        snap = json.loads((native / "snapshot.json").read_bytes())
        ok = ok and any(
            c["device_id"] == anchor
            and c["table"] == "filter"
            and c["family"] == 4
            and c["chain"] == f["chain"]
            and c["policy"].lower() == "accept"
            for c in snap["filters"]
        )
    elif case == "gray-management-data-interface":
        ok = (
            f["interface_role"] == "data"
            and f["local_management_session"] is True
            and f["accepted"] is True
        )
    else:
        from ipaddress import ip_address

        source = ip_address(f["source"])
        prefixes = [ip_network(p) for p in f["reachable_prefixes"]]
        ok = (
            bool(f["ingress"])
            and f["accepted"] is True
            and f["complete_ingress_routes"] is True
            and all(source not in p for p in prefixes)
        )
    if not ok:
        raise ValueError("The independent recording does not establish the registered behavior")
