"""Select existing single-fault captures for a blinded static-snapshot study."""

import argparse
from collections import Counter, defaultdict
from difflib import SequenceMatcher
import hashlib
import hmac
from ipaddress import ip_interface
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sys

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from architecture_cases import raw_observations
from scale.blinding import neutral_bundle
from scale.catalog import FIREWALL_CHAINS as HISTORICAL_CHAINS
from scale.design import (BASE_CONTROL, CASES, CONTROLS, PANEL_REVISION, VERSION, cases_for, key_attestations, deployment_policy,
                          control_run_root, control_topology, controls_for, topology_digest, validate_case_observation,
                          validate_control_shape, validate_health)
from scale.observation_window import fingerprint, validate_window
from scale.profiles import NETWORKS, profile
from scale.verification import connections, read
from snapshot_inputs import put, publish_capture
from tdn_evidence.parsers.correspondence import parse_iptables_save

ROLES = {
    "inner": (
        "inner-peer-loopback",
        "inner-mode",
        "inner-empty-ipv4-header",
        "shared-inner-gateway",
        "gray-cross-level-path",
        "inner-gray-application",
        "inner-cross-level-auth",
        "inner-gray-plaintext-delivery",
        "inner-outbound-protection",
        "shared-layer-key-context",
    ),
    "outer": (
        "outer-mode",
        "outer-eligible-deny",
        "outer-firewall-alternate-path",
        "outer-black-multicast",
        "outer-gray-wrong-ingress",
        "outer-unintended-peer",
        "outer-outbound-protection",
        "outer-ipv4-options",
        "outer-gray-default-admission",
        "outer-gray-source-reachability",
    ),
    "firewall": (
        "firewall-inside-disconnected",
        "firewall-outside-disconnected",
        "firewall-local-empty-udp",
    ),
    "gray-firewall": (
        "gray-cross-level-forward",
        "gray-ordinary-http",
        "gray-authorized-ike-deny",
        "gray-management-data-interface",
    ),
}
MIN_CHANGED_RULE_POSITION = 2
PER_LEVEL = {
    "outer-outbound-protection",
    "outer-eligible-deny",
    "outer-gray-wrong-ingress",
    "gray-cross-level-forward",
    "gray-ordinary-http",
    "gray-authorized-ike-deny",
    "outer-gray-source-reachability",
}
FIREWALL_CHAINS = {c.key: HISTORICAL_CHAINS[c.key] for c in CASES if c.key in HISTORICAL_CHAINS}
FIREWALL_CHAINS.update({"outer-gray-source-reachability":"INPUT", "gray-management-data-interface":"INPUT",
                        "outer-ipv4-options":"INPUT"})


def eligible(spec, kind):
    (role,) = [r for r, kinds in ROLES.items() if kind in kinds]
    inner_levels = {
        d["tunnel"]["local"]: d["level"]
        for d in spec["devices"]
        if d["role"] == "inner"
    }
    result = []
    for d in spec["devices"]:
        if d["role"] != role:
            continue
        if kind in PER_LEVEL:
            flows = (
                d["boundary_flows"] if role == "gray-firewall" else d["tunnel"]["flows"]
            )
            levels = {
                inner_levels[
                    str(
                        ip_interface(
                            f["source"] if role == "gray-firewall" else f["local"]
                        ).ip
                    )
                ]
                for f in flows
            }
        else:
            levels = {d["level"] if role == "inner" else None}
        result.extend((d["id"], level) for level in sorted(levels))
    return sorted(result)


BACKGROUND_PLAN = Path(__file__).with_name("observation-plan.json")


def register(folder, seed=None, background_plan=BACKGROUND_PLAN):
    if folder.exists():
        raise ValueError("A placement registration requires a new study directory")
    seed = seed if seed is not None else secrets.token_bytes(32)
    if len(seed) < 16:
        raise ValueError("The private registration seed must have at least 128 bits")
    rule_types = sorted(
        FIREWALL_CHAINS, key=lambda k: hmac.digest(seed, ("depth/" + k).encode(), "sha256")
    )
    bands = {k: i % 3 for i, k in enumerate(rule_types)}
    ranked_cases = sorted((case.key for case in CASES),
                          key=lambda k: hmac.digest(seed, ("control/" + k).encode(), "sha256"))
    control_order = sorted(CONTROLS, key=lambda k: hmac.digest(seed, k.encode(), "sha256"))
    matched = {key: control_order[i % len(control_order)] for i, key in enumerate(ranked_cases)}
    rows = {}
    for n in NETWORKS:
        spec = profile(n)["topology"]
        for case in CASES:
            population = eligible(spec, case.key)
            key = n + "/" + case.key

            def order(value):
                return hmac.digest(seed, json.dumps([key, value]).encode(), "sha256")

            selected = min(population, key=order)
            rows[key] = {
                "anchor": selected[0],
                "level": selected[1],
                "eligible": len(population),
                "control_variant": matched[case.key],
                "rule_depth_third": bands.get(case.key),
            }
    folder.mkdir(parents=True, mode=0o700)
    put(
        folder / "placement-plan.json",
        {
            "seed": seed.hex(),
            "algorithm": "hmac-sha256/v1",
            "minimum_changed_rule_position": MIN_CHANGED_RULE_POSITION,
            "controls": {n:{k:topology_digest(control_topology(n,k)) for k in CONTROLS} for n in NETWORKS},
            "control_filters_sha256": fingerprint(Path(__file__).with_name("control_filters.py")),
            "deployment_policies": {n:deployment_policy(profile(n)["topology"]) for n in NETWORKS},
            "cells": rows,
            "background_plan_sha256": fingerprint(background_plan),
        },
    )
    from scale.study import initialize

    initialize(folder, panel=True)


def first_filter_rules(snapshot):
    first = {}
    for chain in snapshot["filters"]:
        if chain["table"] != "filter":
            continue
        key = (chain["device_id"], chain["family"], chain["chain"])
        if key in first:
            raise ValueError(f"Duplicate captured firewall chain {key}")
        rules = chain["ordered_rules"]
        if not rules:
            first[key] = None
            continue
        row = rules[0]
        tokens = shlex.split(row["raw_text"])
        if row["ordinal"] != 0 or tokens[:2] != ["-A", chain["chain"]]:
            raise ValueError(f"Missing first rule in captured firewall chain {key}")
        first[key] = tuple(tokens[2:])
    return first


def fixed_high_services(snapshot):
    owners = defaultdict(set)
    for chain in snapshot["filters"]:
        if chain["table"] != "filter":
            continue
        for row in chain["ordered_rules"]:
            tokens = shlex.split(row["raw_text"])
            for flag,value in zip(tokens,tokens[1:]):
                if flag not in {"--sport","--sports","--dport","--dports"}:
                    continue
                for item in value.split(","):
                    if item.isdecimal() and 32768 <= int(item) <= 65535:
                        owners[int(item)].add(chain["device_id"])
    return owners


def changed_first_rules(healthy, faulty):
    return sorted(key for key in healthy.keys() | faulty.keys() if healthy.get(key) != faulty.get(key))


def ipv4_filter_orders(snapshot):
    return {(c["device_id"], c["chain"]): tuple(r["raw_text"] for r in c["ordered_rules"])
            for c in snapshot["filters"] if c["family"] == 4 and c["table"] == "filter"
            and c["chain"] in ("INPUT", "FORWARD")}


def validate_companion_orders(clean, observed, affected):
    for key, before in clean.items():
        after = observed.get(key)
        if key != affected and after is not None and before != after and Counter(before) == Counter(after):
            raise ValueError(f"{key[0]} {key[1]} has a different rule order from the matched control")


def rule_depth_third(position, chain_length):
    if not MIN_CHANGED_RULE_POSITION <= position <= chain_length:
        raise ValueError("A faulty firewall rule must be at row 2 or later in its actual chain")
    eligible_count = chain_length - MIN_CHANGED_RULE_POSITION + 1
    return 3 * (position - MIN_CHANGED_RULE_POSITION) // eligible_count


def changed_rules(clean, faulty, kind, anchor):
    hook = FIREWALL_CHAINS.get(kind) or HISTORICAL_CHAINS.get(kind)
    if not hook:
        return None

    def rules(native):
        text = raw_observations(native)[anchor, "filters4"]
        return [
            (tuple(r["tokens"]), r["action"])
            for r in parse_iptables_save(text)[hook]["rules"]
        ]

    old, new = rules(clean), rules(faulty)
    edits = [e for e in SequenceMatcher(None, old, new, autojunk=False).get_opcodes() if e[0] != "equal"]
    removed_only = bool(edits) and all(op == "delete" for op, *_ in edits)
    rows = old if removed_only else new
    changed = [i for op, a, b, c, d in edits for i in (range(a, b) if removed_only else range(c, d))]
    if not changed:
        raise ValueError(f"No observed change in the registered chain of {anchor}")

    def ports(rows):
        return {
            v
            for tokens, _ in rows
            for i, t in enumerate(tokens)
            if t in {"--sport", "--dport", "--sports", "--dports"}
            for v in tokens[i + 1].split(",")
            if v.isdigit() and int(v) >= 32768
        }

    selectors = [
        {flag: tokens[j + 1] for j, flag in enumerate(tokens) if flag in {"-s", "-i"}}
        for i in changed
        for tokens, _ in [rows[i]]
    ]
    return {
        "hook": hook,
        "length": len(rows),
        "ranks": [i + 1 for i in changed],
        "selectors": selectors,
        "new_high_ports": sorted(ports(new) - ports(old)),
        "mentioned": sorted({word for i in changed for word in rows[i][0]}),
    }


def interface_names(native):
    return {i["name"] for i in read(native / "snapshot.json")["interfaces"]}


def child_names(snapshot):
    return {
        name
        for tunnel in snapshot["tunnels"]
        for name in re.findall(
            r"([^\s{}]+)\s*\{mode=", tunnel.get("all_runtime_connections") or ""
        )
    }


def linked_endpoints(native, device):
    return {
        tuple(sorted(link["endpoint_interface_ids"]))
        for link in read(native / "snapshot.json")["links"]
        if link["relation"] == "veth"
        and link["status"] == "observed"
        and any(
            end.split(":", 1)[0] == device for end in link["endpoint_interface_ids"]
        )
    }


def verify_level(spec, kind, anchor, level, difference):
    if kind not in PER_LEVEL or kind == "outer-outbound-protection":
        return
    d = next(d for d in spec["devices"] if d["id"] == anchor)
    inners = {
        x["tunnel"]["local"]: x["level"]
        for x in spec["devices"]
        if x["role"] == "inner"
    }
    if d["role"] == "gray-firewall":
        flows = [(f["source"], f["ingress"]) for f in d["boundary_flows"]]
    else:
        flows = [(f["local"], f["inside"]) for f in d["tunnel"]["flows"]]

    def selects(rule, ip, iface):
        if "-i" in rule:
            return rule["-i"] == iface
        return "-s" in rule and ip_interface(rule["-s"]).network == ip_interface(ip).network

    if not any(
        inners[str(ip_interface(ip).ip)] == level and selects(rule, ip, iface)
        for ip, iface in flows
        for rule in difference["selectors"]
    ):
        raise ValueError("Observed rule change does not identify the registered level")


def detector_input(source, n, output, seed, *, protocol=None, variant=BASE_CONTROL):
    observations_only = (protocol or {}).get("method_version") == VERSION
    name, _ = publish_capture(
        source,
        output / "private-inputs",
        [] if observations_only else connections(source / "native"),
        intent=control_topology(n, variant) if observations_only else profile(n)["topology"],
        declared_catalogue=True,
    )
    policy = (
        read(output / "placement-plan.json")["deployment_policies"][n] if observations_only else None
    )
    public = neutral_bundle(output / "private-inputs" / name, output / "raw", seed, policy=policy)
    return name, public


def collect_control(folder, network, kind, output, schedule):
    from capture_stable import capture_stable
    from restore_health import verify
    from scale.design import control_profile
    from scale.observation_window import freeze_then_confirm

    protocol = read(folder / "protocol.json")
    if protocol.get("panel_revision") != PANEL_REVISION or protocol.get("placement_sha256") != fingerprint(
        folder / "placement-plan.json"
    ):
        raise ValueError("Control collection needs an intact current registration")
    plan = read(folder / "placement-plan.json")
    registered = control_profile(network, kind)
    if (
        fingerprint(schedule) != plan["background_plan_sha256"]
        or topology_digest(registered["topology"]) != plan["controls"][network][kind]
    ):
        raise ValueError("Control design or observation schedule differs from registration")

    def collect():
        if capture_stable(registered, output)["converged"] is not True:
            raise ValueError("The healthy network did not converge")

    def confirm():
        report = verify(registered, repair=False)
        path = output / "control-health.json"
        put(path, report)
        validate_health(network, report)
        return path

    freeze_then_confirm(output, schedule, collect, confirm)


def prepare(folder, candidates):
    protocol = read(folder / "protocol.json")
    current = protocol.get("method_version") == VERSION
    cases = CASES if current else cases_for(protocol)
    controls = controls_for(protocol)
    registered_plan = protocol.get("placement_sha256")
    if registered_plan != fingerprint(folder / "placement-plan.json"):
        raise ValueError("The placement assignments have changed since registration")
    plan = read(folder / "placement-plan.json")
    if set(plan["cells"]) != {n + "/" + case.key for n in NETWORKS for case in cases}:
        raise ValueError("The placement plan does not match the registered catalogue")
    if current and (protocol.get("panel_revision") != PANEL_REVISION or
                    plan.get("control_filters_sha256") != fingerprint(Path(__file__).with_name("control_filters.py"))):
        raise ValueError("Register a fresh panel with the current healthy rule order and matched controls")
    schedule = plan.get("background_plan_sha256", fingerprint(BACKGROUND_PLAN))
    pool = read(candidates)

    def resolve(p):
        return (candidates.parent / p).resolve()

    if (folder / "approved-panel.json").exists():
        raise ValueError("This panel has already been sealed")
    results = []
    errors = []
    entries = defaultdict(list)
    registered = set()
    for row in pool["trials"]:
        key = (row["network"], row["case"], row["anchor"], row["level"])
        trial = resolve(row["trial"])
        if trial in registered:
            raise ValueError("One independent observation can be registered only once")
        if row.get("rule_depth_third") not in (None, 0, 1, 2):
            raise ValueError("Invalid firewall depth in candidate catalogue")
        registered.add(trial)
        entries[key].append(row)
    if set(pool["controls"]) != set(NETWORKS):
        raise ValueError("Supply the registered controls for each topology")
    control_sources = set()
    for n in NETWORKS:
        seed = hmac.digest(bytes.fromhex(plan["seed"]), n.encode(), "sha256")
        paths = pool["controls"][n] if current else {BASE_CONTROL: pool["controls"][n]}
        if not isinstance(paths, dict) or set(paths) != set(controls):
            raise ValueError(f"Supply {', '.join(controls)} for {n}")
        healthy_contexts = None
        baselines = {}
        for k in controls:
            control = resolve(paths[k])
            try:
                if (
                    control in control_sources
                    or control in registered
                    or read(control / "capture.json")["converged"] is not True
                ):
                    raise ValueError("A control must be a distinct converged capture")
                control_sources.add(control)
                health_path = control / "control-health.json"
                validate_window(
                    control,
                    schedule,
                    fingerprint(health_path) if current else None,
                    require_metadata=current,
                    require_variant=current,
                )
                if current:
                    validate_health(n, read(health_path))
                    if topology_digest(control_topology(n, k)) != plan["controls"][n][k]:
                        raise ValueError("The registered control design changed")
                    observations = read(control / "snapshot/native/snapshot.json")
                    validate_control_shape(
                        n, k, observations, read(control / "snapshot/spec.json"), healthy=True
                    )
                    if read(control / "capture.json").get("control_variant") != k:
                        raise ValueError("Healthy capture names a different control variant")
                    contexts = set(key_attestations(control / "snapshot/native", observations,
                                                    healthy=True, require_complete=True))
                    if healthy_contexts is None:
                        healthy_contexts = contexts
                    if contexts != healthy_contexts:
                        raise ValueError(
                            "The controls have different public key-origin evidence available"
                        )
                raw, public = detector_input(control / "snapshot", n, folder, seed, protocol=protocol, variant=k)
                if any(public == row["bundle"] or raw == row["source_bundle"] for _, _, row in results):
                    raise ValueError("A control reused another scored input")
                native = control / "snapshot/native"
                clean = read(native / "snapshot.json")
                baselines[k] = (native, interface_names(native), child_names(clean), first_filter_rules(clean),
                                set(fixed_high_services(clean)) if current else set(), ipv4_filter_orders(clean))
                results.append(
                    (
                        n,
                        k,
                        dict(
                            control=True,
                            control_variant=k,
                            observed=False,
                            bundle=public,
                            source_bundle=raw,
                            snapshot=str(control / "snapshot"),
                        ),
                    )
                )
            except (KeyError, OSError, TypeError, ValueError) as error:
                errors.append([n, k, str(error)])
        for case in cases:
            target = plan["cells"][n + "/" + case.key]
            variant = target["control_variant"] if current else BASE_CONTROL
            if variant not in baselines:
                errors.append([n, case.key, "Missing qualified matched control: " + variant])
                continue
            clean_native, clean_names, clean_children, clean_first_rules, healthy_services, clean_orders = baselines[variant]
            matching = entries.get((n, case.key, target["anchor"], target["level"]), [])
            if not matching:
                errors.append([n, case.key, "Missing independently captured location"])
                continue
            if current:
                matching = [r for r in matching if r.get("control_variant") == variant]
                if not matching:
                    errors.append([n, case.key, "No candidate names the registered healthy configuration " + variant])
                    continue
            candidates_at_depth = [
                r
                for r in matching
                if r.get("rule_depth_third", target["rule_depth_third"]) == target["rule_depth_third"]
            ]
            if not candidates_at_depth:
                errors.append([n, case.key, "Missing registered firewall depth at this location"])
                continue
            entry = min(
                candidates_at_depth,
                key=lambda row: hmac.digest(seed, str(row["location_sha256"]).encode(), "sha256"),
            )
            trial = resolve(entry["trial"])
            capture = trial / "capture"
            try:
                receipt = read(trial / "cell.json")
                if (
                    receipt["network"] != n
                    or receipt["case"] != case.key
                    or receipt["observed"] is not True
                    or read(capture / "capture.json")["converged"] is not True
                    or read(trial / "post-health.json")["ready"] is not True
                ):
                    raise ValueError("Missing stable, exercised and restored trial")
                path = (trial / entry["location_evidence"]).resolve()
                if not path.is_relative_to((trial / "operator").resolve()) or not path.is_file():
                    raise ValueError("Missing independent operator location evidence")
                body = path.read_bytes()
                if hashlib.sha256(body).hexdigest() != entry["location_sha256"]:
                    raise ValueError("The independent operator observation has changed")
                faulty_snapshot = read(capture / "snapshot/native/snapshot.json")
                if current:
                    if read(capture / "capture.json").get("control_variant") != variant:
                        raise ValueError("Fault capture names a different control variant")
                    if set(key_attestations(capture / "snapshot/native", faulty_snapshot, require_complete=True)) != healthy_contexts:
                        raise ValueError(
                            "Available public key-origin evidence differs from the matched control"
                        )
                    validate_case_observation(
                        case.key,
                        target["anchor"],
                        target["level"],
                        body,
                        trial / "operator",
                        capture / "snapshot/native",
                    )
                    validate_control_shape(
                        n,
                        variant,
                        faulty_snapshot,
                        read(capture / "snapshot/spec.json"),
                        healthy=False,
                    )
                    validate_companion_orders(clean_orders, ipv4_filter_orders(faulty_snapshot),
                                              (target["anchor"], FIREWALL_CHAINS.get(case.key)))
                    single_services = [
                        port
                        for port, owners in fixed_high_services(faulty_snapshot).items()
                        if port not in healthy_services and len(owners) == 1
                    ]
                    if single_services:
                        raise ValueError(
                            f"A single device has a new high service port absent from its matched control: {sorted(single_services)}"
                        )
                changed_heads = changed_first_rules(
                    clean_first_rules, first_filter_rules(faulty_snapshot)
                )
                if changed_heads:
                    locations = ", ".join(
                        f"{dev} IPv{family} {chain}" for dev, family, chain in changed_heads
                    )
                    raise ValueError(f"Firewall rule 1 differs from the healthy control in {locations}")
                difference = changed_rules(
                    clean_native,
                    capture / "snapshot/native",
                    case.key,
                    target["anchor"],
                )
                if (
                    not difference
                    and target["anchor"] not in body.decode()
                    and linked_endpoints(clean_native, target["anchor"])
                    == linked_endpoints(capture / "snapshot/native", target["anchor"])
                ):
                    raise ValueError(
                        "The registered anchor is absent from the operator observation and link change"
                    )
                verify_level(
                    profile(n)["topology"],
                    case.key,
                    target["anchor"],
                    target["level"],
                    difference,
                )
                if difference:
                    observed_third = rule_depth_third(difference["ranks"][0], difference["length"])
                    if observed_third != target["rule_depth_third"]:
                        raise ValueError(
                            "Observed firewall rule depth differs from the registered sample stratum"
                        )
                validate_window(capture, schedule, entry["location_sha256"], require_metadata=current,
                                require_variant=current)
                raw, public = detector_input(capture / "snapshot", n, folder, seed, protocol=protocol, variant=variant)
                if current and any(
                    public == row["bundle"] or raw == row["source_bundle"] for _, _, row in results
                ):
                    raise ValueError("A scored trial reused another capture")
                results.append(
                    (
                        n,
                        case.key,
                        dict(
                            observed=True,
                            control_variant=variant,
                            bundle=public,
                            source_bundle=raw,
                            snapshot=str(capture / "snapshot"),
                            anchor=target["anchor"],
                            level=target["level"],
                            rule_position=difference,
                            location_evidence=str(path),
                            location_sha256=entry["location_sha256"],
                            new_tunnel_names=sorted(child_names(faulty_snapshot) - clean_children),
                            new_interface_names=sorted(
                                interface_names(capture / "snapshot/native") - clean_names
                            ),
                        ),
                    )
                )
            except (KeyError, OSError, TypeError, ValueError) as error:
                errors.append([n, case.key, str(error)])
    for case in cases:
        selected = [r for _, k, r in results if k == case.key]
        if len(selected) == len(NETWORKS):
            names = set.intersection(*(set(r["new_interface_names"]) for r in selected))
            ports = set.intersection(
                *(set((r["rule_position"] or {}).get("new_high_ports", [])) for r in selected)
            )
            tunnels = set.intersection(*(set(r["new_tunnel_names"]) for r in selected))
            if names or ports or tunnels:
                errors.append(
                    [
                        "all",
                        case.key,
                        "Repeated interface name, tunnel name or high service port absent from matching controls",
                        {
                            "interfaces": sorted(names),
                            "tunnels": sorted(tunnels),
                            "ports": sorted(ports),
                        },
                    ]
                )
    rejected = {(e[0], e[1]) for e in errors}
    qualified = {(n, k) for n, k, _ in results if (n, k) not in rejected and ("all", k) not in rejected}
    audit = {
        "cells_checked": len(plan["cells"]),
        "control_sessions": len(controls) * len(NETWORKS),
        "qualified_controls": sum(k in controls for _, k in qualified),
        "qualified_faults": sum(k not in controls for _, k in qualified),
        "errors": errors,
    }
    (folder / "panel-preflight.json").write_text(json.dumps(audit, indent=2) + "\n")
    if errors:
        raise ValueError(f"{len(errors)} outstanding panel checks; see panel-preflight.json")
    for n, kind, record in results:
        put(folder / "measurements" / n / kind / "cell.json", record)
    put(
        folder / "approved-panel.json",
        {
            "method_version": protocol.get("method_version", 2),
            "protocol_sha256": fingerprint(folder / "protocol.json"),
            "minimum_changed_rule_position": MIN_CHANGED_RULE_POSITION,
            "background_plan_sha256": schedule,
            "placement_sha256": hashlib.sha256(
                (folder / "placement-plan.json").read_bytes()
            ).hexdigest(),
            "candidate_manifest_sha256": hashlib.sha256(candidates.read_bytes()).hexdigest(),
            "inputs": {n + "/" + k: r["bundle"] for n, k, r in results},
            "sources": {n + "/" + k: r["source_bundle"] for n, k, r in results},
            "matched_controls": {n + "/" + k: r["control_variant"] for n, k, r in results},
        },
    )


def approved_panel(folder, *, for_execution=True):
    seal = read(folder / "approved-panel.json")
    if seal.get("minimum_changed_rule_position") != MIN_CHANGED_RULE_POSITION:
        raise ValueError(
            "The saved panel predates the row-one check. Requalify its captures before a new detector run."
        )
    protocol = read(folder / "protocol.json")
    cases_for(protocol)
    if seal["method_version"] != protocol.get("method_version"):
        raise ValueError("The protocol and approved panel use different versions")
    if seal["method_version"] == VERSION and seal.get("protocol_sha256") != fingerprint(
        folder / "protocol.json"
    ):
        raise ValueError("The approved protocol has changed")
    if seal.get("placement_sha256") != fingerprint(folder / "placement-plan.json"):
        raise ValueError("The approved placement plan has changed")
    if for_execution and seal["method_version"] == VERSION and protocol.get("panel_revision") != PANEL_REVISION:
        raise ValueError("Register a fresh matched-control panel before running the detectors")
    if seal["method_version"] == VERSION and protocol.get("panel_revision") == PANEL_REVISION:
        expected = {k: v["control_variant"] for k, v in read(folder / "placement-plan.json")["cells"].items()}
        expected.update({n + "/" + k: k for n in NETWORKS for k in CONTROLS})
        if seal.get("matched_controls") != expected:
            raise ValueError("Sealed control assignments differ from the registration")
    return seal


def verify_panel(folder, workers):
    from concurrent.futures import ThreadPoolExecutor
    from scale.verification import REGISTERED_PROOF_SUITES, verify
    from scale.review import lean_verdict, record_lean
    from scale.study import archive

    seal = approved_panel(folder)
    protocol = read(folder / "protocol.json")
    if (
        seal["placement_sha256"]
        != hashlib.sha256((folder / "placement-plan.json").read_bytes()).hexdigest()
    ):
        raise ValueError("The sealed placement assignments have changed")
    approved = seal["inputs"]
    controls = controls_for(protocol)
    expected = {
        n + "/" + k for n in NETWORKS for k in [*controls, *(c.key for c in cases_for(protocol))]
    }
    if set(approved) != expected:
        raise ValueError("Every registered capture and control must be present")
    os.environ["TDN_BENCHMARK_LEAN_TIMEOUT"] = str(protocol["lean_process_timeout_seconds"])
    repo = HERE.parents[2]
    sources = set((repo / "TDN").rglob("*.lean")) | set((repo / "mcp/tdn_evidence").rglob("*.py"))
    for base in (HERE, HERE / "perimeter", HERE / "scale"):
        sources.update(p for p in base.iterdir() if p.suffix in {".lean", ".py", ".json"})
    put(
        folder / "checker-sources.json",
        {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)},
    )

    def run(cell):
        n, k = cell.split("/")
        p = folder / "measurements" / n / k
        rec = read(p / "cell.json")
        if rec["bundle"] != approved[cell] or (
            protocol.get("method_version") == VERSION and seal["sources"][cell] != rec["source_bundle"]
        ):
            raise ValueError("Panel registration differs")
        native = Path(rec["snapshot"])
        seed = hmac.digest(
            bytes.fromhex(read(folder / "placement-plan.json")["seed"]),
            n.encode(),
            "sha256",
        )
        variant = seal.get("matched_controls", {}).get(cell, BASE_CONTROL)
        if detector_input(native, n, folder, seed, protocol=protocol, variant=variant) != (
            rec["source_bundle"],
            rec["bundle"],
        ):
            raise ValueError("The TDN source snapshot has changed since blind registration")
        is_control = k in controls
        if protocol.get("method_version") == VERSION and rec.get("control_variant") != variant:
            raise ValueError("The scored cell differs from its sealed control assignment")
        proof_root = control_run_root(folder, n, variant)
        if is_control:
            source = proof_root / "raw/controls" / n
            source.mkdir(parents=True, exist_ok=True)
            if not (source / "snapshot").exists():
                (source / "snapshot").symlink_to(native, target_is_directory=True)
            if (source / "snapshot").resolve() != native.resolve():
                raise ValueError("Different control registered for " + n)
            dest = proof_root / "controls" / (n + "-frozen")
            dest.parent.mkdir(exist_ok=True)
        else:
            dest = p / "tdn"
        if (dest / "verification.json").is_file():
            checks = read(dest / "verification.json")
        else:
            archive(dest)
            checks = verify(proof_root, n, native, dest, control=is_control,
                            control_variant=variant if protocol.get("method_version") == VERSION else None,
                            registered_policy=(read(folder / "placement-plan.json")["deployment_policies"][n]
                                               if protocol.get("method_version") == VERSION else None))
        if protocol.get("panel_revision") == PANEL_REVISION:
            missing = REGISTERED_PROOF_SUITES - checks.keys()
            if missing:
                raise ValueError(f"Incomplete Lean verification for {cell}. Missing {', '.join(sorted(missing))}")
        if k == BASE_CONTROL:
            if not checks or any(c["status"] != "pass" for c in checks.values()):
                raise ValueError("Clean recheck failed for " + n)
        elif is_control:
            matched = read(folder / "controls" / (n + "-frozen") / "verification.json")
            if set(checks) != set(matched):
                result, failures = "needs_repair", {}
                errors = {
                    key: checks.get(key, {}).get("status", "missing")
                    for key in set(checks) | set(matched)
                    if key not in matched or checks.get(key, {}).get("status") != "pass"
                }
            else:
                result, failures, errors = lean_verdict(checks, matched)
            status = {"detected": "false_alarm", "needs_repair": "incomplete", "missed": "accepted"}[
                result
            ]
            put(
                p / "tdn-control.json",
                {"status": status, "failed_assertions": failures, "incomplete_checks": errors},
            )
        else:
            record_lean(folder, n, k)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(run, [n + "/" + BASE_CONTROL for n in NETWORKS]))
        list(pool.map(run, [n + "/" + k for n in NETWORKS for k in controls if k != BASE_CONTROL]))
        list(pool.map(run, [c for c in approved if c.split("/")[1] not in controls]))


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument(
        "action", choices=["catalog", "register", "collect-control", "prepare", "astra", "tdn"]
    )
    cli.add_argument("study", nargs="?", type=Path)
    cli.add_argument("--candidates", type=Path)
    cli.add_argument("--network", choices=NETWORKS)
    cli.add_argument("--control", choices=CONTROLS)
    cli.add_argument(
        "--output", type=Path, help="Fresh directory for an already deployed healthy control"
    )
    cli.add_argument(
        "--background-plan",
        type=Path,
        default=BACKGROUND_PLAN,
        help="Shared workload and observation schedule to freeze at registration",
    )
    cli.add_argument("--workers", type=int, choices=range(1, 5), default=2)
    args = cli.parse_args()
    if args.action == "catalog":
        from scale.design import clause_coverage

        print(
            json.dumps(
                {
                    "method_version": VERSION,
                    "cases": [vars(c) for c in CASES],
                    "clause_cases": clause_coverage(CASES),
                },
                indent=2,
            )
        )
    elif args.study is None:
        cli.error(f"{args.action} requires a study directory")
    elif args.action == "register":
        register(args.study.resolve(), background_plan=args.background_plan)
    elif args.action == "collect-control":
        if not (args.network and args.control and args.output):
            cli.error("collect-control requires --network, --control and --output")
        collect_control(
            args.study.resolve(), args.network, args.control, args.output.resolve(), args.background_plan
        )
    elif args.action == "prepare":
        if not args.candidates:
            cli.error("prepare requires --candidates")
        prepare(args.study.resolve(), args.candidates.resolve())
    elif args.action == "tdn":
        verify_panel(args.study.resolve(), args.workers)
    else:
        from scale.study import stream

        stream(args.study.resolve(), "astra", args.workers)
