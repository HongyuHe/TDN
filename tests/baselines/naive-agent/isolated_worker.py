"""Restore, inject one case, and collect a fresh snapshot on the experiment worker."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

from worker import command, docker, now, write_json
from mutate import apply
from prepare_blind_networks import repair
from rollback import restore
from validate_live import evaluate


def must(record):
    if record["returncode"]:
        raise RuntimeError(record)
    return record


def establish(profiles):
    devices = [d for p in profiles for d in p["topology"]["devices"] if "tunnel" in d]
    loads, initiations = [], []
    def load(device):
        return {"device": device["id"], "commands": [must(docker(device["id"], argv)) for argv in [
            ["swanctl", "--load-creds", "--clear", "--noprompt"], ["swanctl", "--load-conns"]]]}
    with ThreadPoolExecutor(max_workers=8) as pool:
        loads = list(pool.map(load, devices))
    with ThreadPoolExecutor(max_workers=8) as pool:
        terminated = list(pool.map(lambda d: docker(d["id"], ["swanctl", "--terminate", "--ike", "msc", "--force"]), devices))
    for role in ["outer", "inner"]:
        pairs = [d for d in devices if d["role"] == role and d.get("site") == "A"]
        with ThreadPoolExecutor(max_workers=8) as pool:
            initiations.extend(pool.map(lambda d: {"device": d["id"], **docker(d["id"],
                ["swanctl", "--initiate", "--child", "protected", "--timeout", "12"])}, pairs))
    attempts = []
    for _ in range(45):
        time.sleep(2)
        with ThreadPoolExecutor(max_workers=8) as pool:
            states = list(pool.map(lambda d: {"device": d["id"], **docker(d["id"],
                ["swanctl", "--list-sas", "--raw"])}, devices))
        attempts.append({"at": now(), "states": states})
        if all(s["returncode"] == 0 and s["stdout"].count("state=ESTABLISHED") >= 1
               and s["stdout"].count("state=INSTALLED") >= 1
               and not re.search(r"state=(DELETING|REKEYING|CONNECTING)", s["stdout"]) for s in states):
            return {"terminations": terminated, "loads": loads, "initiations": initiations,
                    "states": states, "convergence_attempts": attempts, "expected_endpoints": len(devices),
                    "installed_child_endpoints": len(devices), "established_endpoints": len(devices),
                    "no_closing_sessions": True}
    raise ValueError({"tunnel_sessions_not_settled": attempts[-1]})


def clean(profile, baseline, journal_root):
    for case in profile["mutations"]:
        if case["operation"] == "ospf":
            name = case["device"] + "-routing"
            info = command(["docker", "inspect", name])
            if info["returncode"] == 0:
                item = json.loads(info["stdout"])[0]
                device = json.loads(must(command(["docker", "inspect", case["device"]]))["stdout"])[0]
                if item["HostConfig"]["NetworkMode"] not in {"container:" + case["device"], "container:" + device["Id"]}:
                    raise ValueError("Unexpected routing helper ownership")
                must(command(["docker", "rm", "-f", name]))
    saved = journal_root / "private/baseline"
    saved.parent.mkdir(parents=True, exist_ok=True)
    if not saved.exists():
        saved.symlink_to(baseline / "private/baseline", target_is_directory=True)
    result = restore(profile, journal_root)
    tunnels = establish([profile])
    if tunnels["installed_child_endpoints"] != tunnels["expected_endpoints"]:
        raise ValueError("Clean tunnel establishment failed")
    return {"rollback": result, "tunnels": tunnels}


def fingerprints(profile):
    deployment = Path(profile["deployment_directory"])
    records = {}
    for path in sorted((deployment / "devices").rglob("*")):
        relative = path.relative_to(deployment)
        if path.is_file() and not path.is_symlink() and not any(x in relative.parts for x in ["private", "conf.d"]):
            records[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()

    def inspect(device):
        name = device["id"]
        data = {}
        for key, argv in {
            "filters4": ["iptables-save", "-t", "filter"],
            "filters6": ["ip6tables-save", "-t", "filter"],
            "routes4": ["ip", "-j", "-4", "route", "show", "table", "all"],
            "rules4": ["ip", "-j", "-4", "rule", "show"],
            "interfaces": ["ip", "-j", "link", "show"],
            "source_checks": ["sysctl", "net.ipv4.conf.all.rp_filter", *[
                "net.ipv4.conf." + i["name"] + ".rp_filter" for i in device["interfaces"]]],
        }.items():
            body = must(docker(name, argv))["stdout"]
            if key.startswith("filters"):
                body = "\n".join(re.sub(r"\[\d+:\d+\]", "[0:0]", line) for line in body.splitlines() if not line.startswith("#"))
            elif key == "interfaces":
                body = json.dumps(sorted((x["ifname"], sorted(x["flags"]), x["mtu"]) for x in json.loads(body)))
            elif key in {"routes4", "rules4"}:
                entries = json.loads(body)
                for item in entries:
                    item.pop("expires", None)
                    item.pop("used", None)
                body = json.dumps(sorted(entries, key=lambda x: json.dumps(x, sort_keys=True)), sort_keys=True)
            data[name + "/" + key] = hashlib.sha256(body.encode()).hexdigest()
        return data

    with ThreadPoolExecutor(max_workers=4) as pool:
        for item in pool.map(inspect, profile["topology"]["devices"]):
            records.update(item)
    return records


def collect(profile, target, sources, run_id):
    spec = copy.deepcopy(profile["topology"])
    for device in spec["devices"]:
        rows = json.loads(must(docker(device["id"], ["ip", "-j", "-d", "address", "show"]))["stdout"])
        declared = {i["name"] for i in device["interfaces"]}
        for iface in rows:
            if iface["ifname"] not in declared and iface.get("linkinfo", {}).get("info_kind") == "dummy":
                device["interfaces"].append({"name": iface["ifname"], "zone": "local", "mtu": iface["mtu"]})
    target.mkdir(parents=True, exist_ok=False)
    write_json(target / "spec.json", spec)
    results = []
    commands = [
        [sys.executable, str(sources / "collect_native_v2.py"), "--spec", str(target / "spec.json"),
         "--output", str(target / "native"), "--configuration-id", profile["network"], "--run-id", run_id,
         "--platform-interface-names", "gre0,gretap0,erspan0", "--skip-active-probes"],
        [sys.executable, str(sources / "collect_processing.py"), "--spec", str(target / "spec.json"),
         "--output", str(target / "processing")],
    ]
    for argv in commands:
        result = command(argv, timeout=360)
        results.append(result)
        write_json(target / "collection.json", results)
        must(result)
    manifest = json.loads((target / "native/manifest.json").read_text())
    if not manifest["convergence"]["consistent"] or manifest["collection_failures"]:
        raise ValueError({"changed": manifest["convergence"]["changed"], "failures": manifest["collection_failures"]})
    snapshot = json.loads((target / "native/snapshot.json").read_text())
    if any(re.search(r"\b(DELETING|REKEYING|CONNECTING)\b", t["observed_state"])
           or t["observed_state"].count("ESTABLISHED") < 1
           or t["observed_state"].count("INSTALLED") < 1 for t in snapshot["tunnels"]):
        raise ValueError("Snapshot contains unsettled tunnel sessions")
    return {"at": now(), "native_observations": len(manifest["files"]), "convergence": manifest["convergence"]["consistent"]}


def run(args):
    profile = json.loads(args.profile.read_text())
    root, baseline = args.root, args.baseline
    network = profile["network"]
    if args.phase == "baseline":
        target = root / "controls" / network
        target.mkdir(parents=True, exist_ok=False)
        journal = target / "maintenance"
        journal.mkdir()
        old_journal = baseline / "public/mutations" / (network + ".json")
        if old_journal.exists():
            write_json(journal / "public/mutations" / old_journal.name, json.loads(old_journal.read_text()))
        write_json(target / "clean.json", clean(profile, baseline, journal))
        outcome = evaluate(profile, target, "clean")
        write_json(target / "live-summary.json", outcome)
        if outcome["violated"] or outcome["errors"]:
            raise ValueError(outcome)
        write_json(target / "fingerprints.json", fingerprints(profile))
        write_json(target / "collection-summary.json", collect(profile, target / "snapshot", args.sources, root.name))
        return {"network": network, "phase": args.phase, "status": "collected"}
    if args.phase == "inject":
        case = next(c for c in profile["mutations"] if c["case_id"] == args.case)
        target = root / "cases" / args.case
        target.mkdir(parents=True, exist_ok=False)
        prior = fingerprints(profile)
        expected = json.loads((root / "controls" / network / "fingerprints.json").read_text())
        difference = [k for k in prior.keys() | expected.keys() if prior.get(k) != expected.get(k)]
        write_json(target / "before.json", {"at": now(), "fingerprints": prior, "clean_baseline_mismatches": difference})
        if difference:
            raise ValueError({"network": network, "unclean_before_injection": difference})
        selected = {**profile, "mutations": [case]}
        write_json(target / "single-profile.json", selected)
        private = target / "private"
        private.mkdir()
        (private / "baseline").symlink_to(baseline / "private/baseline", target_is_directory=True)
        result = {"started_at": now(), "case": case["case_id"], "network": network,
                  "injection": apply(selected, target), "repairs": repair(selected)}
        result["tunnels"] = establish([profile])
        write_json(target / "injection.json", result)
        if result["tunnels"]["installed_child_endpoints"] != result["tunnels"]["expected_endpoints"]:
            raise ValueError("Faulty configuration did not establish every tunnel endpoint")
        outcome = evaluate(selected, target, "single-fault")
        write_json(target / "live-summary.json", outcome)
        if outcome["violated"] != 1 or outcome["errors"]:
            raise ValueError(outcome)
        write_json(target / "after.json", {"at": now(), "fingerprints": fingerprints(profile)})
        write_json(target / "collection-summary.json", collect(profile, target / "snapshot", args.sources, root.name))
        return {"case": args.case, "phase": args.phase, "status": "collected"}
    target = root / "cases" / args.case
    selected = json.loads((target / "single-profile.json").read_text())
    write_json(target / "restore.json", clean(selected, baseline, target))
    actual = fingerprints(profile)
    expected = json.loads((root / "controls" / network / "fingerprints.json").read_text())
    differences = [k for k in actual.keys() | expected.keys() if actual.get(k) != expected.get(k)]
    write_json(target / "restored.json", {"at": now(), "fingerprints": actual, "clean_baseline_mismatches": differences})
    if differences:
        raise ValueError({"network": network, "restore_mismatch": differences})
    return {"case": args.case, "phase": args.phase, "status": "restored"}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("phase", choices=["baseline", "inject", "restore"])
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--baseline", required=True, type=Path)
    p.add_argument("--profile", required=True, type=Path)
    p.add_argument("--sources", required=True, type=Path)
    p.add_argument("--case")
    a = p.parse_args()
    print(json.dumps(run(a)), flush=True)
