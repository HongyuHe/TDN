"""Prepare clean controls and consistent faulty peer configurations on the worker."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import time

from worker import command, docker, now, write_json
from mutate import assign, config_file
from rollback import restore


def field(text, side):
    return re.search(side + r"\s*\{[^}]*\bid\s*=\s*([^\s}]+)", text, re.S)[1]


def repair(profile):
    devices = {d["id"]: d for d in profile["topology"]["devices"]}
    changes = []
    for case in profile["mutations"]:
        device = case["device"]
        if case["operation"] == "transport_mode":
            peer = devices[device]["tunnel"]["peer"]
            path = config_file(profile, peer)
            path.write_text(assign(path.read_text(), "mode", "transport"))
            changes.append({"reason": "Match the intentionally wrong transport mode at both tunnel endpoints", "devices": [device, peer]})
        elif case["operation"] == "duplicate_certificate":
            peer = devices[device]["tunnel"]["peer"]
            identity = field(config_file(profile, device).read_text(), "local")
            path = config_file(profile, peer)
            text = re.sub(r"(remote\s*\{[^}]*\bid\s*=\s*)[^\s}]+", lambda m: m[1] + identity,
                          path.read_text(), count=1, flags=re.S)
            path.write_text(text)
            changes.append({"reason": "Bind peer authentication to the intentionally duplicated certificate identity", "devices": [device, peer]})
        elif case["operation"] == "ikev1":
            for name in [device, case["parameters"]["peer"]]:
                tunnel = devices[name]["tunnel"]
                for chain, flag, source, destination in [
                    ("INPUT", "-i", tunnel["remote"], tunnel["local"]),
                    ("OUTPUT", "-o", tunnel["local"], tunnel["remote"]),
                ]:
                    rule = [chain, flag, tunnel["outside"], "-s", source, "-d", destination,
                            "-p", "udp", "--sport", "500", "--dport", "500", "-j", "ACCEPT"]
                    if docker(name, ["iptables", "-C", *rule])["returncode"]:
                        result = docker(name, ["iptables", "-I", chain, "1", *rule[1:]])
                        if result["returncode"]:
                            raise RuntimeError(result)
            changes.append({"reason": "Permit the intentionally selected IKEv1 exchange between its exact endpoints", "devices": [device, case["parameters"]["peer"]]})
        elif case["operation"] == "allow_http":
            program = "from pathlib import Path;Path('/tmp/network-www/index.html').write_text('Laboratory user file transfer\\nSynthetic user payload: example research dataset.\\n')"
            result = docker(device, ["python3", "-c", program])
            if result["returncode"]:
                raise RuntimeError(result)
            changes.append({"reason": "Make the unapproved HTTP application demonstrably user-data transfer", "devices": [device]})
    return changes


def establish(profiles):
    devices = [d for p in profiles for d in p["topology"]["devices"] if "tunnel" in d]
    def load(d):
        return {"device": d["id"], "commands": [docker(d["id"], argv) for argv in [
            ["swanctl", "--terminate", "--ike", "msc"],
            ["swanctl", "--load-creds", "--clear", "--noprompt"], ["swanctl", "--load-conns"]]]}
    with ThreadPoolExecutor(max_workers=8) as pool:
        loads = list(pool.map(load, devices))
    initiations = []
    for role in ["outer", "inner"]:
        pairs = [d for d in devices if d["role"] == role and d.get("site") == "A"]
        with ThreadPoolExecutor(max_workers=8) as pool:
            initiations.extend(pool.map(lambda d: {"device": d["id"], **docker(d["id"],
                ["swanctl", "--initiate", "--child", "protected", "--timeout", "12"])}, pairs))
    time.sleep(3)
    with ThreadPoolExecutor(max_workers=8) as pool:
        states = list(pool.map(lambda d: {"device": d["id"], **docker(d["id"],
            ["swanctl", "--list-sas", "--raw"])}, devices))
    return {"loads": loads, "initiations": initiations, "states": states,
            "established_endpoints": sum("ESTABLISHED" in s["stdout"] for s in states),
            "expected_endpoints": len(devices),
            "installed_child_endpoints": sum("state=INSTALLED" in s["stdout"] for s in states)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["clean", "repair"])
    parser.add_argument("--profiles", required=True, type=Path)
    parser.add_argument("--old-root", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    profiles = [json.loads(p.read_text()) for p in sorted(args.profiles.glob("net-*.json"))]
    output = args.root / "public" / (args.phase + "-preparation.json")
    if output.exists():
        raise ValueError("Preparation already recorded")
    result = {"started_at": now(), "phase": args.phase, "changes": []}
    write_json(output, result)
    if args.phase == "clean":
        for p in profiles:
            result["changes"].append(restore(p, args.old_root))
    else:
        for p in profiles:
            result["changes"].append({"network": p["network"], "repairs": repair(p)})
    write_json(output, result)
    result["tunnels"] = establish(profiles)
    result["ended_at"] = now()
    write_json(output, result)
    print(json.dumps({"phase": args.phase, "output": str(output),
                      "established_endpoints": result["tunnels"]["established_endpoints"],
                      "expected_endpoints": result["tunnels"]["expected_endpoints"]}))


if __name__ == "__main__":
    main()
