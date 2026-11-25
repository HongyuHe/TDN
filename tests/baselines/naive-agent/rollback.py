"""Restore the selected deployments from their pre-injection worker backups."""

import argparse
import json
from pathlib import Path
import shutil

from worker import command, docker, now, write_json


def restore_directory(source, target):
    target.mkdir(parents=True, exist_ok=True)
    for entry in target.iterdir():
        saved = source / entry.name
        if not saved.exists() and not saved.is_symlink():
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
    for entry in source.iterdir():
        destination = target / entry.name
        if entry.is_symlink():
            if destination.exists() or destination.is_symlink():
                destination.unlink()
            destination.symlink_to(entry.readlink())
        elif entry.is_dir():
            restore_directory(entry, destination)
        else:
            shutil.copy2(entry, destination)


def restore(profile, root):
    backup = root / "private/baseline" / profile["network"]
    journal_path = root / "public/mutations" / (profile["network"] + ".json")
    journal = json.loads(journal_path.read_text()) if journal_path.exists() else {"cases": []}
    records = []
    for case in profile["mutations"]:
        operation, device, p = case["operation"], case["device"], case["parameters"]
        if operation == "ospf":
            entries = [e for e in journal["cases"] if e["case_id"] == case["case_id"]]
            launched = [r for e in entries for r in e["commands"] if r["argv"][:2] == ["docker", "run"] and r["returncode"] == 0]
            for launch in launched:
                records.append(command(["docker", "rm", "-f", launch["stdout"].strip()]))
        elif operation == "unused_interface":
            records.append(docker(device, ["ip", "link", "del", p["interface"]]))
        elif operation == "allow_unlisted_peer":
            records.append(docker(device, ["ip", "route", "del", p["destination"] + "/32", "via", p["gateway"], "dev", "black"]))
        elif operation in {"allow_http", "allow_multicast"}:
            pattern = "network-service.py" if operation == "allow_multicast" else "http.server"
            port = str(p["destination_port"])
            program = r'''
import os, signal, sys
from pathlib import Path
for path in Path('/proc').glob('[0-9]*/cmdline'):
    try:
        pid = int(path.parent.name)
        words = path.read_bytes().decode().split('\0')
        if pid != os.getpid() and sys.argv[1] in ' '.join(words) and sys.argv[2] in words and words[0] == 'python3':
            os.kill(pid, signal.SIGTERM)
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        pass
'''
            records.append(docker(device, ["python3", "-c", program, pattern, port]))
    target = Path(profile["deployment_directory"])
    for name in ["ca", "devices"]:
        restore_directory(backup / "deployment" / name, target / name)
    for entry in json.loads((backup / "runtime.json").read_text()):
        for kind, executable in [("iptables", "iptables-restore"), ("ip6tables", "ip6tables-restore")]:
            records.append(command(["docker", "exec", "-i", entry["device"], executable], input_text=entry[kind]["stdout"]))
    for entry in journal["cases"]:
        if "prior_sysctls" in entry:
            values = [line.replace(" ", "") for line in entry["prior_sysctls"]["stdout"].splitlines()]
            device = next(c["device"] for c in profile["mutations"] if c["case_id"] == entry["case_id"])
            records.append(docker(device, ["sysctl", "-w", *values]))
    for device in profile["topology"]["devices"]:
        if "tunnel" not in device:
            continue
        for argv in [["swanctl", "--terminate", "--ike", "msc"],
                     ["swanctl", "--load-creds", "--clear", "--noprompt"], ["swanctl", "--load-conns"]]:
            records.append(docker(device["id"], argv))
    destination = root / "public/rollback" / (profile["network"] + "-" + now().replace(":", "") + ".json")
    write_json(destination, {"network": profile["network"], "at": now(), "commands": records})
    return {"network": profile["network"], "record": str(destination)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--network")
    args = parser.parse_args()
    for path in sorted(Path(args.profiles).glob("net-*.json")):
        profile = json.loads(path.read_text())
        if args.network and profile["network"] != args.network:
            continue
        print(json.dumps(restore(profile, Path(args.root))), flush=True)


if __name__ == "__main__":
    main()
