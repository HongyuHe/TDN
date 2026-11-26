"""Record the active benchmark deployments using public Linux and strongSwan state."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from cohort import NETWORKS

HERE = Path(__file__).resolve().parent


def local_command(argv, timeout=20):
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return completed.returncode, completed.stdout, completed.stderr


def read_device(device):
    name = device["id"]
    cmd = ["docker", "exec", name]
    code, out, err = local_command([*cmd, "ip", "-j", "-d", "link", "show"])
    item = {"device": name, "role": device["role"], "interfaces_ok": code == 0}
    if code:
        item["error"] = err.strip()
        return item
    item["interfaces"] = [{k: row[k] for k in ("ifname", "flags", "ifindex", "link_index", "mtu", "operstate")
                           if k in row} for row in json.loads(out)]
    if device["role"] in ("inner", "outer"):
        code, out, err = local_command([*cmd, "swanctl", "--list-sas", "--raw"])
        item.update(sas_ok=code == 0, established=out.count("state=ESTABLISHED"), installed=out.count("state=INSTALLED"))
        if code:
            item["sas_error"] = err.strip()
        code, out, _ = local_command([*cmd, "swanctl", "--list-certs", "--type", "x509_crl"])
        if not code:
            item["crl_dates"] = [line.strip() for line in out.splitlines() if any(s in line.lower() for s in ("update", "expired", "validity"))]
    return item


def collect_network(profile):
    devices = profile["topology"]["devices"]
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(read_device, devices))
    lookup = {(d["device"], i["ifname"]): i for d in rows for i in d.get("interfaces", [])}
    links = []
    for link in profile["topology"]["links"]:
        first, second = (lookup.get((p["device"], p["interface"]), {}) for p in (link["a"], link["b"]))
        reciprocal = (first.get("link_index") is not None and second.get("link_index") is not None
                      and first["link_index"] == second.get("ifindex") and second["link_index"] == first.get("ifindex"))
        links.append({**link, "reciprocal": reciprocal, "up": all("UP" in end.get("flags", []) for end in (first, second))})
    return {"network": profile["network"], "devices": rows, "links": links}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.output:
        parser.error("--output is required")
    from cohort import runtime_profile
    profiles = [runtime_profile(n) for n in NETWORKS]
    workers = {p["worker"] for p in profiles}
    if len(workers) != 1:
        raise ValueError("Profiles require distinct worker connections")
    source = Path(__file__).read_text()
    remote = source[:source.index("def main():")].replace("from cohort import NETWORKS", "NETWORKS = " + repr(NETWORKS)) + "\nprint(json.dumps([collect_network(p) for p in " + repr(profiles) + "]))\n"
    start = datetime.now(timezone.utc).isoformat()
    proc = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=yes",
                           workers.pop(), "sudo", "-n", "python3", "-"], input=remote, capture_output=True, text=True, timeout=220)
    if proc.returncode:
        raise SystemExit(proc.stderr[-1200:])
    data = {"started_at": start, "finished_at": datetime.now(timezone.utc).isoformat(), "networks": json.loads(proc.stdout)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as out:
        json.dump(data, out, indent=2)
        out.write("\n")
    for n in data["networks"]:
        peers = [r for r in n["devices"] if r["role"] in ("inner", "outer")]
        print(n["network"], len(n["devices"]), "devices,", sum(r["reciprocal"] and r["up"] for r in n["links"]),
              "/", len(n["links"]), "links up and paired,", sum(r.get("installed", 0) > 0 for r in peers), "/", len(peers), "tunnel endpoints with an installed SA")


if __name__ == "__main__":
    main()
