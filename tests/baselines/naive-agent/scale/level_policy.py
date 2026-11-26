"""Read the study authority's current designation of each Red enclave on its own admin host."""

from concurrent.futures import ThreadPoolExecutor
import json
import subprocess

FILE = "/run/tdn-red-enclave.json"
LABEL = "MSC Red enclave security level "


def node_cmd(dev, *args, data=None, check=True):
    p = subprocess.run(
        ["docker", "exec", "-i", dev, *args],
        input=data,
        text=True,
        capture_output=True,
        timeout=16,
    )
    if check and p.returncode:
        raise ValueError(
            "Red enclave inventory operation failed on " + dev + ": " + p.stderr[-140:]
        )
    return p


def bindings(spec):
    nodes = {d["id"]: d for d in spec["devices"]}
    for link in spec["links"]:
        a, b = nodes[link["a"]["device"]], nodes[link["b"]["device"]]
        if {a["role"], b["role"]} != {"host", "inner"}:
            continue
        red, inner = (a, b) if a["role"] == "host" else (b, a)
        prefix, _, suffix = red["id"].split("_", 2)
        aw = prefix + "_AW_" + suffix
        if aw not in nodes or nodes[aw]["role"] != "admin":
            raise ValueError("Missing Red administrative owner")
        yield red["id"], inner["id"], aw, red["level"]


def designate(row, level):
    red, inner, aw, _ = row
    if not level.startswith("S") or not level[1:].isdigit():
        raise ValueError("Unknown security level")
    data = json.dumps({"red_host": red, "security_level": level})
    write = "from pathlib import Path;import sys,os;p=Path(sys.argv[1]);q=p.with_suffix('.tmp');q.write_text(sys.stdin.read());q.chmod(0o600);os.replace(q,p)"
    node_cmd(aw, "python3", "-c", write, FILE, data=data)
    node_cmd(red, "ip", "link", "set", "dev", "red", "alias", LABEL + level)


def inventory(spec, install=False):
    def one(row):
        red, inner, aw, original = row
        p = node_cmd(aw, "cat", FILE, check=False)
        if install and p.returncode:
            designate(row, original)
            p = node_cmd(aw, "cat", FILE)
        if p.returncode:
            raise ValueError("No recorded classification at " + aw)
        record = json.loads(p.stdout)
        if record["red_host"] != red:
            raise ValueError("The authority names another enclave")
        iface = json.loads(
            node_cmd(red, "ip", "-j", "-d", "link", "show", "dev", "red").stdout
        )[0]
        if iface.get("ifalias") != LABEL + record["security_level"]:
            raise ValueError("Interface and admin classification disagree")
        return {
            "admin": aw,
            "path": FILE,
            "red": red,
            "attached_inner": inner,
            "record": record,
            "interface": {
                "name": iface["ifname"],
                "ifindex": iface["ifindex"],
                "link_index": iface["link_index"],
                "alias": iface["ifalias"],
            },
        }

    with ThreadPoolExecutor(max_workers=10) as pool:
        return list(pool.map(one, bindings(spec)))


def effective_topology(spec, records):
    from copy import deepcopy

    active = deepcopy(spec)
    nodes = {d["id"]: d for d in active["devices"]}
    for row in records:
        for field in ("red", "attached_inner"):
            nodes[row[field]]["level"] = row["record"]["security_level"]
    return active
