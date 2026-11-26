"""Measure one registered change, retain its baseline and held readings, then restore it."""

from contextlib import contextmanager
import json
from pathlib import Path
import secrets
import sys

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

import architecture_cases
import delivery_lab
import mode_lab
import peer_lab
import unplug_lab
from attachment_view import attachments, live
from run_architecture_trial import active_change
from scale.catalog import BY_NAME, CASES
from snapshot_inputs import put
from supervisor_transport import call


INSTALL = """
import hashlib,json,os,subprocess,sys
from pathlib import Path
os.umask(0o077)
r=json.load(sys.stdin); root=Path('/var/tmp/tdn-scale-study')
if root.is_symlink() or root.stat().st_uid or root.stat().st_mode & 0o077:raise ValueError('Unexpected owner')
body=r['files']
if set(body)!= {'fixtures.py','architecture_worker.py','level_policy.py'}:raise ValueError('Unregistered source')
key=hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest()
dst=root/('worker-'+key);dst.mkdir(exist_ok=True)
for n,t in body.items():
    f=dst/n
    if not f.exists():
        with f.open('x') as s:s.write(t)
    if f.is_symlink() or f.read_text()!=t:raise ValueError('Worker installed with another digest')
p=subprocess.run([sys.executable,str(dst/'fixtures.py')],input=json.dumps(r['request']),text=True)
sys.exit(p.returncode)
"""


def remote_case(p, key, nonce, action):
    data = {
        "files": {
            "fixtures.py": (HERE / "scale/fixtures.py").read_text(),
            "architecture_worker.py": (HERE / "architecture_worker.py").read_text(),
            "level_policy.py": (HERE / "scale/level_policy.py").read_text(),
        },
        "request": {
            "network": p["network"],
            "case": key,
            "action": action,
            "nonce": nonce,
        },
    }
    proc = call(
        p["worker"],
        ["sudo", "-n", "python3", "-c", INSTALL],
        data=json.dumps(data).encode(),
        timeout=135,
    )
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode(errors="replace")[-1400:])
    return json.loads(proc.stdout)


def install_policy(p):
    return remote_case(
        p, "inner-cross-level-auth", "0000000000000000", "inventory-init"
    )


def change_and_read(p, key):
    prefix = p["topology"]["devices"][0]["id"].split("_")[0]
    if key in {c.key for c in CASES[11:]}:
        return lambda action, token: remote_case(
            p, key, token, action
        ), lambda token: remote_case(p, key, token, "observe")
    if key in {"inner-mode", "outer-mode", "inner-peer-loopback"}:
        peer = key == "inner-peer-loopback"
        node = prefix + ("_O_A1" if key == "outer-mode" else "_I_A1")

        def operation(action, token):
            return (
                peer_lab.change(p, action, token)
                if peer
                else mode_lab.edit(p, node, action, token)
            )

        def observation(*_):
            rows = mode_lab.snapshot(p)
            if peer:
                ip = peer_lab.loaded_peers(rows)[node]
                faulty = ip == "127.0.0.2"
                fresh = peer_lab.reconnect(p, faulty=faulty)
                return {
                    "gateway": node,
                    "loaded": ip,
                    "fresh": fresh,
                    "observed": faulty and not fresh["cross_site_child_installed"],
                }
            mode = next(r["mode"] for r in rows if r["device"] == node)
            return {"gateway": node, "mode": mode, "observed": mode == "TRANSPORT"}

        return operation, observation
    if key in {"firewall-inside-disconnected", "firewall-outside-disconnected"}:
        side = key.split("-")[1]

        def observation(*_):
            inventory = live(p)
            node = next(
                d for d in inventory["devices"] if d["device"] == prefix + "_OF_A1"
            )
            return {
                "device": node["device"],
                "ifaces": [a["ifname"] for a in node["interfaces"]],
                "attachments": attachments(p, inventory),
                "observed": all(x["ifname"] != side for x in node["interfaces"]),
            }

        return lambda action, token: unplug_lab.change(
            p, action, token, side
        ), observation
    spec = delivery_lab.selection(p, key)

    def observe_packet(*_):
        data = delivery_lab.probe(p, spec)
        if key == "outer-eligible-deny":
            intended = {
                (prefix + "_R_A1", prefix + "_R_B1"),
                (prefix + "_R_B1", prefix + "_R_A1"),
            }
            lost = {(r["source"], r["destination"]) for r in data if not r["delivered"]}
            flag = bool(lost & intended) and bool(
                lost != set((r["source"], r["destination"]) for r in data)
            )
        else:
            flag = len(data) == 1 and data[0]["accepted_by_local_ip"]
        return {"outcomes": data, "observed": flag}

    return lambda action, token: delivery_lab.change(
        spec, action, token
    ), observe_packet


@contextmanager
def held(p, key, out):
    if key not in BY_NAME:
        raise ValueError("Unregistered fault type")
    out.mkdir(parents=True, exist_ok=False)
    if key in architecture_cases.FAMILIES:
        with active_change(p, key, out) as (_, reading):
            yield {"observed": True}
        return
    token = secrets.token_hex(8 if key in {c.key for c in CASES[11:]} else 6)
    change, reading = change_and_read(p, key)
    put(out / "lease.json", {"nonce": token, "case": key, "network": p["network"]})
    before = reading(token)
    put(out / "before.json", before)
    if before["observed"]:
        raise ValueError("The clean control already has this violation")
    attempt = change("edit", token)
    try:
        put(out / "change.json", attempt)
        observed = reading(token)
        put(out / "held.json", observed)
        yield observed
    finally:
        put(out / "restoration.json", change("restore", token))
        if key == "inner-peer-loopback":
            from restore_health import verify

            state = verify(p)
            put(out / "restored-health.json", state)
            if not state["ready"]:
                raise RuntimeError(
                    "The intended peer could not re-establish its tunnel"
                )
        after = reading(token)
        put(out / "after.json", after)
        if after["observed"]:
            raise RuntimeError("The violation is still present after restoration")
