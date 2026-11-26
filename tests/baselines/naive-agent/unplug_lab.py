"""Detach one selected firewall interface into an empty network namespace, with a timed restore."""

import json
from pathlib import Path
from mode_lab import WORKER
from cohort import registered_profile
from supervisor_transport import call


SCRIPT = Path(__file__).with_name("link_parking_worker.py").read_text()


def worker_with_request(request):
    return "import io, sys\nsys.stdin = io.StringIO(" + repr(json.dumps(request)) + ")\n" + SCRIPT


def target(p):
    if not registered_profile(p):
        raise ValueError("Unknown network")
    return next(
        d["id"]
        for d in p["topology"]["devices"]
        if (d["role"], d["id"].rsplit("_", 1)[-1])
        == ("firewall", "A1")
    )


def change(p, action, nonce, side="inside"):
    if side not in ("inside","outside"):
        raise ValueError("Unregistered Outer Firewall interface")
    req = {"device": target(p), "action": action, "nonce": nonce, "side":side}
    req["recovery"] = worker_with_request({**req, "action": "restore"})
    run = call(
        p["worker"], ["sudo", "-n", "python3", "-"],
        data=worker_with_request(req).encode(), timeout=100,
    )
    if run.returncode:
        raise RuntimeError(run.stderr.decode(errors="replace")[-2000:])
    return json.loads(run.stdout)
