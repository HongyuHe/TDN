"""Detach one selected firewall interface into an empty network namespace, with a timed restore."""

import json
from pathlib import Path
from mode_lab import WORKER
from observe_controls import NETWORKS
from supervisor_transport import call


SCRIPT = Path(__file__).with_name("link_parking_worker.py").read_text()


def worker_with_request(request):
    return "import io, sys\nsys.stdin = io.StringIO(" + repr(json.dumps(request)) + ")\n" + SCRIPT


def target(p, gray=False):
    if p["network"] not in NETWORKS:
        raise ValueError("Unknown network")
    return next(
        d["id"]
        for d in p["topology"]["devices"]
        if (d["role"], d["id"].rsplit("_", 1)[-1])
        == (("gray-firewall", "A") if gray else ("firewall", "A1"))
    )


def change(p, action, nonce, side="inside"):
    gray = side == "gray-inner-links"
    req = {"device": target(p, gray), "action": action, "nonce": nonce}
    if gray:
        req["ports"] = (
            ["s1", "s2", "s3", "s4"]
            if p["network"] in ("net-03", "net-04")
            else ["s1", "s2"]
        )
    else:
        req["side"] = side
    req["recovery"] = worker_with_request({**req, "action": "restore"})
    run = call(
        WORKER, ["sudo", "-n", "python3", "-"],
        data=worker_with_request(req).encode(), timeout=100,
    )
    if run.returncode:
        raise RuntimeError(run.stderr.decode(errors="replace")[-2000:])
    return json.loads(run.stdout)
