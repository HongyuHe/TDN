"""Provision private, separately named copies of the registered Twinet profiles on the benchmark worker."""

import argparse
import json

from cohort import NETWORKS, runtime_profile

PROVISION = """
import json, os, subprocess, sys
from pathlib import Path
p, operation = json.load(sys.stdin)
n = p["network"]
prefix = {"net-03":"QF", "net-04":"QR", "net-05":"QM"}[n]
if operation not in ("up", "down"):
    raise ValueError("Expected up or down")
base = Path("/var/tmp/tdn-multilevel-replicas") / n
spec, state = base / "spec.json", base / "state"
topology = p["topology"]
if (topology["name"] != "baseline-" + prefix.lower() or
    any(not d["id"].startswith(prefix + "_") for d in topology["devices"]) or
    Path(p["deployment_directory"]) != state):
    raise ValueError("Expected an isolated benchmark replica")
lease = Path("/var/tmp/tdn-naive-rg-mode-lease")
if lease.exists():
    raise ValueError("Wait for the active experiment to restore its replica before provisioning or removing replicas")
os.umask(0o077)
base.mkdir(exist_ok=True, parents=True)
if base.is_symlink() or base.parent.is_symlink() or any(x.stat().st_uid != 0 for x in (base, base.parent)):
    raise ValueError("Replica directories must be owned by the supervisor")
if spec.exists():
    if json.loads(spec.read_text()) != topology:
        raise ValueError("Existing replica specification differs")
elif operation == "up":
    with spec.open("x") as file:
        json.dump(topology, file)
else:
    raise ValueError("No registered replica to remove")
binary = "/users/hy/tdn-evidence-v2/Twinet/bin/twinet"
result = subprocess.run([binary, "msc", operation, "--spec", str(spec), "--state-dir", str(state)],
                        capture_output=True, text=True, timeout=900)
if result.returncode:
    raise RuntimeError((result.stderr or result.stdout)[-1300:])
print(json.dumps({"network":n, "operation":operation,"devices":len(topology["devices"])}))
"""


def provision(name, operation):
    p = runtime_profile(name)
    from supervisor_transport import call

    result = call(
        p["worker"],
        ["sudo", "-n", "python3", "-c", PROVISION],
        data=json.dumps([p, operation]).encode(),
        timeout=930,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.decode()[-1700:])
    return json.loads(result.stdout)


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("operation", choices=("up", "down"))
    cli.add_argument("network", nargs="*", metavar="NETWORK")
    args = cli.parse_args()
    for name in args.network or NETWORKS:
        print(provision(name, args.operation), flush=True)
