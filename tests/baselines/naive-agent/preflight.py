"""Record the experiment inputs and locate the existing five deployments."""

import argparse
import json
from pathlib import Path
import subprocess

from common import BASE, ROOT, PROFILE_NAMES, now, remote_python, sha256, write_json


INSPECT = r'''
import json
from pathlib import Path
import subprocess
import sys

profiles = json.loads(sys.argv[1])
result = []
for item in profiles:
    device = item['first_encryptor']
    info = json.loads(subprocess.check_output(['docker', 'inspect', device]))[0]
    mounts = [m for m in info['Mounts'] if m['Destination'] == '/etc/swanctl']
    assert len(mounts) == 1
    swanctl = Path(mounts[0]['Source'])
    directory = swanctl.parent.parent.parent
    spec = json.loads((directory / 'spec.json').read_text())
    container_names = [d['id'] for d in spec['devices']]
    observations = []
    for argv in [
        ['docker', 'exec', device, 'openssl', 'x509', '-in', '/etc/swanctl/x509/cert.pem', '-noout', '-dates', '-issuer'],
        ['docker', 'exec', device, 'openssl', 'crl', '-in', '/etc/swanctl/x509crl/ca.crl.pem', '-noout', '-lastupdate', '-nextupdate'],
        ['docker', 'exec', device, 'swanctl', '--list-sas'],
    ]:
        p = subprocess.run(argv, capture_output=True, text=True)
        observations.append({'argv': argv, 'returncode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
    statuses = json.loads(subprocess.check_output(['docker', 'inspect', *container_names]))
    result.append({'id': item['id'], 'profile': item['profile'], 'directory': str(directory),
        'spec': spec, 'devices': [{'id': c['Name'].lstrip('/'), 'running': c['State']['Running'],
                                 'image': c['Image']} for c in statuses], 'observations': observations})
print(json.dumps(result))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    run = BASE / "runs" / args.run_id
    if run.exists():
        raise ValueError("Choose a new run ID; existing experiment records are immutable.")
    run.mkdir(parents=True)
    plan = []
    for number, name in enumerate(PROFILE_NAMES, 1):
        path = ROOT / "data/extraction/networks/profiles" / f"native-{name}.json"
        spec = json.loads(path.read_text())
        first = next(d["id"] for d in spec["devices"] if d["role"] == "inner")
        plan.append({"id": f"net-{number:02}", "profile": name,
                     "first_encryptor": first, "profile_sha256": sha256(path.read_bytes())})
    started = now()
    response = remote_python(INSPECT, [json.dumps(plan)], timeout=120)
    write_json(run / "preflight-command.json", response)
    if response["returncode"]:
        raise RuntimeError(response["stderr"])
    deployments = json.loads(response["stdout"])
    for deployment in deployments:
        assert all(d["running"] for d in deployment["devices"]), deployment["id"]
        write_json(run / "original-profiles" / (deployment["id"] + ".json"), deployment["spec"])
    pdf = ROOT / "docs/CSfC_documentation_v1.3.0.pdf"
    write_json(run / "experiment.json", {
        "run_id": args.run_id, "status": "preparing", "started_at": started,
        "tdn_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "pdf_sha256": sha256(pdf.read_bytes()), "networks": plan,
        "requested_cases": 100, "completed_cases": 0,
        "detector_model": "gpt-6-astra", "detector_reasoning": "high",
        "detector_run": None, "tdn_run": None,
    })
    write_json(run / "deployments.json", deployments)
    print(json.dumps({"run": str(run), "networks": [
        {"id": d["id"], "devices": len(d["devices"]), "directory": d["directory"],
         "crl": d["observations"][1]["stdout"]} for d in deployments]}, indent=2))


if __name__ == "__main__":
    main()
