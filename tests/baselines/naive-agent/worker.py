"""Worker-side backup, public observation, and controlled baseline maintenance."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def command(argv, timeout=25, input_text=None):
    start = time.monotonic()
    try:
        p = subprocess.run(argv, input=input_text, capture_output=True, text=True, timeout=timeout)
        record = {"argv": argv, "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        record = {"argv": argv, "returncode": 124, "stdout": "", "stderr": "Command timed out"}
    if "PRIVATE KEY-----" in record["stdout"] or "PRIVATE KEY-----" in record["stderr"]:
        raise RuntimeError("Refusing to export private key material")
    record.update({"ended_at": now(), "elapsed_seconds": time.monotonic() - start})
    return record


def docker(device, argv, **kwargs):
    return command(["docker", "exec", device, *argv], **kwargs)


def read_deployments(path):
    rows = json.loads(Path(path).read_text())
    for row in rows:
        root = Path(row["directory"]).resolve()
        if not root.is_relative_to("/users/hy/tdn-evidence-v2/private"):
            raise ValueError("The requested deployment is outside the experiment's permitted directory")
        allowed = {d["id"] for d in row["spec"]["devices"]}
        if allowed != {d["id"] for d in row["devices"]}:
            raise ValueError("Deployment inventory mismatch")
    return rows


def backup(deployment, root, label):
    destination = root / "private" / label / deployment["id"]
    if destination.exists():
        raise ValueError("Refusing to overwrite a backup")
    destination.mkdir(parents=True, mode=0o700)
    saved = destination / "deployment"
    saved.mkdir(mode=0o700)
    for name in ["ca", "devices"]:
        shutil.copytree(Path(deployment["directory"]) / name, saved / name, symlinks=True)
    shutil.copy2(Path(deployment["directory"]) / "spec.json", saved / "spec.json")
    states = []
    for device in deployment["spec"]["devices"]:
        name = device["id"]
        entry = {"device": name}
        for kind, argv in {
            "iptables": ["iptables-save"], "ip6tables": ["ip6tables-save"],
            "routes4": ["ip", "-j", "-4", "route", "show", "table", "all"],
            "interfaces": ["ip", "-j", "-d", "addr", "show"],
            "policies": ["ip", "xfrm", "policy", "list"],
        }.items():
            entry[kind] = docker(name, argv)
        states.append(entry)
    write_json(destination / "runtime.json", states)
    return {"network": deployment["id"], "label": label, "path": str(destination), "at": now()}


def renew_crls(deployment):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    root = Path(deployment["directory"])
    renewed = []
    for authority in sorted((root / "ca").iterdir()):
        old = x509.load_pem_x509_crl((authority / "crl.pem").read_bytes())
        key = serialization.load_pem_private_key((authority / "ca-key.pem").read_bytes(), password=None)
        stamp = datetime.now(timezone.utc)
        number = old.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number + 1
        builder = x509.CertificateRevocationListBuilder().issuer_name(old.issuer)
        builder = builder.last_update(stamp - timedelta(minutes=1)).next_update(stamp + timedelta(days=7))
        for item in old:
            builder = builder.add_revoked_certificate(item)
        for extension in old.extensions:
            value = x509.CRLNumber(number) if isinstance(extension.value, x509.CRLNumber) else extension.value
            builder = builder.add_extension(value, critical=extension.critical)
        updated = builder.sign(key, hashes.SHA384()).public_bytes(serialization.Encoding.PEM)
        (authority / "crl.pem").write_bytes(updated)
        (authority / "crl-number").write_text(str(number) + "\n")
        verify = command(["openssl", "crl", "-in", str(authority / "crl.pem"),
                          "-noout", "-verify", "-CAfile", str(authority / "ca.pem")])
        if verify["returncode"]:
            raise RuntimeError(verify)
        renewed.append({"authority": authority.name, "number": number,
                        "revoked_entries_preserved": len(old), "verification": verify})
    loads = []
    for device in deployment["spec"]["devices"]:
        if "tunnel" not in device:
            continue
        source = root / "ca" / device["tunnel"]["trust"] / "crl.pem"
        destination = root / "devices" / device["id"] / "swanctl/x509crl/ca.crl.pem"
        shutil.copyfile(source, destination)
        loads.append(docker(device["id"], ["swanctl", "--flush-certs", "--type", "x509_crl"]))
        loads.append(docker(device["id"], ["swanctl", "--load-creds", "--noprompt"]))
    return {"network": deployment["id"], "renewed": renewed, "loads": loads}


PUBLIC_COMMANDS = {
    "interfaces": ["ip", "-j", "-d", "addr", "show"],
    "routes4": ["ip", "-j", "-4", "route", "show", "table", "all"],
    "routes6": ["ip", "-j", "-6", "route", "show", "table", "all"],
    "rules4": ["ip", "-j", "-4", "rule", "show"],
    "firewall4": ["iptables-save", "-c"],
    "firewall6": ["ip6tables-save", "-c"],
    "policies": ["ip", "xfrm", "policy", "list"],
    "states": ["ip", "-s", "xfrm", "state", "list", "nokeys"],
    "processes": ["ps", "-eo", "pid,comm,args"],
    "sockets": ["ss", "-lnptu"],
    "forwarding": ["sysctl", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"],
}
TUNNEL_COMMANDS = {
    "ipsec_config": ["cat", "/etc/swanctl/swanctl.conf"],
    "ipsec_connections": ["swanctl", "--list-conns", "--raw"],
    "ipsec_sessions": ["swanctl", "--list-sas", "--raw"],
    "certificate": ["openssl", "x509", "-in", "/etc/swanctl/x509/cert.pem", "-noout", "-text", "-fingerprint", "-sha256"],
    "crl": ["openssl", "crl", "-in", "/etc/swanctl/x509crl/ca.crl.pem", "-noout", "-text"],
    "loaded_certificates": ["swanctl", "--list-certs", "--utc"],
}


def collect_device(device):
    commands = dict(PUBLIC_COMMANDS)
    if "tunnel" in device:
        commands.update(TUNNEL_COMMANDS)
    if device["role"] == "switch":
        commands.update({"ovs_bridge": ["ovs-vsctl", "show"],
                         "ovs_flows": ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "br0"]})
    if device["role"] in {"transport", "firewall", "gray-firewall", "gray-router"}:
        commands["routing_config"] = ["vtysh", "-c", "show running-config"]
        commands["routing_neighbors"] = ["vtysh", "-c", "show ip ospf neighbor json"]
    return {"id": device["id"], "role": device["role"],
            "observations": {kind: docker(device["id"], argv) for kind, argv in commands.items()}}


def capture(deployment, root, label):
    start = now()
    with ThreadPoolExecutor(max_workers=6) as pool:
        devices = list(pool.map(collect_device, deployment["spec"]["devices"]))
    result = {"network": deployment["id"], "started_at": start, "ended_at": now(), "devices": devices}
    write_json(root / "public" / label / (deployment["id"] + ".json"), result)
    return {"network": deployment["id"], "devices": len(devices), "started_at": start, "ended_at": result["ended_at"]}


def baseline(deployments, root):
    records = {"started_at": now(), "backups": [], "renewals": [], "initiations": []}
    for deployment in deployments:
        records["backups"].append(backup(deployment, root, "original"))
        records["renewals"].append(renew_crls(deployment))
        write_json(root / "public/baseline-maintenance.json", records)
    for role in ["outer", "inner"]:
        candidates = [d for network in deployments for d in network["spec"]["devices"]
                      if d["role"] == role and d.get("site") == "A"]
        with ThreadPoolExecutor(max_workers=8) as pool:
            records["initiations"].extend(pool.map(
                lambda d: docker(d["id"], ["swanctl", "--initiate", "--child", "protected"], timeout=12), candidates))
    records["captures"] = [capture(d, root, "baseline") for d in deployments]
    for deployment in deployments:
        records["backups"].append(backup(deployment, root, "baseline"))
    records["ended_at"] = now()
    write_json(root / "public/baseline-maintenance.json", records)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["baseline", "capture"])
    parser.add_argument("--deployments", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--label", default="after")
    args = parser.parse_args()
    root = Path(args.root)
    if not root.is_absolute() or not root.name.startswith("tdn-agent-baseline-"):
        raise ValueError("Choose an absolute, separate experiment directory")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    deployments = read_deployments(args.deployments)
    if args.action == "baseline":
        result = baseline(deployments, root)
        print(json.dumps({"finished": True, "ended_at": result["ended_at"], "networks": len(deployments)}))
    else:
        print(json.dumps([capture(d, root, args.label) for d in deployments]))


if __name__ == "__main__":
    main()
