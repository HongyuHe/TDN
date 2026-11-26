"""Refresh expired public revocation lists and establish the benchmark's existing tunnels."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from observe_controls import HERE, NETWORKS


WORKER_DIGEST = "900a1bb124c1c6ebb8d1ea4cea4871df170b589496b5d0763081fdf458c26391"

def refresh_leaf(base, device):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    cert_file = base / "devices" / device["id"] / "swanctl/x509/cert.pem"
    old_bytes = cert_file.read_bytes()
    old = x509.load_pem_x509_certificate(old_bytes)
    now = datetime.now(timezone.utc)
    if old.not_valid_after.replace(tzinfo=timezone.utc) > now:
        return None
    authority = base / "ca" / device["tunnel"]["trust"]
    ca = x509.load_pem_x509_certificate((authority / "ca.pem").read_bytes())
    crl = x509.load_pem_x509_crl((authority / "crl.pem").read_bytes())
    if old.issuer != ca.subject or old.serial_number in {r.serial_number for r in crl}:
        raise ValueError("Unrecognized issuer or revoked endpoint")
    subprocess.run(["openssl", "verify", "-no_check_time", "-CAfile", str(authority / "ca.pem"),
                    str(cert_file)], check=True, capture_output=True)
    signing_key = serialization.load_pem_private_key((authority / "ca-key.pem").read_bytes(), password=None)
    validity = old.not_valid_after - old.not_valid_before
    b = x509.CertificateBuilder().subject_name(old.subject).issuer_name(old.issuer).public_key(old.public_key())
    b = b.serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
    b = b.not_valid_after(min(now + validity, ca.not_valid_after.replace(tzinfo=timezone.utc)))
    for ext in old.extensions:
        b = b.add_extension(ext.value, critical=ext.critical)
    issued = b.sign(signing_key, hashes.SHA384())
    with tempfile.NamedTemporaryFile(dir=cert_file.parent, delete=False) as temporary:
        pending = Path(temporary.name)
        temporary.write(issued.public_bytes(serialization.Encoding.PEM))
    try:
        subprocess.run(["openssl", "verify", "-CAfile", str(authority / "ca.pem"), str(pending)],
                       check=True, capture_output=True)
        archived = base / "benchmark-expired-certificates" / device["id"] / old.fingerprint(hashes.SHA256()).hex()
        archived.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not archived.exists():
            archived.write_bytes(old_bytes)
        os.chmod(pending, cert_file.stat().st_mode & 0o777)
        os.replace(pending, cert_file)
    finally:
        pending.unlink(missing_ok=True)
    return {"device": device["id"], "expired": old.not_valid_after.isoformat(), "renewed_until": issued.not_valid_after.isoformat()}


def prepare(profiles):
    from cryptography import x509
    legacy = Path("/users/hy/tdn-agent-baseline-20261112")
    if hashlib.sha256((legacy / "worker.py").read_bytes()).hexdigest() != WORKER_DIGEST:
        raise ValueError("Legacy CRL renewal implementation changed")
    sys.path.insert(0, str(legacy))
    from worker import renew_crls
    if [p["network"] for p in profiles] != list(NETWORKS):
        raise ValueError("Expected the active benchmark networks")
    renewals = []
    for p in profiles:
        base = Path(p["deployment_directory"])
        if p["topology"] != json.loads((base / "spec.json").read_text()):
            raise ValueError("Deployed topology differs from the benchmark profile")
        expired = []
        for folder in (base / "ca").iterdir():
            old = x509.load_pem_x509_crl((folder / "crl.pem").read_bytes())
            if old.next_update.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
                expired.append(folder.name)
        if expired:
            result = renew_crls({"id": p["network"], "directory": str(base), "spec": p["topology"]})
            if any(x["returncode"] for x in result["loads"]):
                raise ValueError("Failed to install a refreshed revocation list")
            renewals.append({"network": p["network"], "expired": expired, "renewed": [
                {k: r[k] for k in ("authority", "number", "revoked_entries_preserved")} for r in result["renewed"]]})
    leaves = []
    for p in profiles:
        for device in p["topology"]["devices"]:
            if "tunnel" in device:
                record = refresh_leaf(Path(p["deployment_directory"]), device)
                if record:
                    leaves.append(record)
    devices = [d["id"] for p in profiles for d in p["topology"]["devices"] if "tunnel" in d]
    for name in devices:
        for operation in (["--load-creds", "--clear", "--noprompt"], ["--load-conns"]):
            subprocess.run(["docker", "exec", name, "swanctl", *operation], check=True, capture_output=True, timeout=15)
    out = []
    for role in ("outer", "inner"):
        devices = [d["id"] for p in profiles for d in p["topology"]["devices"]
                   if d["role"] == role and d.get("site") == "A"]
        def initiate(name):
            proc = subprocess.run(["docker", "exec", name, "swanctl", "--initiate", "--child", "protected",
                                   "--timeout", "15"], capture_output=True, text=True, timeout=22)
            return {"device": name, "returncode": proc.returncode,
                    "result": [l for l in (proc.stdout + proc.stderr).splitlines()
                               if not l.startswith("plugin ") and ("initiate" in l or "failed" in l)][-2:]}
        with ThreadPoolExecutor(max_workers=6) as pool:
            out.extend(pool.map(initiate, devices))
    return {"renewals": renewals, "certificates": leaves, "initiations": out}


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: prepare_controls.py OUTPUT")
    dest = Path(sys.argv[1])
    if dest.exists():
        raise FileExistsError(dest)
    from cohort import runtime_profile
    profiles = [runtime_profile(n) for n in NETWORKS]
    worker = {p["worker"] for p in profiles}
    if len(worker) != 1:
        raise ValueError("Expected a common worker")
    source = Path(__file__).read_text().split("def main():")[0]
    source = source.replace("from observe_controls import HERE, NETWORKS", "NETWORKS = " + repr(NETWORKS))
    source += "\nprint(json.dumps(prepare(" + repr(profiles) + ")))\n"
    code = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", worker.pop(),
                           "sudo", "-n", "python3", "-"], input=source, capture_output=True, text=True, timeout=180)
    if code.returncode:
        raise SystemExit(code.stderr[-1200:])
    result = json.loads(code.stdout)
    result["recorded_at"] = datetime.now(timezone.utc).isoformat()
    with dest.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    print("Refreshed", len(result["renewals"]), "networks. Established",
          sum(v["returncode"] == 0 for v in result["initiations"]), "of", len(result["initiations"]), "peer pairs.")


if __name__ == "__main__":
    main()
