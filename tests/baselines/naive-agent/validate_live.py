"""Collect independent before/after evidence for the predeclared target violations."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re

from packet_probe import probe
from worker import docker, now, write_json


def configured_value(text, field):
    matches = re.findall(r"(?m)^\s*" + re.escape(field) + r"\s*=\s*([^\n]+)", text)
    if len(matches) != 1:
        raise ValueError(f"Expected one configured {field}")
    return matches[0].strip()


def seconds(value):
    match = re.fullmatch(r"(\d+)([smhd]?)", value)
    if not match:
        raise ValueError("Unsupported time unit")
    return int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]


def config_check(profile, case):
    device = case["device"]
    operation = case["operation"]
    result = {"case_id": case["case_id"], "at": now(), "observations": []}
    if operation == "unused_interface":
        record = docker(device, ["ip", "-j", "link", "show"])
        result["observations"].append(record)
        links = json.loads(record["stdout"])
        violated = any(i["ifname"] == case["parameters"]["interface"] and "UP" in i["flags"] for i in links)
    elif operation == "ospf":
        record = docker(device, ["ps", "-eo", "comm,args"])
        result["observations"].append(record)
        violated = any(line.split()[0] == "ospfd" for line in record["stdout"].splitlines() if line.split())
    elif operation == "duplicate_certificate":
        hashes = []
        for name in [device, case["parameters"]["donor"]]:
            record = docker(name, ["openssl", "x509", "-in", "/etc/swanctl/x509/cert.pem", "-noout", "-fingerprint", "-sha256"])
            result["observations"].append(record)
            if record["returncode"]:
                raise ValueError(record)
            hashes.append(record["stdout"].strip())
        violated = hashes[0] == hashes[1]
    else:
        record = docker(device, ["cat", "/etc/swanctl/swanctl.conf"])
        result["observations"].append(record)
        if record["returncode"]:
            raise ValueError(record)
        text = record["stdout"]
        loaded = docker(device, ["swanctl", "--list-conns", "--raw"])
        result["observations"].append(loaded)
        if loaded["returncode"] or "msc" not in loaded["stdout"]:
            raise ValueError("No loaded connection was observed")
        if operation == "weak_proposal":
            violated = "aes128" in configured_value(text, "proposals")
        elif operation == "psk_authentication":
            violated = bool(re.search(r"auth\s*=\s*psk\b", text)) and bool(re.search(
                r"class=(pre-shared key|shared secret|psk|PSK)", loaded["stdout"]))
        elif operation == "optional_revocation":
            crls = docker(device, ["swanctl", "--list-certs", "--type", "x509_crl"])
            result["observations"].append(crls)
            violated = configured_value(text, "revocation") == "relaxed" and "issuer:" not in crls["stdout"].lower()
        elif operation == "ikev1":
            violated = configured_value(text, "version") == "1" and "version=IKEv1" in loaded["stdout"]
        elif operation == "ike_lifetime":
            violated = seconds(configured_value(text, "reauth_time")) > 86400
        elif operation == "esp_lifetime":
            violated = seconds(configured_value(text, "life_time")) > 28800
        elif operation == "transport_mode":
            violated = configured_value(text, "mode") == "transport" and "mode=TRANSPORT" in loaded["stdout"]
        else:
            raise ValueError(operation)
    if any(r["returncode"] for r in result["observations"]):
        raise ValueError(result)
    result.update({"violated": violated, "status": "observed"})
    return result


def evaluate(profile, root, phase):
    rows = []
    output = root / "public/oracle" / phase / (profile["network"] + ".json")
    if output.exists():
        raise ValueError("Validation output exists; choose a new phase name")
    for case in profile["mutations"]:
        try:
            if case["operation"].startswith("allow_"):
                row = probe(profile, case)
                row.update({"violated": row["result"]["observed"], "status": "observed"})
            else:
                row = config_check(profile, case)
        except Exception as error:
            row = {"case_id": case["case_id"], "status": "error", "error": str(error), "at": now()}
        row["requirement"] = case["requirement"]
        rows.append(row)
        write_json(output, {"network": profile["network"], "phase": phase, "records": rows})
    return {"network": profile["network"], "observed": sum(r["status"] == "observed" for r in rows),
            "violated": sum(r.get("violated", False) for r in rows),
            "errors": [r["case_id"] for r in rows if r["status"] == "error"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--phase", required=True)
    args = parser.parse_args()
    profiles = [json.loads(p.read_text()) for p in sorted(Path(args.profiles).glob("net-*.json"))]
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda p: evaluate(p, Path(args.root), args.phase), profiles))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
