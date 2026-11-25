"""Apply the frozen requirement violations to the selected laboratory devices."""

import argparse
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shutil

from worker import command, docker, now, write_json


LISTENER = r'''
import json
import socket
import sys
from datetime import datetime, timezone
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', int(sys.argv[1])))
s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
             socket.inet_aton(sys.argv[2]) + socket.inet_aton(sys.argv[3]))
while True:
    data, peer = s.recvfrom(65535)
    with open('/tmp/network-service.jsonl', 'a') as stream:
        stream.write(json.dumps({'at': datetime.now(timezone.utc).isoformat(),
                                 'peer': peer, 'bytes': len(data)}) + '\n')
'''


def require_success(record):
    if record["returncode"]:
        raise RuntimeError(json.dumps(record))
    return record


def assign(text, key, value, indentation=None):
    prefix = r"^\s*" if indentation is None else "^" + re.escape(indentation)
    pattern = prefix + re.escape(key) + r"\s*=.*$"
    matches = list(re.finditer(pattern, text, re.M))
    if len(matches) != 1:
        raise ValueError(f"Expected one {key} field, found {len(matches)}")
    match = matches[0]
    old = match.group()
    spaces = old[:len(old) - len(old.lstrip())]
    return text[:match.start()] + spaces + key + " = " + value + text[match.end():]


def config_file(profile, device):
    return Path(profile["deployment_directory"]) / "devices" / device / "swanctl/swanctl.conf"


def rule_command(case):
    p = case["parameters"]
    argv = ["iptables", "-I", p["chain"], "1"]
    for key, flag in [("ingress", "-i"), ("egress", "-o"), ("source", "-s"), ("destination", "-d"), ("protocol", "-p")]:
        if key in p:
            argv += [flag, str(p[key])]
    if "destination_port" in p:
        argv += ["--dport", str(p["destination_port"])]
    return [*argv, "-j", "ACCEPT"]


def configure_authentication(profile, case, journal):
    operation = case["operation"]
    device = case["device"]
    path = config_file(profile, device)
    text = path.read_text()
    parameters = case["parameters"]
    changed = {device}
    if operation == "weak_proposal":
        text = assign(text, "proposals", "aes256gcm16-prfsha384-ecp384,aes128-sha256-modp2048")
        text = assign(text, "esp_proposals", "aes256gcm16-ecp384,aes128-sha256-modp2048")
    elif operation == "duplicate_certificate":
        donor = config_file(profile, parameters["donor"]).parent
        target = path.parent
        for relative in ["x509/cert.pem", "private/key.pem"]:
            shutil.copyfile(donor / relative, target / relative)
        local_id = re.search(r"local\s*\{[^}]*\bid\s*=\s*([^\s}]+)", (donor / "swanctl.conf").read_text(), re.S)[1]
        text = re.sub(r"(local\s*\{[^}]*\bid\s*=\s*)[^\s}]+", lambda m: m[1] + local_id, text, count=1, flags=re.S)
    elif operation == "psk_authentication":
        secret = secrets.token_hex(32)
        for name in [device, parameters["peer"]]:
            item = config_file(profile, name)
            current = item.read_text()
            current, count = re.subn(r"(?m)^(\s*auth\s*=\s*).*$", r"\g<1>psk", current)
            if count != 2:
                raise ValueError("Expected local and remote authentication methods")
            current = re.sub(r"(?m)^\s*(certs|cacerts|revocation)\s*=.*\n", "", current)
            current += "\ninclude conf.d/credentials.conf\n"
            private = item.parent / "conf.d/credentials.conf"
            private.parent.mkdir(exist_ok=True)
            private.write_text('secrets {\n ike-peer {\n  secret = "' + secret + '"\n }\n}\n')
            private.chmod(0o600)
            item.write_text(current)
            changed.add(name)
        return changed
    elif operation == "optional_revocation":
        text = assign(text, "revocation", "relaxed")
        for crl in (path.parent / "x509crl").glob("*"):
            if crl.is_file():
                crl.unlink()
        journal.append(require_success(docker(device, ["swanctl", "--flush-certs", "--type", "x509_crl"])))
    elif operation == "ikev1":
        for name in [device, parameters["peer"]]:
            item = config_file(profile, name)
            current = assign(item.read_text(), "version", "1")
            current = assign(current, "proposals", "aes256-sha384-ecp384")
            item.write_text(current)
            changed.add(name)
        return changed
    elif operation == "ike_lifetime":
        text = assign(text, "reauth_time", str(parameters["hours"]) + "h")
    elif operation == "esp_lifetime":
        text = assign(text, "life_time", str(parameters["hours"]) + "h")
    elif operation == "transport_mode":
        text = assign(text, "mode", "transport")
    else:
        raise ValueError(operation)
    path.write_text(text)
    return changed


def start_ospf(profile, case, root, journal):
    device = case["device"]
    definition = next(d for d in profile["topology"]["devices"] if d["id"] == device)
    address = next(i["address"] for i in definition["interfaces"] if i["name"] == "black")
    iface = ipaddress.ip_interface(address)
    directory = root / "private/services" / device
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o755)
    (directory / "zebra.conf").write_text(f"hostname {device}\n")
    (directory / "ospfd.conf").write_text(
        f"hostname {device}\nrouter ospf\n ospf router-id {iface.ip}\n network {iface.network} area 0.0.0.0\n")
    for chain, flag in [("INPUT", "-i"), ("OUTPUT", "-o")]:
        journal.append(require_success(docker(device, ["iptables", "-I", chain, "1", flag, "black", "-p", "ospf", "-j", "ACCEPT"])))
    shell = "mkdir -p /run/frr; chown frr:frrvty /run/frr; /usr/lib/frr/zebra -d -A 127.0.0.1 -f /config/zebra.conf; exec /usr/lib/frr/ospfd -A 127.0.0.1 -f /config/ospfd.conf"
    helper = device + "-routing"
    journal.append(require_success(command([
        "docker", "run", "-d", "--name", helper,
        "--network", "container:" + device, "--pid", "container:" + device,
        "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--cap-add", "SYS_ADMIN", "--user", "root",
        "--mount", f"type=bind,src={directory},dst=/config,readonly",
        "--entrypoint", "/bin/sh", profile["topology"]["router_image"], "-c", shell,
    ])))


def apply(profile, root):
    network = profile["network"]
    if not (root / "private/baseline" / network / "runtime.json").is_file():
        raise ValueError("A complete baseline backup is required")
    journal_path = root / "public/mutations" / (network + ".json")
    if journal_path.exists():
        raise ValueError("A mutation journal already exists; restore before retrying")
    journal = {"network": network, "started_at": now(), "cases": [], "configuration_loads": []}
    changed = set()
    for case in profile["mutations"]:
        entry = {"case_id": case["case_id"], "started_at": now(), "commands": []}
        journal["cases"].append(entry)
        write_json(journal_path, journal)
        operation = case["operation"]
        device = case["device"]
        p = case["parameters"]
        try:
            if operation in {"weak_proposal", "duplicate_certificate", "psk_authentication", "optional_revocation", "ikev1", "ike_lifetime", "esp_lifetime", "transport_mode"}:
                changed.update(configure_authentication(profile, case, entry["commands"]))
            elif operation == "ospf":
                start_ospf(profile, case, root, entry["commands"])
            elif operation == "unused_interface":
                entry["commands"].append(require_success(docker(device, ["ip", "link", "add", p["interface"], "type", "dummy"])))
                entry["commands"].append(require_success(docker(device, ["ip", "link", "set", p["interface"], "up"])))
            else:
                entry["commands"].append(require_success(docker(device, rule_command(case))))
                if operation == "allow_unlisted_peer":
                    entry["commands"].append(require_success(docker(device, ["ip", "route", "add", p["destination"] + "/32", "via", p["gateway"], "dev", "black"])))
                if case["requirement"] == "MSC-PF-18":
                    keys = ["net.ipv4.conf.all.rp_filter", f"net.ipv4.conf.{p['ingress']}.rp_filter"]
                    entry["prior_sysctls"] = docker(device, ["sysctl", *keys])
                    entry["commands"].append(require_success(docker(device, ["sysctl", "-w", *[key + "=0" for key in keys]])))
                if operation == "allow_multicast":
                    program = "from pathlib import Path;import sys;Path('/tmp/network-service.py').write_text(sys.argv[1])"
                    entry["commands"].append(require_success(docker(device, ["python3", "-c", program, LISTENER])))
                    entry["commands"].append(require_success(command(["docker", "exec", "-d", device,
                        "python3", "/tmp/network-service.py", str(p["destination_port"]), p["destination"], p["local_address"]])))
                if operation == "allow_http":
                    program = "from pathlib import Path;p=Path('/tmp/network-www');p.mkdir(exist_ok=True);(p/'index.html').write_text('Device status\\n')"
                    entry["commands"].append(require_success(docker(device, ["python3", "-c", program])))
                    entry["commands"].append(require_success(command(["docker", "exec", "-d", device,
                        "python3", "-m", "http.server", str(p["destination_port"]), "--bind", p["destination"], "--directory", "/tmp/network-www"])))
                    entry["commands"].append(require_success(docker(device, ["iptables", "-I", "OUTPUT", "1", "-o", p["ingress"], "-p", "tcp", "--sport", str(p["destination_port"]), "-j", "ACCEPT"])))
            entry["status"] = "applied"
        except Exception as error:
            entry["status"] = "failed"
            entry["error"] = str(error)
            write_json(journal_path, journal)
            raise
        entry["ended_at"] = now()
        write_json(journal_path, journal)
    for device in sorted(changed):
        for argv in [["swanctl", "--load-creds", "--clear", "--noprompt"],
                     ["swanctl", "--load-conns"], ["swanctl", "--terminate", "--ike", "msc"]]:
            result = docker(device, argv)
            journal["configuration_loads"].append(result)
            write_json(journal_path, journal)
            if argv[1] != "--terminate":
                require_success(result)
    journal["ended_at"] = now()
    journal["status"] = "applied_awaiting_validation"
    write_json(journal_path, journal)
    return {"network": network, "cases_applied": len(journal["cases"]), "ended_at": journal["ended_at"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", required=True)
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    root = Path(args.root)
    for path in sorted(Path(args.profiles).glob("net-*.json")):
        print(json.dumps(apply(json.loads(path.read_text()), root)), flush=True)


if __name__ == "__main__":
    main()
