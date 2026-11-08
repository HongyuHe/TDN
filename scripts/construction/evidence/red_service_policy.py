"""Declare and apply a narrow Red test-service policy to existing native profiles."""

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import shlex
import subprocess
import time


BODY = "TDN Red service on TCP 8080\n"


def utc():
    return datetime.now(timezone.utc).isoformat()


def hosts_for_profile(spec):
    hosts = {}
    for device in spec["devices"]:
        if device["role"] != "host":
            continue
        addresses = [str(ipaddress.ip_interface(port["address"]).ip)
                     for port in device["interfaces"] if port["zone"] == "red" and port.get("address")]
        if len(addresses) != 1:
            raise ValueError("Each test host must have exactly one Red IPv4 address")
        hosts[device["id"]] = addresses[0]
    rows = []
    for device in spec["devices"]:
        if device["role"] != "inner":
            continue
        tunnel = device["tunnel"]
        local = [(name, address) for name, address in hosts.items()
                 if ipaddress.ip_address(address) in ipaddress.ip_network(tunnel["local_ts"])]
        remote = [(name, address) for name, address in hosts.items()
                  if ipaddress.ip_address(address) in ipaddress.ip_network(tunnel["remote_ts"])]
        if len(local) != 1 or len(remote) != 1:
            raise ValueError("Test policy requires one host at each configured Inner subnet")
        rows.append({"profile": spec["name"], "inner": device["id"],
                     "host": local[0][0], "localAddress": local[0][1],
                     "peerHost": remote[0][0], "peerAddress": remote[0][1],
                     "level": device.get("level"), "inside": tunnel["inside"],
                     "outside": tunnel["outside"], "localSubnet": tunnel["local_ts"],
                     "remoteSubnet": tunnel["remote_ts"], "reqid": tunnel["reqid"]})
    if len({row["host"] for row in rows}) != len(rows) or set(hosts) != {row["host"] for row in rows}:
        raise ValueError("Every declared host must have exactly one Inner policy")
    return rows


def inner_rules(before, row):
    result, removed = [], []
    for line in before.splitlines():
        tokens = shlex.split(line)
        if tokens[:2] != ["-A", "FORWARD"] or "-j" not in tokens or tokens[tokens.index("-j") + 1] != "ACCEPT":
            result.append(line)
            continue
        def field(name):
            return tokens[tokens.index(name) + 1] if name in tokens else None
        if {field("-i"), field("-o")} != {row["inside"], row["outside"]}:
            raise ValueError("Unexpected Inner forwarding allowance")
        if field("--reqid") != str(row["reqid"]) or field("--pol") != "ipsec" or field("--mode") != "tunnel":
            raise ValueError("Missing Inner encryption guard")
        if field("-p") not in {"tcp", "udp", "esp", "icmp"}:
            raise ValueError("Unexpected Inner application protocol")
        direction = field("-i") == row["inside"]
        source = row["localAddress"] if direction else row["peerAddress"]
        destination = row["peerAddress"] if direction else row["localAddress"]
        if ipaddress.ip_address(source) not in ipaddress.ip_network(field("-s")) or ipaddress.ip_address(destination) not in ipaddress.ip_network(field("-d")):
            raise ValueError("Existing Inner policy does not bind the declared pair")
        removed.append(line)
    if not removed:
        raise ValueError("No recognized Inner forwarding policy")
    additions = []
    for outbound in [True, False]:
        source, destination = (row["localAddress"], row["peerAddress"]) if outbound else (row["peerAddress"], row["localAddress"])
        ingress, egress = (row["inside"], row["outside"]) if outbound else (row["outside"], row["inside"])
        base = ["-A", "FORWARD", "-s", source + "/32", "-d", destination + "/32", "-i", ingress, "-o", egress]
        policy = ["-m", "policy", "--dir", "out" if outbound else "in", "--pol", "ipsec", "--reqid", str(row["reqid"]), "--mode", "tunnel"]
        for port in ["--dport", "--sport"]:
            additions.append(shlex.join(base + ["-p", "tcp", "-m", "tcp", port, "8080"] + policy + ["-j", "ACCEPT"]))
        for kind in ["8", "0"]:
            additions.append(shlex.join(base + ["-p", "icmp", "-m", "icmp", "--icmp-type", kind] + policy + ["-j", "ACCEPT"]))
    position = result.index("COMMIT")
    result[position:position] = additions
    return "\n".join(result) + "\n", removed, additions


def host_rules(before, row):
    line = f'-A INPUT -s {row["peerAddress"]}/32 -d {row["localAddress"]}/32 -i red -p tcp -m tcp --dport 8080 -j ACCEPT'
    lines = before.splitlines()
    if tuple(shlex.split(line)) not in {tuple(shlex.split(item)) for item in lines if item.startswith("-A ")}:
        lines.insert(lines.index("COMMIT"), line)
    return "\n".join(lines) + "\n"


def rule_lines(text):
    chains = {}
    for line in text.splitlines():
        if line.startswith("-A "):
            tokens = tuple(shlex.split(line))
            chains.setdefault(tokens[1], []).append(tokens)
        elif line.startswith(":"):
            name, policy, _ = line.split()
            chains[name] = policy
    return chains


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    rows = [row for path in args.spec for row in hosts_for_profile(json.loads(path.read_text()))]
    records, plans, changed, cases = [], [], [], []
    started, error = utc(), None

    def command(argv, stdin=None, timeout=30, check=True):
        began = utc()
        try:
            value = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
            code, stdout, stderr = value.returncode, value.stdout, value.stderr
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr = 124, str(exc.stdout or ""), "collector timeout"
        record = {"id": "command-%04d" % len(records), "started_at": began, "ended_at": utc(),
                  "command": argv, "returncode": code, "stdout": stdout, "stderr": stderr}
        records.append(record)
        if check and code:
            raise RuntimeError("Command failed: " + shlex.join(argv) + "\n" + stderr)
        return record

    def table(device):
        return command(["docker", "exec", device, "iptables-save", "-t", "filter"])["stdout"]

    try:
        for row in rows:
            for device, transform in [(row["inner"], lambda text: inner_rules(text, row)[0]),
                                      (row["host"], lambda text: host_rules(text, row))]:
                before = table(device)
                proposed = transform(before)
                (args.output / (device + ".before.rules")).write_text(before)
                (args.output / (device + ".proposed.rules")).write_text(proposed)
                command(["docker", "exec", "-i", device, "iptables-restore", "--test"], proposed)
                plans.append({"device": device, "before": before, "proposed": proposed})
            command(["docker", "exec", row["host"], "ss", "-lntup"])
        if args.apply:
            for plan in plans:
                changed.append(plan)
                command(["docker", "exec", "-i", plan["device"], "iptables-restore"], plan["proposed"])
                after = table(plan["device"])
                (args.output / (plan["device"] + ".after.rules")).write_text(after)
                if rule_lines(after) != rule_lines(plan["proposed"]):
                    raise RuntimeError("Ordered rule read-back differs: " + plan["device"])
            for row in rows:
                prepare = "from pathlib import Path; p=Path('/tmp/tdn-red-service'); p.mkdir(exist_ok=True); (p/'index.html').write_text(" + repr(BODY) + ")"
                command(["docker", "exec", row["host"], "python3", "-c", prepare])
                listeners = command(["docker", "exec", row["host"], "ss", "-lntp"])
                if row["localAddress"] + ":8080" not in listeners["stdout"]:
                    command(["docker", "exec", "-d", row["host"], "python3", "-m", "http.server", "8080",
                             "--bind", row["localAddress"], "--directory", "/tmp/tdn-red-service"])
            for row in rows:
                deadline = time.monotonic() + 45
                while True:
                    listeners = command(["docker", "exec", row["host"], "ss", "-lntp"])
                    if row["localAddress"] + ":8080" in listeners["stdout"] or time.monotonic() >= deadline:
                        break
                    time.sleep(1)
                if row["localAddress"] + ":8080" not in listeners["stdout"]:
                    raise RuntimeError("Expected Red service listener missing: " + row["host"])
                ping = command(["docker", "exec", row["host"], "ping", "-n", "-c", "1", "-W", "2", row["peerAddress"]], check=False)
                cases.append({"id": row["host"] + "/paired-ping", "device": row["host"], "kind": "icmp-echo",
                              "observation": ping["id"], "expected": True, "observed": ping["returncode"] == 0})
                targets = [("paired-http", row["peerAddress"], 8080, True), ("wrong-port", row["peerAddress"], 8081, False)]
                other = next((other for other in rows if other["profile"] == row["profile"] and other["level"] != row["level"]), None)
                if other:
                    targets.append(("cross-level", other["localAddress"], 8080, False))
                for label, address, port, expected in targets:
                    before = command(["docker", "exec", row["inner"], "iptables", "-nvx", "-L", "FORWARD"])
                    probe = "import http.client,json; c=http.client.HTTPConnection(" + repr(address) + "," + str(port) + ",timeout=2)\ntry:\n c.request('GET','/'); r=c.getresponse(); body=r.read().decode(); ok=r.status==200 and body==" + repr(BODY) + "; print(json.dumps({'connected':True,'status':r.status,'body':body,'service_ok':ok}))\nexcept Exception as e:\n print(json.dumps({'connected':False,'error':type(e).__name__}))\n"
                    result = command(["docker", "exec", row["host"], "python3", "-c", probe])
                    response = json.loads(result["stdout"])
                    observed = response.get("service_ok", False) if expected else response["connected"]
                    after = command(["docker", "exec", row["inner"], "iptables", "-nvx", "-L", "FORWARD"])
                    cases.append({"id": row["host"] + "/" + label, "device": row["host"], "kind": "tcp-http",
                                  "destination": address, "port": port, "observation": result["id"],
                                  "beforeCounter": before["id"], "afterCounter": after["id"],
                                  "expected": expected, "observed": observed})
            if any(case["expected"] != case["observed"] for case in cases):
                raise RuntimeError("Red service validation failed")
    except Exception as exc:
        error = str(exc)
        for plan in reversed(changed):
            command(["docker", "exec", "-i", plan["device"], "iptables-restore"], plan["before"], check=False)
        raise
    finally:
        policy = {"schema": "tdn-red-service-policy/v1", "decision": "New supervisor-selected emulation workload for RG-035; not inferred from previously broad rules.",
                  "scope": "Exact paired Red hosts use TCP HTTP 8080 requests/replies and ICMP echo request/reply diagnostics. Existing local IKE and Outer/Gray rules remain unchanged.",
                  "icmpPortRepresentation": "ICMP has no transport port; the Lean packet model uses 0 in the unused port fields.",
                  "services": [{"device": row["host"], "inner": row["inner"], "address": row["localAddress"],
                                "protocol": "tcp", "port": 8080, "purpose": "HTTP test endpoint"} for row in rows],
                  "diagnostics": [{"device": row["host"], "inner": row["inner"], "address": row["localAddress"],
                                   "protocol": "icmp", "types": [0, 8], "port": None, "modelPort": 0} for row in rows],
                  "pairs": rows, "started_at": started, "ended_at": utc(), "applied": args.apply,
                  "error": error, "cases": cases, "records": records}
        (args.output / "observations.json").write_text(json.dumps(policy, indent=2) + "\n")
        (args.output / "collector.py").write_bytes(Path(__file__).read_bytes())
        for index, path in enumerate(args.spec):
            (args.output / ("profile-%d.json" % index)).write_bytes(path.read_bytes())
        manifest = {"files": [{"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                              for path in sorted(args.output.iterdir()) if path.is_file()]}
        (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"applied": args.apply, "pairs": len(rows), "cases": len(cases), "all_expected": all(case["expected"] == case["observed"] for case in cases)}))


if __name__ == "__main__":
    main()
