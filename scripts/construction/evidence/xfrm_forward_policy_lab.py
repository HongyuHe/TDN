"""Observe Linux forwarding-policy selection in three temporary namespaces."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess


def now():
    return datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    names = ["tdnxf" + str(os.getpid()) + "-" + str(i) for i in range(3)]
    source, gateway, destination = names
    created, records, cases = [], [], []
    error = None
    started = now()

    def run(command, allow_failure=False):
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        record = {"id": "xfrm-%04d" % len(records), "at": now(), "command": command,
                  "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        records.append(record)
        if result.returncode and not allow_failure:
            raise RuntimeError(result.stderr or result.stdout)
        return record

    def net(name, *command, allow_failure=False):
        return run(["ip", "netns", "exec", name, *command], allow_failure)

    def policy(direction, level="required", match_source="10.200.1.2/32", priority=100, template=True):
        command = ["ip", "xfrm", "policy", "add", "src", match_source, "dst", "10.100.1.2/32",
                   "dir", direction, "priority", str(priority), "action", "allow"]
        if template:
            command += ["tmpl", "src", "172.20.21.1", "dst", "172.20.11.1", "proto", "esp",
                        "mode", "tunnel", "reqid", "201", "level", level]
        return command

    scenarios = [
        ("no_policy", [], True),
        ("required_in_only", [policy("in")], True),
        ("required_fwd", [policy("fwd")], False),
        ("optional_fwd", [policy("fwd", level="use")], True),
        ("nonmatching_fwd", [policy("fwd", match_source="10.200.1.3/32")], True),
        ("higher_priority_bypass", [policy("fwd"), policy("fwd", match_source="10.200.1.0/24", priority=10, template=False)], True),
        ("lower_priority_bypass", [policy("fwd"), policy("fwd", match_source="10.200.1.0/24", priority=200, template=False)], False),
    ]
    try:
        run(["uname", "-a"])
        run(["ip", "-Version"])
        for name in names:
            run(["ip", "netns", "add", name])
            created.append(name)
            run(["ip", "-n", name, "link", "set", "lo", "up"])
            net(name, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0")
        for left, left_port, left_ip, right, right_port, right_ip in [
            (source, "s0", "10.200.1.2/24", gateway, "g0", "10.200.1.1/24"),
            (gateway, "g1", "10.100.1.1/24", destination, "d0", "10.100.1.2/24"),
        ]:
            run(["ip", "-n", left, "link", "add", left_port, "type", "veth", "peer", "name", right_port, "netns", right])
            for name, port, address in [(left, left_port, left_ip), (right, right_port, right_ip)]:
                run(["ip", "-n", name, "addr", "add", address, "dev", port])
                run(["ip", "-n", name, "link", "set", port, "up"])
        net(gateway, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        net(source, "ip", "route", "add", "default", "via", "10.200.1.1")
        net(destination, "ip", "route", "add", "default", "via", "10.100.1.1")
        for name in names:
            net(name, "ip", "-j", "address", "show")
            net(name, "ip", "-j", "route", "show", "table", "all")
            net(name, "ip", "xfrm", "state", "list", "nokeys")
            net(name, "iptables-save")
        for label, commands, expected in scenarios:
            net(gateway, "ip", "xfrm", "policy", "flush")
            installations = [net(gateway, *command)["id"] for command in commands]
            policies = net(gateway, "ip", "-d", "xfrm", "policy", "list")
            before = net(gateway, "cat", "/proc/net/xfrm_stat")
            probe = net(source, "ping", "-n", "-c", "1", "-W", "1", "10.100.1.2", allow_failure=True)
            after = net(gateway, "cat", "/proc/net/xfrm_stat")
            cases.append({"id": label, "expected_forwarding": expected,
                          "observed_forwarding": probe["returncode"] == 0,
                          "installations": installations, "policies": policies["id"],
                          "before": before["id"], "probe": probe["id"], "after": after["id"]})
    except Exception as exc:
        error = str(exc)
        raise
    finally:
        for name in reversed(created):
            run(["ip", "netns", "del", name], allow_failure=True)
        document = {"schema": "tdn-xfrm-forward-policy/v1", "started_at": started, "ended_at": now(),
                    "namespaces": names, "records": records, "cases": cases, "error": error,
                    "scope": "Single IPv4 ICMP request per policy configuration; empty SA databases; no encryption or IKE authentication claim."}
        (args.output / "observations.json").write_text(json.dumps(document, indent=2) + "\n")
        (args.output / "collector.py").write_bytes(Path(__file__).read_bytes())
        files = [{"path": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                 for p in sorted(args.output.iterdir()) if p.is_file()]
        (args.output / "manifest.json").write_text(json.dumps({"files": files}, indent=2) + "\n")
    mismatches = [case["id"] for case in cases if case["observed_forwarding"] != case["expected_forwarding"]]
    print(json.dumps({"cases": len(cases), "mismatches": mismatches}))
    if mismatches:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
