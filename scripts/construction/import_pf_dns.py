"""Bind complete PF rule/state inventories to the reusable DNS history proof."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from import_macsec_runtime import validate_files
from import_snapshot import quoted
from validate_evidence import require


def addresses(text):
    result = []
    interface = None
    for line in text.splitlines():
        header = re.match(r"^(\w+): flags=", line)
        if header:
            interface = header[1]
        item = re.match(r"\s+(inet6?) (\S+)", line)
        if item:
            require(interface is not None, "Address without interface")
            raw = item[2].split("%")[0]
            address = ipaddress.ip_address(raw)
            scope = interface if address.version == 6 and address.is_link_local else None
            result.append({"address": str(address), "scope": scope,
                           "family": "inet6" if address.version == 6 else "inet"})
    require(result and len({(r["address"], r["scope"]) for r in result}) == len(result),
            "Missing or duplicate local binding")
    return result


def rules(text):
    result = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("  ["):
            require(re.fullmatch(r"  \[ (Evaluations:.*|Inserted:.*|Last Active Time:.*) \]", line),
                    "Unknown rule metadata")
            continue
        match = re.fullmatch(
            r"@(\d+) block return out quick (?:on (\w+) )?(inet6?) proto (tcp|udp) "
            r"from (\S+) to any port = domain", line)
        require(match is not None, "Unsupported rule, normalization or non-quick action")
        require(int(match[1]) == len(result), "Nonconsecutive rule order")
        address = ipaddress.ip_address(match[5])
        require((address.version == 6) == (match[3] == "inet6"), "Wrong rule family")
        result.append({"address": str(address), "scope": match[2], "family": match[3],
                       "protocol": match[4]})
    require(result, "Empty PF rules")
    return result


def parse(path):
    digest = validate_files(path)
    data = json.loads((path / "observations.json").read_text())
    require(data["error"] is None, "Failed PF collection")
    records = data["records"]
    require(len({r["id"] for r in records}) == len(records), "Duplicate record")
    require(all(r["returncode"] == 0 for r in records), "Failed observation")
    guests = {}
    for r in records:
        if r["command"][0] != "ssh":
            continue
        command = r["command"]
        require(command[-2] == "root@127.0.0.1" and "-p" in command, "Unbound PF guest")
        port = command[command.index("-p") + 1]
        guests.setdefault(port, []).append(r)
    require(set(guests) == {"22222", "22223"}, "Incomplete selected guest inventory")
    outputs = []
    for port, rows in sorted(guests.items()):
        def get(command, count=None):
            selected = [r for r in rows if r["command"][-1] == command]
            require(selected and (count is None or len(selected) == count),
                    "Missing or ambiguous command: " + command)
            return selected
        interface_rows = get("ifconfig -a")
        local = addresses(interface_rows[0]["stdout"])
        require(all(addresses(r["stdout"]) == local for r in interface_rows),
                "Local addresses changed")
        flag_rows = [r for r in rows if r["command"][-1] == "pfctl -vvs Interfaces"]
        flag_names = []
        if flag_rows:
            require(len(flag_rows) == 2 and len(interface_rows) == 2, "Missing skip interval")
            expected_interfaces = set(re.findall(r"^(\w+): flags=", interface_rows[0]["stdout"], re.M))
            for r in flag_rows:
                headers = [line for line in r["stdout"].splitlines() if line and not line[0].isspace()]
                require(all(re.fullmatch(r"\w+", line) for line in headers),
                        "Skipped interface or unknown effective interface flag")
                require(expected_interfaces <= set(headers) and len(headers) == len(set(headers)),
                        "Incomplete effective interface flags")
                if flag_names:
                    require(headers == flag_names, "Effective interface inventory changed")
                flag_names = headers
        raw_rules = get("pfctl -sr -vv", 2)
        parsed = rules(raw_rules[0]["stdout"])
        require(rules(raw_rules[1]["stdout"]) == parsed, "Filter changed over interval")
        require(rules(get("pfctl -a '*' -sr -vv", 1)[0]["stdout"]) == parsed,
                "Recursive rules differ")
        all_settings = get("pfctl -sa -vv", 1)[0]["stdout"]
        require(all_settings.startswith("FILTER RULES:\n") and "\nINFO:\n" in all_settings,
                "Missing complete settings filter section")
        require(rules(all_settings[len("FILTER RULES:\n"):all_settings.index("\nINFO:\n")]) == parsed,
                "All-settings filter or scrub inventory differs")
        require("Reassemble                       no" in all_settings,
                "Different reassembly setting requires review")
        for command, count in [("pfctl -sn -vv", 2), ("pfctl -a '*' -sn -vv", 1),
                               ("pfctl -s Anchors -v", 1), ("pfctl -s Tables -v", 1),
                               ("pfctl -ss -vv", 2)]:
            require(all(not r["stdout"].strip() for r in get(command, count)),
                    "Active translation, anchor, table or cached state")
        for r in get("pfctl -si", 2):
            require(r["stdout"].startswith("Status: Enabled") and
                    re.search(r"current entries\s+0\s", r["stdout"]),
                    "PF disabled or cache nonempty")
        expected = {(r["address"], r["scope"], r["family"], protocol)
                    for r in local for protocol in ("tcp", "udp")}
        actual = [(r["address"], r["scope"], r["family"], r["protocol"]) for r in parsed]
        require(len(actual) == len(set(actual)) and set(actual) == expected,
                "Expanded rules omit or add a local address/transport")
        config = get("cat /etc/pf.conf", 1)[0]["stdout"]
        require(config == "set block-policy return\nblock return out quick proto { tcp, udp } from self to any port 53\n",
                "Different intended PF config")
        require(get("sha256 /etc/pf.conf", 1)[0]["stdout"].strip().endswith(
            hashlib.sha256(config.encode()).hexdigest()), "Config hash mismatch")
        require(get("freebsd-version -kru", 1)[0]["stdout"].splitlines()[:2] ==
                ["14.4-RELEASE-p11"] * 2, "Different kernel family requires source review")
        outputs.append({"guest_port": port, "addresses": local, "guards": parsed,
                        "unskipped_interfaces": flag_names,
                        "observation_ids": [r["id"] for r in rows],
                        "kernel": get("uname -a", 1)[0]["stdout"],
                        "host": get("sysctl kern.hostuuid kern.boottime", 1)[0]["stdout"]})
    probes = [r for r in records if r["command"][0] != "ssh"]
    require(len(probes) == 2 and all("3 packets transmitted, 3 received, 0% packet loss" in
                                    r["stdout"] for r in probes), "No bidirectional useful traffic")
    return {"bundle": str(path), "manifest_sha256": digest, "guests": outputs,
            "scope": "Fixed captured rules and address bindings, initially empty state, no administrative/state-sync injection. Effective skip flags are checked when the complete interface observations are present; see hook_applicability_checked. Implicit default PASS is preserved.",
            "source_contract": "FreeBSD releng/14.4: default keep_state=0; no translation; no matching scrub rule means no PFDESC_TCP_NORM. Stateless normalization may still reject packets. All explicit rules are quick denials.",
            "pending": ([] if all(g["unskipped_interfaces"] for g in outputs) else
                        ["Effective per-interface skip flags"]),
            "hook_applicability_checked": all(g["unskipped_interfaces"] for g in outputs)}


def binding(row):
    scope = "none" if row["scope"] is None else "some " + quoted(row["scope"])
    return "{ address := " + quoted(row["address"]) + ", scopeInterface := " + scope + " }"


def generate(report):
    lines = ["import TDN.Targets.StatefulDNS", "", "namespace TDN.Imported.FreshFreeBSDDNS",
             "open Targets.StatefulDNS", ""]
    for i, guest in enumerate(report["guests"]):
        name = "guest" + str(i)
        lines += ["def " + name + "Addresses : List LocalAddress := [" +
                  ", ".join(binding(r) for r in guest["addresses"]) + "]",
                  "def " + name + "Guards : List Guard := [" +
                  ", ".join("{ binding := " + binding(r) + ", protocol := " +
                            quoted(r["protocol"]) + " }" for r in guest["guards"]) + "]",
                  "lemma " + name + "_coverage : ∀ address ∈ " + name + "Addresses,",
                  '    ∀ protocol ∈ ["tcp", "udp"],',
                  "    { binding := address, protocol := protocol } ∈ " + name + "Guards := by",
                  "  unfold " + name + "Addresses " + name + "Guards", "  decide", "",
                  "theorem " + name + "_dns_denied_after_any_history",
                  "    {events : List (Option Packet)} {cache : List Unit}",
                  "    (run : (StatefulFilter.lts (policy " + name + "Guards)).MTr [] events cache)",
                  "    (packet : Packet) (request : ConventionalLocalRequest " + name + "Addresses packet) :",
                  "    StatefulFilter.verdict (policy " + name + "Guards) cache packet = .deny :=",
                  "  local_dns_denied_after_any_history _ _ " + name + "_coverage run packet request", ""]
        if guest["unskipped_interfaces"]:
            lines += ["theorem " + name + "_enabled_egress_dns_denial",
                      "    {events : List (Option Packet)} {cache : List Unit}",
                      "    (run : (StatefulFilter.lts (policy " + name + "Guards)).MTr [] events cache)",
                      "    (packet : Packet) (request : ConventionalLocalRequest " + name + "Addresses packet) :",
                      "    hookVerdict true [] " + name + "Guards cache packet = .deny :=",
                      "  enabled_egress_denies_local_dns _ _ " + name + "_coverage run packet request", ""]
    lines += ["end TDN.Imported.FreshFreeBSDDNS", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--lean", type=Path, required=True)
    args = parser.parse_args()
    report = parse(args.bundle)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    args.lean.write_text(generate(report))
    print(json.dumps({"guests": len(report["guests"]), "rules": sum(len(r["guards"]) for r in report["guests"])}))
