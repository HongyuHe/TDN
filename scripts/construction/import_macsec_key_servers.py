"""Bind CKN lengths and configured key-server priorities without claiming KGS approval."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from import_macsec_algorithms import LAUNCH_PIN
from import_macsec_runtime import parse as parse_runtime
from validate_evidence import require


def parse(cases):
    results = []
    arrangements = []
    for path in map(Path, cases):
        runtime = parse_runtime(path)
        require(hashlib.sha256((path / "collector.source.py").read_bytes()).hexdigest() == LAUNCH_PIN,
                "Unreviewed EAP launch source")
        case = json.loads((path / "case.json").read_text())
        require(case["script_sha256"] == LAUNCH_PIN and
                {case["authenticator"], case["supplicant"]} == {"P0", "P1"},
                "Incomplete EAP arrangement")
        arrangements.append(case["authenticator"])
        evidence = json.loads((path / "evidence.json").read_text())
        devices = {row["id"]: row for row in evidence["devices"]}
        require(len(devices) == len(evidence["devices"]) and set(devices) == {"P0", "P1", "AS"},
                "Unexpected device inventory")
        require(all(devices[name]["site"] == ("central" if name in [case["authenticator"], "AS"] else "remote")
                    for name in devices), "Declared sites differ from reviewed arrangement")
        commands = json.loads((path / "commands.json").read_text())
        peers = []
        for name in ["P0", "P1"]:
            logs = [row for row in commands if row["command"][0] == "cat" and
                    Path(row["command"][-1]).name == name + ".log"]
            require(len(logs) == 1 and logs[0]["returncode"] == 0, "Incomplete peer log")
            log = logs[0]["stdout"]
            priorities = set(re.findall(r"KaY: Initialize[^\n]*\bpriority=(\d+)", log))
            require(len(priorities) == 1, "Missing or changing local key-server priority")
            priority = int(next(iter(priorities)))
            expected = 0 if name == case["authenticator"] else 1
            require(priority == expected, "Local priority differs from source-bound configuration")
            #* The retained log redacts the CKN bytes. Preserve only its reported length.
            lengths = re.findall(r"KaY: CKN - hexdump\(len=(\d+)\):[^\n]*", log)
            require(len(lengths) == 1, "Missing or multiple reported CKN lengths")
            size = int(lengths[0])
            require(size >= 16, "CKN length below required minimum")
            peers.append({"device": name, "site": devices[name]["site"], "priority": priority,
                          "ckn_bytes": size, "ckn_value_exported": False,
                          "log_observation": logs[0]["id"]})
        results.append({"bundle": str(path), "manifest_sha256": runtime["manifest_sha256"],
                        "source_sha256": LAUNCH_PIN, "peers": peers, "central_site": "central",
                        "configured_key_server": case["authenticator"]})
    require(len(results) == 2 and set(arrangements) == {"P0", "P1"}, "Both distinct role arrangements required")
    return results


def generate(cases):
    values = []
    for case in cases:
        left, right = case["peers"]
        values.append("⟨" + ", ".join([json.dumps(left["site"]), json.dumps(right["site"]),
            str(left["priority"]), str(right["priority"]), "some " + json.dumps(case["central_site"]),
            str(min(left["ckn_bytes"], right["ckn_bytes"]))]) + "⟩")
    return """import TDN.Requirements.MACsecKeyServer

namespace TDN.Deployments.FinalMACsecKeyServers
open Requirements

/-- The two entries retain the forward and reverse EAP role arrangements. -/
def settings : List MACsecKeyServerSettings := [""" + ", ".join(values) + """]

lemma local_settings : ∀ s ∈ settings, s.Checked := by decide

theorem configured_server_matches_central_site (s : MACsecKeyServerSettings)
    (member : s ∈ settings) (central : String) (present : s.centralSite = some central) :
    selectedKeyServer s = central :=
  checked_key_server_is_central (local_settings s member) present

theorem configured_priorities_are_distinct (s : MACsecKeyServerSettings) (member : s ∈ settings) :
    s.leftPriority ≠ s.rightPriority := checked_pair_has_distinct_priorities (local_settings s member)

lemma both_arrangements_present : settings.length = 2 := by decide

end TDN.Deployments.FinalMACsecKeyServers
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", nargs="+")
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    cases = parse(args.cases)
    Path(args.output).write_text(generate(cases))
    report = {"cases": cases, "whole_RG027_established": False,
              "covered_clauses": ["MD-5 minimum CKN length only", "MD-6 configured0/1 priorities and declared central-site selection"],
              "remaining": [
                  "The public logs retain reported CKN lengths and redact the bytes. No equality of actual CKN values or byte-level length measurement is inferred; trustworthy reporting is an implementation assumption.",
                  "NSA-approved KGS provenance for the actual CAK/CKN is not supplied.",
                  "PSK provisioning requires its own complete observations and approved-source evidence.",
                  "The two EAP arrangements do not themselves establish disabled fallback/rollover CAKs. No false default is inserted for MD-15.",
                  "The theorem concerns configured selection under the lower-priority rule. An all-execution distributed-election guarantee requires its own protocol semantics and assumptions.",
                  "Central and remote are source-declared architectural sites in this supplemental experiment, not measurements of physical geography."]}
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"arrangements": len(cases), "peer_records": sum(len(case["peers"]) for case in cases),
                      "whole_RG027_established": False}))


if __name__ == "__main__":
    main()
