"""Import actual guest clock adjustments and their subsequent measured offsets."""
import argparse
from datetime import datetime
from decimal import Decimal
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from import_service_authorization import require, validate_public_bundle

SERVER_SOURCE = "46dec72a6f07f993e41ea83fb9ccb3b6e4cf3d93c37dd1613e43a4f690f5e1bc"
GRAY_COLLECTOR = "101a95264a4f2c3a1753595a655a197fcce3fe6134321b01a5c459b88e972be2"


def microseconds(value):
    scaled = Decimal(value) * 1000000
    require(scaled == scaled.to_integral_value(), "Sub-microsecond text needs an explicit rounding rule")
    return int(scaled)


def read_offset(row, source, red, adjusting=False):
    require(row["returncode"] == 0, "Clock query or adjustment failed")
    text = row["stdout"] + "\n" + row["stderr"]
    if red:
        pattern = (r"step time server " + re.escape(source) + r" offset ([+-]?\d+\.\d+) sec"
                   if adjusting else r"(?m)^server " + re.escape(source) +
                   r", stratum ([1-9]|1[0-5]), offset ([+-]?\d+\.\d+), delay \d+\.\d+")
        matches = re.findall(pattern, text)
        require(len(matches) == 1, "Missing source-bound FreeBSD offset")
        return microseconds(matches[0] if adjusting else matches[0][1])
    matches = re.findall(r"(?m)^\d{4}-\d{2}-\d{2} [\d:.]+ \(\+0000\) ([+-]?\d+\.\d+) "
                         r"\+/- \d+\.\d+ " + re.escape(source) + r" s(?:[1-9]|1[0-5]) no-leap$", text)
    require(len(matches) == 1, "Missing source-bound Linux offset")
    if adjusting:
        steps = re.findall(r"CLOCK: time stepped by ([+-]?\d+\.\d+)", text)
        require(len(steps) == 1 and microseconds(steps[0]) == microseconds(matches[0]),
                "Actual clock-step diagnostic missing or inconsistent")
    return microseconds(matches[0])


def parse_bundle(path, red):
    path = Path(path)
    data = validate_public_bundle(path)
    require("error" in data and data["error"] is None, "Explicit successful collection required")
    require(hashlib.sha256((path / "ntp-server.py").read_bytes()).hexdigest() == SERVER_SOURCE,
            "Unreviewed laboratory time server source")
    if not red:
        require(hashlib.sha256((path / "collector.source.py").read_bytes()).hexdigest() == GRAY_COLLECTOR,
                "Unreviewed synchronous Gray collector")
    rows = data["records"]
    require(len({row["id"] for row in rows}) == len(rows), "Duplicate command identity")
    expected = {"22222": "10.1.1.20", "22223": "10.2.1.20"} if red else {
        "22452": "10.100.1.20", "22453": "10.200.1.20"}
    guest_rows = {}
    for index, row in enumerate(rows):
        command = row.get("command", [])
        if command and command[0] == "ssh":
            require("-p" in command and command[-2] == "root@127.0.0.1", "Unexpected guest endpoint")
            port = command[command.index("-p") + 1]
            guest_rows.setdefault(port, []).append((index, row))
    require(set(guest_rows) == set(expected), "Incomplete selected guest inventory")
    corrections = []
    boot_ids = []
    for port, source in expected.items():
        guest = guest_rows[port]
        queries = [(i, row) for i, row in guest if row["command"][-1] == "ntpdate -q -u " + source]
        adjustments = [(i, row) for i, row in guest if row["command"][-1] == "ntpdate -b -u " + source]
        require(len(queries) == 3 and len(adjustments) == 1, "Complete before/adjustment/after sequence required")
        before, adjustment, after = queries[1], adjustments[0], queries[2]
        require(queries[0][0] < before[0] < adjustment[0] < after[0], "Clock commands are out of order")
        sequence = [queries[0], before, adjustment, after]
        for (_, left), (_, right) in zip(sequence, sequence[1:]):
            end = datetime.fromisoformat(left["ended_at"] if red else left["at"])
            start = datetime.fromisoformat(right["started_at"] if red else right["at"])
            require(end.tzinfo is not None and start.tzinfo is not None and end <= start,
                    "Collector times are unordered or lack timezone")
        values = [read_offset(row, source, red, i == 1)
                  for i, (_, row) in enumerate([before, adjustment, after])]
        require(abs(values[0]) > 1000000 and abs(values[2]) <= 1000,
                "Retained correction does not reach the selected one-millisecond sample bound")
        require(values[0] < 0 and values[1] < 0, "Expected forward displacement and corrective negative step")
        #* Match the requested time server to the explicit installed source address.
        address_commands = [row for row in rows if row["command"][:3] == ["ip", "netns", "exec"] and
                            source + "/24" in row["command"] and row["returncode"] == 0]
        require(len(address_commands) == 1, "Source address setup missing or duplicated")
        interface_command = "ifconfig vtnet2; netstat -rn" if red else \
            "ip -j address show gray; ip -j route; swanctl --list-sas; ip -s xfrm state list nokeys"
        interface_rows = [row for _, row in guest if row["command"][-1] == interface_command]
        require(len(interface_rows) == 1 and interface_rows[0]["returncode"] == 0, "Client interface readback missing")
        if red:
            matches = re.findall(r"\binet ([\d.]+) netmask 0xffffff00", interface_rows[0]["stdout"])
            require(len(matches) == 1, "Ambiguous Red client interface")
            address = matches[0]
        else:
            interfaces, _ = json.JSONDecoder().raw_decode(interface_rows[0]["stdout"])
            require(len(interfaces) == 1 and interfaces[0]["ifname"] == "gray", "Wrong Gray client interface")
            addresses = [row["local"] for row in interfaces[0]["addr_info"]
                         if row["family"] == "inet" and row["prefixlen"] == 24]
            require(len(addresses) == 1, "Ambiguous Gray client address")
            address = addresses[0]
            identity_rows = [row for _, row in guest if row["command"][-1] == "cat /proc/sys/kernel/random/boot_id"]
            require(len(identity_rows) == 1 and identity_rows[0]["returncode"] == 0 and
                    re.fullmatch(r"[0-9a-f-]{36}\n?", identity_rows[0]["stdout"]), "Guest boot identity missing")
            boot_ids.append(identity_rows[0]["stdout"].strip())
        require(ipaddress.ip_address(source) in ipaddress.ip_interface(address + "/24").network,
                "Client and recorded source are not on the same selected subnet")
        corrections.append({"client": ("Red-FreeBSD-guest:" if red else "Gray-Linux-guest:") + port,
                            "source": source, "client_address": address,
                            "before_order": before[0], "adjustment_order": adjustment[0], "after_order": after[0],
                            "before_offset_us": values[0], "applied_offset_us": values[1], "after_offset_us": values[2],
                            "observations": [row["id"] for _, row in [before, adjustment, after]],
                            "bundle": str(path), "runtime_backend": data["runtime_backend"]})
    require(red or len(set(boot_ids)) == 2, "Distinct Gray guest clock identities required")
    controls = [row for row in rows if row["command"][:2] == ["docker", "exec"] and "ping" in row["command"]]
    require(len(controls) == 1 and controls[0]["returncode"] == 0 and
            " 0% packet loss" in controls[0]["stdout"], "Protected traffic did not pass after correction")
    require(rows.index(controls[0]) > max(row["after_order"] for row in corrections),
            "Protected traffic control predates the corrections")
    return {"path": str(path), "manifest_sha256": hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest(),
            "corrections": corrections, "positive_control": controls[0]["id"], "boot_ids": boot_ids}


def generate(cases):
    records = [row for case in cases for row in case["corrections"]]
    values = []
    for row in records:
        values.append("⟨" + ", ".join([json.dumps(row["client"]), json.dumps(row["source"]),
            *[str(row[key]) for key in ["before_order", "adjustment_order", "after_order"]],
            *["(" + str(row[key]) + ")" for key in ["before_offset_us", "applied_offset_us", "after_offset_us"]],
            "true"]) + "⟩")
    return """import TDN.Requirements.TrustedClockSynchronization

namespace TDN.Deployments.FreshClockCorrections
open ClockSamples Requirements

/-- Two separately recorded experiments are preserved in these client identifiers.
The list does not assert one simultaneous combined deployment snapshot. -/
def corrections : List Correction := [""" + ",\n  ".join(values) + """]

/-- One millisecond is the selected measurement threshold, not a CP timing bound. -/
lemma corrected_samples : ∀ r ∈ corrections, CorrectedAtSample 1000 r := by decide
lemma initially_displaced : ∀ r ∈ corrections, 1000 < r.beforeOffsetUs.natAbs := by decide

theorem each_observed_correction_reduces_offset :
    ∀ r ∈ corrections, r.afterOffsetUs.natAbs < r.beforeOffsetUs.natAbs :=
  all_checked_clock_corrections_improve_offset corrections 1000 corrected_samples initially_displaced

lemma complete_selected_clock_inventory : corrections.length = 4 := by decide

end TDN.Deployments.FreshClockCorrections
"""


def main():
    parser = argparse.ArgumentParser()
    for name in ["red", "gray", "output", "report"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    cases = [parse_bundle(args.red, True), parse_bundle(args.gray, False)]
    Path(args.output).write_text(generate(cases))
    report = {"cases": cases, "server_source_sha256": SERVER_SOURCE,
              "gray_collector_sha256": GRAY_COLLECTOR, "sample_tolerance_microseconds": 1000,
              "whole_RG042_established": False,
              "limits": [
                  "Only actual successful -b adjustments count. Query-only ntpdate output sometimes says step time and cannot substitute for an adjustment command.",
                  "Offsets are NTP-reported estimates; collector truth and client implementation remain assumptions.",
                  "Red records have start/end times. The pinned Gray collector records one timestamp after each synchronous command returns. These are collector completion times, unaffected by guest clock steps.",
                  "The source servers derive time from their worker clocks and have no supplied organizational trust record or authenticated-time guarantee.",
                  "The Gray experiment uses a Gray data interface. Compliance with the requirement's Gray Management Network placement has not been established.",
                  "The temporary servers were removed after collection. No persistent service or future drift bound is established.",
                  "The Red and Gray observations concern different named experimental deployments and collection intervals.",
                  "The expected two-client inventory is complete for each selected correction experiment, not for every component to which SR-3/SR-4 apply."]}
    Path(args.report).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"clock_corrections": 4, "post_adjustment_offset_us":
                      [row["after_offset_us"] for case in cases for row in case["corrections"]],
                      "whole_RG042_established": False}))


if __name__ == "__main__":
    main()
