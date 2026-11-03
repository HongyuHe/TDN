"""Bind guest time discipline and certificate checks to observed source interfaces."""

import ast
import csv
from datetime import datetime
from decimal import Decimal
import hashlib
import io
import json
from pathlib import Path
import shlex

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require


CAPABILITIES = ["devices", "sources", "clock_uses", "clock_events", "source_exchanges", "coverage", "observations"]
LEAN_VIEW = "clock_synchronization"
SCOPE = "Four isolated guest clock corrections and certificate-use cases with observed Red/Gray-management source attachments"
SOURCE_HASHES = {
    "bootstrap-source.py": "1de5030b848a03d4e24c71e9c3feb545b6407fd103aae891339f7e8b7185d954",
    "configure-source.py": "a29cb81b49f27ee5def41f86083da43ec9e75f34a1827966324d2bfe81db191a",
    "observe-source.py": "eed85921bdded4aeff1d4ee02dcd91f5e17884d187a194c5d7d5d7eb0218bdc8",
    "clock_ntp_source.py": "dae8a3df15fb207bc09694241211068657af5884f85c5e7b45d3c7963601886b",
}


def one(rows, condition, message):
    matches = [row for row in rows if condition(row)]
    require(len(matches) == 1, message)
    return matches[0]


def nested_record(state, command):
    row = one(state["records"], lambda record: record["command"] == command,
              "Clock state lacks its exact command")
    require(row["returncode"] == 0, "Clock observation command failed")
    return row["stdout"]


def seconds(value):
    return datetime.fromisoformat(value).timestamp()


def ntp_timestamp(nanoseconds):
    whole, fraction = divmod(nanoseconds, 10**9)
    return (((whole + 2_208_988_800) << 32) + fraction * 2**32 // 10**9).to_bytes(8, "big")


def parse(directory):
    root = Path(directory)
    manifest_hash = validate_files(root)
    for name, expected in SOURCE_HASHES.items():
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == expected,
                "Unreviewed clock experiment source")
    syntax = ast.parse((root / "observe-source.py").read_text())
    lab = one(syntax.body, lambda node: isinstance(node, ast.ClassDef) and node.name == "Lab",
              "Clock collector class is missing")
    observer_method = one(lab.body, lambda node: isinstance(node, ast.FunctionDef)
                          and node.name == "collect_guest_clock", "Clock observer is missing")
    observer = ast.literal_eval(observer_method.body[0].value)
    phase_rows = {}
    for phase in ["bootstrap", "configure-001", "observe-001"]:
        validate_files(root / phase)
        document = json.loads((root / phase / "observations.json").read_text())
        require(document["error"] is None, "Clock experiment phase failed")
        phase_rows[phase] = document["records"]
    all_rows = sum(phase_rows.values(), [])
    by_id = {row["id"]: row for row in all_rows}
    require(len(by_id) == len(all_rows), "Duplicate clock observation")
    rows = phase_rows["observe-001"]
    order = {row["id"]: index for index, row in enumerate(rows)}
    for row in all_rows:
        require(seconds(row["startedAt"]) <= seconds(row["endedAt"]), "Invalid observation interval")
    sources = json.loads((root / "observe-001/time-sources.json").read_text())
    require(sources == json.loads((root / "configure-001/time-sources.json").read_text()),
            "Time sources changed between setup and capture")
    require({source["id"] for source in sources} == {"TC_TIME_RED", "TC_TIME_GRAY"},
            "Incomplete time-source inventory")
    links_row = one(rows, lambda row: row["command"] == ["ip", "-j", "-d", "link", "show"],
                    "Missing current clock topology")
    require(links_row["returncode"] == 0, "Clock topology command failed")
    links = json.loads(links_row["stdout"])
    exchanges = []
    projected_sources = []
    for source in sources:
        zone = source["zone"]
        require(zone in ["red", "gray"] and source["managementNetwork"] == (zone == "gray"),
                "Clock source management role differs")
        require(source["id"] == "TC_TIME_" + zone.upper() and source["namespace"] == "tc31ntp-" + zone
                and source["bridge"] == "tc31" + zone, "Clock source identity differs")
        address_row = one(rows, lambda row: row["command"] ==
                          ["ip", "netns", "exec", source["namespace"], "ip", "-j", "address"],
                          "Missing current source interface")
        require(address_row["returncode"] == 0, "Source interface observation failed")
        interface = one(json.loads(address_row["stdout"]), lambda item: item["ifname"] == source["interface"],
                        "Time source interface is absent")
        require(any(address.get("local") == source["address"] for address in interface["addr_info"]),
                "Time source address differs from its raw interface")
        host_link = one(links, lambda link: link["ifname"] == f"tc31n{zone[0]}h",
                        "Time source host link is absent")
        require(host_link["master"] == source["bridge"] and host_link["link_index"] == interface["ifindex"]
                and "UP" in host_link["flags"] and "UP" in interface["flags"],
                "Time source bridge/peer binding differs")
        source_packets = [json.loads(line) for line in
                          (root / f"observe-001/{source['id']}-exchanges.jsonl").read_text().splitlines()]
        require(source_packets and [packet["sequence"] for packet in source_packets] == list(range(len(source_packets))),
                "Incomplete source exchange sequence")
        for packet in source_packets:
            request = bytes.fromhex(packet["requestHex"])
            response = bytes.fromhex(packet["responseHex"])
            require(packet["source"] == source["id"] and packet["serverAddress"] == source["address"]
                    and len(request) >= 48 and len(response) == 48 and request[0] & 7 == 3
                    and response[0] == 0x24 and response[1] == 8
                    and response[24:32] == request[40:48], "NTP response does not match its source/request")
            require(packet["receivedUnixNs"] <= packet["sentUnixNs"], "NTP source timestamps are reversed")
            require(response[16:24] == response[32:40] == ntp_timestamp(packet["receivedUnixNs"])
                    and response[40:48] == ntp_timestamp(packet["sentUnixNs"]),
                    "NTP packet timestamps differ from their source records")
            exchanges.append(dict(packet, observation=f"ntp:{source['id']}:{packet['sequence']}"))
        projected_sources.append(dict(source, linkAddress=interface["address"],
                                      interfaceObservation=address_row["id"], topologyObservation=links_row["id"],
                                      upstreamClock="shared worker CLOCK_REALTIME; no time-server synchronization proof"))
    cases = json.loads((root / "observe-001/cases.json").read_text())
    require(len(cases) == 4 and {case["guest"]["id"] for case in cases} == {"TC_I_A", "TC_I_B", "TC_O_A", "TC_O_B"},
            "Incomplete guest clock-use cases")
    uses = []
    for case in cases:
        guest = case["guest"]
        index = guest["index"]
        require(isinstance(index, int) and 0 <= index < 4, "Invalid guest index")
        require(guest["id"] == ["TC_I_A", "TC_I_B", "TC_O_A", "TC_O_B"][index]
                and guest["zone"] == ("red" if index < 2 else "gray")
                and guest["layer"] == ("inner" if index < 2 else "outer"), "Guest role binding differs")
        source = one(projected_sources, lambda item: item["zone"] == guest["zone"], "Missing layer source")
        selected_rows = []
        for name, stage in [("before", "before-negative-clock"), ("wrongClock", "incorrect-clock"),
                            ("synchronized", "corrected-clock"), ("after", "after-certificate-authentication")]:
            row = one(rows, lambda row: row.get("stage") == stage and row["command"][0] == "ssh"
                      and str(22610 + index) == row["command"][row["command"].index("-p") + 1],
                      "Missing exact guest clock observation")
            require(row["returncode"] == 0 and shlex.split(row["command"][-1]) == ["sudo", "python3", "-c", observer]
                    and json.loads(row["stdout"]) == case[name], "Clock state differs from its raw observation")
            selected_rows.append(row)
        states = [case[name] for name in ["before", "wrongClock", "synchronized", "after"]]
        require(len({state["kernelBootId"] for state in states}) == 1 and
                len({state["charonPid"] for state in states}) == 1 and states[0]["charonPid"] > 0,
                "Clock-use process or kernel changed")
        require(all(state["observerTimeNamespace"] == state["charonTimeNamespace"] for state in states),
                "Observed process clock namespace differs")
        require(all(first["clockMonotonicNs"] < second["clockMonotonicNs"] for first, second in zip(states, states[1:])),
                "Guest observation order differs")
        require(case["wrongClock"]["clockRealtimeNs"] < 1_600_000_000 * 10**9,
                "Negative case lacks its actual incorrect clock")
        after = case["after"]
        tracking = next(csv.reader(io.StringIO(nested_record(after, ["chronyc", "-c", "tracking"]))))
        selected = list(csv.reader(io.StringIO(nested_record(after, ["chronyc", "-c", "sources"]))))
        require(len(tracking) == 14 and tracking[1] == source["address"] and tracking[-1] == "Normal",
                "Clock tracking source/status differs")
        remaining = Decimal(tracking[4])
        skew = Decimal(tracking[9])
        require(remaining.is_finite() and skew.is_finite() and abs(remaining) <= Decimal("0.05") and 0 <= skew <= 1000,
                "Clock does not meet its selected synchronization criterion")
        require(len(selected) == 1 and selected[0][:3] == ["^", "*", source["address"]],
                "Chrony selected a different source")
        require(after["chronyConfig"].splitlines()[0] == f"server {source['address']} iburst minpoll 0 maxpoll 1"
                and "makestep 0.1 -1" in after["chronyConfig"], "Clock discipline configuration differs")
        processes = nested_record(after, ["ps", "-eo", "pid,comm,args"])
        chrony_process = [line for line in processes.splitlines() if "/usr/sbin/chronyd" in line]
        service = nested_record(after, ["systemctl", "show", "chrony", "-p", "MainPID", "-p", "ExecStart", "-p", "ActiveState"])
        main_pid = one(service.splitlines(), lambda line: line.startswith("MainPID="), "Chrony PID is absent").split("=", 1)[1]
        require(chrony_process and any(line.split()[0] == main_pid for line in chrony_process)
                and all("-x" not in shlex.split(line)[2:] for line in chrony_process),
                "Clock adjustment is disabled or unavailable")
        clock_interface = one(json.loads(nested_record(after, ["ip", "-j", "address"])),
                              lambda interface: interface["ifname"] == "clock0", "Guest has no clock interface")
        expected_mac = f"52:54:31:00:{index:02x}:01"
        expected_address = f"10.{203 if index < 2 else 204}.0.{11 + index % 2}"
        require(clock_interface["address"] == expected_mac and
                any(address.get("local") == expected_address for address in clock_interface["addr_info"]),
                "Guest clock address/MAC binding differs")
        qemu = one(phase_rows["bootstrap"], lambda row: row["command"][0] == "qemu-system-x86_64"
                   and guest["id"] in row["command"], "Guest has no observed VM launch")
        require(qemu["returncode"] == 0 and
                f"tap,id=clock,ifname=tc31c{index},script=no,downscript=no" in qemu["command"] and
                f"virtio-net-pci,netdev=clock,mac={expected_mac}" in qemu["command"], "Guest tap/MAC attachment differs")
        tap = one(links, lambda link: link["ifname"] == f"tc31c{index}", "Guest tap is absent")
        require(tap["master"] == source["bridge"] and "UP" in tap["flags"], "Guest and source bridge differ")
        negative = by_id[case["negativeAuthentication"]]
        correction = by_id[case["clockCorrection"]]
        positive = by_id[case["positiveAuthentication"]]
        require(all(row["command"][0] == "ssh" and
                    row["command"][row["command"].index("-p") + 1] == str(22610 + index)
                    for row in [negative, correction, positive]), "Clock action belongs to another guest")
        require(all(shlex.split(row["command"][-1]) ==
                    ["sudo", "swanctl", "--initiate", "--child", "protected", "--timeout", "20"]
                    for row in [negative, positive]), "Authentication observation uses a different command")
        require(negative["returncode"] != 0 and "subject certificate invalid (valid from" in negative["stdout"],
                "Negative authentication lacks the certificate-time failure")
        require(positive["returncode"] == 0 and "authentication of" in positive["stdout"]
                and "CHILD_SA protected" in positive["stdout"] and "established" in positive["stdout"],
                "Corrected clock lacks successful authentication")
        require(correction["returncode"] == 0 and shlex.split(correction["command"][-1]) ==
                ["sudo", "chronyc", "waitsync", "30", "0.05", "1000", "1"], "Clock correction criterion differs")
        require(case["selectedCriterion"]["maximumRemainingCorrectionSeconds"] == 0.05 and
                case["selectedCriterion"]["maximumSkewPpm"] == 1000, "Declared clock criterion differs from its command")
        sequence = [selected_rows[0]["id"], selected_rows[1]["id"], negative["id"], correction["id"],
                    selected_rows[2]["id"], positive["id"], selected_rows[3]["id"]]
        require(all(order[first] < order[second] for first, second in zip(sequence, sequence[1:])),
                "Correction and certificate-use order differs")
        matching_packets = [packet for packet in exchanges if packet["source"] == source["id"]
                            and packet["clientAddress"] == expected_address and
                            seconds(negative["endedAt"]) <= packet["receivedUnixNs"] / 10**9 <= seconds(correction["endedAt"])]
        require(bool(matching_packets), "No source exchange during the actual clock correction")
        uses.append({"device": guest["id"], "role": guest["layer"], "source": source["id"],
                     "sourceAddress": source["address"], "clockInterface": "clock0", "clientAddress": expected_address,
                     "kernelBootId": after["kernelBootId"], "clockId": after["kernelBootId"] + ":CLOCK_REALTIME",
                     "process": after["charonPid"], "executable": after["charonExecutable"],
                     "executableAndLibraries": after["charonExecutableAndLibraries"],
                     "remainingCorrectionSeconds": tracking[4], "skewPpm": tracking[9],
                     "remainingCorrectionNanoseconds": int(remaining * 10**9),
                     "maximumRemainingCorrectionNanoseconds": 50_000_000,
                     "skewMilliPpm": int(skew * 1000), "maximumSkewMilliPpm": 1_000_000,
                     "selectedCriterion": case["selectedCriterion"], "observationSequence": sequence,
                     "ntpObservations": [packet["observation"] for packet in matching_packets],
                     "runtimeInventory": after["records"], "negativeClockUnixNs": case["wrongClock"]["clockRealtimeNs"],
                     "correctedClockUnixNs": case["synchronized"]["clockRealtimeNs"],
                     "clockUsedAfterCorrectionUnixNs": after["clockRealtimeNs"]})
    require(len({use["kernelBootId"] for use in uses}) == 4, "Guest clocks are not distinct kernels")
    clock_events = []
    for index, row in enumerate(rows):
        if row["command"][0] != "ssh":
            continue
        port = int(row["command"][row["command"].index("-p") + 1])
        require(22610 <= port <= 22613, "Clock command uses an unknown guest port")
        use = one(uses, lambda use: use["device"] == ["TC_I_A", "TC_I_B", "TC_O_A", "TC_O_B"][port - 22610],
                  "Clock command refers to an unknown guest")
        command = shlex.split(row["command"][-1])
        kind = None
        if command == ["sudo", "systemctl", "stop", "chrony"]:
            kind = "disciplineStopped"
        elif command[:5] == ["sudo", "date", "-u", "-s", "2020-01-01 00:00:00"]:
            kind = "clockSet"
        elif command == ["sudo", "systemctl", "start", "chrony"]:
            kind = "disciplineStarted"
        elif command[:3] == ["sudo", "chronyc", "waitsync"] and row["returncode"] == 0:
            kind = "selectedSynchronizationCriterionMet"
        elif command[:3] == ["sudo", "swanctl", "--initiate"]:
            kind = "certificateAuthenticationSucceeded" if row["returncode"] == 0 else "certificateAuthenticationFailed"
        if kind:
            clock_events.append({"device": use["device"], "clockId": use["clockId"], "source": use["source"],
                                 "kind": kind, "controllerOrder": index, "observation": row["id"],
                                 "startedAt": row["startedAt"], "endedAt": row["endedAt"]})
    report = {"devices": [{"id": use["device"], "role": use["role"]} for use in uses]
              + [{"id": source["id"], "role": "timeService"} for source in projected_sources],
              "sources": projected_sources, "clock_uses": uses, "clock_events": clock_events, "source_exchanges": exchanges,
              "coverage": [{"clients": [use["device"] for use in uses],
                            "scope": "Four guest crypto clients in a separate clock experiment. No full MSC profile claim.",
                            "sourceClock": "Both time services use the unchanged shared worker clock. Their own synchronization duties remain unproved.",
                            "managementServices": "Two time servers are present. No SIEM/KGS/AW is declared in this experiment; raw process/service inventories are retained.",
                            "eventCompleteness": "Complete collector-issued mutating-command sequence during the controlled experiment. No kernel-wide audit or all-time completeness claim.",
                            "trust": "Operator-selected laboratory sources. UTC accuracy, source certification and continuous synchronization remain outside this capture."}],
              "observations": [{"id": row["id"], "record": row} for row in all_rows],
              "rawObservationIds": sorted(by_id), "manifestSha256": manifest_hash,
              "projectionVersion": "guest-clock-use-v1", "scope": ["Collector truth, VM/OS/chrony/strongSwan behavior and declared virtual network zones remain explicit assumptions."]}
    return {"runtime_backend": "isolated-kvm-clock-use"}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    if observation.startswith("ntp:"):
        packet = one(report["source_exchanges"], lambda item: item["observation"] == observation,
                     "Unknown clock source exchange")
        require(not stderr, "NTP packet records do not contain a stderr stream")
        path = Path(directory) / f"observe-001/{packet['source']}-exchanges.jsonl"
        return path.read_text().splitlines(keepends=True)[packet["sequence"]]
    row = one(report["observations"], lambda item: item["id"] == observation, "Unknown clock observation")
    return row["record"]["stderr" if stderr else "stdout"]


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
