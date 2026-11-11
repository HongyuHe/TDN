"""Expose captured probes and packet headers without changing forwarding exports."""
import hashlib
import json
from pathlib import Path
import re

from . import mixed
from .eap import export_report, query_report
from .parsers.snapshot import require


CAPABILITIES = ["devices", "probes", "packet_headers", "esp_tunnels", "control_probes"]
LEAN_VIEW = "mixed_protocol_observations"
SCOPE = "Saved probe outcomes and field-only packet captures, bound to their collection commands"


def parse(directory):
    directory = Path(directory)
    manifest, operational = mixed.validated_experiment(directory)
    evidence = json.loads((directory / "evidence.json").read_text())
    commands = json.loads((directory / "commands.json").read_text())
    by_id = {row["id"]: row for row in commands}
    devices = operational["devices"]
    raw_ids = set()
    probes = []
    for probe in evidence["probes"]:
        row = by_id[probe["observation_id"]]
        device = probe["source_device"]
        argv = row["command"]
        require(device in devices and row["device_id"] == device and
                argv[:5] == ["ip", "netns", "exec", devices[device]["namespace"], "ping"] and
                argv[-1] == probe["destination"], "Probe command binding differs")
        match = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received,", row["stdout"])
        require(match is not None and row["returncode"] in [0, 1], "Probe lacks a successful ping measurement")
        sent, received = map(int, match.groups())
        require(sent > 0 and 0 <= received <= sent, "Invalid ping packet counts")
        outcome = "delivered" if received else "no_reply"
        require(outcome == probe["observed_result"] and (received > 0) == (row["returncode"] == 0),
                "Probe outcome differs from command response")
        probes.append(dict(probe, device=device, transmitted=sent, received=received,
                           startedAt=row["started_at"], finishedAt=row["ended_at"],
                           observation=row["id"], observedMeaning="Echo replies observed" if received else
                           "No echo reply observed; the capture does not identify the drop location"))
        raw_ids.add(row["id"])
    headers, header_files = [], {}
    for path in sorted(directory.glob("phase-*-headers-*.json")):
        match = re.fullmatch(r"phase-(\d+)-headers-(.+)\.json", path.name)
        require(match is not None, "Unsupported packet capture filename")
        phase, device = int(match[1]), match[2]
        require(device in devices, "Packet capture has an unknown device")
        rows = [r for r in commands if len(r["command"]) == 8 and
                r["command"][-2] == "--output" and Path(r["command"][-1]).name == path.name]
        require(len(rows) == 1, "Packet capture command missing or ambiguous")
        row = rows[0]
        require(row["command"][:5] == ["ip", "netns", "exec", devices[device]["namespace"], "python3"] and
                Path(row["command"][5]).name == "pairing_headers_v6.py" and
                row["device_id"] == device and row["returncode"] == 0 and row["capture_phase"] == phase,
                "Packet capture command binding differs")
        doc = json.loads(path.read_text())
        summary = json.loads(row["stdout"])
        require(summary["frames"] == len(doc["frames"]) and
                summary["parse_or_capacity_errors"] == doc["parse_or_capacity_errors"] == 0,
                "Packet capture counts or parser errors differ")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        raw_name = "header-" + path.name
        header_files[raw_name] = path.name
        raw_ids.add(row["id"])
        for index, frame in enumerate(doc["frames"]):
            require(device + ":" + frame["interface"] in operational["operational"]["interfaces"],
                    "Packet capture interface absent from observed inventory")
            headers.append(dict(frame, device=device, phase=phase, observation=row["id"],
                                captureObservation=raw_name, captureFile=path.name,
                                captureSha256=digest, frameIndex=index))
    require(bool(headers), "No packet-header captures")
    for probe in operational["operational"]["control_probes"]:
        raw_ids.update([probe["senderObservation"], probe["receiverObservation"]])
    tunnels = []
    for phase_name in operational["phase_files"]:
        phase = json.loads((directory / phase_name).read_text())
        for device, records in phase.items():
            states = records["xfrm"]
            observation = states["observation_id"]
            raw_ids.add(observation)
            #* The operational parser has already checked the command and its exact response.
            from .native_keys import blocks
            for identity, _ in blocks(states["value"]):
                source, destination, protocol, spi, reqid, mode = identity
                if protocol != "esp" or mode != "tunnel":
                    continue
                observed = [h for h in headers if h["device"] == device and
                            h["headers"].get("esp", {}).get("spi") == spi and
                            any(h["headers"].get(ip, {}).get("source") == source and
                                h["headers"].get(ip, {}).get("destination") == destination
                                for ip in ["ipv4", "ipv6"])]
                tunnels.append({"device": device, "role": devices[device]["role"],
                    "statePhase": phase_name, "observation": observation,
                    "source": source, "destination": destination, "protocol": protocol,
                    "spi": spi, "reqid": reqid, "mode": mode,
                    "matchingHeaders": [{k: h[k] for k in ["captureFile", "captureSha256", "frameIndex", "phase", "interface", "packet_type"]}
                                        for h in observed],
                    "meaning": "ESP tunnel state with outer IP endpoints; header matches are equality checks across recorded phases, not proof of an atomic snapshot or inner payload identity"})
    report = {"devices": list(devices.values()), "probes": probes, "packet_headers": headers,
              "esp_tunnels": tunnels, "control_probes": operational["operational"]["control_probes"],
              "manifestSha256": operational["manifest_sha256"], "rawObservationIds": sorted(raw_ids),
              "headerFiles": header_files, "projectionVersion": "mixed-observations-v1",
              "scope": [SCOPE, "Header-only capture cannot identify encrypted inner payloads or establish causal correspondence between different interfaces.",
                        "Probe outcomes and packet headers supplement the forwarding model; they do not prove all possible traffic behavior.",
                        "ESP tunnel mode does not assert a separately configured GRE or IP-in-IP device."]}
    return manifest, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    if observation in report["headerFiles"]:
        return "" if stderr else (Path(directory) / report["headerFiles"][observation]).read_text()
    require(observation in report["rawObservationIds"], "Observation is outside the validated packet capture")
    rows = json.loads((Path(directory) / "commands.json").read_text())
    row = next(r for r in rows if r["id"] == observation)
    return row.get("stderr" if stderr else "stdout", "")


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
