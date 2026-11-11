"""Expose peer-bound MKA timers and MACsec settings from captured command records."""
import json
from pathlib import Path
import re

from .eap import export_report, query_report
from .parsers.public_manifest import validate_files
from .parsers.snapshot import require

CAPABILITIES = ["devices", "parameters", "probes", "observations", "coverage"]
LEAN_VIEW = "mka_parameters"
SCOPE = "Saved two-peer software MACsec experiment using an instrumented hostap build; observed timer and controlled-port settings."


def one(rows, message):
    require(len(rows) == 1, message)
    return rows[0]


def values(text):
    rows = [line.split("=", 1) for line in text.splitlines() if "=" in line]
    require(len({row[0] for row in rows}) == len(rows), "Duplicate MKA status field")
    return dict(rows)


def parse(directory):
    directory = Path(directory)
    manifest_hash = validate_files(directory)
    document = json.loads((directory / "events.json").read_text())
    require(document["schema_version"] == "csfc-authentication-events/v1" and document["error"] is None,
            "Incomplete MKA experiment")
    rows = document["records"]
    require(len({row["id"] for row in rows}) == len(rows), "Duplicate observation ID")
    launches = [row for row in rows if len(row["command"]) > 5 and row["command"][:3] == ["ip", "netns", "exec"]
                and Path(row["command"][4]).name == "wpa_supplicant"]
    require(len(launches) == 2, "Expected exactly two MKA peers")
    devices, parameters, used = [], [], set()
    for launch in launches:
        argv = launch["command"]
        require(launch["returncode"] == 0 and all(flag in argv for flag in ["-i", "-f", "-c"]),
                "Unsuccessful or incomplete daemon launch")
        device = argv[3]
        require(device not in {row["id"] for row in devices}, "Duplicate MKA peer namespace")
        physical = argv[argv.index("-i") + 1]
        log_path = argv[argv.index("-f") + 1]
        prefix = ["ip", "netns", "exec", device]
        status = one([row for row in rows if row["command"][:4] == prefix and
                      row["command"][4:5] == ["wpa_cli"] and row["command"][-1] == "status"], "Missing peer MKA status")
        links = one([row for row in rows if row["command"] == prefix + ["ip", "-j", "-d", "link"]],
                    "Missing peer link inventory")
        logs = [row for row in rows if row["command"] == ["cat", log_path]]
        require(bool(logs) and len({row["stdout"] for row in logs}) == 1, "Missing or inconsistent peer log")
        log = logs[0]
        binary = one([row for row in rows if row["command"] == ["sha256sum", argv[4]]], "Missing daemon binary hash")
        require(all(row["returncode"] == 0 for row in [status, links, log, binary]), "Failed required observation")
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)\n?", binary["stdout"])
        require(match is not None and match[2] == argv[4], "Unbound daemon binary hash")
        state = values(status["stdout"])
        interface = one([row for row in json.loads(links["stdout"]) if row.get("linkinfo", {}).get("info_kind") == "macsec"],
                        "Expected exactly one MACsec interface per peer")
        settings = interface["linkinfo"]["info_data"]
        require(interface["link"] == physical and settings["offload"] == "off", "Unsupported interface binding or offload")
        sci = settings["sci"]
        require(state["actor_sci"].replace(":", "").split("@")[0] == sci[:12] and
                int(state["actor_sci"].split("@")[1]) == int(sci[12:], 16), "MKA actor and MACsec SCI differ")
        offsets = re.findall(r"create_transmit_sc -> (\S+) \(conf_offset=(\d+)\)", log["stdout"])
        offset = one(offsets, "Missing or ambiguous transmit confidentiality offset")
        require(offset[0].replace(":", "") == sci[:12] + str(int(sci[12:], 16)), "Logged transmit SCI differs")
        timers = re.findall(r"EVIDENCE delay LPN=(\d+) normalHello=(\d+) boundedHello=(\d+) lifetime=(\d+)", log["stdout"])
        require(bool(timers) and len({row[1:] for row in timers}) == 1, "Missing or inconsistent instrumented MKA timers")
        normal, active, lifetime = map(int, timers[0][1:])
        delay_flags = re.findall(r"Delay Protect\.*:\s*(Yes|No)", log["stdout"])
        require(bool(delay_flags), "Missing advertised MKA data-delay protection")
        require(int(state["MKA Hello Time"]) == active, "MKA status and logged active hello differ")
        enabled = re.findall(r"macsec_drv_enable_controlled_port -> (TRUE|FALSE)", log["stdout"])
        require(bool(enabled), "Missing controlled-port update")
        summary = one([row for row in rows if row["command"] == prefix + ["ip", "-s", "macsec", "show"]
                       and row["ended_at"] < links["started_at"]], "Missing contemporaneous MACsec state")
        require(summary["returncode"] == 0 and re.search(r"TXSC: " + re.escape(sci) + r" on SA " + str(settings["encoding_sa"]), summary["stdout"]),
                "Installed transmit association differs")
        fields = one(re.findall(r"(?m)^\d+: " + re.escape(interface["ifname"]) + r": (.+)$", summary["stdout"]),
                     "Missing MACsec setting summary").split()
        require(len(fields) % 2 == 0 and len(set(fields[::2])) * 2 == len(fields), "Malformed MACsec setting summary")
        printed = dict(zip(fields[::2], fields[1::2]))
        for field in ["protect", "encrypt"]:
            require(type(settings[field]) is bool and printed[field] == ("on" if settings[field] else "off"),
                    "MACsec JSON and text settings differ")
        require(str(settings["window"]) == printed["window"] and settings["validation"] == printed["validate"],
                "MACsec receive settings differ")
        public_config = directory / (Path(argv[argv.index("-c") + 1]).name + ".public")
        configured_policy, configured_integrity = None, None
        if public_config.is_file():
            config = values("\n".join(line.strip() for line in public_config.read_text().splitlines()))
            require(config.get("mka_cak") == "[REDACTED_CAK]", "Public config must redact the CAK")
            require(config.get("mka_ckn") == state["ckn"], "Configured and active MKA CKN differ")
            configured_policy = int(config["macsec_policy"])
            configured_integrity = int(config["macsec_integ_only"])
            require(configured_policy in [0, 1] and configured_integrity in [0, 1], "Unsupported MACsec configuration mode")
            require(int(config["macsec_replay_window"]) == settings["window"], "Configured and observed replay windows differ")
        sources = [launch["id"], status["id"], links["id"], log["id"], binary["id"], summary["id"]]
        used.update(sources)
        devices.append({"id": device, "role": "MACsec peer", "physicalIface": physical, "macsecIface": interface["ifname"]})
        parameters.append({"device": device, "sci": sci, "daemonSha256": match[1],
                           "instrumentedBuild": True, "dataDelayProtectionLogged": all(flag == "Yes" for flag in delay_flags),
                           "configuredMacsecPolicy": configured_policy, "configuredIntegrityOnly": configured_integrity,
                           "publicConfiguration": public_config.name if public_config.is_file() else None,
                           "normalHelloMilliseconds": normal, "activeHelloMilliseconds": active,
                           "lifetimeMilliseconds": lifetime, "confidentialityOffset": int(offset[1]),
                           "controlledPortEnabled": enabled[-1] == "TRUE", "protectFrames": settings["protect"],
                           "encryptFrames": settings["encrypt"], "receiveValidation": settings["validation"],
                           "replayProtection": settings["replay_protect"], "replayWindow": settings["window"],
                           "transmitAssociationNumber": settings["encoding_sa"], "secured": state["Secured"] == "Yes",
                           "sourceObservations": sources})
    probes = [{"id": row["id"], "name": row["probe"], "exitCode": row["returncode"],
               "observedResult": row["observed_result"], "stdout": row["stdout"]} for row in rows if "probe" in row]
    used.update(row["id"] for row in probes)
    report = {"devices": devices, "parameters": parameters, "probes": probes,
              "observations": [{"id": row["id"], "record": row} for row in rows if row["id"] in used],
              "coverage": [{"peerCount": len(devices), "limitations": [
                  "Timers are logged by the captured instrumented build; no universal daemon conformance is inferred.",
                  "Replay window feasibility and the behavior implied by MACsec policy need explicit interpretation; legacy captures omit public configuration.",
                  "The experiment has no nested MSC topology or product approval."]}],
              "scope": SCOPE, "manifestSha256": manifest_hash, "projectionVersion": "mka-parameters-v1"}
    return {"runtime_backend": document["runtime_backend"], "started_at": document["started_at"], "ended_at": document["ended_at"]}, report


validated_experiment = parse


def query_experiment(directory, collection, category, device, offset, limit):
    manifest, report = parse(directory)
    return query_report(manifest, report, CAPABILITIES, collection, category, device, offset, limit)


def read_experiment_raw(directory, observation, stderr=False):
    _, report = parse(directory)
    row = one([item["record"] for item in report["observations"] if item["id"] == observation], "Unknown MKA observation")
    return row.get("stderr" if stderr else "stdout", "")


def export_experiment(directory, destination):
    _, report = parse(directory)
    return export_report(report, destination, LEAN_VIEW)
