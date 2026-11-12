"""Bind final MACsec protection settings and enabled delay-protection implementation."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from import_macsec_algorithms import parse_bindings, LAUNCH_PIN, WRAPPERS
from import_macsec_runtime import parse as parse_runtime, validate_files
from validate_evidence import require

CALLBACK_PATCH = "79bbc0fc48a09603f7a13cfb5769b350f785cb47a5abbc53caa7cecf2e9fa01f"


def parse(cases, bindings, runtime, callback):
    sources = parse_bindings(Path(bindings), Path(runtime))
    callback = Path(callback)
    callback_manifest = validate_files(callback)
    require(hashlib.sha256((callback / "hostapd.full.patch").read_bytes()).hexdigest() == CALLBACK_PATCH,
            "Reviewed delay callback/driver patch changed")
    require(hashlib.sha256((callback / "wpa_auth_kay.after.c").read_bytes()).hexdigest() ==
            WRAPPERS["hostapd-2.12"][1], "Authenticator callback differs from bound final source")
    data = json.loads((callback / "observations.json").read_text())
    require("error" in data and data["error"] is None, "Callback build failed")
    builds = [row for row in data["records"] if row.get("command", [])[-2:] == ["make", "-j4"]]
    require(len(builds) == 1 and builds[0]["returncode"] == 0, "Successful callback build missing")
    entries, observations, controls = [], [], []
    for supplied in cases:
        path = Path(supplied)
        case = parse_runtime(path)
        require(hashlib.sha256((path / "collector.source.py").read_bytes()).hexdigest() == LAUNCH_PIN,
                "Reviewed source/configuration launcher differs")
        evidence = json.loads((path / "evidence.json").read_text())
        raw = json.loads((path / "commands.json").read_text())
        commands = {row["id"]: row for row in raw}
        require(len(raw) == len(commands), "Duplicate observation ID")
        identities = {row["id"]: row for row in evidence["devices"]}
        description = json.loads((path / "case.json").read_text())
        require({description["authenticator"], description["supplicant"]} == {"P0", "P1"},
                "Complete role inventory required")
        for port in case["ports"]:
            name = port["id"].rsplit("/", 1)[1]
            logs = [row for row in raw if row["command"][0] == "cat" and
                    row["command"][-1].endswith("/" + name + ".log")]
            require(len(logs) == 1 and logs[0]["returncode"] == 0, "Complete peer log required")
            log = logs[0]["stdout"]
            timers = re.findall(r"EVIDENCE delay LPN=(\d+) normalHello=(\d+) boundedHello=(\d+) lifetime=(\d+)", log)
            require(timers and all(tuple(map(int, row[1:])) == (2000, 500, 6000) for row in timers),
                    "Enabled delay timer observations missing or changed")
            flags = re.findall(r"Delay Protect\.*:\s*(\S+)", log)
            require(flags and set(flags) == {"Yes"}, "Delay protection not consistently advertised")
            require("set_receive_lowest_pn" in log, "Receive threshold update callback not observed")
            config = (path / (name + ".conf.public")).read_text()
            for setting in ["macsec_policy=1", "macsec_replay_protect=1", "macsec_replay_window=0"]:
                require(len(re.findall(r"(?m)^\s*" + re.escape(setting) + r"\s*$", config)) == 1,
                        "Required secured-port configuration missing")
            require(port["receiveValidation"] == "strict" and port["replayProtection"] is True,
                    "Actual strict receive validation and enabled replay protection required")
            require(port["replay_window"] == 0 and port["confidentialityOffset"] == 0 and
                    all(port[k] for k in ["controlledPortEnabled", "protectFrames", "encryptFrames"]),
                    "Actual secure data-port settings differ")
            entries.append({**port, "normal_hello_ms": 2000, "active_hello_ms": 500,
                            "lifetime_ms": 6000, "delay_protection_enabled": True,
                            "must_secure": True, "timer_samples": len(timers),
                            "delay_advertisements": len(flags)})
            observations.append({"bundle": str(path), "manifest_sha256": case["manifest_sha256"],
                                 "device": name, "log": logs[0]["id"],
                                 "runtime_observations": case["observations"]})
        probes = evidence["probes"]
        require(len(probes) == 8 and len({p["id"] for p in probes}) == 8,
                "Complete bidirectional delay/useful controls required")
        for device in ["P0", "P1"]:
            selected = [p for p in probes if p["source_device"] == device]
            require(len(selected) == 4 and sum(p["expected_result"] == "no_reply" for p in selected) == 1,
                    "Both peer directions need delayed rejection and useful controls")
        for probe in probes:
            command = commands[probe["observation_id"]]
            namespace = identities[probe["source_device"]]["namespace"]
            require(command["command"][:5] == ["ip", "netns", "exec", namespace, "ping"] and
                    command["command"][-1] == probe["destination"], "Control command binding differs")
            expected = probe["expected_result"]
            require((expected == "delivered" and command["returncode"] == 0 and " 0% packet loss" in command["stdout"]) or
                    (expected == "no_reply" and command["returncode"] == 1 and "100% packet loss" in command["stdout"]),
                    "Raw control result differs")
            controls.append({"bundle": str(path), "probe": probe["id"], "observation": command["id"],
                             "result": expected})
    require(entries, "Empty protection inventory")
    return {"devices": entries, "observations": observations, "controls": controls,
            "source_bindings": sources, "callback_bundle": str(callback),
            "callback_manifest_sha256": callback_manifest, "callback_patch_sha256": CALLBACK_PATCH,
            "implementation_contract": [
                "Delay protection denotes the enabled reviewed timed-PN history, authenticated MKA advertisement and receive-lowest-PN callback path.",
                "Final binary/source continuity and correct compilation/execution use the same explicit contract as the final algorithm importer.",
                "With the observed zero replay window, the Linux receive next-PN field represents the enforced lower acceptance threshold.",
                "The general freshness theorem additionally requires a matching authenticated counter sample, a valid non-wrapping counter space and a stated sample-age bound. Finite delayed probes do not prove an unconditional physical latency bound.",
                "Normal Hello remains 2000 milliseconds while the selected bounded active interval is 500 milliseconds; lifetime is 6000 milliseconds under INT-028.",
                "Zero is an observed feasible replay window and is the smallest natural-number window; no smaller feasible value is assumed.",
                "Required policy, full encryption and strict receive validation give the local must-secure interpretation. Whole-network alternative physical paths remain separately proved."]}


def generate(data):
    rows = []
    for index, entry in enumerate(data["devices"]):
        rows.append("  { device := " + str(index) + """,
    dataDelayProtection := true, lifetimeMilliseconds := 6000,
    helloMilliseconds := 2000, activeHelloMilliseconds := 500,
    replayWindow := 0, feasibleReplayWindow := fun n => n < 2 ^ 32,
    confidentialityOffset := 0, mustSecure := true,
    dataPort := ⟨true, true, true, 0⟩ }""")
    return """import TDN.Requirements.Protocol

namespace TDN.Deployments.FinalMACsecProtection
open Requirements
def devices : List MACsecProtection := [
""" + ",\n".join(rows) + """
]

theorem selected_protection_configuration : msc_macsec_protection_parameters devices := by
  apply macsec_protection_from_local_checks devices
  · simp [devices]
  · simp [devices]
  · simp [devices]
  · simp [devices]

lemma runtime_inventory_nonempty : devices.length = """ + str(len(rows)) + """ := by native_decide

end TDN.Deployments.FinalMACsecProtection
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", nargs="+")
    for name in ["bindings", "runtime", "callback", "output", "report"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    data = parse(args.cases, args.bindings, args.runtime, args.callback)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"ports": len(data["devices"]), "finite_controls": len(data["controls"])}))


if __name__ == "__main__":
    main()
