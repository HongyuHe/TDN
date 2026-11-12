"""Bind the retained cover sender to fixed-record proofs and finite observations."""
import argparse
import hashlib
import json
from pathlib import Path


AUDITED_SOURCE = "0e431d829b3dadc643d04786e5c986b8a53fa3c8a1c69b381e616c1ecd2e0a27"
KERNEL_SOURCE = "b773475493c33e70e68e66092c7d778db309465f85cc0cebfcf20277e1ae190c"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_bundle(path):
    path = Path(path)
    manifest = json.loads((path / "manifest.json").read_text())
    names = []
    for row in manifest["files"]:
        name = Path(row["path"])
        require(not name.is_absolute() and ".." not in name.parts, "Unsafe manifest path")
        source = path / name
        require(not source.is_symlink() and source.is_file(), "Missing or linked input")
        require(hashlib.sha256(source.read_bytes()).hexdigest() == row["sha256"], "Bundle hash mismatch")
        names.append(str(name))
    actual = {str(p.relative_to(path)) for p in path.rglob("*")
              if p.is_file() and p.name != "manifest.json"}
    require(len(names) == len(set(names)) and set(names) == actual, "Incomplete manifest inventory")
    return manifest


def bind_attachments(state, devices, evidence, commands):
    """Check raw namespace peers and every veth before deriving firewall attachment."""
    interfaces = {}
    peers = {}
    namespace_ids = []
    suffixes = {"interfaces": ["ip", "-j", "-d", "address"],
                "namespace_inode": None, "namespace": ["readlink", "/proc/self/ns/net"],
                "peer_nsids": ["ip", "-j", "netns", "list-id"],
                "bridge_links": ["bridge", "-j", "-d", "link", "show"]}
    for device, identity in devices.items():
        namespace = identity["namespace"]
        for key, suffix in suffixes.items():
            suffix = suffix or ["stat", "-Lc", "%i", "/var/run/netns/" + namespace]
            value = state[device][key]
            raw = commands[value["observation_id"]]
            require(raw["device_id"] == device and raw["command"] ==
                    ["ip", "netns", "exec", namespace] + suffix and
                    raw["returncode"] == value["returncode"] == 0 and raw["stdout"] == value["value"],
                    "Unbound attachment observation")
        inode = int(state[device]["namespace_inode"]["value"].strip())
        require(state[device]["namespace"]["value"].strip() == "net:[" + str(inode) + "]",
                "Observed namespace identity mismatch")
        namespace_ids.append(inode)
        rows = json.loads(state[device]["interfaces"]["value"])
        require(len({row["ifname"] for row in rows}) == len(rows), "Duplicate interface name")
        interfaces[device] = {row["ifname"]: row for row in rows}
        peer_rows = json.loads(state[device]["peer_nsids"]["value"])
        require(len({row["nsid"] for row in peer_rows}) == len(peer_rows), "Ambiguous namespace peers")
        peers[device] = {row["nsid"]: row.get("name") for row in peer_rows}
    require(len(set(namespace_ids)) == len(namespace_ids), "Duplicate device namespace")
    attached = {device + ":" + name for device, rows in interfaces.items() for name, row in rows.items()
                if row.get("linkinfo", {}).get("info_kind") == "veth"}
    expected = [name for link in evidence["links"] for name in link["endpoints"]]
    require(len(expected) == len(set(expected)) and set(expected) == attached,
            "Declared link inventory omits observed veth attachments")
    for link in evidence["links"]:
        require(link["relation"] == "veth" and len(link["endpoints"]) == 2, "Unsupported attachment")
        left, right = [value.split(":") for value in link["endpoints"]]
        for a, z in [(left, right), (right, left)]:
            port, other = interfaces[a[0]][a[1]], interfaces[z[0]][z[1]]
            require(port["link_index"] == other["ifindex"] and
                    peers[a[0]].get(port["link_netnsid"]) == devices[z[0]]["namespace"],
                    "Observed peer differs from declared attachment")
    bridge = json.loads(state["BF"]["bridge_links"]["value"])
    require({row["ifname"] for row in bridge} == {"p1", "p2"} and len(bridge) == 2 and
            all(row["master"] == "br0" and row["state"] == "forwarding" and
                row["ifindex"] == interfaces["BF"][row["ifname"]]["ifindex"] for row in bridge),
            "Incomplete forwarding bridge membership")
    for device in ["OA", "OB"]:
        mac = interfaces[device]["macsec0"]
        settings = mac["linkinfo"]["info_data"]
        require(mac["linkinfo"]["info_kind"] == "macsec" and mac["link"] == "black" and
                settings["offload"] == "off" and settings["encrypt"] is True and
                settings["protect"] is True and settings["validation"] == "strict" and
                settings["inc_sci"] is True and settings["icv_len"] == 16,
                "MACsec software-path confidentiality settings differ")
    return interfaces


def parse(bundle):
    bundle = Path(bundle)
    manifest = validate_bundle(bundle)
    evidence = json.loads((bundle / "evidence.json").read_text())
    require("error" in evidence and evidence["error"] is None, "Collection must explicitly succeed")
    require(evidence["configuration_id"] == "outer-MACsec-cover-v4" and
            evidence["runtime_backend"] == "supplemental-linux-netns-static-routes",
            "Unexpected cover experiment")
    source = bundle / "macsec_cover_endpoint_v4.py"
    require(hashlib.sha256(source.read_bytes()).hexdigest() == AUDITED_SOURCE and
            manifest["code_hashes"][source.name] == AUDITED_SOURCE, "Unreviewed sender source")
    commands = json.loads((bundle / "commands.json").read_text())
    by_id = {row["id"]: row for row in commands}
    require(len(by_id) == len(commands), "Duplicate command identity")
    devices = {row["id"]: row for row in evidence["devices"]}
    require(len(devices) == len(evidence["devices"]), "Duplicate device identity")
    outer = sorted(name for name, row in devices.items() if row["role"] == "outer")
    require(outer == ["OA", "OB"] and devices["BF"]["role"] == "outer-ethernet-firewall",
            "Incomplete selected Outer/firewall inventory")
    tunnel = [row for row in evidence["tunnels"] if row["layer"] == "outer"]
    require(len(tunnel) == 1 and tunnel[0]["mechanism"] == "MACsec" and
            sorted(tunnel[0]["endpoints"]) == outer, "Outer mechanism inventory mismatch")
    before = json.loads((bundle / "stable-before.json").read_text())
    after = json.loads((bundle / "stable-after.json").read_text())
    require(set(before) == set(after) == set(devices), "Incomplete observed device inventory")
    before_interfaces = bind_attachments(before, devices, evidence, by_id)
    after_interfaces = bind_attachments(after, devices, evidence, by_id)
    kernel_path = Path(__file__).resolve().parents[2] / "data/construction/2026-10-24T014455Z/references/transec/linux-v6.8-macsec.c"
    require(hashlib.sha256(kernel_path.read_bytes()).hexdigest() == KERNEL_SOURCE,
            "Reviewed MACsec software-path source changed")
    endpoints = []
    for device in outer:
        namespace = devices[device]["namespace"]
        links = [row for row in evidence["links"] if device + ":black" in row["endpoints"]]
        require(len(links) == 1 and links[0]["zone"] == "black" and
                any(peer.startswith("BF:") for peer in links[0]["endpoints"]),
                "Outer firewall attachment missing")
        for state in [before, after]:
            record = state[device]["macsec"]
            raw = by_id[record["observation_id"]]
            require(raw["command"] == ["ip", "netns", "exec", namespace, "ip", "-s", "macsec", "show"]
                    and raw["device_id"] == device and raw["returncode"] == record["returncode"] == 0
                    and raw["stdout"] == record["value"], "Unbound MACsec runtime observation")
            first = record["value"].splitlines()[0]
            require("macsec0: protect on validate strict" in first and "encrypt on" in first,
                    "Cover port does not use full MACsec encryption")
        ready = json.loads((bundle / (device + "-ready.json")).read_text())
        events = json.loads((bundle / (device + "-cover-events.json")).read_text())
        settings = events["settings"]
        remote = "OB" if device == "OA" else "OA"
        require(settings["peer"] == before_interfaces[remote]["macsec0"]["address"] ==
                after_interfaces[remote]["macsec0"]["address"], "Sender peer does not match observed MACsec peer")
        require(all(settings[key] == ready[key] for key in
                    ["interval_ms", "frame_body_bytes", "queue_limit", "interface"]),
                "Ready/event settings disagree")
        require(settings["interface"] == "macsec0" and ready["tun"] == "tfc0" and
                settings["interval_ms"] == 20 and settings["frame_body_bytes"] == 512 and
                settings["queue_limit"] == 64 and ready["max_payload_bytes"] == 488,
                "Sender settings differ from reviewed source defaults")
        invocations = [row for row in commands if row["command"][:5] ==
                       ["ip", "netns", "exec", namespace, "python3"] and
                       len(row["command"]) > 5 and Path(row["command"][5]).name == source.name]
        require(len(invocations) == 1, "Missing or duplicate sender invocation")
        invocation = invocations[0]
        expected = ["--peer", settings["peer"], "--ready", settings["ready"], "--output", settings["output"]]
        require(invocation["command"][6:] == expected and invocation["device_id"] == device and
                invocation["returncode"] == 0 and json.loads(invocation["stdout"]) == events["stats"],
                "Sender invocation differs from recorded process settings or result")
        for key, suffix in [("ready", "-ready.json"), ("output", "-cover-events.json")]:
            require(Path(settings[key]).name == device + suffix, "Cross-device sender output")
        rows = events["send_events"]
        require(rows and all(row["sequence"] == index + 1 for index, row in enumerate(rows)),
                "Incomplete send-attempt sequence")
        require(all(isinstance(row[key], int) and not isinstance(row[key], bool) and row[key] >= 0
                    for row in rows for key in ["at_ns", "schedule_lag_ns", "body_length", "queue_after_send"]),
                "Invalid numeric send observation")
        require(all(row["body_length"] == 512 and row["queue_after_send"] <= 64 and
                    row["kind"] in {"data", "dummy"} for row in rows), "Record-size or queue mismatch")
        require(events["started_at_ns"] == ready["ready_at_ns"] and
                events["started_at_ns"] <= rows[0]["at_ns"] <= rows[-1]["at_ns"] <= events["ended_at_ns"] and
                all(a["at_ns"] < b["at_ns"] for a, b in zip(rows, rows[1:])),
                "Unordered or out-of-interval send observations")
        stats = events["stats"]
        require(all(isinstance(value, int) and not isinstance(value, bool) and value >= 0
                    for value in stats.values()), "Invalid sender statistics")
        require(stats["data_frames_sent"] + stats["dummy_frames_sent"] + stats["send_errors"] == len(rows),
                "Send attempts do not reconcile with successes and errors")
        require(0 < stats["data_frames_sent"] <= sum(row["kind"] == "data" for row in rows) and
                0 < stats["dummy_frames_sent"] <= sum(row["kind"] == "dummy" for row in rows),
                "Useful data and padding evidence required")
        require(stats["max_queue_depth"] <= 64 and stats["shutdown_queued_packets"] <= 64,
                "Observed queue exceeded configured capacity")
        endpoints.append({"device": device, "body_bytes": 512, "header_bytes": 24,
                          "interval_ns": 20000000, "queue_limit": 64, "events": rows,
                          "stats": stats, "max_observed_lag_ns": max(row["schedule_lag_ns"] for row in rows)})
    controls = []
    for probe in evidence["probes"]:
        raw = by_id[probe["observation_id"]]
        namespace = devices[probe["source_device"]]["namespace"]
        require(raw["command"][:5] == ["ip", "netns", "exec", namespace, "ping"] and
                raw["command"][-1] == probe["destination"], "Control command mismatch")
        delivered = raw["returncode"] == 0 and " 0% packet loss" in raw["stdout"]
        failed = raw["returncode"] == 1 and "100% packet loss" in raw["stdout"]
        require((probe["expected_result"] == "delivered" and delivered) or
                (probe["expected_result"] == "no_reply" and failed), "Control result mismatch")
        controls.append(probe["id"])
    require(len(controls) == len(set(controls)) == 6, "Complete six-control inventory required")
    return {"bundle": str(bundle), "manifest_sha256": hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest(),
            "source_sha256": AUDITED_SOURCE, "kernel_family_source_sha256": KERNEL_SOURCE,
            "confidentiality_offset_bytes": 0,
            "offset_basis": "Reviewed Linux v6.8 macsec_encrypt software path encrypts all bytes after macsec_hdr_len; observed offload=off, encrypt=true. Deployed-kernel correspondence is an explicit implementation assumption.",
            "endpoints": endpoints, "controls": controls,
            "scope": [
                "Two Outer endpoints in a supplemental namespace experiment with the OR-9 objective selected.",
                "The Black bridge is not the Public Internet; publicInternet=false is the declared lab scope.",
                "The review binds retained source bytes to the successful invocation path; the collector's executed-source correspondence remains trusted.",
                "Both captured phases bind complete veth inventories, namespace peer IDs, reciprocal interface indices and BF bridge membership. The architectural roles remain declared source meanings.",
                "Zero confidentiality offset is derived from the reviewed software path and the observed offload=off configuration; it is not a directly exported offset field or a byte-identical deployed-kernel verification.",
                "A send event records an attempt, including errors. Per-attempt success is not exported. Failed attempts consume a queued payload.",
                "Record length and queue safety hold for every modeled execution, under reviewed sender semantics and encodable sequence numbers.",
                "Only equal supplied schedules/outcomes imply equal size observations. No hard real-time or traffic-independent OS schedule is assumed.",
                "MACsec confidentiality, runtime persistence, peer authenticity, physical TRANSEC controls and organizational approval remain external to the size/queue theorem."]}


def generate(data):
    lines = ["import TDN.Requirements.TrafficFlowConfidentialitySpec", "", "namespace TDN.Deployments.SnapshotTfcCoverTraffic",
             "open Requirements CoverTraffic", "set_option maxRecDepth 100000", "set_option maxHeartbeats 0", "",
             "/-- Parameters come from both recorded sender invocations and their settings readback. -/",
             "def sender : CoverTraffic.Config := ⟨512, 24, 64, 20000000⟩",
             "lemma valid_parameters : sender.Valid := by native_decide", "",
             "def installations : List CoverInstallation := [" + ", ".join(
                 "⟨" + json.dumps(row["device"]) + ", ⟨false, true, true, true, true⟩, sender, true⟩"
                 for row in data["endpoints"]) + "]", "",
             "/-- The declared laboratory scope selects the MACsec-to-firewall objective. -/",
             "theorem selected_cover_enablement :",
             "    msc_transec_conditions (installations.map CoverInstallation.use) := by",
             "  exact (transec_conditions_from_cover_installations installations (by native_decide) (by native_decide)).1", "",
             "/-- Arbitrary arrivals and link failures preserve the size and capacity guarantee. -/",
             "theorem all_sender_traces_obey_size_and_capacity : ScheduledCoverGuarantee sender :=",
             "  scheduled_cover_guarantee_from_parameters sender valid_parameters", ""]
    for endpoint in data["endpoints"]:
        name = endpoint["device"]
        rows = endpoint["events"]
        lines += ["/-- Every exported attempt is retained, including failed send calls. -/",
                  "def attempts" + name + " : List (Nat × Nat × Nat) := [" + ", ".join(
                      "⟨" + str(row["body_length"]) + ", " + str(row["queue_after_send"]) + ", " +
                      str(row["schedule_lag_ns"]) + "⟩" for row in rows) + "]",
                  "theorem recorded_attempts" + name + " :",
                  "    ∀ row ∈ attempts" + name + ", row.1 = sender.recordBytes ∧",
                  "      row.2.1 ≤ sender.queueLimit ∧ row.2.2 ≤ " + str(endpoint["max_observed_lag_ns"]) + " := by native_decide",
                  "lemma recorded_attempt_count" + name + " : attempts" + name + ".length = " + str(len(rows)) + " := by native_decide", ""]
    lines += ["end TDN.Deployments.SnapshotTfcCoverTraffic", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    for name in ["bundle", "output", "report"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    data = parse(args.bundle)
    Path(args.output).write_text(generate(data))
    summary = {**data, "endpoints": [{key: value for key, value in row.items() if key != "events"} |
                                    {"attempt_count": len(row["events"])} for row in data["endpoints"]]}
    Path(args.report).write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"endpoints": len(data["endpoints"]), "attempts": sum(len(row["events"]) for row in data["endpoints"]),
                      "whole_RG032_established": False}))


if __name__ == "__main__":
    main()
