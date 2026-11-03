"""Bind private-input equality observations to public installed MACsec associations."""
import json
from pathlib import Path
import re

from .snapshot import require


def parse(directory, report):
    path = Path(directory) / "macsec-provisioning.json"
    if not path.exists():
        return []
    source = json.loads(path.read_text())
    require(source["schema"] == "macsec-provisioning/v1", "Unknown key provisioning schema")
    entries = source["installations"]
    commands = json.loads((Path(directory) / "commands.json").read_text())
    by_id = {c["id"]: c for c in commands}
    for command in commands:
        argv = command["command"]
        if argv[4:6] == ["ip", "macsec"] and "key" in argv:
            require(argv[6] == "add", "MACsec key updates require a generation-aware parser")
    indexed = {row["observation_id"]: row for row in entries}
    require(len(indexed) == len(entries), "Duplicate provisioning observation")
    installed_commands = {c["id"] for c in commands if c["command"][4:7] == ["ip", "macsec", "add"]
                          and "key" in c["command"]}
    require(set(indexed) == installed_commands, "Provisioning record omits an installation")
    validated, seen = [], set()
    for entry in entries:
        command = by_id[entry["observation_id"]]
        device = entry["device"]
        require(device in report["devices"] and command["device_id"] == device and command["returncode"] == 0,
                "Unbound or failed key installation")
        prefix = ["ip", "netns", "exec", report["devices"][device]["namespace"]]
        argv = command["command"]
        require(argv[:4] == prefix, "Key installation namespace differs")
        argv = argv[4:]
        require(argv[:3] == ["ip", "macsec", "add"] and argv[3] == entry["logical_interface"] and
                argv[4] == entry["direction"] and entry["direction"] in ["tx", "rx"],
                "Key installation association differs")
        key_position, sa_position = argv.index("key"), argv.index("sa")
        require(int(argv[sa_position + 1]) == entry["association_number"] and
                argv[key_position + 1] == entry["installed_key_id"] and
                argv[key_position + 2:] == ["[REDACTED_TEST_KEY]"], "Key installation arguments differ")
        require(re.fullmatch(r"[0-9a-f]{64}", entry["key_sha256"]) is not None and
                entry["key_bytes"] in [16, 32], "Invalid public key-material reference")
        ports = [p for p in report["operational"]["mac_ports"] if p["device"] == device and
                 p["logical"] == entry["logical_interface"]]
        require(len(ports) == 1, "Installation has no unique observed MACsec port")
        port = ports[0]
        direction = entry["direction"]
        require(entry["association_number"] == port[direction + "_an"] and
                entry["installed_key_id"].ljust(32, "0") == port[direction + "_key_id"],
                "Installed association/key ID differs from provisioning")
        if direction == "rx":
            sci = int(argv[argv.index("address") + 1].replace(":", ""), 16) * 65536 + int(argv[argv.index("port") + 1])
            require(sci == port["rx_sci"], "Provisioned receive SCI differs")
        for previous in entry["equal_to_installations"]:
            require(previous in seen, "Key equality points to a missing or later installation")
            prior = indexed[previous]
            require(prior["key_sha256"] == entry["key_sha256"] and prior["key_bytes"] == entry["key_bytes"],
                    "Direct key equality conflicts with public references")
        seen.add(entry["observation_id"])
        validated.append(entry | {"physical_interface": port["physical"], "tag": port["tag"],
            "sci": port[direction + "_sci"], "raw_command": command["command"],
            "equality_method": source["equality_method"]})
    require(len(validated) == 2 * len(report["operational"]["mac_ports"]),
            "Observed MACsec association lacks provisioning evidence")
    for entry in validated:
        peers = [p for p in validated if p["device"] != entry["device"] and
                 p["direction"] != entry["direction"] and p["sci"] == entry["sci"] and
                 p["association_number"] == entry["association_number"]]
        require(len(peers) == 1, "Provisioned association has no unique peer")
        peer = peers[0]
        require(peer["observation_id"] in entry["equal_to_installations"] or
                entry["observation_id"] in peer["equal_to_installations"],
                "Peer key equality was not observed by the collector")
        entry["peer_observation_id"] = peer["observation_id"]
        entry["peer_device"] = peer["device"]
    return validated
