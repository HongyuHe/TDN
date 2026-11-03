"""Bind each observed ESP epoch to successful, privately compared AEAD installations."""
import json
from pathlib import Path
import re

from .family import encode_address
from .execution import state_blocks
from .snapshot import require


def selector(entry):
    return (entry["source"], entry["destination"], entry["spi"])


def parse(directory, report):
    directory = Path(directory)
    path = directory / "ipsec-provisioning.json"
    if not path.exists():
        return None
    source = json.loads(path.read_text())
    require(source["schema"] == "ipsec-provisioning/v1", "Unknown IPsec provisioning schema")
    commands = json.loads((directory / "commands.json").read_text())
    positions = {c["id"]: index for index, c in enumerate(commands)}
    by_id = {c["id"]: c for c in commands}
    entries = source["installations"]
    indexed = {e["observation_id"]: e for e in entries}
    require(len(indexed) == len(entries), "Duplicate IPsec installation observation")
    installed = {c["id"] for c in commands if c["command"][4:8] == ["ip", "xfrm", "state", "add"]}
    require(set(indexed) == installed, "IPsec provisioning omits an installation")
    previous_positions = []
    for entry in entries:
        command = by_id[entry["observation_id"]]
        previous_positions.append(positions[command["id"]])
        device = entry["device"]
        require(device in report["devices"] and command["device_id"] == device and command["returncode"] == 0,
                "Unbound or failed ESP installation")
        require(command["command"][:4] == ["ip", "netns", "exec", report["devices"][device]["namespace"]],
                "ESP installation namespace differs")
        argv = command["command"][4:]
        expected = ["ip", "xfrm", "state", "add", "src", entry["source"], "dst", entry["destination"],
            "proto", entry["protocol"], "spi", str(entry["spi"]), "reqid", str(entry["reqid"]),
            "mode", entry["mode"], "flag", "af-unspec", "replay-window", "32", "aead", entry["aead"],
            "[REDACTED_TEST_KEY]", str(entry["icv_bits"])]
        require(argv == expected, "ESP installation arguments differ or use an unsupported feature")
        require(entry["protocol"] == "esp" and entry["mode"] == "tunnel" and
                entry["aead"] == "rfc4106(gcm(aes))" and entry["icv_bits"] == 128 and
                entry["key_and_salt_bytes"] == 36 and
                re.fullmatch(r"[0-9a-f]{64}", entry["key_and_salt_sha256"]) is not None,
                "Unsupported AEAD material or algorithm")
        require(entry["install_epoch"] == command["id"] and entry["started_at"] == command["started_at"] and
                entry["ended_at"] == command["ended_at"], "ESP installation epoch/time differs")
        for previous in entry["equal_to_installations"]:
            require(previous in indexed and positions[previous] < positions[command["id"]],
                    "ESP equality points to a missing or later installation")
            prior = indexed[previous]
            require(prior["key_and_salt_sha256"] == entry["key_and_salt_sha256"] and
                    prior["key_and_salt_bytes"] == entry["key_and_salt_bytes"] and
                    prior["aead"] == entry["aead"] and prior["icv_bits"] == entry["icv_bits"],
                    "ESP equality conflicts with public material references")
    require(previous_positions == sorted(previous_positions), "ESP installation records are out of order")
    phases = []
    for filename in report["phase_files"]:
        observations = json.loads((directory / filename).read_text())
        phase = []
        for device, values in observations.items():
            observation = values["xfrm"]["observation_id"]
            cutoff = positions[observation]
            active = {}
            for command in commands[:cutoff]:
                if command["device_id"] != device or command["command"][4:7] != ["ip", "xfrm", "state"]:
                    continue
                argv = command["command"][4:]
                if argv[3:] == ["flush"]:
                    require(command["returncode"] == 0, "Failed ESP state flush")
                    active.clear()
                elif argv[3] == "add":
                    entry = indexed[command["id"]]
                    require(selector(entry) not in active, "Ambiguous active ESP installation epoch")
                    active[selector(entry)] = entry
                elif argv[3:] != ["list", "nokeys"]:
                    raise ValueError("ESP state mutation needs an explicit epoch parser")
            actual = state_blocks(values["xfrm"]["value"], encode_address)
            require(len(actual) == len(active), "Observed ESP inventory differs from active installations")
            for state in actual:
                matches = [entry for entry in active.values() if [entry["reqid"], entry["spi"],
                    encode_address(entry["source"]), encode_address(entry["destination"])] == state]
                require(len(matches) == 1, "Observed ESP state has no unique installation epoch")
                entry = matches[0]
                blocks = [block for block in re.split(r"(?m)(?=^src )", values["xfrm"]["value"])
                          if block.strip() and state_blocks(block, encode_address) == [state]]
                require(len(blocks) == 1 and re.search(r"\baead rfc4106\(gcm\(aes\)\) <<Keys hidden>> 128\b", blocks[0]),
                        "Observed ESP algorithm differs from provisioned AEAD")
                addresses = {a[1] for name, interface in report["operational"]["interfaces"].items()
                             if name.startswith(device + ":") for a in interface["addresses"]}
                outgoing, incoming = entry["source"] in addresses, entry["destination"] in addresses
                require(outgoing != incoming, "ESP direction is not uniquely bound to endpoint ownership")
                ports = [name for name, interface in report["operational"]["interfaces"].items()
                         if name.startswith(device + ":") and any(a[1] ==
                            (entry["source"] if outgoing else entry["destination"]) for a in interface["addresses"])]
                require(bool(ports), "ESP state has no relevant interface")
                phase.append(entry | {"phase": filename, "observed_state_id": observation,
                    "direction": "outbound" if outgoing else "inbound", "local_state": state,
                    "local_interfaces": ports, "mark": None, "if_id": None,
                    "salt_bytes": 4, "key_bits": 256, "equality_method": source["equality_method"]})
        for binding in phase:
            peers = [other for other in phase if other["device"] != binding["device"] and
                     other["direction"] != binding["direction"] and selector(other) == selector(binding)]
            require(len(peers) == 1, "ESP epoch has no unique opposite endpoint")
            peer = peers[0]
            require(peer["observation_id"] in binding["equal_to_installations"] or
                    binding["observation_id"] in peer["equal_to_installations"],
                    "Peer ESP key-and-salt equality was not observed")
            binding["peer_install_epoch"] = peer["install_epoch"]
            binding["peer_device"] = peer["device"]
        phases.append({"phase": filename, "bindings": phase})
    require(bool(phases), "No ESP observation phase")
    return {"selectedPhase": phases[-1]["phase"], "activeBindings": phases[-1]["bindings"],
        "phases": phases, "installations": entries,
        "scope": "Each phase binds separate local installation epochs. The execution model selects the final phase; earlier keys are not unioned with it. Manual provisioning establishes no IKE/CHILD_SA authentication."}
