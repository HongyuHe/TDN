"""Check private-input equality records against public installation observations."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tdn_evidence.parsers.macsec_provisioning import parse


def fixture():
    addresses = {"A": "02:00:00:00:00:01", "B": "02:00:00:00:00:02"}
    scis = {node: int(address.replace(":", ""), 16) * 65536 + 1 for node, address in addresses.items()}
    report = {"devices": {node: {"namespace": "fixture-" + node} for node in addresses},
              "operational": {"mac_ports": []}}
    for node, peer, tx, rx in [("A", "B", "01", "02"), ("B", "A", "02", "01")]:
        report["operational"]["mac_ports"].append({"device": node, "logical": "macsec0",
            "physical": "gray", "tag": 1, "tx_sci": scis[node], "rx_sci": scis[peer],
            "tx_an": 0, "rx_an": 0, "tx_key_id": tx.ljust(32, "0"), "rx_key_id": rx.ljust(32, "0")})
    commands, entries = [], []
    for index, (node, direction, peer, key_id, equals) in enumerate([
            ("A", "tx", "A", "01", []), ("B", "tx", "B", "02", []),
            ("A", "rx", "B", "02", ["cmd-1"]), ("B", "rx", "A", "01", ["cmd-0"])]):
        command = ["ip", "netns", "exec", "fixture-" + node, "ip", "macsec", "add", "macsec0", direction]
        if direction == "rx":
            command += ["port", "1", "address", addresses[peer]]
        command += ["sa", "0", "pn", "1", "on", "key", key_id, "[REDACTED_TEST_KEY]"]
        commands.append({"id": "cmd-" + str(index), "device_id": node, "returncode": 0, "command": command})
        entries.append({"observation_id": "cmd-" + str(index), "device": node,
            "logical_interface": "macsec0", "direction": direction, "association_number": 0,
            "installed_key_id": key_id, "key_bytes": 32,
            "key_sha256": hashlib.sha256(peer.encode() * 32).hexdigest(), "equal_to_installations": equals})
    return report, commands, {"schema": "macsec-provisioning/v1", "installations": entries,
                              "equality_method": "Synthetic unit-test fixture"}


class MACsecProvisioningTests(unittest.TestCase):
    def evaluate(self, mutate=None):
        report, commands, evidence = fixture()
        if mutate:
            mutate(report, commands, evidence)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "commands.json").write_text(json.dumps(commands))
            (directory / "macsec-provisioning.json").write_text(json.dumps(evidence))
            return parse(directory, report)

    def test_binds_peer_associations_and_direct_equality(self):
        entries = self.evaluate()
        self.assertEqual(len(entries), 4)
        self.assertEqual(entries[0]["peer_observation_id"], "cmd-3")
        self.assertEqual(entries[1]["peer_observation_id"], "cmd-2")

    def test_equal_key_ids_without_equality_observation_are_insufficient(self):
        def mutate(report, commands, evidence):
            for entry in evidence["installations"]:
                entry["equal_to_installations"] = []
        with self.assertRaisesRegex(ValueError, "equality was not observed"):
            self.evaluate(mutate)

    def test_wrong_material_and_installation_id_are_rejected(self):
        def material(report, commands, evidence):
            evidence["installations"][2]["key_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "conflicts with public references"):
            self.evaluate(material)
        def identifier(report, commands, evidence):
            report["operational"]["mac_ports"][0]["rx_key_id"] = "99".ljust(32, "0")
        with self.assertRaisesRegex(ValueError, "key ID differs"):
            self.evaluate(identifier)

    def test_missing_installation_and_unknown_update_are_rejected(self):
        def missing(report, commands, evidence):
            evidence["installations"].pop()
        with self.assertRaisesRegex(ValueError, "omits an installation"):
            self.evaluate(missing)
        def update(report, commands, evidence):
            command = copy.deepcopy(commands[0])
            command["id"] = "update"
            command["command"][6] = "set"
            commands.append(command)
        with self.assertRaisesRegex(ValueError, "generation-aware parser"):
            self.evaluate(update)


if __name__ == "__main__":
    unittest.main()
