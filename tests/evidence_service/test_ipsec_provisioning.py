"""Keep reinstalled ESP keys separate when public SPI and endpoints stay unchanged."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tdn_evidence.parsers.ipsec_provisioning import parse


def fixture():
    devices = {n: {"namespace": "fixture-" + n} for n in ["A", "B"]}
    interfaces = {"A:port": {"addresses": [["inet", "10.0.0.1", 24]]},
                  "B:port": {"addresses": [["inet", "10.0.0.2", 24]]}}
    report = {"devices": devices, "operational": {"interfaces": interfaces},
              "phase_files": ["before.json", "after.json"]}
    commands, installations, phases = [], [], {}
    raw = "src 10.0.0.1 dst 10.0.0.2\n proto esp spi 0x00000100 reqid 7 mode tunnel\n aead rfc4106(gcm(aes)) <<Keys hidden>> 128\n"
    def command(device, argv):
        identifier = "cmd-" + str(len(commands))
        commands.append({"id": identifier, "device_id": device, "returncode": 0,
            "command": ["ip", "netns", "exec", devices[device]["namespace"]] + argv,
            "started_at": identifier + "-start", "ended_at": identifier + "-end"})
        return commands[-1]
    for epoch, phase in enumerate(report["phase_files"]):
        if epoch:
            for device in devices:
                command(device, ["ip", "xfrm", "state", "flush"])
        first = None
        for device in devices:
            row = command(device, ["ip", "xfrm", "state", "add", "src", "10.0.0.1", "dst", "10.0.0.2",
                "proto", "esp", "spi", "256", "reqid", "7", "mode", "tunnel", "flag", "af-unspec",
                "replay-window", "32", "aead", "rfc4106(gcm(aes))", "[REDACTED_TEST_KEY]", "128"])
            installations.append({"observation_id": row["id"], "device": device,
                "install_epoch": row["id"], "started_at": row["started_at"], "ended_at": row["ended_at"],
                "source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "esp", "spi": 256,
                "reqid": 7, "mode": "tunnel", "aead": "rfc4106(gcm(aes))", "icv_bits": 128,
                "key_and_salt_bytes": 36, "key_and_salt_sha256": hashlib.sha256(bytes([epoch]) * 36).hexdigest(),
                "equal_to_installations": [first] if first else []})
            first = row["id"]
        phases[phase] = {}
        for device in devices:
            row = command(device, ["ip", "xfrm", "state", "list", "nokeys"])
            phases[phase][device] = {"xfrm": {"observation_id": row["id"], "value": raw}}
    evidence = {"schema": "ipsec-provisioning/v1", "installations": installations,
                "equality_method": "Synthetic unit-test fixture"}
    return report, commands, evidence, phases


class IPsecProvisioningTests(unittest.TestCase):
    def evaluate(self, mutate=None):
        report, commands, evidence, phases = fixture()
        if mutate:
            mutate(report, commands, evidence, phases)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, value in {"commands.json": commands, "ipsec-provisioning.json": evidence, **phases}.items():
                (directory / name).write_text(json.dumps(value))
            return parse(directory, report)

    def test_same_public_spi_has_distinct_installation_epochs(self):
        result = self.evaluate()
        self.assertEqual(result["selectedPhase"], "after.json")
        before, after = [p["bindings"] for p in result["phases"]]
        self.assertEqual(before[0]["local_state"], after[0]["local_state"])
        self.assertNotEqual(before[0]["install_epoch"], after[0]["install_epoch"])
        self.assertNotEqual(before[0]["key_and_salt_sha256"], after[0]["key_and_salt_sha256"])
        self.assertEqual(after[0]["peer_install_epoch"], after[1]["install_epoch"])

    def test_key_material_mismatch_is_rejected(self):
        def mutate(report, commands, evidence, phases):
            evidence["installations"][-1]["key_and_salt_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "equality conflicts"):
            self.evaluate(mutate)

    def test_peer_local_request_ids_may_differ(self):
        def mutate(report, commands, evidence, phases):
            for row in commands:
                if row["device_id"] == "B" and "reqid" in row["command"]:
                    row["command"][row["command"].index("reqid") + 1] = "9"
            for entry in evidence["installations"]:
                if entry["device"] == "B":
                    entry["reqid"] = 9
            for phase in phases.values():
                phase["B"]["xfrm"]["value"] = phase["B"]["xfrm"]["value"].replace("reqid 7", "reqid 9")
        result = self.evaluate(mutate)
        self.assertEqual([entry["reqid"] for entry in result["activeBindings"]], [7, 9])

    def test_missing_generation_and_unobserved_equality_are_rejected(self):
        def missing(report, commands, evidence, phases):
            evidence["installations"].pop()
        with self.assertRaisesRegex(ValueError, "omits an installation"):
            self.evaluate(missing)
        def equality(report, commands, evidence, phases):
            evidence["installations"][-1]["equal_to_installations"] = []
        with self.assertRaisesRegex(ValueError, "equality was not observed"):
            self.evaluate(equality)

    def test_unsupported_selector_is_rejected(self):
        def mutate(report, commands, evidence, phases):
            commands[0]["command"] += ["mark", "9"]
        with self.assertRaisesRegex(ValueError, "unsupported feature"):
            self.evaluate(mutate)


if __name__ == "__main__":
    unittest.main()
