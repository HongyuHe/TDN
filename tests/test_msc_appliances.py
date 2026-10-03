"""Exercise missing evidence and dangerous changes at the startup abstraction."""

import copy
import json
import unittest

from scripts import import_msc_snapshot as importer
from scripts import msc_appliances as parser


class ApplianceEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        status = json.loads((importer.CURRENT_EVIDENCE / "snapshot/status.json").read_text())
        cls.observations = {d["device"]: d for d in status["devices"]}

    def test_namespace_inventory_includes_frr_sidecar(self):
        parsed = parser.parse_appliance(self.observations["OF_A1"])
        self.assertEqual([c["name"] for c in parsed["containers"]], ["OF_A1", "OF_A1-frr"])
        self.assertIn("ospfd", [p["name"] for p in parsed["processes"]])
        self.assertNotIn("ospfd", self.observations["OF_A1"]["facts"]["processes"].split())

    def test_remote_boot_command_cannot_be_hidden_by_pid_one_sleep(self):
        observation = copy.deepcopy(self.observations["OF_A1"])
        raw = json.loads(observation["facts"]["appliance"])
        raw["containers"][0]["script"] = raw["containers"][0]["script"].replace(
            'exec "$@"', 'tftp -g -r configuration 192.0.2.1\nexec "$@"')
        observation["facts"]["appliance"] = json.dumps(raw)
        program = parser.parse_appliance(observation)["containers"][0]["program"]
        self.assertIn("unknown", program[0])
        self.assertIn("tftp", program[0]["unknown"])

    def test_ovs_remote_configuration_targets_are_retained(self):
        observation = copy.deepcopy(self.observations["G_A1"])
        baseline = parser.parse_appliance(observation)["containers"][0]["program"]
        self.assertIn({"startSwitch": []}, baseline)
        observation["facts"]["ovs"] += '\n    Manager "tcp:192.0.2.1:6640"\n'
        changed = parser.parse_appliance(observation)["containers"][0]["program"]
        self.assertIn({"startSwitch": ['"tcp:192.0.2.1:6640"']}, changed)
        observation["errors"] = {"ovs": "unavailable"}
        unknown = parser.parse_appliance(observation)["containers"][0]["program"]
        self.assertIn("unknown", unknown[0])

    def test_extra_resolver_and_tab_directive_survive(self):
        observation = copy.deepcopy(self.observations["O_A1"])
        raw = json.loads(observation["facts"]["appliance"])
        raw["containers"][0]["resolver"] += "nameserver\t192.0.2.1 # added resolver\n"
        observation["facts"]["appliance"] = json.dumps(raw)
        servers = parser.parse_appliance(observation)["containers"][0]["resolver"]["servers"]
        self.assertEqual(servers, [2189394995, 3221225985])
        with self.assertRaisesRegex(ValueError, "invalid resolver"):
            parser.parse_resolver("nameserver\n")

    def test_missing_and_failed_observations_remain_unknown(self):
        observation = copy.deepcopy(self.observations["O_A1"])
        observation["errors"] = {"appliance": "permission denied"}
        self.assertIsNone(parser.parse_appliance(observation))
        observation["errors"] = {}
        del observation["facts"]["appliance"]
        self.assertIsNone(parser.parse_appliance(observation))

    def test_false_clock_and_unknown_startup_remain_visible(self):
        observation = copy.deepcopy(self.observations["O_A1"])
        raw = json.loads(observation["facts"]["appliance"])
        raw["ntp_synchronized"] = False
        raw["containers"][0]["command"] = ["remote-bootstrap", "192.0.2.1"]
        observation["facts"]["appliance"] = json.dumps(raw)
        parsed = parser.parse_appliance(observation)
        self.assertFalse(parsed["ntpSynchronized"])
        self.assertIn("unknown", parsed["containers"][0]["program"][0])
        raw["containers"][0]["entrypoint"] = False
        observation["facts"]["appliance"] = json.dumps(raw)
        with self.assertRaisesRegex(ValueError, "startup arguments"):
            parser.parse_appliance(observation)


if __name__ == "__main__":
    unittest.main()
