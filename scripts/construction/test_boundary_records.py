"""Check declared-policy binding and raw capture preservation."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from boundary_records import build


class BoundaryRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native_path = Path("outputs/mcp/exported/v31r-baseline-red-services-multi_protocol_execution.json")
        cls.intent_path = Path("outputs/mcp/exported/v31r-red-services-red_service_policy.json")
        cls.underlay_path = Path("outputs/mcp/exported/v31r-underlay-policy-underlay_control_policy.json")

    def project(self, intent=None, underlay=None):
        with tempfile.TemporaryDirectory(dir="outputs/attempts/RG-035") as directory:
            root = Path(directory)
            intent_path = self.intent_path
            underlay_path = self.underlay_path
            if intent is not None:
                intent_path = root / "intent.json"
                intent_path.write_text(json.dumps(intent))
            if underlay is not None:
                underlay_path = root / "underlay.json"
                underlay_path.write_text(json.dumps(underlay))
            destination = root / "result.json"
            with contextlib.redirect_stdout(io.StringIO()):
                build(self.native_path, intent_path, destination, underlay_path)
            return json.loads(destination.read_text())

    def test_raw_capture_and_declared_policy_remain_separate(self):
        result = self.project()
        self.assertEqual(result["native"]["rawBundle"], json.loads(self.native_path.read_text()))
        self.assertEqual(result["declaredRedPolicy"], json.loads(self.intent_path.read_text()))
        self.assertEqual(result["declaredUnderlayPolicy"], json.loads(self.underlay_path.read_text()))
        self.assertEqual(len(result["services"]), 8)
        self.assertEqual(len(result["redEndpoints"]), 16)
        self.assertEqual(len(result["controls"]), 16)
        self.assertEqual({row["hook"] for row in result["controls"]}, {"input", "output"})
        self.assertTrue(all(row["port"] in [0, 8080] for row in result["redEndpoints"]))

    def test_mismatched_red_address_is_rejected(self):
        intent = json.loads(self.intent_path.read_text())
        intent["services"][0]["address"] = "10.255.255.1"
        with self.assertRaisesRegex(ValueError, "address differs"):
            self.project(intent=intent)

    def test_forwarded_control_approval_is_rejected(self):
        underlay = json.loads(self.underlay_path.read_text())
        underlay["approvals"][0]["hook"] = "forward"
        with self.assertRaisesRegex(ValueError, "Unsupported declared"):
            self.project(underlay=underlay)

    def test_unrecorded_control_interface_is_rejected(self):
        underlay = json.loads(self.underlay_path.read_text())
        underlay["approvals"][0]["interface"] = "unrecorded"
        with self.assertRaisesRegex(ValueError, "interface is absent"):
            self.project(underlay=underlay)


if __name__ == "__main__":
    unittest.main()
