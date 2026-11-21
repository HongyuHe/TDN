"""Exercise rejected JSON traces through the same Lean command used by deployments."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = "TDN.Deployments.DualStack_RedV4_GrayV4_BlackV4"
DATA = ROOT / "data/evidence/spec006-fragment-offset/spec005-size-field/spec004-wire-fields/DualStack_RedV4_GrayV4_BlackV4_SampleTrace.json"

class ForwardingReplayTests(unittest.TestCase):
    def check_rejection(self, actions, message):
        original = json.loads(DATA.read_text())
        records = {f"{MODULE}.witnessState{i}": original[f"{MODULE}.witnessState{i}"] for i in range(len(actions) + 1)}
        records[f"{MODULE}.witnessActions"] = actions
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "record.json").write_text(json.dumps(records))
            file = root / "Trial.lean"
            file.write_text(f'import TDN.Import.ForwardingTrace\nimport {MODULE}\nnamespace {MODULE}\n'
                            'replay_forwarding_trace config from "record.json"\n')
            result = subprocess.run(["lake", "env", "lean", str(file)], cwd=ROOT, capture_output=True, text=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stdout + result.stderr)

    def test_empty_trace_cannot_demonstrate_delivery(self):
        self.check_rejection([], "at least one forwarding action")

    def test_valid_prefix_cannot_demonstrate_delivery(self):
        self.check_rejection(["route", "filter"], "delivered")

    def test_wrong_recorded_hop_is_rejected(self):
        self.check_rejection(["drop", "filter"], "admits")

if __name__ == "__main__":
    unittest.main()
