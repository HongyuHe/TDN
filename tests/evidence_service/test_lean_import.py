"""The actual Lean command must reject data outside the declared type."""
from pathlib import Path
import json
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class LeanImportTests(unittest.TestCase):
    def run_lean(self, value, body, success):
        with tempfile.TemporaryDirectory(prefix="tdn-lean-import-") as name:
            directory = Path(name)
            (directory / "data.json").write_text(json.dumps(value))
            code = 'import TDN.Import.Command\nimport TDN.Semantics.FiniteExecution\n' + body
            path = directory / "Check.lean"
            path.write_text(code)
            result = subprocess.run(["lake", "env", "lean", str(path)], cwd=ROOT, text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
            return result.stdout + result.stderr

    def test_relative_path_and_kernel_decide(self):
        self.run_lean({"ports": [{"owner": 1, "name": "eth0", "stack": [2, 1], "payloadOrigin": False}]},
                      'tdn_data ports : List TDN.Execution.PortData from "data.json" ["ports"]\nexample : ports.length = 1 := by decide\n', True)

    def test_unknown_field_rejected(self):
        output = self.run_lean({"ports": [{"owner": 1, "name": "eth0", "stack": [], "payloadOrigin": False, "ignored": True}]},
                              'tdn_data ports : List TDN.Execution.PortData from "data.json" ["ports"]\n', False)
        self.assertIn("unrecognized evidence fields", output)

    def test_bad_finite_index_rejected(self):
        output = self.run_lean({"nodes": [0, 4]}, 'tdn_data nodes : List (Fin 4) from "data.json" ["nodes"]\n', False)
        self.assertIn("outside Fin 4", output)

    def test_changed_data_breaks_local_check(self):
        self.run_lean({"ports": [{"owner": 1, "name": "eth0", "stack": [], "payloadOrigin": False}]},
                      'tdn_data ports : List TDN.Execution.PortData from "data.json" ["ports"]\nexample : (ports[0]!).stack = [2, 1] := by decide\n', False)

    def test_parameterized_record_can_be_imported_twice(self):
        self.run_lean({"ranges": [{"low": 1, "high": 8, "label": 3}]},
                      'import TDN.Semantics.Addressing\ntdn_data first : List (TDN.Addressing.Range Nat) from "data.json" ["ranges"]\ntdn_data second : List (TDN.Addressing.Range Nat) from "data.json" ["ranges"]\nexample : first = second := by decide\n', True)


if __name__ == "__main__":
    unittest.main()
