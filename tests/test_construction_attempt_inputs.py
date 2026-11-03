"""Preserve temporary Lean fixtures and the data files they actually import."""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(__file__).parents[1] / "scripts/construction/record_attempt.py"
SPEC = importlib.util.spec_from_file_location("tdn_record_attempt", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AttemptInputsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        (self.root / "outputs/fixtures").mkdir(parents=True)

    def tearDown(self):
        self.temporary.cleanup()

    def test_fixture_and_relative_json_are_captured(self):
        (self.root / "outputs/fixtures/Check.lean").write_text(
            'tdn_data items : List Nat from "items.json" ["values"]\n')
        (self.root / "outputs/fixtures/items.json").write_text('{"values": [1, 2]}')
        selected, missing = MODULE.referenced_inputs(
            self.root, ["lake", "env", "lean", "outputs/fixtures/Check.lean"], [])
        self.assertEqual(selected, ["outputs/fixtures/Check.lean", "outputs/fixtures/items.json"])
        self.assertEqual(missing, [])

    def test_multiline_imports_and_explicit_inputs_are_captured(self):
        (self.root / "outputs/fixtures/Check.lean").write_text(
            'tdn_data a : List Nat\n  from "a.json" ["a"]\n'
            'tdn_data b : List Nat from "b.json" ["b"]\n')
        for name in ["a.json", "b.json", "case.json"]:
            (self.root / "outputs/fixtures" / name).write_text("{}")
        selected, missing = MODULE.referenced_inputs(self.root,
            ["lake", "env", "lean", "outputs/fixtures/Check.lean"], ["outputs/fixtures/case.json"])
        self.assertEqual(len(selected), 4)
        self.assertEqual(missing, [])

    def test_missing_reference_is_recorded(self):
        (self.root / "outputs/fixtures/Check.lean").write_text(
            'tdn_data a : Nat from "absent.json" ["a"]\n')
        _, missing = MODULE.referenced_inputs(self.root, ["outputs/fixtures/Check.lean"], [])
        self.assertEqual(missing, ["outputs/fixtures/absent.json"])

    def test_private_and_outside_inputs_are_rejected(self):
        for name in ["private/key.json", "../outside.json"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                MODULE.referenced_inputs(self.root, [], [name])

    def test_repeated_arguments_are_deduplicated(self):
        (self.root / "outputs/fixtures/Check.lean").write_text("example : True := by trivial\n")
        selected, _ = MODULE.referenced_inputs(self.root, ["outputs/fixtures/Check.lean"],
                                               ["outputs/fixtures/Check.lean"])
        self.assertEqual(selected, ["outputs/fixtures/Check.lean"])

    def test_completed_attempt_retains_exact_fixture_and_data(self):
        scripts = self.root / "scripts/construction"
        scripts.mkdir(parents=True)
        for name in ["record_attempt.py", "record.py"]:
            shutil.copy2(SOURCE.parent / name, scripts / name)
        (self.root / "lean-toolchain").write_text("test-toolchain\n")
        (self.root / "lake-manifest.json").write_text("{}")
        fixture = self.root / "outputs/fixtures/check.py"
        data = self.root / "outputs/fixtures/case.json"
        fixture.write_text('print("recorded fixture ran")\n')
        data.write_text('{"value": 7}')
        result = subprocess.run([sys.executable, "scripts/construction/record_attempt.py",
            "--label", "retention", "--run-dir", "outputs/run", "--input", "outputs/fixtures/case.json",
            "--", sys.executable, "outputs/fixtures/check.py"], cwd=self.root, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = json.loads(next((self.root / "outputs/run/experiments").glob("*.attempt.json")).read_text())
        record = json.loads((self.root / receipt["source_checkpoint"]).read_text())
        paths = [row["path"] for row in record["files"]]
        self.assertEqual(len(paths), len(set(paths)))
        copied = self.root / record["checkpoint"]
        data.write_text('{"value": 9}')
        self.assertEqual((copied / "outputs/fixtures/case.json").read_text(), '{"value": 7}')
        self.assertEqual((copied / "outputs/fixtures/check.py").read_bytes(), fixture.read_bytes())
        self.assertIn("recorded fixture ran", (self.root / receipt["log"]).read_text())


if __name__ == "__main__":
    unittest.main()
