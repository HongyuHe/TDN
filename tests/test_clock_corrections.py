"""Ensure queries, failed steps and mismatched sources cannot establish a correction."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_clock_corrections import parse_bundle, microseconds


class ClockImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.paths = {}
        for red, name in [(True, "independent-Red-clocks-v3"), (False, "independent-Gray-clocks-v3")]:
            self.paths[red] = Path(self.temp.name) / name
            shutil.copytree(ROOT / "data/snapshots/2026-10-24T014455Z" / name, self.paths[red])

    def tearDown(self):
        self.temp.cleanup()

    def read(self, red=True):
        return json.loads((self.paths[red] / "observations.json").read_text())

    def save(self, data, red=True):
        path = self.paths[red] / "observations.json"
        path.write_text(json.dumps(data))
        manifest = json.loads((self.paths[red] / "manifest.json").read_text())
        row = next(row for row in manifest["files"] if row["path"] == path.name)
        row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.paths[red] / "manifest.json").write_text(json.dumps(manifest))

    def test_actual_corrections(self):
        values = [row["after_offset_us"] for red in [True, False]
                  for row in parse_bundle(self.paths[red], red)["corrections"]]
        self.assertEqual(values, [26, 18, -16, 3])

    def test_query_cannot_substitute_for_adjustment(self):
        data = self.read()
        data["records"][12]["command"][-1] = "ntpdate -q -u 10.1.1.20"
        self.save(data)
        with self.assertRaisesRegex(ValueError, "before/adjustment/after"):
            parse_bundle(self.paths[True], True)

    def test_failed_step(self):
        data = self.read()
        data["records"][12]["returncode"] = 1
        self.save(data)
        with self.assertRaisesRegex(ValueError, "adjustment failed"):
            parse_bundle(self.paths[True], True)

    def test_wrong_reported_source(self):
        data = self.read()
        data["records"][12]["stdout"] = data["records"][12]["stdout"].replace("10.1.1.20", "10.9.9.20")
        self.save(data)
        with self.assertRaisesRegex(ValueError, "source-bound"):
            parse_bundle(self.paths[True], True)

    def test_missing_guest(self):
        data = self.read()
        data["records"] = [row for row in data["records"] if "22223" not in row["command"]]
        self.save(data)
        with self.assertRaisesRegex(ValueError, "guest inventory"):
            parse_bundle(self.paths[True], True)

    def test_reordered_step(self):
        data = self.read()
        data["records"][12], data["records"][13] = data["records"][13], data["records"][12]
        self.save(data)
        with self.assertRaisesRegex(ValueError, "out of order"):
            parse_bundle(self.paths[True], True)

    def test_large_residual_offset(self):
        data = self.read()
        data["records"][13]["stdout"] = data["records"][13]["stdout"].replace("+0.000026", "+0.200026")
        self.save(data)
        with self.assertRaisesRegex(ValueError, "one-millisecond"):
            parse_bundle(self.paths[True], True)

    def test_linux_query_output_cannot_substitute_for_step_diagnostic(self):
        data = self.read(False)
        for field in ["stdout", "stderr"]:
            data["records"][19][field] = "\n".join(line for line in data["records"][19][field].splitlines()
                                                    if not line.startswith("CLOCK:"))
        self.save(data, False)
        with self.assertRaisesRegex(ValueError, "clock-step diagnostic"):
            parse_bundle(self.paths[False], False)

    def test_duplicate_linux_boot_id(self):
        data = self.read(False)
        data["records"][33]["stdout"] = data["records"][11]["stdout"]
        self.save(data, False)
        with self.assertRaisesRegex(ValueError, "Distinct Gray"):
            parse_bundle(self.paths[False], False)

    def test_explicit_collection_success_required(self):
        data = self.read()
        data["error"] = ""
        self.save(data)
        with self.assertRaisesRegex(ValueError, "Explicit successful"):
            parse_bundle(self.paths[True], True)

    def test_fractional_microsecond_requires_explicit_rounding(self):
        with self.assertRaisesRegex(ValueError, "rounding"):
            microseconds("0.0000001")


if __name__ == "__main__":
    unittest.main()
