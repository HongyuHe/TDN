import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/construction"))
from import_recorded_operations import issuances, management, parse, power, retained_tests

SOURCE = ROOT / "artifacts/snapshots/2026-10-24T014455Z"


class RecordedOperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def copy(self, name):
        target = self.base / name
        shutil.copytree(SOURCE / name, target)
        return target

    def change(self, bundle, name, update):
        data = json.loads((bundle / name).read_text())
        update(data)
        (bundle / name).write_text(json.dumps(data))
        manifest = json.loads((bundle / "manifest.json").read_text())
        for row in manifest["files"]:
            content = (bundle / row["path"]).read_bytes()
            row["sha256"] = hashlib.sha256(content).hexdigest()
            if "bytes" in row:
                row["bytes"] = len(content)
        (bundle / "manifest.json").write_text(json.dumps(manifest))

    def test_actual_selected_records(self):
        result = parse(SOURCE)
        self.assertEqual(len(result["assignments"]), 10)
        self.assertEqual(len(result["issuances"]), 4)
        self.assertEqual(len(result["retained_tests"]), 12)
        self.assertEqual(result["power"]["states"][-1], [False, False])

    def test_failed_process_exit_is_rejected(self):
        bundle = self.copy("aw-power-event-v5")
        self.change(bundle, "observations.json", lambda d: d.update(error="Owned AW did not power off"))
        with self.assertRaisesRegex(ValueError, "process-exit"):
            power(bundle)

    def test_guest_still_answers_is_rejected(self):
        bundle = self.copy("aw-power-event-v5")
        self.change(bundle, "observations.json", lambda d: next(r for r in d["records"]
                    if r.get("probe") == "AW-final-unused-state-powered-off").update(returncode=0))
        with self.assertRaisesRegex(ValueError, "still answered"):
            power(bundle)

    def test_reordered_use_window_is_rejected(self):
        bundle = self.copy("aw-power-event-v5")
        self.change(bundle, "observations.json", lambda d: next(r for r in d["records"]
                    if r.get("probe") == "AW-final-unused-state-powered-off").update(at="2026-01-01T00:00:00+00:00"))
        with self.assertRaisesRegex(ValueError, "reordered"):
            power(bundle)

    def test_wrong_guest_cannot_supply_power_evidence(self):
        bundle = self.copy("aw-power-event-v5")
        def update(d):
            c = next(r["command"] for r in d["records"]
                     if r.get("probe") == "AW-final-unused-state-powered-off")
            c[c.index("-p") + 1] = "22223"
        self.change(bundle, "observations.json", update)
        with self.assertRaisesRegex(ValueError, "different guest"):
            power(bundle)

    def test_other_csr_is_rejected(self):
        bundle = self.copy("ca-enterprise-v2")
        def update(d):
            c = next(r["command"] for r in d["records"] if r["id"] == "ca-0036")
            c[c.index("-in") + 1] = "/different/request.pem"
        self.change(bundle, "events.json", update)
        with self.assertRaisesRegex(ValueError, "CSR signing"):
            issuances(bundle)

    def test_missing_loaded_chain_is_rejected(self):
        bundle = self.copy("ca-enterprise-v2")
        def update(d):
            r = next(r for r in d["records"] if r["id"] == "ca-0054")
            r["stdout"] = r["stdout"].replace("loaded certificate from '/etc/swanctl/x509ca/enterprise-inner-root.pem'", "")
        self.change(bundle, "events.json", update)
        with self.assertRaisesRegex(ValueError, "chain not loaded"):
            issuances(bundle)

    def test_wrong_mounted_credential_is_rejected(self):
        bundle = self.copy("ca-enterprise-v2")
        def update(d):
            c = next(r["command"] for r in d["records"] if r["id"] == "ca-0051")
            c[c.index("-v") + 1] = "/other/credentials:/etc/swanctl"
        self.change(bundle, "events.json", update)
        with self.assertRaisesRegex(ValueError, "mounted credential"):
            issuances(bundle)

    def test_retained_test_bytes_must_match(self):
        bundle = self.copy("native-management-20261024T015900Z")
        result = management(bundle)
        probe = result["snapshot"]["probes"][0]
        oid = probe["observation_ids"][0]
        o = next(o for o in result["snapshot"]["observations"] if o["id"] == oid)
        (bundle / o["raw_path"]).write_text('{"stdout": "changed", "stderr": ""}')
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            retained_tests(result)


if __name__ == "__main__":
    unittest.main()
