import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp"))
from tdn_evidence.mixed_observations import parse, read_experiment_raw

SOURCE = ROOT / "data/snapshots/2026-11-01T022125Z/manual-pairings/layers-ipsec-macsec-integrated"


class MixedObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "capture"
        shutil.copytree(SOURCE, self.bundle)

    def tearDown(self):
        self.temp.cleanup()

    def change(self, filename, transform):
        path = self.bundle / filename
        value = json.loads(path.read_text())
        transform(value)
        path.write_text(json.dumps(value))
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        row = next(r for r in manifest["files"] if r["path"] == filename)
        row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def test_real_observations_and_source_bound_esp(self):
        _, report = parse(self.bundle)
        self.assertEqual(len(report["probes"]), 6)
        self.assertEqual(len(report["packet_headers"]), 538)
        self.assertTrue(any(r["role"] == "inner" and r["matchingHeaders"] for r in report["esp_tunnels"]))
        self.assertEqual(report["control_probes"], [])
        raw = read_experiment_raw(self.bundle, "header-phase-2-headers-IA.json")
        self.assertEqual(json.loads(raw)["frames"][0], json.loads((self.bundle / "phase-2-headers-IA.json").read_text())["frames"][0])

    def test_changed_probe_destination_rejected(self):
        self.change("evidence.json", lambda d: d["probes"][2].update(destination="192.0.2.5"))
        with self.assertRaisesRegex(ValueError, "Probe command binding"):
            parse(self.bundle)

    def test_declared_success_with_zero_replies_rejected(self):
        def edit(rows):
            row = next(r for r in rows if r["id"] == "cmd-0428")
            row["stdout"] = row["stdout"].replace("3 received,", "0 received,")
        self.change("commands.json", edit)
        with self.assertRaisesRegex(ValueError, "Probe outcome"):
            parse(self.bundle)

    def test_incomplete_header_capture_rejected(self):
        self.change("phase-2-headers-IA.json", lambda d: d["frames"].pop())
        with self.assertRaisesRegex(ValueError, "capture counts"):
            parse(self.bundle)

    def test_unbound_header_interface_rejected(self):
        self.change("phase-2-headers-IA.json", lambda d: d["frames"][0].update(interface="missing"))
        with self.assertRaisesRegex(ValueError, "interface absent"):
            parse(self.bundle)

    def test_wrong_header_collector_rejected(self):
        def edit(rows):
            row = next(r for r in rows if r["id"] == "cmd-0431")
            row["command"][5] = "/unrelated-collector.py"
        self.change("commands.json", edit)
        with self.assertRaisesRegex(ValueError, "capture command binding"):
            parse(self.bundle)

    def test_unlisted_raw_file_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside the validated"):
            read_experiment_raw(self.bundle, "header-../../private.json")

    def test_existing_control_framing_observations_remain_readable(self):
        path = ROOT / "data/snapshots/2026-11-01T043810Z/mixed-framing-004/layers-ipsec-ipsec-integrated"
        _, report = parse(path)
        self.assertEqual(len(report["control_probes"]), 2)
        probe = report["control_probes"][0]
        raw = json.loads(read_experiment_raw(path, probe["receiverObservation"]))
        self.assertEqual(raw["receivedHex"], probe["payloadHex"])


if __name__ == "__main__":
    unittest.main()
