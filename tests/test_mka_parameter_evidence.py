import hashlib
import json
import re
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp"))
from tdn_evidence.mka_parameters import parse

SOURCE = ROOT / "data/snapshots/2026-11-11T041724Z/mka-parameters"


class MkaParameterEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "capture"
        shutil.copytree(SOURCE, self.bundle)
        self.document = json.loads((self.bundle / "events.json").read_text())

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        path = self.bundle / "events.json"
        path.write_text(json.dumps(self.document))
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        for row in manifest["files"]:
            row["sha256"] = hashlib.sha256((self.bundle / row["path"]).read_bytes()).hexdigest()
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def test_saved_peer_timing_and_interface_binding(self):
        _, report = parse(self.bundle)
        self.assertEqual(len(report["parameters"]), 2)
        for row in report["parameters"]:
            self.assertEqual((row["normalHelloMilliseconds"], row["activeHelloMilliseconds"],
                              row["lifetimeMilliseconds"]), (2000, 500, 6000))
            self.assertEqual(row["confidentialityOffset"], 0)
            self.assertTrue(row["controlledPortEnabled"])
            self.assertTrue(row["instrumentedBuild"])

    def test_manifest_tampering_rejected(self):
        path = self.bundle / "events.json"
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            parse(self.bundle)

    def test_missing_peer_rejected(self):
        launch = next(row for row in self.document["records"]
                      if len(row["command"]) > 4 and Path(row["command"][4]).name == "wpa_supplicant")
        self.document["records"].remove(launch)
        self.save()
        with self.assertRaisesRegex(ValueError, "exactly two"):
            parse(self.bundle)

    def test_status_and_logged_timer_disagreement_rejected(self):
        row = next(row for row in self.document["records"] if row["command"][-1] == "status")
        row["stdout"] = row["stdout"].replace("MKA Hello Time=500", "MKA Hello Time=2000")
        self.save()
        with self.assertRaisesRegex(ValueError, "active hello differ"):
            parse(self.bundle)

    def test_different_peer_sci_rejected(self):
        row = next(row for row in self.document["records"] if row["command"][-1] == "status")
        row["stdout"] = re.sub(r"actor_sci=[^@\n]+", "actor_sci=00:00:00:00:00:00", row["stdout"])
        self.save()
        with self.assertRaisesRegex(ValueError, "SCI differ"):
            parse(self.bundle)

    def test_unbound_offset_rejected(self):
        for row in self.document["records"]:
            if row["command"][0] == "cat":
                row["stdout"] = row["stdout"].replace("create_transmit_sc ->", "unobserved_transmit_sc ->")
        self.save()
        with self.assertRaisesRegex(ValueError, "confidentiality offset"):
            parse(self.bundle)

    def test_conflicting_public_configuration_rejected(self):
        config = next(self.bundle.glob("*.conf.public"))
        config.write_text(config.read_text().replace("macsec_replay_window=2", "macsec_replay_window=7"))
        self.save()
        with self.assertRaisesRegex(ValueError, "Configured and observed replay windows differ"):
            parse(self.bundle)

    def test_disabled_data_delay_flag_is_preserved(self):
        for row in self.document["records"]:
            row["stdout"] = row["stdout"].replace("Delay Protect....: Yes", "Delay Protect....: No")
        self.save()
        _, report = parse(self.bundle)
        self.assertTrue(all(not row["dataDelayProtectionLogged"] for row in report["parameters"]))

    def test_noncompliant_observed_lifetime_is_preserved(self):
        for row in self.document["records"]:
            row["stdout"] = row["stdout"].replace("lifetime=6000", "lifetime=9000")
        self.save()
        _, report = parse(self.bundle)
        self.assertEqual({row["lifetimeMilliseconds"] for row in report["parameters"]}, {9000})


if __name__ == "__main__":
    unittest.main()
