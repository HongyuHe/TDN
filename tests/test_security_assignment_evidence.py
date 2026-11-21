import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp"))
from tdn_evidence.security_assignments import export_red_connectivity, parse

SOURCE = ROOT / "data/extraction/networks/profiles/security-level-assignments-20261111"


class SecurityAssignmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "policy"
        shutil.copytree(SOURCE, self.bundle)
        self.policy = json.loads((self.bundle / "policy.json").read_text())

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        path = self.bundle / "policy.json"
        path.write_text(json.dumps(self.policy))
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        for row in manifest["files"]:
            row["sha256"] = hashlib.sha256((self.bundle / row["path"]).read_bytes()).hexdigest()
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def test_complete_explicit_labels(self):
        _, report = parse(self.bundle)
        self.assertEqual(len(report["assignments"]), 12)
        self.assertTrue(all(r["evidenceStatus"] == "declared" for r in report["assignments"]))
        shared = {r["profileLevel"]: r["assignedLevel"] for r in report["assignments"] if r["profile"] == "shared"}
        self.assertEqual(shared["SECRET_US_ONLY"]["classification"], shared["SECRET_COALITION"]["classification"])
        self.assertNotEqual(shared["SECRET_US_ONLY"]["dissemination"], shared["SECRET_COALITION"]["dissemination"])

    def test_missing_assignment_rejected(self):
        self.policy["profiles"][0]["assignments"].pop()
        self.save()
        with self.assertRaisesRegex(ValueError, "Incomplete Inner"):
            parse(self.bundle)

    def test_missing_dimension_rejected(self):
        del self.policy["profiles"][0]["assignments"][0]["assignedLevel"]["compartments"]
        self.save()
        with self.assertRaisesRegex(ValueError, "four security dimensions"):
            parse(self.bundle)

    def test_unknown_inner_rejected(self):
        self.policy["profiles"][0]["assignments"][0]["innerDevice"] = "UNKNOWN"
        self.save()
        with self.assertRaisesRegex(ValueError, "Incomplete Inner"):
            parse(self.bundle)

    def test_wrong_profile_level_rejected(self):
        self.policy["profiles"][0]["assignments"][0]["profileLevel"] = "S2"
        self.save()
        with self.assertRaisesRegex(ValueError, "Unbound Inner"):
            parse(self.bundle)

    def test_wrong_cohort_rejected(self):
        self.policy["profiles"][0]["snapshotSha256"] = self.policy["profiles"][1]["snapshotSha256"]
        self.save()
        with self.assertRaisesRegex(ValueError, "source hash"):
            parse(self.bundle)

    def test_runtime_or_approval_claim_rejected(self):
        self.policy["realClassificationApproval"] = True
        self.save()
        with self.assertRaisesRegex(ValueError, "experimental policy"):
            parse(self.bundle)

    def test_unrecorded_modification_rejected(self):
        path = self.bundle / "baseline-spec.json"
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            parse(self.bundle)

    def test_duplicate_set_value_rejected(self):
        self.policy["profiles"][0]["assignments"][0]["assignedLevel"]["compartments"] = ["A", "A"]
        self.save()
        with self.assertRaisesRegex(ValueError, "security-label set"):
            parse(self.bundle)

    def change_shared(self, kind, change):
        path = self.bundle / f"shared-{kind}.json"
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))
        profile = next(row for row in self.policy["profiles"] if row["id"] == "shared")
        profile[kind + "Sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.save()

    def connectivity(self):
        destination = Path(self.temp.name) / "export.json"
        export_red_connectivity(self.bundle, destination)
        return json.loads(destination.read_text())["profiles"]

    def test_connectivity_distinguishes_networks_labels_and_physical_hosts(self):
        profiles = self.connectivity()
        self.assertEqual([len(p["probes"]) for p in profiles.values()], [12, 56])
        shared = profiles["shared"]
        hosts = {row["host"]: row for row in shared["endpoints"]}
        us, coalition = (hosts[name]["assignedLevel"] for name in ("V31F_R_A2", "V31F_R_A3"))
        self.assertEqual(us["classification"], coalition["classification"])
        self.assertNotEqual(us["dissemination"], coalition["dissemination"])
        places = {row["device"]: row for row in shared["placements"]}
        self.assertEqual(places["V31F_I_A4"]["host"], places["V31F_O_A1"]["host"])
        self.assertEqual(places["V31F_I_A4"]["virtualization"], "container-shared-kernel")

    def test_unexpected_probe_result_survives_export(self):
        def change(snapshot):
            row = next(p for p in snapshot["probes"] if p["expected_result"] == "no_reply")
            row["observed_result"] = "delivered"
        self.change_shared("snapshot", change)
        differences = [row for row in self.connectivity()["shared"]["probes"] if row["expected"] != row["observed"]]
        self.assertEqual(len(differences), 1)

    def test_wrong_configured_peer_survives_export(self):
        def change(specification):
            inner = next(d for d in specification["devices"] if d["id"] == "V31F_I_A2")
            inner["tunnel"]["peer"] = "V31F_I_B3"
        self.change_shared("spec", change)
        peers = {p["sourceInner"]: p["peerInner"] for p in self.connectivity()["shared"]["configuredPeers"]}
        self.assertEqual(peers["V31F_I_A2"], "V31F_I_B3")

    def test_incomplete_probe_matrix_rejected(self):
        self.change_shared("snapshot", lambda snapshot: snapshot["probes"].pop())
        with self.assertRaisesRegex(ValueError, "each ordered distinct network pair"):
            self.connectivity()


if __name__ == "__main__":
    unittest.main()
