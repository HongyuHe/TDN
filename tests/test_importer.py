from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("validator", Path(__file__).parents[1]/"scripts/construction/validate_evidence.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)

class ImporterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.tmp.name)
        self.raw = b"synthetic importer test fixture\n"
        (self.root/"raw.txt").write_bytes(self.raw)
        self.now = "2026-10-17T20:00:00Z"
        observed = {"status":"observed","observation_ids":["obs-1"]}
        self.snapshot = {"schema_version":validator.SCHEMA,"snapshot_id":"fixture","scope":{"expected_device_ids":["device-1"],"expected_interface_ids":["interface-1"]},"devices":[{"id":"device-1","role":"inner","site":"site-1","security_level_id":"level-1",**observed}],"interfaces":[{"id":"interface-1","device_id":"device-1",**observed}],"links":[],"routes":[],"filters":[],"tunnels":[],"credentials":[],"probes":[],"management":{"profile":"none","applicability":"optional_disabled","records":[],"failures":[]},"observations":[{"id":"obs-1","collector":"test","device_id":"device-1","command":"fixture","started_at":self.now,"ended_at":self.now,"returncode":0,"raw_path":"raw.txt","raw_sha256":hashlib.sha256(self.raw).hexdigest(),"sanitizer":"fixture","parse_status":"parsed"}],"limitations":[]}
        self.manifest = {key:[] for key in validator.MANIFEST_FIELDS}
        self.manifest.update({"schema_version":validator.SCHEMA,"snapshot_id":"fixture","run_id":"fixture-run","configuration_id":"fixture-config","emulation_id":"synthetic-only","started_at":self.now,"ended_at":self.now,"inventory_complete":{name:{"complete":True,"reason":"Synthetic test fixture enumeration"} for name in (*validator.CATEGORIES,"management")}})

    def tearDown(self):
        self.tmp.cleanup()

    def save(self):
        (self.root/"snapshot.json").write_text(json.dumps(self.snapshot))
        self.manifest["files"] = [{"path":name,"sha256":hashlib.sha256((self.root/name).read_bytes()).hexdigest(),"bytes":(self.root/name).stat().st_size,"category":"fixture"} for name in ("snapshot.json","raw.txt")]
        (self.root/"manifest.json").write_text(json.dumps(self.manifest))

    def rejects(self, expression):
        self.save()
        with self.assertRaisesRegex(validator.EvidenceError, expression):
            validator.validate_bundle(self.root)

    def test_valid_management_free_bundle(self):
        self.save()
        result = validator.validate_bundle(self.root)
        self.assertTrue(result["integrity_valid"])
        self.assertFalse(result["claims"]["whole_group_establishment"])
        self.assertEqual(result["management_profile"],"none")

    def test_tampered_raw_rejected(self):
        self.save()
        (self.root/"raw.txt").write_bytes(b"tamper")
        with self.assertRaises(validator.EvidenceError):
            validator.validate_bundle(self.root)

    def test_duplicate_device_rejected(self):
        self.snapshot["devices"].append(copy.deepcopy(self.snapshot["devices"][0]))
        self.rejects("duplicate")

    def test_missing_expected_device_rejected(self):
        self.snapshot["scope"]["expected_device_ids"].append("device-missing")
        self.rejects("differs from expected")

    def test_false_completeness_is_not_success(self):
        self.manifest["inventory_complete"]["devices"]["complete"] = False
        self.save()
        report = validator.validate_bundle(self.root)
        self.assertIn("Incomplete devices inventory",report["data_path_blockers"])

    def test_observed_fact_requires_provenance(self):
        self.snapshot["devices"][0]["observation_ids"] = []
        self.rejects("requires provenance")

    def test_observed_fact_rejects_failed_collector(self):
        self.snapshot["observations"][0]["returncode"] = 1
        self.rejects("failed/unparsed")

    def test_dangling_peer_rejected(self):
        self.snapshot["tunnels"] = [{"id":"tunnel-1","device_id":"device-1","peer_device_id":"missing","status":"observed","observation_ids":["obs-1"]}]
        self.rejects("unknown peer")

    def test_unsupported_filter_preserved_and_excluded(self):
        self.snapshot["filters"] = [{"id":"filter-1","device_id":"device-1","status":"observed","observation_ids":["obs-1"],"policy":"drop","ordered_rules":[{"ordinal":1,"matches":{"stateful_conntrack":"established"},"action":"accept"}]}]
        self.save()
        report=validator.validate_bundle(self.root)
        self.assertTrue(report["unsupported_filters"])
        self.assertTrue(report["data_path_blockers"])

    def test_virtual_link_cannot_assert_physical_claim(self):
        self.snapshot["links"] = [{"id":"link-1","endpoint_interface_ids":["interface-1","interface-1"],"relation":"veth","physical_claim_supported":True,"status":"observed","observation_ids":["obs-1"]}]
        self.rejects("virtual link")

    def test_snapshot_hash_required(self):
        self.save()
        self.manifest["files"] = self.manifest["files"][1:]
        (self.root/"manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(validator.EvidenceError,"snapshot.json must be hashed"):
            validator.validate_bundle(self.root)

    def test_parsed_negative_ping_is_observed(self):
        self.snapshot["observations"].append({**self.snapshot["observations"][0], "id":"obs-negative", "returncode":1, "observation_kind":"probe", "tested_program":"ping", "collector_status":"success", "probe_outcome":"no_reply", "timed_out":False})
        self.snapshot["probes"] = [{"id":"probe-negative", "source_device":"device-1", "destination":"target", "status":"observed", "observation_ids":["obs-negative"]}]
        self.save()
        self.assertTrue(validator.validate_bundle(self.root)["integrity_valid"])

    def test_probe_timeout_cannot_be_negative_success(self):
        observation={**self.snapshot["observations"][0], "returncode":1, "observation_kind":"probe", "tested_program":"ping", "collector_status":"success", "probe_outcome":"no_reply", "timed_out":True}
        self.assertFalse(validator.observation_supports(observation,"probes"))
        observation["timed_out"]=False
        self.assertFalse(validator.observation_supports(observation,"devices"))
        observation["returncode"]=2
        self.assertFalse(validator.observation_supports(observation,"probes"))

    def test_traversal_rejected(self):
        with self.assertRaisesRegex(validator.EvidenceError,"traversal"):
            validator.safe_path(self.root,"../outside")

if __name__ == "__main__":
    unittest.main()
