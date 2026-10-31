"""Exercise collection coverage, immutability, cancellation and vendor parsing."""
from pathlib import Path
import json
import tempfile
import time
import unittest
from scripts.construction.evidence_service.adapters import bird_routes, linux_routes, Unsupported, ADAPTERS, Adapter, register_adapter
from scripts.construction.evidence_service.service import EvidenceService


class FakeTransport:
    def __init__(self, changed=False):
        self.changed = changed
        self.calls = 0

    def run(self, device, argv):
        self.calls += 1
        if "route" in argv:
            metric = self.calls if self.changed else 0
            rows = [{"dst": "default", "dev": "eth0", "metric": metric, "flags": []}]
            return 0, json.dumps(rows).encode(), b""
        if "rule" in argv:
            return 0, b'[{"priority":32766,"src":"all","table":"main"}]', b""
        return 0, b"[]", b""


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"store": "store", "networks": [{"id": "test", "devices": [
            {"id": "router", "worker": "local", "container": "router", "adapters": ["linux"]}]}]}))
        self.service = EvidenceService(self.config, FakeTransport())

    def tearDown(self):
        self.service.pool.shutdown(wait=True)
        self.temp.cleanup()

    def collect(self, capabilities=None):
        job = self.service.collect_evidence("test", capabilities or ["linux.fib4", "linux.fib6"])
        for _ in range(200):
            status = self.service.collection_status(job["id"])
            if status["status"] != "running":
                break
            time.sleep(.01)
        self.assertEqual(status["status"], "complete")
        return job["id"]

    def test_capture_query_and_bundle(self):
        ident = self.collect()
        result = self.service.query_evidence(ident, limit=1)
        self.assertEqual(result["next_offset"], 1)
        self.assertEqual(result["consistency"], "stable-during-recheck")
        bundle = self.service.prepare_lean_bundle(ident)
        self.assertEqual(bundle["routes"], 2)
        self.assertEqual(bundle, self.service.prepare_lean_bundle(ident))

    def test_raw_tampering_rejected(self):
        ident = self.collect()
        raw = next((self.service.root / ident / "raw").glob("*.stdout"))
        raw.write_text("[]")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.service.query_evidence(ident)

    def test_unknown_capability_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown capabilities"):
            self.service.collect_evidence("test", ["linux.magic"])

    def test_missing_is_not_empty_success(self):
        ident = self.collect(["linux.fib4"])
        result = self.service.query_evidence(ident, "linux.fib6")
        self.assertFalse(result["requested_capability_collected"])
        with self.assertRaisesRegex(ValueError, "Missing forwarding coverage"):
            self.service.prepare_lean_bundle(ident)

    def test_changed_capture_cannot_be_prepared(self):
        self.service.transport = FakeTransport(changed=True)
        ident = self.collect()
        with self.assertRaisesRegex(ValueError, "unchanged"):
            self.service.prepare_lean_bundle(ident)

    def test_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            self.service.read_manifest("../../config.json")

    def test_invalid_limits(self):
        with self.assertRaises(ValueError):
            self.service.query_evidence("absent", limit=0)

    def test_unknown_settings_rejected(self):
        data = json.loads(self.config.read_text())
        data["unknown"] = True
        self.config.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            EvidenceService(self.config)

    def test_forwarding_export_accepts_another_adapter_name(self):
        register_adapter("alternate-test", Adapter("test-v1", {key: ADAPTERS["linux"].capabilities[key] for key in ["fib4", "fib6"]}))
        try:
            self.service.networks["test"].devices[0].adapters = ["alternate-test"]
            ident = self.collect(["alternate-test.fib4", "alternate-test.fib6"])
            self.assertEqual(self.service.prepare_lean_bundle(ident)["routes"], 2)
        finally:
            del ADAPTERS["alternate-test"]

    def test_cancellation_keeps_partial_capture_unpublished(self):
        original = self.service.transport.run
        def delayed(device, argv):
            time.sleep(.05)
            return original(device, argv)
        self.service.transport.run = delayed
        job = self.service.collect_evidence("test", ["linux.fib4", "linux.fib6"])
        self.service.cancel_collection(job["id"])
        for _ in range(100):
            state = self.service.collection_status(job["id"])
            if state["status"] != "running":
                break
            time.sleep(.01)
        self.assertEqual(state["status"], "cancelled")
        self.assertFalse((self.service.root / job["id"]).exists())


class ParserTests(unittest.TestCase):
    def test_bird_route_and_attributes(self):
        rows = bird_routes('BIRD 2.15.1 ready.\nAccess restricted\nTable master4:\n10.77.2.0/24 unicast [peer 12:00:00] * (100) [AS65002i]\n via 172.30.231.12 on eth0\n BGP.as_path: 65002\n')
        self.assertEqual(rows[0]["next_hops"][0]["gateway"], "172.30.231.12")
        self.assertEqual(rows[0]["attributes"], ["BGP.as_path: 65002"])
        self.assertTrue(rows[0]["selected"])

    def test_bird_unknown_output_rejected(self):
        with self.assertRaises(Unsupported):
            bird_routes("Error: routing table unavailable")

    def test_linux_unknown_field_rejected(self):
        with self.assertRaises(Unsupported):
            linux_routes('[{"dst":"default","encap":{"type":"mpls"}}]')

    def test_linux_multipath_not_silently_dropped(self):
        with self.assertRaises(Unsupported):
            linux_routes('[{"dst":"default","nhid":3}]')

    def test_linux_keeps_table_and_protocol(self):
        rows = linux_routes('[{"dst":"default","dev":"eth0","table":"local","protocol":"bird","flags":[]}]')
        self.assertEqual(rows[0]["table"], 255)
        self.assertEqual(rows[0]["protocol"], "bird")


if __name__ == "__main__":
    unittest.main()
