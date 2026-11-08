"""Check raw-bound execution exports against retained configurations and unsupported inputs."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tdn_evidence.parsers.execution import binding_records, parse_execution
from tdn_evidence.service import EvidenceService


ROOT = Path(__file__).resolve().parents[2]
SNAPSHOTS = ROOT / "data/snapshots/2026-10-24T014455Z"
BASELINE = SNAPSHOTS / "native-baseline-20261024T015000Z"
SUPPLEMENT = SNAPSHOTS / "native-baseline-processing-20261024T015100Z"


class ExecutionProjectionTests(unittest.TestCase):
    def test_wire_identity_allows_different_local_request_ids(self):
        snapshot = {"devices": [{"id": "a"}, {"id": "b"}], "interfaces": [], "tunnels": [
            {"id": "a-to-b", "device_id": "a", "peer_device_id": "b", "layer": "inner",
             "endpoints": {"local": "0.0.0.1", "remote": "0.0.0.2"}, "observation_ids": ["obs"]}]}
        states = {"a": [[10, 99, 1, 2]], "b": [[20, 99, 1, 2]]}
        policies = {"a": {"out": [[10, 1, 1, 2, 0, 255, 0, 255, 100, 99]]},
                    "b": {"in": [[20, 1, 1, 2, 0, 255, 0, 255, 100, None]]}}
        result = binding_records(snapshot, {}, {}, [], policies, states)
        self.assertEqual(len(result["ipsecTunnelBindings"]), 1)
        binding = result["ipsecTunnelBindings"][0]
        self.assertTrue(binding["senderInstalled"] and binding["receiverInstalled"])
        self.assertEqual(binding["senderPolicies"][0]["id"], 10)
        self.assertEqual(binding["receiverPolicies"][0]["id"], 20)

    def test_retained_configurations_reproduced(self):
        cases = [
            (BASELINE, SUPPLEMENT, "FreshBaselineExecution", True),
            (SNAPSHOTS / "native-shared-four-levels-20261024T015300Z-coverage-v1",
             SNAPSHOTS / "native-shared-processing-20261024T015500Z", "FreshSharedExecution", False),
        ]
        for snapshot, supplement, namespace, epoch_union in cases:
            with self.subTest(namespace=namespace):
                result = parse_execution(snapshot, supplement, epoch_union)
                previous = json.loads((ROOT / "data/evidence" / (namespace + ".json")).read_text())
                keys = {"devices": "devices", "ifaces": "ports", "routes": "routes",
                        "links": "links", "switches": "bridges",
                        "redSources": "redSources", "blackIfaces": "blackIfaces"}
                for original, current in keys.items():
                    self.assertEqual(result[current], previous["TDN.Imported." + namespace + "." + original])
                self.assertFalse(result["scope"]["claimsSimultaneousEpochs"])
                self.assertTrue(result["sourceBindings"])
                observed_mtu = {row["id"]: row["mtu"] for row in result["sourceInterfaces"]}
                self.assertEqual({row["interfaceId"]: row["mtu"] for row in result["ifaceBindings"]},
                                 observed_mtu)
                self.assertTrue(all(row["observationIds"] for row in result["ifaceBindings"]))

    def test_service_requires_processing_supplement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"store": "store", "saved_snapshots": {"baseline": str(BASELINE)}}))
            service = EvidenceService(path)
            try:
                with self.assertRaisesRegex(ValueError, "saved_execution_supplements"):
                    service.prepare_lean_bundle("baseline", "multi_protocol_execution")
            finally:
                service.pool.shutdown(wait=True)

    def test_unknown_supplement_binding_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"store": "store",
                "saved_execution_supplements": {"absent": str(SUPPLEMENT)}}))
            with self.assertRaisesRegex(ValueError, "unknown saved snapshot"):
                EvidenceService(path)

    def test_tampered_supplement_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "supplement"
            shutil.copytree(SUPPLEMENT, target)
            with (target / "observations.json").open("a") as stream:
                stream.write(" ")
            with self.assertRaisesRegex(ValueError, "Supplement hash mismatch"):
                parse_execution(BASELINE, target)

    def test_normalized_mtu_must_match_raw_interface(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "snapshot"
            shutil.copytree(BASELINE, target)
            data_path = target / "snapshot.json"
            snapshot = json.loads(data_path.read_text())
            snapshot["interfaces"][0]["mtu"] += 1
            data_path.write_text(json.dumps(snapshot))
            manifest_path = target / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            for item in manifest["files"]:
                if item["path"] == "snapshot.json":
                    item["sha256"] = hashlib.sha256(data_path.read_bytes()).hexdigest()
                    item["bytes"] = data_path.stat().st_size
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "Interface MTU normalization mismatch"):
                parse_execution(target, SUPPLEMENT)

    def test_unmodeled_policy_routing_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "supplement"
            shutil.copytree(SUPPLEMENT, target)
            data_path = target / "observations.json"
            data = json.loads(data_path.read_text())
            for record in data["records"]:
                if record["kind"] == "policy-routing4":
                    rules = json.loads(record["stdout"])
                    rules[0]["fwmark"] = "0x1"
                    record["stdout"] = json.dumps(rules)
            data_path.write_text(json.dumps(data))
            manifest_path = target / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            for item in manifest["files"]:
                item["sha256"] = hashlib.sha256((target / item["path"]).read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "Nontrivial policy routing"):
                parse_execution(BASELINE, target)


if __name__ == "__main__":
    unittest.main()
