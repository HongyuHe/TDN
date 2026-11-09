"""Validate mixed-profile exports and preserve their observation boundaries."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from tdn_evidence.mixed import validated_experiment, execution_values, read_experiment_raw
from tdn_evidence.service import EvidenceService


ROOT = Path(__file__).resolve().parents[2]
PAIRINGS = ROOT / "data/snapshots/2026-10-24T014455Z/pairings-v7"


class MixedProjectionTests(unittest.TestCase):
    def test_all_six_profiles_preserve_retained_configuration(self):
        previous = json.loads((ROOT / "data/evidence/TunnelMatrix_Configs.json").read_text())
        paths = sorted(path for path in PAIRINGS.iterdir() if path.is_dir())
        self.assertEqual(len(paths), 6)
        for path in paths:
            with self.subTest(profile=path.name):
                _, report = validated_experiment(path)
                values = execution_values(report)
                namespace = "TDN.Deployments.Pairing" + "".join(piece.capitalize() for piece in path.name.split("-")[1:])
                for key in ["devices", "ports", "routes", "links", "bridges", "redSources", "grayIfaces", "blackIfaces"]:
                    self.assertEqual(values[key], previous[namespace + "." + ("ifaces" if key == "ports" else key)])
                macs = copy.deepcopy(values["macIfaces"])
                for port in macs:
                    port["transmitAssociation"]["keyGeneration"] = 0
                    for association in port["receiveAssociations"]:
                        association["keyGeneration"] = 0
                self.assertEqual(macs, previous[namespace + ".macIfaces"])
                carriers = copy.deepcopy(values["carriers"])
                for port in carriers:
                    self.assertEqual(port["transmit"].pop("protocol"), "l2tpv3")
                    self.assertEqual(port["transmit"].pop("networkProtocol"), "udp")
                self.assertEqual(carriers, previous[namespace + ".carriers"])
                ids = [key["generationIndex"] for key in values["macsecKeyBindings"]]
                self.assertEqual(len(ids), len(set(ids)))

    def test_service_queries_exports_and_raw_allowlist(self):
        source = PAIRINGS / "layers-macsec-ipsec-standalone"
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"store": "store", "saved_experiments": {
                "mixed": {"path": str(source), "parser": "mixed-protocol-v1"}}}))
            service = EvidenceService(config)
            try:
                self.assertIn("mixed", service.list_networks()["saved"])
                result = service.query_evidence("mixed", "mac_ports", limit=1)
                self.assertEqual(result["total"], 2)
                self.assertEqual(result["next_offset"], 1)
                self.assertIn("linux-netns", result["runtime_backend"])
                observation = result["records"][0]["sources"][0]["id"]
                self.assertIsInstance(service.read_raw("mixed", observation), str)
                first = service.prepare_lean_bundle("mixed", "multi_protocol_execution")
                self.assertEqual(first, service.prepare_lean_bundle("mixed", "multi_protocol_execution"))
                with self.assertRaisesRegex(ValueError, "validated operational capture"):
                    service.read_raw("mixed", "unrelated-provisioning-command")
            finally:
                service.pool.shutdown(wait=True)


if __name__ == "__main__":
    unittest.main()
