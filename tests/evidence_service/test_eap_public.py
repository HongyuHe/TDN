"""Exercise complete public transcripts and reject inconsistent capture bindings."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from tdn_evidence.eap import parse as correlation
from tdn_evidence.eap_public import parse, detailed_exchange, configured_endpoints
from tdn_evidence.service import EvidenceService


ROOT = Path(__file__).resolve().parents[2]
CAPTURES = Path(__file__).parent / "fixtures/eap-public"
FORWARD = CAPTURES / "eap-tls-forward-v31-full-public-v2"


class EAPPublicTests(unittest.TestCase):
    def setUp(self):
        _, self.report = correlation(FORWARD)

    def test_complete_transcripts_in_both_roles(self):
        fingerprints = []
        for case in sorted(CAPTURES.iterdir()):
            _, report = parse(case)
            exchange = report["exchanges"][0]
            self.assertEqual(len(exchange["clientMessages"]), 10)
            self.assertEqual(exchange["clientMessages"][7]["type"], 25)
            self.assertEqual(len(bytes.fromhex(exchange["deviceNonceHex"])), 32)
            self.assertEqual(exchange["masterSessionKeyBytes"], 64)
            self.assertEqual(exchange["cipherSuite"], 0x1302)
            fingerprints.append(exchange["serverCertificateSha256"])
        self.assertEqual(len(set(fingerprints)), 1)

    def test_incomplete_old_transcript_is_rejected(self):
        report = copy.deepcopy(self.report)
        report['events'] = [e for e in report['events'] if not
            (e['kind'] == 'tls_message' and e['messageType'] == 25) and not
            (e['kind'] == 'public_record' and e['recordType'] == 'TLS_HANDSHAKE' and
             bytes.fromhex(e['hex'])[0] == 25)]
        with self.assertRaisesRegex(ValueError, "Incomplete or unsupported"):
            detailed_exchange(report)

    def test_peer_transcript_difference_is_rejected(self):
        report = copy.deepcopy(self.report)
        record = next(e for e in report["events"] if e["device"] == "AS" and
            e["kind"] == "public_record" and e["recordType"] == "TLS_HANDSHAKE")
        raw = bytearray.fromhex(record["hex"])
        raw[-1] ^= 1
        record["hex"] = raw.hex()
        with self.assertRaisesRegex(ValueError, "TLS peer transcripts differ"):
            detailed_exchange(report)

    def test_wrong_backend_session_is_rejected(self):
        report = copy.deepcopy(self.report)
        record = next(e for e in report["events"] if e["kind"] == "public_record" and
                      e["recordType"] == "RADIUS_RESPONSE")
        raw = bytearray.fromhex(record["hex"])
        offset = 20
        while offset < len(raw):
            kind, size = raw[offset:offset + 2]
            if kind == 102:
                raw[offset + 3] ^= 1
            offset += size
        record["hex"] = raw.hex()
        with self.assertRaisesRegex(ValueError, "EAP-Key-Name"):
            detailed_exchange(report)

    def test_wrong_msk_and_malformed_backend_are_rejected(self):
        report = copy.deepcopy(self.report)
        record = next(e for e in report["events"] if e["kind"] == "reference" and e["title"] == "MSK: ")
        record["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "full MSKs differ"):
            detailed_exchange(report)
        report = copy.deepcopy(self.report)
        record = next(e for e in report["events"] if e["kind"] == "public_record" and
                      e["recordType"] == "RADIUS_REQUEST")
        raw = bytearray.fromhex(record["hex"])
        raw[21] = 0
        record["hex"] = raw.hex()
        with self.assertRaisesRegex(ValueError, "attribute length"):
            detailed_exchange(report)

    def test_service_query_and_immutable_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "config.json"
            config.write_text(json.dumps({"store": "store", "saved_experiments": {
                "eap": {"path": str(FORWARD), "parser": "eap-public-v1"}}}))
            service = EvidenceService(config)
            try:
                self.assertEqual(service.describe_capabilities("eap")["saved_experiment"]["lean_views"],
                                 ["authentication_exchange"])
                self.assertEqual(service.query_evidence("eap", "exchanges")["total"], 1)
                result = service.prepare_lean_bundle("eap", "authentication_exchange")
                self.assertEqual(result, service.prepare_lean_bundle("eap", "authentication_exchange"))
            finally:
                service.pool.shutdown(wait=True)

    def test_configured_backend_must_match_observed_address(self):
        exchange = detailed_exchange(self.report)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ["P0", "P1", "AS"]:
                text = (FORWARD / (name + ".conf.public")).read_text()
                (directory / (name + ".conf.public")).write_text(
                    text.replace("auth_server_addr=10.88.0.2", "auth_server_addr=10.88.0.99"))
            with self.assertRaisesRegex(ValueError, "no observed endpoint"):
                configured_endpoints(directory, self.report, exchange)


if __name__ == "__main__":
    unittest.main()
