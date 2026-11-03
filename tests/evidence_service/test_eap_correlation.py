"""Check authentic captured exchanges and reject broken cross-event bindings."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tdn_evidence.eap import parse
from tdn_evidence.service import EvidenceService


ROOT = Path(__file__).resolve().parents[2]
CAPTURE = Path(__file__).parent / "fixtures/eap-public"
FORWARD = CAPTURE / "eap-tls-forward-v31-full-public-v2"


def replace_commands(directory, transform):
    path = directory / "commands.json"
    records = json.loads(path.read_text())
    transform(records)
    path.write_text(json.dumps(records, indent=2) + "\n")
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    record = next(row for row in manifest["files"] if row["path"] == "commands.json")
    record.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


class EAPCorrelationTests(unittest.TestCase):
    def test_both_role_arrangements_have_bound_transmissions(self):
        for case in sorted(CAPTURE.iterdir()):
            with self.subTest(case=case.name):
                _, report = parse(case)
                auth = report["authentication"][0]
                self.assertEqual(len(auth["peers"]), 2)
                self.assertEqual(len({p["cakSha256"] for p in auth["peers"]}), 1)
                self.assertTrue(report["wire_frames"])
                self.assertTrue(any("no separate client TLS" in line for line in report["scope"]))

    def test_rejects_different_session_even_with_new_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "capture"
            shutil.copytree(FORWARD, directory)
            def mutate(records):
                for record in records:
                    if record["command"][0] == "cat" and record["command"][-1].endswith("/AS.log"):
                        lines = record["stdout"].splitlines()
                        record["stdout"] = "\n".join(line.rsplit("digest=", 1)[0] + "digest=" + "0" * 64
                            if "TDN_REF title=TDN_EAP_SESSION" in line else line for line in lines)
            replace_commands(directory, mutate)
            with self.assertRaisesRegex(ValueError, "session identifiers disagree"):
                parse(directory)

    def test_rejects_unbound_wire_association_even_with_new_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "capture"
            shutil.copytree(FORWARD, directory)
            def mutate(records):
                for record in records:
                    if record["command"][0] == "cat" and record["command"][-1].endswith("-headers.log"):
                        rows = [json.loads(line) for line in record["stdout"].splitlines()]
                        for row in rows:
                            if row["ethertype"] == "88e5":
                                row["macsec_an"] = 3
                        record["stdout"] = "\n".join(json.dumps(row) for row in rows)
            replace_commands(directory, mutate)
            with self.assertRaisesRegex(ValueError, "No bound encrypted transmission"):
                parse(directory)

    def test_service_exposes_authentication_view_and_limits_raw_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "config.json"
            config.write_text(json.dumps({"store": "store", "saved_experiments": {
                "eap": {"path": str(FORWARD), "parser": "eap-correlation-v1"}}}))
            service = EvidenceService(config)
            try:
                self.assertEqual(service.describe_capabilities("eap")["saved_experiment"]["lean_views"],
                                 ["authentication_correlation"])
                self.assertEqual(service.collection_status("eap")["status"], "complete")
                self.assertEqual(service.query_evidence("eap", "authentication")["total"], 1)
                result = service.prepare_lean_bundle("eap", "authentication_correlation")
                self.assertEqual(result, service.prepare_lean_bundle("eap", "authentication_correlation"))
                with self.assertRaisesRegex(ValueError, "validated authentication capture"):
                    service.read_raw("eap", "cmd-0000")
                with self.assertRaisesRegex(ValueError, "authentication_correlation"):
                    service.prepare_lean_bundle("eap", "multi_protocol_execution")
            finally:
                service.pool.shutdown(wait=True)


if __name__ == "__main__":
    unittest.main()
