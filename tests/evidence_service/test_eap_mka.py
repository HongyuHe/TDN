"""Check public MKA correspondence and reject unsupported event ordering."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tdn_evidence.eap_mka import parse, causal_mka, frame
from tdn_evidence.eap_public import parse as public_exchange
from tdn_evidence.service import EvidenceService


CAPTURES = Path(__file__).parent / "fixtures/eap-mka"
FORWARD = CAPTURES / "eap-tls-forward-v31-mka-public-v2"


class EAPMKATests(unittest.TestCase):
    def setUp(self):
        _, self.report = public_exchange(FORWARD)

    def test_both_arrangements_bind_messages_to_packets(self):
        for directory in sorted(CAPTURES.iterdir()):
            _, report = parse(directory)
            self.assertGreater(len(report["mka_messages"]), 20)
            self.assertTrue(any(link["kind"] == "matching_message" for link in report["causal_links"]))
            self.assertEqual({entry["event"]["device"] for message in report["mka_messages"]
                              for entry in message["authenticatedReceives"]}, {"P0", "P1"})

    def test_failed_send_is_rejected(self):
        report = copy.deepcopy(self.report)
        next(event for event in report["events"] if event["kind"] == "mka_send_result")["result"] = -1
        with self.assertRaisesRegex(ValueError, "send did not succeed"):
            causal_mka(FORWARD, report)

    def test_missing_peer_send_is_rejected(self):
        report = copy.deepcopy(self.report)
        receive = next(event for event in report["events"] if event.get("recordType") == "MKA_RECEIVE")
        report["events"] = [event for event in report["events"] if not
            (event.get("recordType") == "MKA_SEND" and event["hex"] == receive["hex"])]
        with self.assertRaisesRegex(ValueError, "matching peer send"):
            causal_mka(FORWARD, report)

    def test_wrong_authenticated_frame_is_rejected(self):
        report = copy.deepcopy(self.report)
        event = next(event for event in report["events"] if event.get("recordType") == "MKA_AUTHENTICATED")
        event["hex"] = event["hex"][:-2] + ("00" if event["hex"][-2:] != "00" else "01")
        with self.assertRaisesRegex(ValueError, "matching received frame"):
            causal_mka(FORWARD, report)

    def test_declared_frame_length_must_match_bytes(self):
        event = next(event for event in self.report["events"] if event.get("recordType") == "MKA_SEND")
        with self.assertRaisesRegex(ValueError, "length mismatch"):
            frame(event["hex"] + "00")

    def test_observers_are_required_for_each_received_frame(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            commands = json.loads((FORWARD / "commands.json").read_text())
            for command in commands:
                if len(command["command"]) == 2 and Path(command["command"][1]).name == "P0-headers.log":
                    rows = [json.loads(line) for line in command["stdout"].splitlines()]
                    command["stdout"] = "\n".join(json.dumps(row) for row in rows
                        if row.get("mka_hex") is None or row["pkttype"] == 4)
            (directory / "commands.json").write_text(json.dumps(commands))
            with self.assertRaisesRegex(ValueError, "incoming packet observation"):
                causal_mka(directory, self.report)

    def test_service_exposes_causal_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "config.json"
            config.write_text(json.dumps({"store": "store", "saved_experiments": {
                "eap": {"path": str(FORWARD.resolve()), "parser": "eap-mka-public-v1"}}}))
            service = EvidenceService(config)
            try:
                self.assertGreater(service.query_evidence("eap", "causal_links")["total"], 200)
                result = service.prepare_lean_bundle("eap", "authentication_causal_history")
                self.assertEqual(result, service.prepare_lean_bundle("eap", "authentication_causal_history"))
            finally:
                service.pool.shutdown(wait=True)

    def test_export_order_is_stable_across_processes(self):
        program = "import json,sys;from tdn_evidence.eap_mka import parse;print(json.dumps(parse(sys.argv[1])[1],sort_keys=True))"
        outputs = [subprocess.check_output([sys.executable, "-c", program, str(FORWARD)],
            env=dict(os.environ, PYTHONHASHSEED=seed)) for seed in ["1", "2"]]
        self.assertEqual(*outputs)


if __name__ == "__main__":
    unittest.main()
