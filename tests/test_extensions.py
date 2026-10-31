import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parents[1]/"scripts/construction"))
from import_extensions import decode_bridge_http,import_eap
from source_paths import source_path
from validate_evidence import EvidenceError

class ExtensionTests(unittest.TestCase):
    def observed_filter(self):
        records=json.loads((source_path("http_crl")/"commands.json").read_text())
        return next(r["stdout"] for r in records if r["command"][-3:]==["ebtables","-L","--Lc"])

    def test_broadened_http_exception_is_rejected(self):
        text=self.observed_filter();decode_bridge_http(text)
        with self.assertRaisesRegex(EvidenceError,"broader or unsupported"):
            decode_bridge_http(text.replace("--ip-dport 80 ",""))

    def test_wrong_http_response_peer_is_rejected(self):
        text=self.observed_filter().replace("--ip-src 10.12.0.2 --ip-dst 10.11.0.1","--ip-src 10.12.0.3 --ip-dst 10.11.0.1")
        with self.assertRaisesRegex(EvidenceError,"response endpoint"):
            decode_bridge_http(text)

    def test_eap_success_retains_missing_data_channel(self):
        report=import_eap("eap_forward_v4")
        self.assertTrue(report["authentication_success"])
        self.assertEqual(report["experiment_error"],"No MACsec interface at P0")
        self.assertGreater(len(report["event_observations"]),4)
        self.assertTrue(any(s["macsec_interfaces"] for s in report["interface_observations"]))
        reverse=import_eap("eap_reverse_v4")
        self.assertEqual(reverse["data_probe_status"],"runtime_error")

if __name__=="__main__":unittest.main()
