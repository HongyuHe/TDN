import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts/construction"))
from loaded_policy import parse_configuration,proposal_modes,immediate_sections
from validate_evidence import EvidenceError

class LoadedPolicyTests(unittest.TestCase):
    def test_explicit_gcm_and_cbc_hmac(self):
        self.assertEqual(proposal_modes("aes256gcm16-ecp384,aes256-sha384-ecp384",True),[{"mode":"gcm","hmac":False},{"mode":"cbc","hmac":True}])
    def test_no_default_expansion(self):
        for value in [None,"", "default","aes256gcm16-default"]:
            with self.assertRaises(EvidenceError):proposal_modes(value,True)
    def test_missing_integrity(self):
        with self.assertRaises(EvidenceError):proposal_modes("aes256-ecp384",True)
    def test_unknown_algorithm(self):
        with self.assertRaises(EvidenceError):proposal_modes("chacha20poly1305-ecp384",True)
    def test_no_hidden_include(self):
        with self.assertRaises(EvidenceError):parse_configuration("include other.conf")
    def test_runtime_all_children(self):
        self.assertEqual(immediate_sections("protected {local_ts=[a]} bypass {local_ts=[b]}"),["protected","bypass"])
