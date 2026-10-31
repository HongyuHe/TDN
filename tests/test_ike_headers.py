import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts/construction"))
from source_paths import source_path
from import_ike_headers import validate_headers
from validate_evidence import EvidenceError

class IKEHeaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        records=json.loads((source_path("ikev2_headers")/"events.json").read_text())["records"]
        capture=next(r for r in records if r["command"][-1:]==["/tmp/ike-headers.jsonl"] and "cat" in r["command"])
        cls.rows=[json.loads(l) for l in capture["stdout"].splitlines()]
        cls.peers=sorted({r["source"] for r in cls.rows})
    def test_actual_complete_headers(self):
        validate_headers(self.rows,1500,self.peers)
    def test_ip_fragment_rejected(self):
        rows=copy.deepcopy(self.rows);rows[0]["more_fragments"]=True
        with self.assertRaisesRegex(EvidenceError,"fragmentation"):validate_headers(rows,1500,self.peers)
    def test_pmtu_too_small(self):
        with self.assertRaisesRegex(EvidenceError,"path bound"):validate_headers(self.rows,1200,self.peers)
    def test_mixed_sa_rejected(self):
        rows=copy.deepcopy(self.rows);rows[-1]["ike_initiator_spi"]="abcdef0123456789"
        with self.assertRaisesRegex(EvidenceError,"mixes distinct"):validate_headers(rows,1500,self.peers)
    def test_missing_fragment_rejected(self):
        rows=copy.deepcopy(self.rows);rows.pop(2)
        with self.assertRaisesRegex(EvidenceError,"incomplete"):validate_headers(rows,1500,self.peers)
