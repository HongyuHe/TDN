import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts/construction"))
from source_paths import source_path
from import_events import parse_ike_trace,import_mka
from import_mechanisms import probe_outcome
from validate_evidence import EvidenceError

class EventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        events=json.loads((source_path("ikev2")/"events.json").read_text())
        cls.record=next(r for r in events["records"] if "--initiate" in r["command"])
        cls.text=cls.record["stdout"]
    def test_objective_trace(self):
        parsed=parse_ike_trace(self.text)
        self.assertEqual(parsed["initial_message_bytes"],[312,345])
        self.assertEqual(parsed["fragment_counts"],[2,2,11,11])
        self.assertFalse(parsed["revocation_status_available"])
    def test_swapped_phase_rejected(self):
        lines=self.text.splitlines()
        first=next(i for i,l in enumerate(lines) if "generating IKE_INTERMEDIATE request 1 [ KE ]" in l)
        second=next(i for i,l in enumerate(lines) if "generating IKE_AUTH request 2 [ IDi " in l)
        lines[first],lines[second]=lines[second],lines[first]
        with self.assertRaisesRegex(EvidenceError,"out of order"):parse_ike_trace("\n".join(lines))
    def test_fragment_reordering_is_permitted(self):
        text=self.text.replace("EF(1/11)","EF(TEMP/11)").replace("EF(2/11)","EF(1/11)").replace("EF(TEMP/11)","EF(2/11)")
        self.assertEqual(parse_ike_trace(text)["fragment_counts"],[2,2,11,11])
    def test_missing_encrypted_fragment_rejected(self):
        text="\n".join(l for l in self.text.splitlines() if "generating IKE_INTERMEDIATE request 1 [ EF(2/2) ]" not in l)
        with self.assertRaisesRegex(EvidenceError,"fragment sequence"):parse_ike_trace(text)
    def test_duplicate_ike_proposal_rejected(self):
        line=next(l for l in self.text.splitlines() if "selected proposal: IKE:" in l)
        with self.assertRaisesRegex(EvidenceError,"ambiguous IKE proposal"):parse_ike_trace(self.text+"\n"+line)
    def test_negative_probe_runtime_error_rejected(self):
        command={"command":["ping"],"returncode":2,"stdout":"3 packets transmitted, 0 received","stderr":""}
        with self.assertRaises(EvidenceError):probe_outcome(command)
    def test_negative_probe_missing_summary_rejected(self):
        command={"command":["ping"],"returncode":1,"stdout":"","stderr":""}
        with self.assertRaises(EvidenceError):probe_outcome(command)
    def test_mka_matching_and_mismatched(self):
        positive=import_mka(source_path("mka_matching"))
        negative=import_mka(source_path("mka_mismatched"))
        self.assertEqual(positive["received"],3)
        self.assertEqual(negative["received"],0)
        self.assertTrue(all(p["active_rx_sas"]>0 and p["secured"] for p in positive["peers"]))
        self.assertTrue(all(p["active_rx_sas"]==0 and not p["secured"] and p["icv_rejections"]>0 for p in negative["peers"]))
