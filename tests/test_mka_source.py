from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parents[1]/"scripts/construction"))
from import_mka_audit import source_parameters
from source_paths import source_path
from validate_evidence import EvidenceError

class MKASourceTests(unittest.TestCase):
    def test_changed_delay_comparison_rejected(self):
        root=source_path("mka_audit");header=(root/"ieee802_1x_kay.h").read_text();source=(root/"ieee802_1x_kay.c").read_text()
        with self.assertRaisesRegex(EvidenceError,"delay flag expression"):source_parameters(header,source.replace("kay->mka_hello_time <= MKA_BOUNDED_HELLO_TIME","kay->mka_hello_time >= MKA_BOUNDED_HELLO_TIME"))
    def test_added_delay_assignment_rejected(self):
        root=source_path("mka_audit")
        with self.assertRaisesRegex(EvidenceError,"additional delay flag"):source_parameters((root/"ieee802_1x_kay.h").read_text(),(root/"ieee802_1x_kay.c").read_text()+"\nbody->delay_protect = true;\n")
