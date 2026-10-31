import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts/construction"))
from source_paths import source_path
from import_domains import validate_declaration,has_figure_six,bind_native_declaration
from validate_evidence import EvidenceError

class DomainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.data=json.loads(source_path("domain_declaration").read_text())
    def test_all_declared_configs(self):self.assertEqual(len(validate_declaration(self.data)),3)
    def test_missing_control_dimension_rejected(self):
        d=copy.deepcopy(self.data);del d["configurations"][0]["security_levels"][0]["other_controls"]
        with self.assertRaises(KeyError):validate_declaration(d)
    def test_shared_inner_across_red_networks_rejected(self):
        d=copy.deepcopy(self.data);c=d["configurations"][0];c["red_networks"][1]["inner_device_ids"]=c["red_networks"][0]["inner_device_ids"]
        with self.assertRaisesRegex(EvidenceError,"shared across"):validate_declaration(d)
    def test_wrong_level_reference_rejected(self):
        d=copy.deepcopy(self.data);d["configurations"][0]["red_networks"][0]["security_level_id"]="UNKNOWN"
        with self.assertRaises(EvidenceError):validate_declaration(d)

class NativeDeclarationTests(unittest.TestCase):
    def test_full_level_controls_required(self):
        levels=[{"classification":"TOP_SECRET","dissemination_controls":[]},{"classification":"SECRET","dissemination_controls":[]}]
        self.assertFalse(has_figure_six(levels))
        levels.extend({"classification":"SECRET","dissemination_controls":[control]} for control in ["US_ONLY","COALITION"])
        self.assertTrue(has_figure_six(levels))

    def test_wrong_manifest_binding_rejected(self):
        bundle=source_path("native_baseline")
        manifest=json.loads((bundle/"manifest.json").read_text());snapshot=json.loads((bundle/"snapshot.json").read_text())
        config=next(c for c in json.loads(source_path("native_declaration").read_text())["configurations"] if c["configuration_id"]==manifest["configuration_id"])
        bind_native_declaration(config,bundle,manifest,snapshot)
        config["snapshot_manifest_sha256"]="0"*64
        with self.assertRaisesRegex(EvidenceError,"manifest binding"):bind_native_declaration(config,bundle,manifest,snapshot)
