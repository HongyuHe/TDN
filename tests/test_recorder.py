import json
from pathlib import Path
import subprocess
import tempfile
import unittest

class RecorderTests(unittest.TestCase):
    def test_nested_history_referenced_without_recursive_copy(self):
        recorder=Path(__file__).resolve().parents[1]/"scripts/construction/record.py"
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root=Path(tmp).resolve();nested=root/"outputs/portable/history";nested.mkdir(parents=True)
            (nested/"prior.json").write_text('{"checkpoint":"prior"}')
            (nested/"prior").mkdir();(nested/"prior/old.lean").write_text("def old := 1")
            (root/"outputs/current.lean").write_text("def current := 2")
            run=subprocess.run([sys.executable,str(recorder),"checkpoint","--actor","test","--label","nested","--reason","nested history regression","--paths","outputs"],cwd=root,capture_output=True,text=True,check=True)
            record=json.loads((root/run.stdout.strip()).read_text())
            self.assertEqual([f["path"] for f in record["files"]],["outputs/current.lean"])
            self.assertEqual(record["history_references"][0]["record_manifests"][0]["path"],"outputs/portable/history/prior.json")
            self.assertTrue((nested/"prior/old.lean").exists())

import sys
