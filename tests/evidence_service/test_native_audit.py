"""Check native audit completeness and keep failed observations unavailable."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from tdn_evidence.native_audit import parse

FIXTURE=Path(__file__).parent/'fixtures/native-component-audit'


def refresh(root):
    p=root/'manifest.json';d=json.loads(p.read_text())
    for r in d['files']:r['sha256']=hashlib.sha256((root/r['path']).read_bytes()).hexdigest()
    p.write_text(json.dumps(d))


class NativeAuditTests(unittest.TestCase):
    def test_inventory_and_key_access(self):
        _,r=parse(FIXTURE)
        self.assertEqual(len(r['accounts']),23)
        self.assertEqual(len(r['observations']),282)
        self.assertEqual(r['unavailable'],[])
        keys=[x for x in r['key_access'] if x['kind']=='private-key-access']
        self.assertEqual(len(keys),8)
        self.assertTrue(all(x['mode']=='600' and x['uid']==0 for x in keys))

    def test_failed_command_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'capture';shutil.copytree(FIXTURE,root)
            p=root/'observations.json';d=json.loads(p.read_text());row=d['records'][0];row.update(returncode=127,stdout='',stderr='missing')
            p.write_text(json.dumps(d));refresh(root)
            _,r=parse(root);self.assertEqual(r['unavailable'][0]['observation'],row['id'])
            self.assertFalse(any(x['observation']==row['id'] for x in r['runtime']))

    def test_missing_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'capture';shutil.copytree(FIXTURE,root)
            p=root/'observations.json';d=json.loads(p.read_text());d['records'].pop();p.write_text(json.dumps(d));refresh(root)
            with self.assertRaisesRegex(ValueError,'Incomplete or duplicate'):parse(root)


if __name__=='__main__':unittest.main()
