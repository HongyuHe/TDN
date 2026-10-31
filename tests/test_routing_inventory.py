import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/construction/evidence'))
from derive_routing_inventory import derive
BASE=ROOT/'artifacts/snapshots/2026-10-24T014455Z'
SOURCE=BASE/'native-all-process-inventory-v3'
BUNDLES=[BASE/'native-baseline-20261024T015000Z',BASE/'native-shared-four-levels-20261024T015300Z-coverage-v1']


class RoutingInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.bundle=Path(self.temp.name)/'inventory'
        shutil.copytree(SOURCE,self.bundle)

    def tearDown(self):
        self.temp.cleanup()

    def read(self,name):
        return json.loads((self.bundle/name).read_text())

    def save(self,name,data):
        (self.bundle/name).write_text(json.dumps(data))
        manifest=self.read('manifest.json')
        for row in manifest['files']:
            body=(self.bundle/row['path']).read_bytes()
            row['sha256']=hashlib.sha256(body).hexdigest()
            row['bytes']=len(body)
        (self.bundle/'manifest.json').write_text(json.dumps(manifest))

    def test_real_inventory(self):
        report=derive(self.bundle,BUNDLES)
        devices=[d for c in report['configurations'] for d in c['encryption_devices']]
        self.assertEqual(len(devices),18)
        self.assertTrue(all(d['all_recorded_programs_recognized'] for d in devices))
        self.assertTrue(all(len(d['recorded_host_processes'])==2 for d in devices))

    def test_new_routing_daemon_is_retained_and_unrecognized(self):
        data=self.read('namespace-processes.json')
        original=next(p for p in data['processes'] if p['device_scopes']==['native-ipsec-baseline:NB_O_A1'])
        data['processes'].append({**original,'host_pid':99999999,'name':'ospfd','command':'/usr/lib/frr/ospfd'})
        self.save('namespace-processes.json',data)
        report=derive(self.bundle,BUNDLES)
        device=next(d for c in report['configurations'] for d in c['encryption_devices'] if d['device_id']=='NB_O_A1')
        self.assertFalse(device['all_recorded_programs_recognized'])
        self.assertIn('ospfd',[p['name'] for p in device['recorded_host_processes']])

    def test_process_scope_mismatch(self):
        data=self.read('namespace-processes.json')
        row=next(p for p in data['processes'] if p['device_scopes']==['native-ipsec-baseline:NB_O_A1'])
        row['network_namespace']='net:[0]'
        self.save('namespace-processes.json',data)
        with self.assertRaisesRegex(ValueError,'namespace attribution'):
            derive(self.bundle,BUNDLES)

    def test_missing_device(self):
        data=self.read('observations.json')
        scope=next(s for s in data['scopes'] if s['configuration_id']=='native-ipsec-baseline')
        scope['devices']=scope['devices'][1:]
        self.save('observations.json',data)
        with self.assertRaisesRegex(ValueError,'inventories differ'):
            derive(self.bundle,BUNDLES)

    def test_unbound_inventory(self):
        data=self.read('observations.json')
        scope=next(s for s in data['scopes'] if s['configuration_id']=='native-ipsec-baseline')
        next(d for d in scope['devices'] if d['device_id']=='NB_O_A1')['inventory']['processes']=[]
        self.save('observations.json',data)
        with self.assertRaisesRegex(ValueError,'raw observation'):
            derive(self.bundle,BUNDLES)

    def test_restart_between_reads(self):
        data=self.read('observations.json')
        scope=next(s for s in data['scopes'] if s['configuration_id']=='native-ipsec-baseline')
        next(d for d in scope['devices'] if d['device_id']=='NB_O_A1')['identity_after']='different'
        self.save('observations.json',data)
        with self.assertRaisesRegex(ValueError,'changed during inventory'):
            derive(self.bundle,BUNDLES)


if __name__=='__main__':
    unittest.main()
