"""Check that sizing results preserve source errors and actual fragment bytes."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tdn_evidence.sizing import parse


CAPTURE = Path(__file__).parent / 'fixtures/native-sizing'


class NativeSizingTests(unittest.TestCase):
    def changed(self, update):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'capture'
            shutil.copytree(CAPTURE, directory)
            update(directory)
            manifest = json.loads((directory / 'manifest.json').read_text())
            for row in manifest['files']:
                raw = (directory / row['path']).read_bytes()
                row.update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
            (directory / 'manifest.json').write_text(json.dumps(manifest))
            return parse(directory)

    def test_actual_df_error_and_fragmentation(self):
        _, report = parse(CAPTURE)
        self.assertEqual(len(report['packets']), 152)
        self.assertEqual([case['result'] for case in report['cases']], [0, 1, 0, 0, 0])
        self.assertEqual(report['cases'][1]['packetIds'], [])
        self.assertIn('V31B_I_A1:gray', report['cases'][3]['fragmentedPorts'])
        self.assertIn('V31B_O_A1:black', report['cases'][3]['fragmentedPorts'])

    def test_changed_fragment_flag_rejected(self):
        def update(directory):
            path = directory / 'V31B_I_A1--gray.jsonl'
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            next(row for row in rows if row.get('mf'))['mf'] = False
            path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n')
        with self.assertRaisesRegex(ValueError, 'metadata differs from bytes'):
            self.changed(update)

    def test_repaired_admission_binds_reassembled_lengths(self):
        _, report = parse(CAPTURE.with_name('native-sizing-repaired'))
        self.assertEqual([c['outcome'] for c in report['cases']], ['successful_reply', 'local_size_error',
            'no_reply_with_observed_drops', 'no_reply_with_observed_drops', 'successful_reply'])
        for case in report['cases'][2:4]:
            dropped = case['dropCounterChanges']
            self.assertEqual(len(dropped), 1)
            self.assertEqual(dropped[0]['packets'], 2)
            self.assertEqual(dropped[0]['bytes'], 2 * case['source_ip_bytes'])
            selected = [p for p in report['packets'] if p['id'] in case['packetIds']]
            self.assertTrue(all(p['interface'] == 'red' for p in selected if p['mf'] or p['fragment_offset']))
            self.assertTrue(all(p['ip_bytes'] < case['source_ip_bytes'] for p in selected if p['interface'] != 'red'))

    def test_changed_probe_size_rejected(self):
        def update(directory):
            path = directory / 'cases.json'
            value = json.loads(path.read_text())
            value['cases'][0]['source_ip_bytes'] += 1
            path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'size or interval'):
            self.changed(update)

    def test_missing_capture_rejected(self):
        def update(directory):
            path = directory / 'V31B_R_A1--red.jsonl'
            path.write_text(path.read_text().splitlines()[0] + '\n')
        with self.assertRaisesRegex(ValueError, 'lacks actual traffic'):
            self.changed(update)


if __name__ == '__main__':
    unittest.main()
