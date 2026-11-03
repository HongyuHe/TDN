"""Reject session metadata that disagrees with observed packets or conntrack."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tdn_evidence.management import parse
from tdn_evidence.service import EvidenceService


CAPTURE = Path(__file__).parent / 'fixtures/management-session'


def rewrite(directory, transform):
    commands = json.loads((directory / 'commands.json').read_text())
    transform(directory, commands)
    (directory / 'commands.json').write_text(json.dumps(commands))
    path = directory / 'manifest.json'
    manifest = json.loads(path.read_text())
    for row in manifest['files']:
        file = directory / row['path']
        row.update(sha256=hashlib.sha256(file.read_bytes()).hexdigest(), bytes=file.stat().st_size)
    path.write_text(json.dumps(manifest))


class ManagementSessionTests(unittest.TestCase):
    def mutated(self, change):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'capture'
            shutil.copytree(CAPTURE, directory)
            rewrite(directory, change)
            return parse(directory)

    def test_actual_request_reply_and_negative_attempts(self):
        _, report = parse(CAPTURE)
        session = report['sessions'][0]
        self.assertEqual((session['initiator'], session['responder']), ('AW', 'OUTER'))
        self.assertEqual(len(report['packets']), 36)
        self.assertEqual(len(session['replies']), 8)
        self.assertTrue(all(session['request']['monotonicNs'] < p['monotonicNs'] for p in session['replies']))
        self.assertEqual([(p['dropBefore'], p['dropAfter']) for p in report['probes']], [(0, 1), (1, 2)])

    def test_false_conntrack_initiator_is_rejected(self):
        def change(directory, commands):
            path = directory / 'established.json'
            phase = json.loads(path.read_text())
            observed = phase['OUTER']['conntrack']
            observed['stdout'] = observed['stdout'].replace('src=10.31.0.1 dst=10.31.0.2', 'src=10.31.0.2 dst=10.31.0.1')
            next(c for c in commands if c['id'] == observed['id'])['stdout'] = observed['stdout']
            path.write_text(json.dumps(phase))
        with self.assertRaisesRegex(ValueError, 'original/reply tuple'):
            self.mutated(change)

    def test_reply_without_request_is_rejected(self):
        def change(directory, commands):
            path = directory / 'capture-AW.jsonl'
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            rows = [r for r in rows if 'frame_hex' not in r or
                    bytes.fromhex(r['frame_hex'])[47] & 0x12 != 2]
            text = '\n'.join(json.dumps(r) for r in rows) + '\n'
            path.write_text(text)
            next(c for c in commands if c['command'][0] == 'cat' and
                 Path(c['command'][-1]).name == path.name)['stdout'] = text
        with self.assertRaisesRegex(ValueError, 'one AW connection request'):
            self.mutated(change)

    def test_false_application_tuple_is_rejected(self):
        def change(directory, commands):
            path = directory / 'client.jsonl'
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            rows[0]['local'][1] = 41001
            text = '\n'.join(json.dumps(r) for r in rows) + '\n'
            path.write_text(text)
            next(c for c in commands if c['command'][0] == 'cat' and
                 Path(c['command'][-1]).name == path.name)['stdout'] = text
        with self.assertRaisesRegex(ValueError, 'Application tuple/order'):
            self.mutated(change)

    def test_service_export_and_raw_observation_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / 'config.json'
            config.write_text(json.dumps({'store': 'store', 'saved_experiments': {
                'management': {'path': str(CAPTURE.resolve()), 'parser': 'management-session-v1'}}}))
            service = EvidenceService(config)
            try:
                self.assertEqual(service.query_evidence('management', 'sessions')['total'], 1)
                exported = service.prepare_lean_bundle('management', 'management_sessions')
                self.assertEqual(exported, service.prepare_lean_bundle('management', 'management_sessions'))
                with self.assertRaisesRegex(ValueError, 'outside the validated'):
                    service.read_raw('management', 'cmd-0000')
            finally:
                service.pool.shutdown(wait=True)


if __name__ == '__main__':
    unittest.main()
