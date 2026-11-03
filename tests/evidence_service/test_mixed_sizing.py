"""Check sizing fields against selected actual MACsec, carrier and ESP bytes."""
import json
from pathlib import Path
import unittest

from tdn_evidence.mixed_sizing import frame_fields, drop_counters

FIXTURE = Path(__file__).parent / 'fixtures/mixed-sizing-frames.json'


class MixedSizingTests(unittest.TestCase):
    def test_actual_boundary_encodings(self):
        frames = {r['device']: frame_fields(bytes.fromhex(r['frame_hex']))
                  for r in json.loads(FIXTURE.read_text())['frames']}
        self.assertEqual(frames['IA']['frame_bytes'], 1406)
        self.assertTrue(frames['IA']['macsec']['sciPresent'])
        self.assertEqual(frames['IA']['macsec']['secTagBytes'], 14)
        self.assertEqual(frames['EA']['ip_bytes'], 1446)
        self.assertEqual(frames['EA']['udp']['destinationPort'], 1701)
        self.assertEqual(frames['OA']['ip_bytes'], 1500)
        self.assertEqual(frames['OA']['protocol'], 50)
        self.assertFalse(frames['OA']['mf'])
        self.assertEqual(frames['OA']['fragment_offset'], 0)

    def test_truncated_ipv4_and_macsec_rejected(self):
        for row in json.loads(FIXTURE.read_text())['frames']:
            with self.assertRaises(ValueError):
                frame_fields(bytes.fromhex(row['frame_hex'])[:18])

    def test_drop_rule_identity_preserved(self):
        text = '[2:2722] -A FORWARD -o macsec0 -m length --length 1361:65535 -j DROP\n'
        self.assertEqual(drop_counters(text), {
            '-A FORWARD -o macsec0 -m length --length 1361:65535 -j DROP': (2, 2722)})


if __name__ == '__main__':
    unittest.main()
