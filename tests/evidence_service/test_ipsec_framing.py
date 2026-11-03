"""Check exact BPF recognition and representative IKE/UDP-ESP framing decisions."""
import random
import struct
import unittest
from tdn_evidence.adapters import Unsupported
from tdn_evidence.parsers.ipsec_framing import (
    BYTECODE, BYTECODE_WITH_OPTIONS, PROGRAM_WITH_OPTIONS, canonical,
    canonical_kind, execute, payload_allowed,
)
from tdn_evidence.parsers.packet_policy import parse_rule
from tdn_evidence.projections import atom_json


def packet(port, payload, source_port=40000, ihl=5):
    header = bytes.fromhex('4500000000010000401100000afb00010afb0002')
    header = bytes([0x40 + ihl]) + header[1:] + bytes([1]) * (4 * (ihl - 5))
    total = 4 * ihl + 8 + len(payload)
    header = header[:2] + struct.pack('!H', total) + header[4:]
    return header + struct.pack('!HHHH', source_port, port, len(payload) + 8, 0) + payload


def ike(size=28):
    data = bytearray(size)
    data[17] = 0x20
    data[24:28] = struct.pack('!I', size)
    return bytes(data)


class FramingTests(unittest.TestCase):
    def test_variable_header_program_preserves_old_meaning(self):
        for ihl in range(5, 16):
            for port, payload in [(500, ike()), (4500, bytes(4) + ike()),
                                  (4500, bytes.fromhex('0000000100000001'))]:
                raw = packet(port, payload, ihl=ihl)
                self.assertTrue(execute(raw, PROGRAM_WITH_OPTIONS))
                self.assertEqual(execute(raw), ihl == 5)
        self.assertEqual(canonical_kind(BYTECODE_WITH_OPTIONS), 'ipsecUDPFramingWithOptions')
        self.assertEqual(atom_json({'kind': 'ipsecUDPFramingWithOptions'}), 'ipsecUDPFramingWithOptions')

    def test_variable_header_differential(self):
        rng = random.Random(31028)
        for _ in range(3000):
            body = rng.randbytes(rng.randrange(0, 300))
            if len(body) >= 28 and rng.randrange(2):
                body = body[:17] + b'\x20' + body[18:24] + struct.pack('!I', len(body)) + body[28:]
            if rng.randrange(2):
                body = bytes(4) + body
            port = rng.choice([500, 4500, 501])
            self.assertEqual(execute(packet(port, body, ihl=rng.randrange(5, 16)), PROGRAM_WITH_OPTIONS),
                             payload_allowed(port, body))

    def test_original_counterexample_and_valid_headers(self):
        for port, payload, expected in [(500, b'\xff', False), (4500, b'\xff', False),
                (500, ike(), True), (500, ike(48), True), (4500, bytes(4) + ike(), True),
                (4500, bytes.fromhex('0000000100000001'), True),
                (4500, bytes(8), False), (500, ike() + b'x', False),
                (4500, bytes(4) + ike() + b'x', False), (501, ike(), False)]:
            self.assertEqual(execute(packet(port, payload)), expected)

    def test_raw_header_guards(self):
        good = packet(500, ike())
        for position, value in [(0, 0x46), (0, 0x65), (9, 6), (7, 1), (3, 55), (25, 35)]:
            bad = bytearray(good); bad[position] = value
            self.assertFalse(execute(bytes(bad)))
        self.assertFalse(execute(good[:40]))

    def test_differential_structured_payloads(self):
        rng = random.Random(31021)
        for _ in range(3000):
            size = rng.randrange(0, 500)
            body = bytes(rng.randrange(256) for _ in range(size))
            if size >= 28 and rng.randrange(2):
                body = body[:17] + b'\x20' + body[18:24] + struct.pack('!I', size) + body[28:]
            if rng.randrange(2):
                body = bytes(4) + body
            port = rng.choice([500, 4500, 501])
            self.assertEqual(execute(packet(port, body)), payload_allowed(port, body))

    def test_parser_rejects_changed_or_unbound_program(self):
        rule = {'matches': {'iptables_tokens': ['-p', 'udp', '-m', 'bpf', '--bytecode', BYTECODE]},
            'action': 'accept', 'ordinal': 0, 'raw_text': 'fixture'}
        self.assertIn({'kind': 'ipsecUDPFraming'}, parse_rule(rule)['atoms'])
        self.assertEqual(atom_json({'kind': 'ipsecUDPFraming'}), 'ipsecUDPFraming')
        self.assertTrue(canonical(BYTECODE))
        rule['matches']['iptables_tokens'][-1] = BYTECODE.replace('262144', '0')
        with self.assertRaisesRegex(Unsupported, 'unknown IPsec framing'):
            parse_rule(rule)
        rule['matches']['iptables_tokens'] = ['-m', 'bpf']
        with self.assertRaisesRegex(Unsupported, 'matcher and module'):
            parse_rule(rule)


if __name__ == '__main__':
    unittest.main()
