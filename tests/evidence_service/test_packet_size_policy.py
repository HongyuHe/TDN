"""Preserve exact length-match bounds and reject unsupported variants."""
import unittest

from tdn_evidence.adapters import Unsupported
from tdn_evidence.parsers.packet_policy import parse_rule
from tdn_evidence.parsers.native_nft import actual_conditions, expected_conditions
from tdn_evidence.projections import atom_json


def rule(tokens):
    return {'matches': {'iptables_tokens': tokens}, 'action': 'drop', 'ordinal': 1, 'raw_text': 'recorded length rule'}


class PacketSizePolicyTests(unittest.TestCase):
    def test_literal_limit_and_native_matcher(self):
        source = rule(['-o', 'gray', '-m', 'length', '--length', '1321:65535'])
        parsed = parse_rule(source)
        self.assertEqual(atom_json(parsed['atoms'][1]), {'networkBytesRange': {'low': 1321, 'high': 65535}})
        expressions = [{'match': {'op': '==', 'left': {'meta': {'key': 'oifname'}}, 'right': 'gray'}},
            {'xt': {'type': 'match', 'name': 'length'}}, {'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]
        self.assertEqual(actual_conditions(expressions, 'drop'), expected_conditions(source))

    def test_unsupported_or_unbound_length_is_rejected(self):
        for tokens in [['--length', '1321:65535'], ['-m', 'length'],
            ['-m', 'length', '--length', '65536:70000'], ['-m', 'length', '--length', '1400:1320'],
            ['-m', 'length', '--length', '1321']]:
            with self.subTest(tokens=tokens), self.assertRaises(Unsupported):
                parse_rule(rule(tokens))


if __name__ == '__main__':
    unittest.main()
