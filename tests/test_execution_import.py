"""Exercise supported SPD/SAD parsing and reject changes that affect execution meaning."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "construction"))
from import_execution import policy_blocks, state_blocks
from generate_execution_witness import bound
from validate_evidence import EvidenceError


class ExecutionImportTests(unittest.TestCase):
    def setUp(self):
        self.policy = """src 10.1.0.0/24 dst 10.2.0.0/24
 dir out priority 100
 tmpl src 192.0.2.1 dst 192.0.2.2
 proto esp spi 0x1234 reqid 7 mode tunnel
"""
        self.state = """src 192.0.2.1 dst 192.0.2.2
 proto esp spi 0x1234(4660) reqid 7(0x00000007) mode tunnel
 replay-window 32
"""

    def test_policy_keeps_spi_separate_from_request_identifier(self):
        policy = policy_blocks(self.policy, 1)["out"][0]
        self.assertEqual(policy[0], 7)
        self.assertEqual(policy[9], 4660)
        self.assertTrue(bound(policy, state_blocks(self.state)[0]))

    def test_wrong_spi_does_not_satisfy_explicit_template(self):
        policy = policy_blocks(self.policy, 1)["out"][0]
        state = state_blocks(self.state.replace("0x1234(4660)", "0x4321(17185)"))[0]
        self.assertFalse(bound(policy, state))

    def test_same_wire_spi_different_local_request_does_not_bind_locally(self):
        policy = policy_blocks(self.policy, 1)["out"][0]
        state = state_blocks(self.state.replace("reqid 7(0x00000007)", "reqid 8(0x00000008)"))[0]
        self.assertFalse(bound(policy, state))

    def test_required_policy_survives_empty_sa_inventory(self):
        self.assertEqual(len(policy_blocks(self.policy, 1)["out"]), 1)
        self.assertEqual(state_blocks(""), [])

    def test_marked_policy_is_rejected(self):
        with self.assertRaises(EvidenceError):
            policy_blocks(self.policy + " mark 0x1/0xffffffff\n", 1)

    def test_non_tunnel_state_is_rejected(self):
        with self.assertRaises(EvidenceError):
            state_blocks(self.state.replace("mode tunnel", "mode transport"))

    def test_udp_encapsulation_requires_extension(self):
        with self.assertRaises(EvidenceError):
            state_blocks(self.state + " encap type espinudp sport 4500 dport 4500\n")

    def test_inbound_forward_inventory_must_agree(self):
        with self.assertRaises(EvidenceError):
            policy_blocks(self.policy.replace("dir out", "dir in"), 1)

    def test_socket_policy_is_retained_separately(self):
        result = policy_blocks(self.policy + "src 0.0.0.0/0 dst 0.0.0.0/0\n socket out priority 0\n", 1)
        self.assertEqual(len(result["out"]), 1)
        self.assertEqual(len(result["socket"]), 1)


if __name__ == "__main__":
    unittest.main()
