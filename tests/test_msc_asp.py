"""Check solver semantics, real counterexamples, and readable fact round trips."""

import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
HAS_CLINGO = importlib.util.find_spec("clingo") is not None
if HAS_CLINGO:
    import clingo
    import run_msc_asp as asp


@unittest.skipUnless(HAS_CLINGO, "run with .venv-asp/bin/python for clingo")
class ASPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.facts, cls.cases, _, _ = asp.prepare()

    def evaluate(self, mutation=None, edit=None, suffix=""):
        facts, cases = self.facts, self.cases
        if mutation:
            facts, cases, _, _ = asp.prepare(mutation=mutation)
        program = asp.MODEL / "msc.lp"
        if edit:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            folder = Path(temporary.name) / "model"
            shutil.copytree(asp.MODEL, folder)
            filename, old, new = edit
            path = folder / filename
            source = path.read_text()
            self.assertIn(old, source)
            path.write_text(source.replace(old, new))
            program = folder / "msc.lp"
        return asp.evaluate(facts + suffix, cases, program=program)

    def failures(self, result):
        return {c["name"] for c in result["checks"] if c["status"] == "fail"}

    def test_baseline_has_one_model_and_46_unsat_counterexample_queries(self):
        result = self.evaluate()
        self.assertEqual(result["base_stable_models"], 1)
        self.assertEqual(len(result["checks"]), 46)
        self.assertTrue(all(c["counterexample_query"] == "UNSAT" for c in result["checks"]))
        self.assertEqual(result["statistics"]["states"], 512)
        self.assertEqual(result["statistics"]["transmitted"], 4)
        self.assertEqual(result["statistics"]["delivered"], 32)
        self.assertIn(["unknown", "unknown-device", "unknown"], result["relations"]["decision"])

    def test_gray_bypass_produces_sat_path_counterexample(self):
        result = self.evaluate("gray-bypass")
        self.assertTrue({"site_a_gray_cut", "no_cross_level_gray_bypass"} <= self.failures(result))
        query = next(c for c in result["checks"] if c["name"] == "site_a_gray_cut")
        self.assertEqual(query["counterexample_query"], "SAT")
        self.assertEqual(query["witnesses"], [["site_a_gray_cut", "I_A1", "I_A2"]])
        self.assertIn(["I_A1", "I_A2"], result["relations"]["gray_reach"])

    def test_unguarded_encryptor_admits_untagged_case(self):
        result = self.evaluate("unguarded-encryptor")
        self.assertIn("encryptor_without_policy_drops", self.failures(result))
        self.assertIn(["I_A1:0:untagged", "I_A1", "accept"], result["relations"]["decision"])

    def test_gray_default_accept_fails_deny_all(self):
        self.assertIn("gray_firewall_denies_all", self.failures(self.evaluate("gray-default-accept")))

    def test_cross_level_authorization_exposes_delivery(self):
        result = self.evaluate("cross-level-authorization")
        self.assertIn("cross_level_not_delivered", self.failures(result))
        self.assertIn(["511", "511", "R_A1", "R_B2"], result["relations"]["delivered"])

    def test_unknown_observation_does_not_change_hypothetical_states(self):
        result = self.evaluate("missing-sa")
        self.assertEqual(self.failures(result), {"sampled_tunnels_established"})
        self.assertEqual(len(result["relations"]["delivered"]), 32)

    def test_missing_outer_transition_guard_is_detected(self):
        result = self.evaluate(edit=("flow.lp",
            "outer_encrypted(S,A,B) :- inner_encrypted(S,A,B), outer_send_ready(S).",
            "outer_encrypted(S,A,B) :- inner_encrypted(S,A,B)."))
        self.assertTrue({"outer_failure_closed", "outer_authentication_failure_closed",
                         "outer_policy_loss_closed", "transport_failure_blocks"} <= self.failures(result))

    def test_receiver_inner_guard_bypass_is_detected(self):
        result = self.evaluate(edit=("flow.lp",
            "inner_decrypted(S,R,A,B) :- outer_decrypted(S,R,A,B), inner_ready(R).",
            "inner_decrypted(S,R,A,B) :- outer_decrypted(S,R,A,B)."))
        self.assertIn("receiver_inner_failure_closed", self.failures(result))

    def test_inconsistent_base_is_an_error_not_a_proof(self):
        with self.assertRaisesRegex(ValueError, "exactly one complete stable model"):
            self.evaluate(suffix="\n:- node(\"I_A1\").\n")

    def test_multiple_base_models_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one complete stable model"):
            self.evaluate(suffix="\n{unreviewed_choice}.\n")

    def test_incomplete_state_domain_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "state or host domain"):
            self.evaluate(edit=("flow.lp", "bit(0;1).", "bit(1)."))

    def test_ipv4_terms_preserve_unsigned_order_across_octets(self):
        addresses = [0, 255, 256, 65535, 65536, 2**31 - 1, 2**31, 2**32 - 1]
        symbols = [clingo.parse_term(asp.ipv4(n)) for n in addresses]
        self.assertEqual(symbols, sorted(symbols))
        self.assertEqual(str(symbols[-1]), "ipv4(255,255,255,255)")
        self.assertEqual(asp.tag(0), "some(0)")
        self.assertEqual(asp.tag(-1), "none")

    def test_fact_syntax_and_export_are_reproducible(self):
        facts, cases, _, _ = asp.prepare()
        self.assertEqual((facts, cases), (self.facts, self.cases))
        self.assertIn('device("I_A1", inner, "A", "S1").', facts)
        self.assertIn('requires_policy("I_A1", 0, out, 101).', facts)
        for path, body in [("facts.lp", facts), ("packet_cases.lp", cases)]:
            checked_in = ROOT / "artifacts/msc-node1-asp" / path
            if checked_in.exists():
                self.assertEqual(checked_in.read_text(), body)


if __name__ == "__main__":
    unittest.main()
