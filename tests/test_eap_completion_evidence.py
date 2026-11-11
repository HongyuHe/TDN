import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp"))
from tdn_evidence import eap_completion, eap_mka

CAPTURES = ROOT / "data/snapshots/2026-11-11T055630Z"


class EapCompletionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "capture"
        shutil.copytree(CAPTURES / "eap-tls-forward-v32-complete-causal", self.bundle)
        self.commands = json.loads((self.bundle / "commands.json").read_text())

    def tearDown(self):
        self.temp.cleanup()

    def save(self):
        path = self.bundle / "commands.json"
        path.write_text(json.dumps(self.commands))
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        entry = next(row for row in manifest["files"] if row["path"] == "commands.json")
        entry.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def log(self, device):
        return next(row for row in self.commands if len(row["command"]) == 2 and
                    row["command"][0] == "cat" and Path(row["command"][1]).name == device + ".log")

    def test_both_peer_roles_have_message_bound_paths(self):
        roles = []
        for path in sorted(path for path in CAPTURES.iterdir() if path.is_dir()):
            _, report = eap_completion.parse(path)
            self.assertEqual(report["projectionVersion"], "eap-complete-causal-v1")
            self.assertEqual(len(report["completion_messages"]), 2)
            self.assertEqual({row["device"] for row in report["completion_bindings"]}, {"P0", "P1"})
            roles.append(report["exchanges"][0]["authenticator"])
            for row in report["completion_bindings"]:
                path = row["sessionToCakPath"]
                self.assertEqual(path[0]["device"], "AS")
                self.assertEqual(path[-1]["device"], row["device"])
                self.assertTrue(any(link["kind"] == "matching_message" and link["before"] in path and
                                    link["after"] in path for link in report["causal_links"]))
        self.assertEqual(set(roles), {"P0", "P1"})

    def test_manifest_change_rejected(self):
        path = self.bundle / "commands.json"
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            eap_completion.parse(self.bundle)

    def test_missing_as_send_rejected(self):
        row = self.log("AS")
        row["stdout"] = "\n".join(line for line in row["stdout"].splitlines()
                                    if "type=RADIUS_RESPONSE_SEND" not in line)
        self.save()
        with self.assertRaisesRegex(ValueError, "Expected one public RADIUS_RESPONSE_SEND"):
            eap_completion.parse(self.bundle)

    def test_wrong_backend_bytes_rejected(self):
        row = self.log("AS")
        lines = row["stdout"].splitlines()
        index = next(i for i, line in enumerate(lines) if "type=RADIUS_RESPONSE_SEND" in line)
        lines[index] = lines[index][:-2] + ("00" if lines[index][-2:] != "00" else "01")
        row["stdout"] = "\n".join(lines)
        self.save()
        with self.assertRaisesRegex(ValueError, "AS response bytes differ"):
            eap_completion.parse(self.bundle)

    def test_partial_success_send_rejected(self):
        row = self.log("P0")
        row["stdout"] = row["stdout"].replace("TDN_EAP_SUCCESS_SEND result=22", "TDN_EAP_SUCCESS_SEND result=21")
        self.save()
        with self.assertRaisesRegex(ValueError, "partial completion-message send"):
            eap_completion.parse(self.bundle)

    def test_missing_wire_success_rejected(self):
        for row in self.commands:
            if len(row["command"]) == 2 and Path(row["command"][1]).name.endswith("headers.log"):
                row["stdout"] = "\n".join(json.dumps(json.loads(line) | {"eap_success_hex": None})
                                          for line in row["stdout"].splitlines())
        self.save()
        with self.assertRaisesRegex(ValueError, "Missing outgoing or incoming EAP-Success"):
            eap_completion.parse(self.bundle)

    def test_clock_order_cannot_replace_missing_message_edge(self):
        _, report = eap_mka.parse(self.bundle)
        _, links, bindings = eap_completion.completion(self.bundle, report)
        binding = bindings[0]
        links = [link for link in links if not (link["kind"] == "matching_message" and
                                               link["before"]["device"] == "AS")]
        with self.assertRaisesRegex(ValueError, "No message/process-order path"):
            eap_completion.causal_path(report["events"], links,
                                      binding["asCompletedSession"], binding["cakDerivation"])

    def test_causal_cycle_rejected(self):
        _, report = eap_completion.parse(self.bundle)
        binding = report["completion_bindings"][0]
        links = copy.deepcopy(report["causal_links"])
        links.append({"kind": "matching_message", "before": binding["cakDerivation"],
                      "after": binding["asCompletedSession"]})
        with self.assertRaisesRegex(ValueError, "form a cycle"):
            eap_completion.causal_path(report["events"], links,
                                      binding["asCompletedSession"], binding["cakDerivation"])


if __name__ == "__main__":
    unittest.main()
