"""Adversarial checks for the untrusted snapshot-to-Lean boundary."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("msc_import", ROOT / "scripts/import_msc_snapshot.py")
IMPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPORTER)


class SnapshotImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.snapshot = self.base / "snapshot"
        shutil.copytree(IMPORTER.CURRENT_EVIDENCE / "snapshot", self.snapshot)
        self.checks = self.base / "check.json"
        shutil.copy(IMPORTER.CURRENT_EVIDENCE / "check.json", self.checks)

    def replace_hashed(self, name, value):
        path = self.snapshot / name
        path.write_text(value)
        manifest_path = self.snapshot / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["sha256"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))

    def replace_spec(self, spec):
        digest = hashlib.sha256(json.dumps(spec, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        self.replace_hashed("spec.json", json.dumps(spec))
        status = json.loads((self.snapshot / "status.json").read_text())
        status["spec_sha256"] = digest
        for device in status["devices"]:
            device["deployed_spec_sha256"] = digest
        self.replace_hashed("status.json", json.dumps(status))
        manifest_path = self.snapshot / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["spec_sha256"] = digest
        manifest_path.write_text(json.dumps(manifest))
        checks = json.loads(self.checks.read_text())
        checks["spec_sha256"] = digest
        self.checks.write_text(json.dumps(checks))

    def test_missing_red_attachment_rejected(self):
        spec = json.loads((self.snapshot / "spec.json").read_text())
        spec["links"] = [link for link in spec["links"]
                         if "R_A1" not in {link["a"]["device"], link["b"]["device"]}]
        self.replace_spec(spec)
        with self.assertRaisesRegex(ValueError, "each Red host requires exactly one"):
            IMPORTER.translate(self.snapshot, self.checks)

    def test_shared_inner_attachment_rejected(self):
        spec = json.loads((self.snapshot / "spec.json").read_text())
        link = next(link for link in spec["links"]
                    if "R_A2" in {link["a"]["device"], link["b"]["device"]})
        endpoint = next(end for end in [link["a"], link["b"]] if end["device"] == "I_A2")
        endpoint["device"] = "I_A1"
        endpoint["interface"] = "shared_red"
        next(d for d in spec["devices"] if d["id"] == "I_A1")["interfaces"].append(
            {"name": "shared_red", "zone": "red", "address": "10.1.2.1/24"})
        self.replace_spec(spec)
        with self.assertRaisesRegex(ValueError, "each inner encryptor requires exactly one"):
            IMPORTER.translate(self.snapshot, self.checks)

    def test_multiple_inner_attachments_rejected_in_either_order(self):
        original = json.loads((self.snapshot / "spec.json").read_text())
        for name, address in [("R_A1", "10.99.1.2/24"), ("I_B1", "10.99.1.1/24")]:
            next(d for d in original["devices"] if d["id"] == name)["interfaces"].append(
                {"name": "extra_red", "zone": "red", "address": address})
        extra = {"a": {"device": "R_A1", "interface": "extra_red"},
                 "b": {"device": "I_B1", "interface": "extra_red"}}
        for position in [0, len(original["links"])]:
            spec = json.loads(json.dumps(original))
            spec["links"].insert(position, extra)
            self.replace_spec(spec)
            with self.subTest(position=position), self.assertRaisesRegex(ValueError, "each Red host requires exactly one"):
                IMPORTER.translate(self.snapshot, self.checks)

    def test_red_ownership_requires_matching_site_and_level(self):
        original = json.loads((self.snapshot / "spec.json").read_text())
        for field, value in [("site", "B"), ("level", "S2")]:
            spec = json.loads(json.dumps(original))
            next(d for d in spec["devices"] if d["id"] == "R_A1")[field] = value
            self.replace_spec(spec)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "share site and security level"):
                IMPORTER.translate(self.snapshot, self.checks)

    def test_authorization_independent_of_cable_order_and_orientation(self):
        expected = IMPORTER.translate(self.snapshot, self.checks, as_data=True)["authorized_pairs"]
        spec = json.loads((self.snapshot / "spec.json").read_text())
        spec["links"].reverse()
        for link in spec["links"]:
            link["a"], link["b"] = link["b"], link["a"]
        self.replace_spec(spec)
        actual = IMPORTER.translate(self.snapshot, self.checks, as_data=True)["authorized_pairs"]
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 4)

    def test_checksum_tampering_rejected(self):
        with (self.snapshot / "spec.json").open("a") as out:
            out.write("\n")
        with self.assertRaisesRegex(ValueError, "checksum"):
            IMPORTER.translate(self.snapshot, self.checks)

    def test_rehashed_observed_drift_rejected(self):
        name = "devices/GF_A/observed.iptables"
        body = (self.snapshot / name).read_text().replace(":FORWARD DROP", ":FORWARD ACCEPT")
        self.replace_hashed(name, body)
        with self.assertRaisesRegex(ValueError, "differ"):
            IMPORTER.translate(self.snapshot, self.checks)

    def test_unsupported_rule_not_silently_ignored(self):
        for kind in ["observed", "intended"]:
            name = f"devices/GF_A/{kind}.iptables"
            body = (self.snapshot / name).read_text().replace("COMMIT", "-A FORWARD -j DROP\nCOMMIT")
            self.replace_hashed(name, body)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            IMPORTER.translate(self.snapshot, self.checks)

    def test_exact_ipv4_header_guard_supported_and_other_u32_rejected(self):
        rule = ':FORWARD DROP [0:0]\n-A FORWARD -m u32 --u32 "{}" -j ACCEPT\n'
        for expression in ['0>>0x18&0xf=0x5', '0x0>>0x18&0xf=0x5', '0>>24&15=5']:
            table = IMPORTER.parse_forward_data(rule.format(expression), 'outer')
            self.assertTrue(table['rules'][0]['noOptions'])
        for expression in ['0>>24&15=6', '0>>24&15=5:15', '0>>24&15=5&&4=0', '4>>24&15=5']:
            with self.subTest(expression=expression), self.assertRaisesRegex(ValueError, 'unsupported u32'):
                IMPORTER.parse_forward_data(rule.format(expression), 'outer')
        for text in [rule.format('0>>24&15=5').replace('-m u32 ', ''),
                     ':FORWARD DROP [0:0]\n-A FORWARD -m u32 -j ACCEPT\n']:
            with self.assertRaisesRegex(ValueError, 'incomplete u32'):
                IMPORTER.parse_forward_data(text, 'outer')

    def test_running_identity_not_relabelled(self):
        status = json.loads((self.snapshot / "status.json").read_text())
        status["devices"][0]["deployed_spec_sha256"] = "different-deployment"
        self.replace_hashed("status.json", json.dumps(status))
        with self.assertRaisesRegex(ValueError, "different specification"):
            IMPORTER.translate(self.snapshot, self.checks)

    def test_missing_sa_observation_remains_unknown(self):
        status = json.loads((self.snapshot / "status.json").read_text())
        inner = next(d for d in status["devices"] if d["device"] == "I_A1")
        inner["facts"].pop("sas")
        inner["errors"] = {"sas": "observation unavailable"}
        self.replace_hashed("status.json", json.dumps(status))
        lean = IMPORTER.translate(self.snapshot, self.checks)
        line = next(line for line in lean.splitlines()
                    if 'device := "I_A1", observedAt' in line and "tunnelEstablished :=" in line)
        self.assertIn("tunnelEstablished := none", line)
        self.assertIn("observation unavailable", line)

    def test_probe_identity_mismatch_rejected(self):
        report = json.loads(self.checks.read_text())
        report["spec_sha256"] = "another-specification"
        self.checks.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "identities differ"):
            IMPORTER.translate(self.snapshot, self.checks, include_management=True)

    def test_probe_flags_require_actual_booleans(self):
        original = self.checks.read_text()
        malformed = ["false", "unknown", "true", "", 1, 0, 1.0, None, [], {}, [True]]
        for location in ["report", "probe"]:
            for value in malformed:
                with self.subTest(location=location, value=value):
                    report = json.loads(original)
                    target = report if location == "report" else report["checks"][0]
                    target["passed"] = value
                    self.checks.write_text(json.dumps(report))
                    with self.assertRaisesRegex(ValueError, "Boolean"):
                        IMPORTER.translate(self.snapshot, self.checks, include_management=True)

    def test_missing_probe_flags_and_invalid_collections_rejected(self):
        original = self.checks.read_text()
        for location in ["report", "probe"]:
            report = json.loads(original)
            target = report if location == "report" else report["checks"][0]
            del target["passed"]
            self.checks.write_text(json.dumps(report))
            with self.subTest(location=location), self.assertRaisesRegex(ValueError, "Boolean"):
                IMPORTER.translate(self.snapshot, self.checks, include_management=True)
        for value in [None, {}, "checks", [True]]:
            report = json.loads(original)
            report["checks"] = value
            self.checks.write_text(json.dumps(report))
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "probe"):
                IMPORTER.translate(self.snapshot, self.checks, include_management=True)

    def test_failed_probe_is_preserved_as_false(self):
        report = json.loads(self.checks.read_text())
        report["passed"] = False
        report["checks"][0]["passed"] = False
        self.checks.write_text(json.dumps(report))
        data = IMPORTER.translate(self.snapshot, self.checks, as_data=True, include_management=True)
        self.assertIs(data["checks_passed"], False)
        self.assertIn("def sampledChecksPassed : Bool :=\nfalse", IMPORTER.translate(self.snapshot, self.checks, include_management=True))

    def test_generation_is_reproducible(self):
        self.assertEqual(IMPORTER.translate(self.snapshot, self.checks),
                         (ROOT / "TDN/MSC/Deployment.lean").read_text())

    def test_retained_missing_evidence_remains_an_error(self):
        for device in ["BLACK", "I_A1", "GF_A"]:
            with self.subTest(device=device):
                relative = f"devices/{device}/observed.iptables"
                manifest_path = self.snapshot / "manifest.json"
                before = manifest_path.read_text()
                manifest = json.loads(before)
                del manifest["sha256"][relative]
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError, "unhashed evidence"):
                    IMPORTER.translate(self.snapshot, self.checks)
                manifest_path.write_text(before)

    def test_historical_generation_remains_explicit_and_strict(self):
        self.assertEqual(IMPORTER.translate(IMPORTER.HISTORICAL_EVIDENCE / "snapshot",
                         IMPORTER.HISTORICAL_EVIDENCE / "check.json", include_management=True),
                         (ROOT / "TDN/MSC/HistoricalDeployment.lean").read_text())
        relative = "devices/AW_A1/observed.iptables"
        self.replace_hashed(relative, (self.snapshot / relative).read_text().replace(
            ":FORWARD DROP", ":FORWARD ACCEPT"))
        IMPORTER.translate(self.snapshot, self.checks)
        with self.assertRaisesRegex(ValueError, "differ"):
            IMPORTER.translate(self.snapshot, self.checks, include_management=True)

    def test_unsupported_wildcard_and_repeated_matches(self):
        rules = [
            "-i red+ -j ACCEPT",
            "-i + -j ACCEPT",
            "-m policy --dir in --pol ipsec --reqid 101 --mode tunnel -m policy --dir out --pol ipsec --reqid 201 --mode tunnel -j ACCEPT",
            "-s 10.0.0.0/8 -s 172.16.0.0/12 -j ACCEPT",
            "-p udp -m udp --dport 500 --dports 4500 -j ACCEPT",
        ]
        for rule in rules:
            with self.subTest(rule=rule), self.assertRaisesRegex(ValueError, "unsupported"):
                IMPORTER.parse_forward_data(":FORWARD DROP [0:0]\n-A FORWARD " + rule, "test")

    def sa_fixture(self):
        spec = json.loads((self.snapshot / "spec.json").read_text())
        status = json.loads((self.snapshot / "status.json").read_text())
        tunnel = next(d["tunnel"] for d in spec["devices"] if d["id"] == "I_A1")
        sa = next(d["facts"]["sas"] for d in status["devices"] if d["device"] == "I_A1")
        return tunnel, sa

    def test_sa_tokens_cannot_mix_sessions(self):
        tunnel, sa = self.sa_fixture()
        connecting = sa.replace("ESTABLISHED", "CONNECTING")
        unrelated = sa.replace("I_A1.msc.test", "unrelated.local").replace("I_B1.msc.test", "unrelated.remote")
        self.assertFalse(IMPORTER.sampled_tunnel_established(connecting + unrelated, "I_A1", tunnel))

    def test_sa_binds_endpoints_selectors_and_child(self):
        tunnel, sa = self.sa_fixture()
        mutations = [
            sa.replace("10.100.1.2[500]", "10.100.99.2[500]"),
            sa.replace("10.1.1.0/24", "192.0.2.0/24"),
            sa.replace("10.2.1.0/24", "198.51.100.0/24"),
            sa.replace("reqid 101,", "reqid 999,"),
            sa.replace("INSTALLED", "INSTALLING"),
            sa.split("    remote")[0],
            sa.replace("    remote 10.2.1.0/24", "  protected: #99, reqid 999, INSTALLED, TUNNEL, ESP:AES_GCM_16-256\n    remote 10.2.1.0/24"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertFalse(IMPORTER.sampled_tunnel_established(mutation, "I_A1", tunnel))
        self.assertTrue(IMPORTER.sampled_tunnel_established(sa, "I_A1", tunnel))
        self.assertTrue(IMPORTER.sampled_tunnel_established(sa.replace("ESTABLISHED", "CONNECTING") + sa, "I_A1", tunnel))

    def test_rehashed_mixed_sa_is_not_imported_as_established(self):
        tunnel, sa = self.sa_fixture()
        status = json.loads((self.snapshot / "status.json").read_text())
        obs = next(d for d in status["devices"] if d["device"] == "I_A1")
        obs["facts"]["sas"] = sa.replace("ESTABLISHED", "CONNECTING") + sa.replace("I_A1.msc.test", "wrong.local")
        self.replace_hashed("status.json", json.dumps(status))
        data = IMPORTER.translate(self.snapshot, self.checks, as_data=True)
        self.assertFalse(data["tunnel_observations"]["I_A1"])

    def test_crypto_parser_rejects_hidden_overrides_and_missing_values(self):
        text = (self.snapshot / "devices/I_A1/intended.swanctl.conf").read_text()
        for mutation in [text + "include other.conf\n", text.replace("  version = 2", "  version = 2\n  version = 1"), text.replace("  over_time = 10m\n", ""), text.replace(" msc {", " msc : defaults {")]:
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "swanctl"):
                IMPORTER.parse_crypto_config(mutation, "I_A1")

    def test_crypto_authentication_fields_preserve_weakened_values(self):
        text = (self.snapshot / "devices/I_A1/intended.swanctl.conf").read_text()
        weakened = text.replace("auth = pubkey", "auth = psk").replace("id = I_B1.msc.test", "id = %any").replace("revocation = strict", "revocation = relaxed")
        config = IMPORTER.parse_crypto_config(weakened, "I_A1")
        self.assertEqual(config["localAuth"], "psk")
        self.assertEqual(config["remoteAuth"], "psk")
        self.assertEqual(config["remoteIdentity"], "%any")
        self.assertEqual(config["revocation"], "relaxed")
        self.assertEqual(config["localCertificate"], "cert.pem")
        self.assertEqual(config["remoteCA"], "ca.pem")

    def test_public_certificate_metadata_retains_all_records(self):
        status = json.loads((self.snapshot / "status.json").read_text())
        text = next(d["facts"]["certificates"] for d in status["devices"] if d["device"] == "I_A1")
        records = IMPORTER.parse_public_certificates(text, "I_A1")
        self.assertEqual(len(records), 3)
        self.assertEqual(sum(c["isCA"] for c in records), 1)
        self.assertEqual(records[0]["altNames"], ["I_A1.msc.test"])
        self.assertTrue(records[0]["hasPrivateKey"])
        self.assertFalse(records[1]["hasPrivateKey"])
        self.assertEqual(records[0]["authorityKeyId"], records[2]["subjectKeyId"])
        extra = text.replace("List of X.509 CRLs", text.split("List of X.509 CA Certificates")[1].split("List of X.509 CRLs")[0] + "List of X.509 CRLs")
        self.assertEqual(len(IMPORTER.parse_public_certificates(extra, "I_A1")), 4)

    def test_public_certificate_parser_rejects_ambiguous_or_malformed_fields(self):
        status = json.loads((self.snapshot / "status.json").read_text())
        text = next(d["facts"]["certificates"] for d in status["devices"] if d["device"] == "I_A1")
        for malformed in ["", text.replace("List of X.509 CA Certificates", "List of X.509 Other Certificates"),
                          text.replace("  keyid:", "  keyid: 00\n  keyid:", 1),
                          text.replace("  issuer:", "  unknown:", 1),
                          text.replace("  keyid:     ", "  keyid:     invalid", 1)]:
            with self.subTest(value=malformed[:60]), self.assertRaisesRegex(ValueError, "certificate"):
                IMPORTER.parse_public_certificates(malformed, "I_A1")

    def test_missing_or_failed_certificate_observation_remains_unknown(self):
        original = (self.snapshot / "status.json").read_text()
        for failure in ["missing", "error"]:
            status = json.loads(original)
            observed = next(d for d in status["devices"] if d["device"] == "I_A1")
            if failure == "missing":
                observed["facts"].pop("certificates")
            else:
                observed.setdefault("errors", {})["certificates"] = "unavailable"
            self.replace_hashed("status.json", json.dumps(status))
            data = IMPORTER.translate(self.snapshot, self.checks, as_data=True)
            inventory = next(c for c in data["certificate_inventories"] if c["device"] == "I_A1")
            self.assertIsNone(inventory["certificates"])


if __name__ == "__main__":
    unittest.main()
