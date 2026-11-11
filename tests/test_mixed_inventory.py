import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp"))
from tdn_evidence import mixed
from tdn_evidence.mixed_inventory import parse, read_experiment_raw
from tdn_evidence.service import EvidenceService

SOURCE = ROOT / "data/snapshots/2026-11-01T022125Z/manual-pairings/layers-ipsec-macsec-integrated"


class MixedInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name) / "capture"
        shutil.copytree(SOURCE, self.bundle)

    def tearDown(self):
        self.temp.cleanup()

    def change(self, filename, transform):
        path = self.bundle / filename
        value = json.loads(path.read_text())
        transform(value)
        path.write_text(json.dumps(value))
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        row = next(r for r in manifest["files"] if r["path"] == filename)
        row.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))

    def test_complete_join_preserves_original_packet_configuration(self):
        _, report = parse(self.bundle)
        _, original = mixed.validated_experiment(self.bundle)
        self.assertEqual(report["execution"], mixed.execution_values(original))
        self.assertEqual(len(report["components"]), 7)
        self.assertEqual({d["id"] for d in report["components"] if d["kind"] == "other"}, {"HA", "HB"})
        self.assertFalse(any(d["kind"] == "workstation" for d in report["components"]))
        self.assertEqual(len(report["interfaces"]), 22)
        self.assertEqual(len(report["networks"]), 2)
        self.assertEqual({d["id"] for d in report["components"] if d["infrastructure"]}, {"IA", "IB", "OA", "OB"})
        self.assertTrue(all(len(b["forwardingObservations"]) == 2 for b in report["componentRoleBindings"]
                            if b["infrastructure"]))
        self.assertEqual({s["originDomain"] for s in report["sourceEntries"]}, {1, 2})
        self.assertEqual({s["hostIface"] for s in report["sourceEntries"]}, set(report["execution"]["redSources"]))
        for interface in report["interfaces"]:
            binding = next(b for b in report["interfaceBindings"] if b["interface"] == interface["id"])
            self.assertEqual(interface["mtu"], binding["rawInterface"]["mtu"])
            self.assertEqual(report["ifaceNames"][binding["iface"]], interface["id"])
        self.assertEqual({i["installation"]["direction"] for i in report["installations"]}, {"inbound", "outbound"})
        self.assertEqual(len(report["installations"]), 4)
        self.assertTrue(all(not a["certificateAuth"] and not a["pskAuth"] and not a["authenticationEstablished"]
                            for a in report["authentication"]))
        self.assertEqual([p["file"] for p in report["phases"]], ["stable-before.json", "stable-after.json"])
        self.assertEqual(report["provenance"]["activeIpsecPhase"], "stable-after.json")

    def test_virtual_interfaces_have_explicit_attachment_interpretations(self):
        _, report = parse(self.bundle)
        interfaces = {i["id"]: i for i in report["interfaces"]}
        self.assertEqual(interfaces["OA:macsec0"]["zone"], "black")
        self.assertFalse(interfaces["OA:macsec0"]["physical"])
        self.assertFalse(interfaces["OA:macsec0"]["externalData"])
        self.assertEqual(interfaces["BF:br0"]["zone"], "black")
        self.assertEqual(interfaces["HA:lo"]["zone"], "local")
        self.assertEqual(len(report["macsecPeerEndpoints"]), 2)

    def test_duplicate_declared_device_is_rejected(self):
        self.change("evidence.json", lambda d: d["devices"].append(dict(d["devices"][0])))
        with self.assertRaisesRegex(ValueError, "Duplicate declared device"):
            parse(self.bundle)

    def test_red_host_site_mismatch_is_rejected(self):
        def edit(d):
            next(x for x in d["devices"] if x["id"] == "HA")["site"] = "B"
        self.change("evidence.json", edit)
        with self.assertRaisesRegex(ValueError, "Each site|Red host"):
            parse(self.bundle)

    def test_red_host_level_mismatch_is_rejected(self):
        def edit(d):
            next(x for x in d["devices"] if x["id"] == "HA")["security_level_id"] = "L2"
        self.change("evidence.json", edit)
        with self.assertRaisesRegex(ValueError, "Red host"):
            parse(self.bundle)

    def test_tunnel_endpoint_role_mismatch_is_rejected(self):
        def edit(d):
            next(x for x in d["tunnels"] if x["layer"] == "inner")["endpoints"] = ["IA", "OA"]
        self.change("evidence.json", edit)
        with self.assertRaisesRegex(ValueError, "endpoints"):
            parse(self.bundle)

    def test_authentication_claim_cannot_be_inferred_from_installed_sas(self):
        def edit(d):
            d["tunnels"][0]["authentication"] = "EAP-TLS authenticated"
        self.change("evidence.json", edit)
        with self.assertRaisesRegex(ValueError, "authentication interpretation"):
            parse(self.bundle)

    def test_source_and_phase_files_are_available_as_raw_resources(self):
        self.assertEqual(json.loads(read_experiment_raw(self.bundle, "source-evidence")),
                         json.loads((self.bundle / "evidence.json").read_text()))
        self.assertEqual(json.loads(read_experiment_raw(self.bundle, "phase-after")),
                         json.loads((self.bundle / "stable-after.json").read_text()))
        with self.assertRaisesRegex(ValueError, "outside the joined"):
            read_experiment_raw(self.bundle, "../../private")

    def test_source_hash_mismatch_is_rejected(self):
        (self.bundle / "evidence.json").write_text("{}")
        with self.assertRaises(ValueError):
            parse(self.bundle)

    def test_disabled_transit_forwarding_is_rejected(self):
        phase = json.loads((self.bundle / "stable-before.json").read_text())
        observation = phase["IA"]["bridge_netfilter"]["observation_id"]
        self.change("stable-before.json", lambda d: d["IA"]["bridge_netfilter"].update(
            value=d["IA"]["bridge_netfilter"]["value"].replace("/ipv4/ip_forward=1", "/ipv4/ip_forward=0")))
        def change_command(rows):
            row = next(r for r in rows if r["id"] == observation)
            row["stdout"] = row["stdout"].replace("/ipv4/ip_forward=1", "/ipv4/ip_forward=0")
        self.change("commands.json", change_command)
        with self.assertRaisesRegex(ValueError, "Transit encryptor lacks"):
            parse(self.bundle)

    def test_service_discovers_queries_and_exports_the_join(self):
        config = Path(self.temp.name) / "config.json"
        config.write_text(json.dumps({"store": "store", "saved_experiments": {
            "mixed": {"path": str(self.bundle), "parser": "mixed-deployment-inventory-v1"}}}))
        service = EvidenceService(config)
        try:
            self.assertEqual(service.describe_capabilities("mixed")["saved_experiment"]["lean_views"],
                             ["mixed_deployment_inventory"])
            self.assertEqual(service.query_evidence("mixed", "components")["total"], 7)
            first = service.prepare_lean_bundle("mixed", "mixed_deployment_inventory")
            self.assertEqual(first, service.prepare_lean_bundle("mixed", "mixed_deployment_inventory"))
        finally:
            service.pool.shutdown(wait=True)


if __name__ == "__main__":
    unittest.main()
