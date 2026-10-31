from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parents[1]/"scripts/construction"))
from import_inventory import dns_servers
from validate_evidence import EvidenceError

class ResolverTests(unittest.TestCase):
    def test_literal_inherited_server(self):
        self.assertEqual(str(dns_servers("nameserver 130.127.132.51\nsearch example.test\n")[0]),"130.127.132.51")
    def test_empty_servers_rejected(self):
        with self.assertRaises(EvidenceError):dns_servers("search example.test\n")
    def test_hostname_server_rejected(self):
        with self.assertRaises(ValueError):dns_servers("nameserver dns.example.test\n")
    def test_extra_server_tokens_rejected(self):
        with self.assertRaises(EvidenceError):dns_servers("nameserver 1.1.1.1 unexpected\n")

class SourcePortTests(unittest.TestCase):
    def test_reply_source_port_not_destination(self):
        from import_snapshot import parse_rule
        r=parse_rule({"matches":{"iptables_tokens":["-p","tcp","--sport","8443"]},"action":"accept","ordinal":0,"raw_text":"reply"})
        self.assertIn({"kind":"sourcePorts","values":[8443]},r["atoms"])
        self.assertNotIn({"kind":"destinationPorts","values":[8443]},r["atoms"])
    def test_source_port_range_is_not_silently_broadened(self):
        from import_snapshot import parse_rule,Unsupported
        with self.assertRaises(Unsupported):parse_rule({"matches":{"iptables_tokens":["-p","tcp","--sport","1:65535"]},"action":"accept","ordinal":0,"raw_text":"range"})

class InventoryNamespaceTests(unittest.TestCase):
    def test_cross_namespace_process_attribution_rejected(self):
        import hashlib,json,shutil,tempfile
        from import_inventory import inventory
        from source_paths import source_path
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root=Path(tmp)/"bundle";shutil.copytree(source_path("native_process_inventory"),root)
            path=root/"namespace-processes.json";data=json.loads(path.read_text())
            current=data["processes"][0]["network_namespace"]
            data["processes"][0]["network_namespace"]=next(n for n in data["namespace_owners"] if n!=current)
            path.write_text(json.dumps(data))
            manifest=json.loads((root/"manifest.json").read_text())
            for entry in manifest["files"]:
                content=(root/entry["path"]).read_bytes();entry["sha256"]=hashlib.sha256(content).hexdigest();entry["bytes"]=len(content)
            (root/"manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(EvidenceError,"process namespace association|process scopes"):inventory(root)
