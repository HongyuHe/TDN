import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).parents[1]/"scripts/construction"))
from source_paths import source_path
from analyze_topology import analyze, components, raw_interface_kind, verify_peer_namespace, inactive_fallback, adjacency_projection
from validate_evidence import EvidenceError

class TopologyTests(unittest.TestCase):
    def mutate_bundle(self,mutation,message,source_key="adjacency"):
        source=source_path(source_key)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            root=Path(temp)/"bundle"
            shutil.copytree(source,root)
            snapshot=json.loads((root/"snapshot.json").read_text())
            mutation(snapshot)
            (root/"snapshot.json").write_text(json.dumps(snapshot))
            manifest=json.loads((root/"manifest.json").read_text())
            for entry in manifest["files"]:
                if entry["path"]=="snapshot.json":
                    entry["sha256"]=hashlib.sha256((root/"snapshot.json").read_bytes()).hexdigest()
                    entry["bytes"]=(root/"snapshot.json").stat().st_size
            (root/"manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(EvidenceError,message):
                analyze(root,Path(temp)/"out.lean",Path(temp)/"report.json")

    def test_changed_veth_to_loopback_rejected(self):
        def mutate(snapshot):
            next(i for i in snapshot["interfaces"] if i["link_kind"]=="veth")["link_kind"]="loopback"
        self.mutate_bundle(mutate,"kind differs")

    def test_missing_veth_link_rejected(self):
        def mutate(snapshot):
            snapshot["links"]=[l for l in snapshot["links"] if l["id"]!="link-000"]
        self.mutate_bundle(mutate,"cover every observed veth")

    def test_unknown_raw_interface_kind_rejected(self):
        with self.assertRaisesRegex(EvidenceError,"unsupported raw"):
            raw_interface_kind({"ifname":"hidden","link_type":"ether","linkinfo":{"info_kind":"vxlan"}})

    def test_namespace_ifindex_collision_rejected(self):
        a={"ifindex":10,"link_index":11,"link_netnsid":2}
        b={"ifindex":11,"link_index":10,"link_netnsid":3}
        pids={"A":100,"B":200,"C":300}
        aliases={"alias-A":100,"alias-B":200,"alias-C":300}
        wrong={"A":{2:"alias-C"},"B":{3:"alias-A"}}
        with self.assertRaisesRegex(EvidenceError,"peer namespace"):
            verify_peer_namespace(a,b,"A","B",pids,aliases,wrong)
        correct={"A":{2:"alias-B"},"B":{3:"alias-A"}}
        verify_peer_namespace(a,b,"A","B",pids,aliases,correct)

    def test_inactive_fallback_requires_all_conditions(self):
        import copy
        raw={"flags":["NOARP"],"operstate":"DOWN","addr_info":[],"linkinfo":{"info_kind":"gre","info_data":{"local":"any","remote":"any"}}}
        self.assertEqual(inactive_fallback(raw),"gre")
        for key,value in [("flags",["UP"]),("operstate","UP"),("addr_info",[{"local":"10.0.0.1"}]),("master","br0"),("link_index",10),("link","eth0")]:
            changed=copy.deepcopy(raw);changed[key]=value
            with self.assertRaises(EvidenceError):inactive_fallback(changed)
        for endpoint in ["local","remote"]:
            changed=copy.deepcopy(raw);changed["linkinfo"]["info_data"][endpoint]="192.0.2.1"
            with self.assertRaises(EvidenceError):inactive_fallback(changed)

    def test_only_bridge_gc_timer_is_ignored_for_adjacency_consistency(self):
        a=[{"ifname":"br0","linkinfo":{"info_kind":"bridge","info_data":{"gc_timer":1,"vlan_filtering":0}}}]
        b=[{"ifname":"br0","linkinfo":{"info_kind":"bridge","info_data":{"gc_timer":2,"vlan_filtering":0}}}]
        self.assertEqual(adjacency_projection(a),adjacency_projection(b))
        b[0]["linkinfo"]["info_data"]["vlan_filtering"]=1
        self.assertNotEqual(adjacency_projection(a),adjacency_projection(b))

    def test_inactive_fallback_route_is_rejected(self):
        def mutate(snapshot):
            route=dict(snapshot["routes"][0])
            route["id"]="mutation-gre-route"
            route["output_interface"]="gre0"
            snapshot["routes"].append(route)
        self.mutate_bundle(mutate,"fallback tunnel has a route",source_key="coherent_baseline")

    def test_inactive_fallback_bridge_membership_is_rejected(self):
        def mutate(snapshot):
            snapshot["links"].append({"id":"mutation-gre-attachment","status":"observed","endpoint_interface_ids":["BLACK:gre0","BLACK:lo"],"relation":"bridge_attachment","physical_claim_supported":False,"observation_ids":snapshot["interfaces"][0]["observation_ids"]})
        self.mutate_bundle(mutate,"fallback tunnel has a route or declared link",source_key="coherent_baseline")


    def test_raw_fallback_route_cannot_hide_in_normalization(self):
        source=source_path("coherent_baseline")
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            root=Path(temp)/"bundle"
            shutil.copytree(source,root)
            snapshot=json.loads((root/"snapshot.json").read_text())
            obs=next(o for o in snapshot["observations"] if o["device_id"]=="BLACK" and o["kind"]=="routes4")
            path=root/obs["raw_path"]
            raw=json.loads(path.read_text());routes=json.loads(raw["stdout"])
            routes.append({"dst":"192.0.2.0/24","nexthops":[{"dev":"gre0"}]})
            raw["stdout"]=json.dumps(routes);path.write_text(json.dumps(raw))
            obs["raw_sha256"]=hashlib.sha256(path.read_bytes()).hexdigest()
            (root/"snapshot.json").write_text(json.dumps(snapshot))
            manifest=json.loads((root/"manifest.json").read_text())
            for entry in manifest["files"]:
                entry["sha256"]=hashlib.sha256((root/entry["path"]).read_bytes()).hexdigest()
                entry["bytes"]=(root/entry["path"]).stat().st_size
            (root/"manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(EvidenceError,"raw route reference"):
                analyze(root,Path(temp)/"out.lean",Path(temp)/"report.json")

    def test_bypass_edge_breaks_cut(self):
        original={(0,1),(1,0),(1,2),(2,1)}
        labels=components(3,original,{1})
        self.assertNotEqual(labels[0],labels[2])
        mutated=original|{(0,2),(2,0)}
        labels=components(3,mutated,{1})
        self.assertEqual(labels[0],labels[2])

if __name__=="__main__":
    unittest.main()
