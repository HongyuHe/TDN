import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).parents[1]/"scripts/construction"))
from analyze_topology import validated_graph
from native_runtime import ovs_rows,uuid_set
from source_paths import source_path
from validate_evidence import EvidenceError

class NativeTests(unittest.TestCase):
    def mutate(self,callback,message):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root=Path(tmp)/"bundle";shutil.copytree(source_path("native_baseline"),root)
            snapshot=json.loads((root/"snapshot.json").read_text())
            callback(root,snapshot)
            (root/"snapshot.json").write_text(json.dumps(snapshot))
            manifest=json.loads((root/"manifest.json").read_text())
            for entry in manifest["files"]:
                data=(root/entry["path"]).read_bytes();entry["sha256"]=hashlib.sha256(data).hexdigest();entry["bytes"]=len(data)
            (root/"manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(EvidenceError,message):validated_graph(root)

    def change_table(self,root,snapshot,kind,change):
        record=next(r for r in snapshot["native_runtime"] if r["kind"]==kind)
        change(record["raw_value"])
        for oid in record["observation_ids"]:
            obs=next(o for o in snapshot["observations"] if o["id"]==oid)
            path=root/obs["raw_path"];raw=json.loads(path.read_text());raw["stdout"]=json.dumps(record["raw_value"])+"\n";path.write_text(json.dumps(raw));obs["raw_sha256"]=hashlib.sha256(path.read_bytes()).hexdigest()

    def test_ovs_dangling_port_uuid_rejected(self):
        def change(root,snapshot):
            def corrupt(table):table["data"][0][table["headings"].index("ports")][1].pop()
            self.change_table(root,snapshot,"native-ovs-bridge",corrupt)
        self.mutate(change,"Bridge/Port coverage")

    def test_ovs_wrong_raw_ifindex_rejected(self):
        def change(root,snapshot):
            def corrupt(table):table["data"][0][table["headings"].index("ifindex")]+=1
            self.change_table(root,snapshot,"native-ovs-interface",corrupt)
        self.mutate(change,"identity/options/error")

    def test_ovs_tunnel_port_rejected(self):
        def change(root,snapshot):
            def corrupt(table):
                row=next(row for row in table["data"] if row[table["headings"].index("type")]=="")
                row[table["headings"].index("type")]="geneve"
            self.change_table(root,snapshot,"native-ovs-interface",corrupt)
        self.mutate(change,"patch/tunnel/system")

    def test_ovs_omitted_membership_rejected(self):
        def change(root,snapshot):
            chosen=next(l for l in snapshot["links"] if l["relation"]=="ovs_bridge_membership")
            snapshot["links"].remove(chosen)
        self.mutate(change,"membership count")

    def test_frr_namespace_mismatch_rejected(self):
        def change(root,snapshot):
            record=next(r for r in snapshot["native_runtime"] if r["kind"]=="FRR control namespace association")
            obs=next(o for o in snapshot["observations"] if o["id"] in record["observation_ids"] and o["command"][0]=="readlink")
            raw=json.loads((root/obs["raw_path"]).read_text());raw["stdout"]="net:[1]\nnet:[2]\n";path=root/obs["raw_path"];path.write_text(json.dumps(raw));obs["raw_sha256"]=hashlib.sha256(path.read_bytes()).hexdigest();record["network_namespace_identities"]=["net:[1]","net:[2]"]
        self.mutate(change,"namespace identity mismatch")

if __name__=="__main__":unittest.main()
