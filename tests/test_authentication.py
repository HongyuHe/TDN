import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).parents[1]/"scripts/construction"))
from import_authentication import certificate_parameters,negative_trial,selected_exchange
from source_paths import source_path
from validate_evidence import EvidenceError

class AuthenticationTests(unittest.TestCase):
    def test_credential_curve_is_not_inferred_from_bit_count(self):
        events=json.loads((source_path("auth_after")/"events.json").read_text())
        cert=next(r for r in events["records"] if r["command"][3:5]==["openssl","x509"])
        certificate_parameters(cert["stdout"],"I_A1.msc.test")
        with self.assertRaisesRegex(EvidenceError,"P384"):
            certificate_parameters(cert["stdout"].replace("secp384r1","secp521r1"),"I_A1.msc.test")

    def test_failure_exit_is_not_signature_policy_evidence(self):
        events=json.loads((source_path("auth_negative")/"events.json").read_text())
        records={r["id"]:r for r in events["records"]}
        negative_trial(records)
        changed=copy.deepcopy(records)
        for record in changed.values():
            record["stdout"]=record["stdout"].replace("IKE signature scheme ECDSA_WITH_SHA256_DER not acceptable","unrelated connection timeout")
        with self.assertRaisesRegex(EvidenceError,"rejection cause"):
            negative_trial(changed)

    def test_restoration_must_use_same_pair_and_sha384(self):
        events=json.loads((source_path("auth_negative")/"events.json").read_text())
        records={r["id"]:r for r in events["records"]}
        positive=next(r for r in records.values() if "--initiate" in r["command"] and r["returncode"]==0)
        positive["stdout"]=positive["stdout"].replace("ECDSA_WITH_SHA384_DER","ECDSA_WITH_SHA256_DER")
        with self.assertRaisesRegex(EvidenceError,"authentication differs"):
            negative_trial(records)

if __name__=="__main__":unittest.main()
