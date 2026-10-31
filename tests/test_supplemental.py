import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parents[1]/"scripts/construction"))
from import_management import tls_sample
from import_supplemental import checked_certificate_statuses,parse_ntp,mechanism_bundle
from source_paths import source_path,source_collection
from validate_evidence import EvidenceError

class SupplementalTests(unittest.TestCase):
    def test_tls_timeout_is_not_certificate_refusal(self):
        result={"client_certificate":False,"tls_version":"TLSv1.3","cipher":["TLS_AES_256_GCM_SHA384","TLSv1.3",256],"result":"rejected","error":"TimeoutError"}
        with self.assertRaisesRegex(EvidenceError,"certificate-required"):
            tls_sample(result,"case","source","target")

    def test_tls_success_requires_application_response(self):
        result={"client_certificate":True,"tls_version":"TLSv1.3","cipher":["TLS_AES_256_GCM_SHA384","TLSv1.3",256],"result":"delivered"}
        with self.assertRaisesRegex(EvidenceError,"application response"):
            tls_sample(result,"case","source","target")

    def test_hierarchical_ca_checks_each_certificate(self):
        text='[CFG] checking certificate status of "CN=peer"\ncrl correctly signed by issuer\ncrl is valid: today\ncertificate status is good\n[CFG] checking certificate status of "CN=issuer"\ncrl correctly signed by root\ncrl is valid: today\ncertificate status is good\n'
        self.assertEqual(checked_certificate_statuses(text),["peer","issuer"])
        with self.assertRaises(EvidenceError):
            checked_certificate_statuses(text.replace("certificate status is good","certificate status is revoked",1))

    def test_ntp_must_echo_origin_and_not_claim_clock_adjustment(self):
        value={"server":["10.0.0.2",123],"mode":4,"stratum":2,"origin_matches":True,"system_clock_adjusted":False,"round_trip_seconds":0.1}
        record={"id":"r","command":["python3"],"returncode":0,"stderr":"","stdout":json.dumps(value)}
        evidence={"links":[{"endpoints":["CLIENT:p","TIME:p"],"addresses":["10.0.0.1/30","10.0.0.2/30"]}]}
        parse_ntp(record,"time-red",evidence)
        for key,bad in [("origin_matches",False),("system_clock_adjusted",True),("stratum",16)]:
            changed=copy.deepcopy(value);changed[key]=bad;record["stdout"]=json.dumps(changed)
            with self.assertRaises(EvidenceError):parse_ntp(record,"time-red",evidence)

    def test_mixed_probe_programs_keep_distinct_counts(self):
        paths=source_collection("utility")
        path=next(p for p in paths if json.loads((p/"manifest.json").read_text())["configuration_id"]=="central-management")
        case,_,_=mechanism_bundle(path)
        self.assertEqual(len(case["probes"]),4)
        self.assertEqual(len(case["tls"]),2)
        self.assertTrue(all(p["transmitted"]>0 for p in case["probes"]))

    def test_collection_paths_are_portable_and_bounded(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
            path=Path(temp)/"inputs.json"
            bundle=source_collection("utility")[0]
            config={"schema_version":"csfc-construction-inputs/v1","paths":{},"collections":{"utility":{"one":str(bundle)}}}
            path.write_text(json.dumps(config))
            with patch.dict(os.environ,{"TDN_INPUT_MANIFEST":str(path)}):
                self.assertEqual(source_collection("utility"),[bundle])
                config["collections"]["utility"]["one"]="../forbidden"
                path.write_text(json.dumps(config))
                with self.assertRaisesRegex(ValueError,"workspace-relative"):source_collection("utility")

if __name__=="__main__":unittest.main()
