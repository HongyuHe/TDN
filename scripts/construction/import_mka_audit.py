import argparse
import hashlib
import json
import re
from pathlib import Path
from import_provenance import verified_files
from source_paths import source_path
from validate_evidence import require


def source_parameters(header,source):
    constants={}
    for name in ["MKA_HELLO_TIME","MKA_BOUNDED_HELLO_TIME","MKA_LIFE_TIME"]:
        values=re.findall(r"(?m)^#define\s+"+name+r"\s+(\d+)\s*$",header)
        require(len(values)==1,"missing/ambiguous MKA source constant")
        constants[name]=int(values[0])
    require(len(re.findall(r"body->delay_protect\s*=\s*kay->mka_hello_time\s*<=\s*MKA_BOUNDED_HELLO_TIME\s*;",source))==1,"unsupported MKA delay flag expression")
    assignments=re.findall(r"body->delay_protect\s*=\s*([^;]+);",source)
    require(len(assignments)==2 and "false" in assignments,"unexpected additional delay flag assignment")
    require("participant->kek.len = participant->cak.len;" in source,"KEK length no longer follows CAK")
    require(re.search(r"aes_wrap\(participant->kek.key,\s*participant->kek.len,",source),"AES-wrap call does not use KEK length")
    return constants


def generate(output,report_path):
    root=source_path("mka_audit");manifest,files=verified_files(root)
    constants=source_parameters((root/"ieee802_1x_kay.h").read_text(),(root/"ieee802_1x_kay.c").read_text())
    from import_events import import_mka
    matched=import_mka(source_path("mka_matching"))
    require(all(p["hello_ms"]==constants["MKA_HELLO_TIME"] for p in matched["peers"]),"observed hello differs from pinned default")
    cak_bits=matched["public_settings"]["cak_bits"]
    lines=["import TDN.Targets.Protocol","namespace TDN.Imported.MKASource","def helloMs : Nat := "+str(constants["MKA_HELLO_TIME"]),"def lifetimeMs : Nat := "+str(constants["MKA_LIFE_TIME"]),"def boundedHelloMs : Nat := "+str(constants["MKA_BOUNDED_HELLO_TIME"]),"def sourceDelayFlag (hello : Nat) : Bool := decide (hello ≤ boundedHelloMs)","theorem source_timer_constants : helloMs = 2000 ∧ lifetimeMs = 6000 := by decide","theorem required_hello_disables_source_delay_flag : sourceDelayFlag 2000 = false := by decide","def declaredTestCakBits : Nat := "+str(cak_bits),"def sourceDerivedKekBits := declaredTestCakBits","theorem source_derived_test_kek_width : sourceDerivedKekBits = 256 := by decide","theorem full_RG028_fails_under_source_flag_correspondence (devices : List Targets.MACsecProtection) (d : Targets.MACsecProtection) (hd : d ∈ devices) (hhello : d.helloMilliseconds = 2000) (hflag : d.dataDelayProtection = sourceDelayFlag d.helloMilliseconds) : ¬ Targets.msc_macsec_protection_parameters devices := by\n  intro h\n  have bad : false = true := by simpa [hflag, hhello, sourceDelayFlag, boundedHelloMs] using (h d hd).1\n  cases bad", "end TDN.Imported.MKASource"]
    output.write_text("\n\n".join(lines)+"\n")
    report={"bundle":str(root),"manifest_sha256":hashlib.sha256((root/"manifest.json").read_bytes()).hexdigest(),"source_constants":constants,"source_delay_expression":"hello <= 500","observed_matching_hello_ms":[p["hello_ms"] for p in matched["peers"]],"matching_manifest_sha256":matched["manifest_sha256"],"declared_cak_bits":cak_bits,"kek_length_source":"participant->kek.len = participant->cak.len","wrap_source":"aes_wrap uses participant->kek.len","source_line_references":{"ieee802_1x_kay.h":[23,24,25],"ieee802_1x_kay.c":[1312,1317,1656,3782]},"scope":"Pinned source expression and constants plus finite PSK runtime hello logs. The full-target counterexample is conditional on source/build/flag-to-CP correspondence; primitive correctness, all-schedule timing and secure KGS provisioning remain unproved.","audit":json.loads((root/"audit.json").read_text()),"observation_ids":[p["status_observation"] for p in matched["peers"]]}
    report_path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"hello_ms":constants["MKA_HELLO_TIME"],"delay_flag_at_required_hello":False}))

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--lean-output",required=True,type=Path);parser.add_argument("--report",required=True,type=Path);args=parser.parse_args();generate(args.lean_output,args.report)
