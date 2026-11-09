"""Import the observed Auditor readback prefix and its actual retained rotated files."""
import argparse
import hashlib
import json
from pathlib import Path

from evidence.derive_auditor_rotation import derive
from import_admin_sessions import parse as parse_sessions
from validate_evidence import require


def parse(base, derived):
    base, derived = Path(base), Path(derived)
    manifest = json.loads((derived/"manifest.json").read_text())
    require(manifest["files"] == [{"path": "rotation.json",
        "sha256": hashlib.sha256((derived/"rotation.json").read_bytes()).hexdigest()}],
        "Derived rotation manifest differs")
    helper = Path(__file__).parent/"evidence/derive_auditor_rotation.py"
    require(manifest["deriver_sha256"] == hashlib.sha256(helper.read_bytes()).hexdigest(),
            "Derivation source changed")
    recorded = json.loads((derived/"rotation.json").read_text())
    actual = derive(base)
    #* Historical and current paths must identify the same retained manifests.
    compared = []
    for record in (recorded, actual):
        bound = dict(record)
        bound["input_manifests"] = [
            {**entry, "path": str(Path(entry["path"]).resolve())}
            for entry in record["input_manifests"]
        ]
        compared.append(bound)
    require(compared[0] == compared[1], "Derived rotation differs from raw observations")
    session = parse_sessions(base/"role-admin-deploy-v4", base/"role-admin-effective-v3",
                             base/"role-admin-matrix-v3")
    require(session["source_sha256"] == actual["source_sha256"],
            "Rotation/source process binding differs")
    actual["listener_process"] = session["listener_process"]
    actual["checked_audit_files"] = session["audit_files"]
    actual["derived_manifest_sha256"] = hashlib.sha256((derived/"manifest.json").read_bytes()).hexdigest()
    return actual


def string_list(values):
    return "[" + ", ".join(json.dumps(value, ensure_ascii=False) for value in values) + "]"


def generate(data):
    def lists(values):
        return "[" + ", ".join(string_list(row) for row in values) + "]"
    return """import TDN.Requirements.AuditorLogManagement

namespace TDN.Deployments.FreshAuditorRotation
open AuditRotation
set_option maxRecDepth 10000
set_option maxHeartbeats 0

/-- Canonical complete event objects, not only selected fields or hash identities. -/
def observedBefore : List String := """+string_list(data["before_read"])+"""
/-- The source-ordered pre-rotation state is reconstructed from retained files.
Only observedBefore was independently retrieved before the rotation. -/
def before : Store String := ⟨"""+lists(data["before_archives"])+", "+string_list(data["before_active"])+"""⟩
def later : List String := """+string_list(data["later_observed_active"])+"""
def capturedAfter : Store String := ⟨"""+lists(data["after_archives"])+", "+string_list(data["later_observed_active"])+"""⟩

lemma actual_observation_nonempty : observedBefore.length = 8 ∧
    (entries before).length = 10 ∧ later.length = 14 := by decide

lemma observed_before_prefix : observedBefore <+: entries before := by decide

lemma source_ordered_rotation_check :
    capturedAfter = appendEntries (rotate before) later := by decide

/-- The actual Auditor-managed rotation preserves every independently retrieved
earlier record, in order and with multiplicity, in the later captured log files.
Human review and all other audit-management duties remain separate. -/
theorem actual_auditor_rotation_preserves_observed_log :
    observedBefore <+: entries capturedAfter :=
  Requirements.observed_audit_prefix_survives_rotation before capturedAfter observedBefore later
    observed_before_prefix source_ordered_rotation_check

end TDN.Deployments.FreshAuditorRotation
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--derived", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    data = parse(args.base, args.derived)
    Path(args.output).write_text(generate(data))
    Path(args.report).write_text(json.dumps(data,indent=2)+"\n")
    print(json.dumps({"observed_before": len(data["before_read"]),
                      "later_active": len(data["later_observed_active"]),
                      "actor": data["authenticated_role"]}))


if __name__ == "__main__":
    main()
