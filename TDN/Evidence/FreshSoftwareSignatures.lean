import TDN.Targets.SoftwareSignatures

namespace TDN.Imported.FreshSoftwareSignatures
open TDN.Targets

/-- The sole consumer is a laboratory deployment utility. It is not a replacement
for the complete CSfC solution-component inventory. -/
def recordedUses : List SoftwareSignatureUse :=
  [⟨"deployment-utility", "twinet-linux", .mldsa 5 87⟩]

lemma recorded_algorithm_is_approved : ∀ record ∈ recordedUses,
    ApprovedFirmwareSignature (fun _ => False) record.signature := by
  decide

theorem recorded_executable_has_table2_signature_choice :
    msc_software_firmware_signature_choice true ["deployment-utility"]
      (signaturesForComponent recordedUses) (fun _ => False) :=
  software_signature_choice_from_artifact_checks ["deployment-utility"] recordedUses
    (fun _ => False) (by decide) recorded_algorithm_is_approved

end TDN.Imported.FreshSoftwareSignatures
