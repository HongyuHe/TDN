import TDN.Targets.SoftwareSignatures

open TDN.Targets

def uses : List SoftwareSignatureUse :=
  [⟨"router", "image-a", .mldsa 5 87⟩, ⟨"router", "firmware-a", .mldsa 5 87⟩,
   ⟨"firewall", "image-b", .mldsa 5 87⟩]

example : msc_software_firmware_signature_choice true ["router", "firewall"]
    (signaturesForComponent uses) (fun _ => False) :=
  software_signature_choice_from_artifact_checks ["router", "firewall"] uses
    (fun _ => False) (by decide) (by decide)

example : ¬ msc_software_firmware_signature_choice true ["missing-device"]
    (signaturesForComponent uses) (fun _ => False) := by
  unfold msc_software_firmware_signature_choice signaturesForComponent uses
  decide

example : ¬ ApprovedFirmwareSignature (fun _ => False) (.mldsa 3 87) := by decide
example : ¬ ApprovedFirmwareSignature (fun _ => False) (.mldsa 5 65) := by decide
example : ¬ ApprovedFirmwareSignature (fun _ => False) (.lms "unchecked") := by decide
