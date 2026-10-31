import TDN.Targets.Cryptography

namespace TDN.Targets

instance (sp800208Approved : String → Prop) [DecidablePred sp800208Approved]
    (signature : FirmwareSignature) :
    Decidable (ApprovedFirmwareSignature sp800208Approved signature) := by
  cases signature <;> unfold ApprovedFirmwareSignature <;> infer_instance

/-- A signature use names the software artifact and its consuming component.
Deployment evidence must justify that association and the complete inventory. -/
structure SoftwareSignatureUse where
  component : String
  artifact : String
  signature : FirmwareSignature
  deriving DecidableEq, Repr

def signaturesForComponent (records : List SoftwareSignatureUse) (component : String) :
    List FirmwareSignature :=
  (records.filter (fun record => record.component == component)).map SoftwareSignatureUse.signature

/-- Checking each recorded signature and supplying at least one use per component
establishes the algorithm-choice specification. The inventory is an explicit
premise; a signed utility cannot stand in for every device's software and firmware. -/
theorem software_signature_choice_from_artifact_checks
    (components : List String) (records : List SoftwareSignatureUse)
    (sp800208Approved : String → Prop)
    (coverage : ∀ component ∈ components,
      ∃ record ∈ records, record.component = component)
    (approved : ∀ record ∈ records,
      ApprovedFirmwareSignature sp800208Approved record.signature) :
    msc_software_firmware_signature_choice true components
      (signaturesForComponent records) sp800208Approved := by
  intro _ component member
  obtain ⟨record, present, assigned⟩ := coverage component member
  constructor
  · intro empty
    have included : record.signature ∈ signaturesForComponent records component := by
      apply List.mem_map.mpr
      exact ⟨record, List.mem_filter.mpr ⟨present, by simp [assigned]⟩, rfl⟩
    rw [empty] at included
    exact List.not_mem_nil included
  · intro signature included
    obtain ⟨record, filtered, equality⟩ := List.mem_map.mp included
    have present := (List.mem_filter.mp filtered).1
    rw [← equality]
    exact approved record present

end TDN.Targets
