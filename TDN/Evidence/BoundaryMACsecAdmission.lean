import TDN.Evidence.BoundaryMACsecSource
import TDN.Evidence.BoundaryMACsecCounterexamples
import TDN.Targets.PhysicalWireAdmission

namespace TDN.Imported.BoundaryMACsec
open Compliance Targets Targets.Complete MultiProtocolExecution

lemma captured_physical_encodings :
    ∀ records ∈ [protectedCase, unprotectedAllowed],
      records.configuration.linkEncoding records.physicalReady.iface records.physicalReady.frame =
        some records.physicalFrame ∧
      records.configuration.linkEncoding records.wired.iface records.wired.frame = some records.physicalFrame := by
  exact of_decide_eq_true rfl

lemma permitted_native_wire_admission (records : Records)
    (wire : MultiProtocolExecution.Step records.configuration records.physicalReady .linkTransmit records.wired)
    (describes : records.physicalFrame.Describes records.physicalReady.frame)
    (encoding : records.configuration.linkEncoding records.physicalReady.iface records.physicalReady.frame =
      some records.physicalFrame ∧
      records.configuration.linkEncoding records.wired.iface records.wired.frame = some records.physicalFrame)
    (checks : PhysicalChecks records) :
    records.configuration.LinkStepAdmitted records.physicalReady .linkTransmit records.wired := by
  apply native_wire_is_admitted_by_recorded_directional_programs records.configuration
    records.physicalReady records.wired records.physicalFrame wire encoding.1 encoding.2 describes
  · exact checks.2.2.2.2.2.2.2.2.2.2.2.2.1
  · exact checks.2.2.2.2.2.2.2.2.2.2.2.2.2

theorem captured_protected_wire_passes_both_directional_programs :
    protectedCase.configuration.LinkStepAdmitted protectedCase.physicalReady .linkTransmit protectedCase.wired :=
  permitted_native_wire_admission protectedCase protected_native_MACsec_and_wire_steps.2
    captured_frames_describe_actual_native_output.1 (captured_physical_encodings protectedCase (by simp))
    captured_permitted_physical_programs_and_bindings.1

theorem captured_protect_off_wire_passes_both_directional_programs :
    unprotectedAllowed.configuration.LinkStepAdmitted unprotectedAllowed.physicalReady .linkTransmit unprotectedAllowed.wired :=
  permitted_native_wire_admission unprotectedAllowed protect_off_native_MACsec_and_wire_steps.2
    captured_frames_describe_actual_native_output.2.1 (captured_physical_encodings unprotectedAllowed (by simp))
    captured_permitted_physical_programs_and_bindings.2

theorem physical_egress_drop_prevents_an_admitted_native_wire_step :
    ¬ unprotectedDenied.configuration.LinkStepAdmitted unprotectedDenied.physicalReady .linkTransmit unprotectedDenied.wired := by
  intro admission
  have path : unprotectedDenied.configuration.LinkPath unprotectedDenied.physicalReady.iface :=
    Or.inl ⟨unprotectedDenied.sourceCase.mac, by exact of_decide_eq_true rfl, rfl⟩
  obtain ⟨encoded, encoding, _, allowed⟩ := (admission.1 rfl).1 path
  have actual : unprotectedDenied.configuration.linkEncoding unprotectedDenied.physicalReady.iface
      unprotectedDenied.physicalReady.frame = some unprotectedDenied.physicalFrame := rfl
  have same : encoded = unprotectedDenied.physicalFrame := Option.some.inj (encoding.symm.trans actual)
  subst encoded
  have rejects : ¬ LinkAdmission.Admitted unprotectedDenied.configuration.linkPolicies
      unprotectedDenied.sourceCase.mac.physicalIface true (unprotectedDenied.packet .outbound) := by
    exact of_decide_eq_true rfl
  exact rejects allowed

end TDN.Imported.BoundaryMACsec
