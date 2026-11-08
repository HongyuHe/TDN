import TDN.Evidence.BoundaryMACsecData
import TDN.Targets.NativePolicies

namespace TDN.Imported.BoundaryMACsec
open Compliance Targets Targets.Complete MultiProtocolExecution LayeredFrame

instance (records : Records) : DecidableRel records.configuration.physicalLink := by
  intro first second
  change Decidable ((first, second) ∈ records.links)
  infer_instance

lemma captured_routes_and_source_payload_are_nonempty :
    ∀ records ∈ [protectedCase, unprotectedAllowed, unprotectedDenied],
      records.sourceCase.RoutingChecks records.configuration ∧
      records.sourceCase.application ≠ [] ∧ records.inventory.ifaces ≠ [] ∧
      records.macIfaces ≠ [] ∧ records.linkPolicies ≠ [] := by
  exact of_decide_eq_true rfl

lemma captured_frames_describe_actual_native_output :
    protectedCase.physicalFrame.Describes protectedCase.physicalReady.frame ∧
    unprotectedAllowed.physicalFrame.Describes unprotectedAllowed.physicalReady.frame ∧
    unprotectedDenied.physicalFrame.Describes unprotectedDenied.physicalReady.frame := by
  constructor
  · apply checked_MACsec_wire_frame_describes_native _ _
      (protectedCase.sourceCase.mac.transmitAssociation.getD ⟨0, 0, 0, 0⟩)
      (protectedCase.sourceCase.ready protectedCase.configuration).frame.body rfl
    exact of_decide_eq_true rfl
  · constructor
    · apply checked_IP_frame_describes_native _ _ unprotectedAllowed.sourceCase.forwardedHeader rfl
        unprotectedAllowed.logicalNetwork unprotectedAllowed.logicalTransport unprotectedAllowed.sourceCase.application
      · exact of_decide_eq_true rfl
      · rfl
      · rfl
    · apply checked_IP_frame_describes_native _ _ unprotectedDenied.sourceCase.forwardedHeader rfl
        unprotectedDenied.logicalNetwork unprotectedDenied.logicalTransport unprotectedDenied.sourceCase.application
      · exact of_decide_eq_true rfl
      · rfl
      · rfl

lemma protected_native_MACsec_and_wire_steps :
    MultiProtocolExecution.Step protectedCase.configuration
      (protectedCase.sourceCase.ready protectedCase.configuration) .encryptMACsec protectedCase.physicalReady ∧
    MultiProtocolExecution.Step protectedCase.configuration protectedCase.physicalReady .linkTransmit protectedCase.wired := by
  constructor
  · exact .encryptMACsec protectedCase.sourceCase.mac
      (protectedCase.sourceCase.mac.transmitAssociation.getD ⟨0, 0, 0, 0⟩)
      (by exact of_decide_eq_true rfl) rfl rfl ⟨rfl, rfl⟩
  · exact .linkTransmit protectedCase.sourceCase.peerIface rfl (by exact of_decide_eq_true rfl)

lemma protect_off_native_MACsec_and_wire_steps :
    MultiProtocolExecution.Step unprotectedAllowed.configuration
      (unprotectedAllowed.sourceCase.ready unprotectedAllowed.configuration) .passWithoutTransform unprotectedAllowed.physicalReady ∧
    MultiProtocolExecution.Step unprotectedAllowed.configuration unprotectedAllowed.physicalReady .linkTransmit unprotectedAllowed.wired := by
  constructor
  · exact .unprotectedMACsec unprotectedAllowed.sourceCase.mac
      (by exact of_decide_eq_true rfl) rfl rfl rfl (Or.inl rfl)
  · exact .linkTransmit unprotectedAllowed.sourceCase.peerIface rfl (by exact of_decide_eq_true rfl)

theorem captured_protected_payload_follows_native_route_MACsec_and_wire :
    (lts protectedCase.configuration).MTr protectedCase.sourceCase.entry
      [.receive, .route, .forwardFilter, .passWithoutTransform, .encryptMACsec, .linkTransmit] protectedCase.wired := by
  have routed := (routed_MACsec_case_reaches_logical_output protectedCase.sourceCase
    protectedCase.configuration ⟨fun _ => 64, fun _ => 64⟩ rfl
    (captured_routes_and_source_payload_are_nonempty protectedCase (by simp)).1).1
  exact (Cslib.LTS.MTr.append_iff _).mpr
    ⟨protectedCase.sourceCase.ready protectedCase.configuration, routed,
      .stepL protected_native_MACsec_and_wire_steps.1
        (.stepL protected_native_MACsec_and_wire_steps.2 .refl)⟩

theorem captured_protect_off_payload_follows_native_route_and_plain_wire :
    (lts unprotectedAllowed.configuration).MTr unprotectedAllowed.sourceCase.entry
      [.receive, .route, .forwardFilter, .passWithoutTransform, .passWithoutTransform, .linkTransmit] unprotectedAllowed.wired := by
  have routed := (routed_MACsec_case_reaches_logical_output unprotectedAllowed.sourceCase
    unprotectedAllowed.configuration ⟨fun _ => 64, fun _ => 64⟩ rfl
    (captured_routes_and_source_payload_are_nonempty unprotectedAllowed (by simp)).1).1
  exact (Cslib.LTS.MTr.append_iff _).mpr
    ⟨unprotectedAllowed.sourceCase.ready unprotectedAllowed.configuration, routed,
      .stepL protect_off_native_MACsec_and_wire_steps.1
        (.stepL protect_off_native_MACsec_and_wire_steps.2 .refl)⟩

def PhysicalChecks (records : Records) : Prop :=
  records.sourceCase.mac ∈ records.configuration.macIfaces ∧
  records.sourceCase.mac.physicalIface ∈ records.inventory.ifaces ∧
  records.sourceCase.peerIface ∈ records.inventory.ifaces ∧
  records.sender ∈ records.interfaces ∧ records.receiver ∈ records.interfaces ∧
  records.ifaceName records.sourceCase.mac.physicalIface = records.sender.id ∧
  records.configuration.ip.interfaceName records.sourceCase.mac.physicalIface = records.sender.id ∧
  records.sender.device = records.componentName
    (records.configuration.ip.owner records.sourceCase.mac.physicalIface) ∧
  records.ifaceName records.sourceCase.peerIface = records.receiver.id ∧
  records.configuration.ip.interfaceName records.sourceCase.peerIface = records.receiver.id ∧
  records.receiver.device = records.componentName (records.configuration.ip.owner records.sourceCase.peerIface) ∧
  (∃ mac ∈ records.configuration.macIfaces, mac.physicalIface = records.sourceCase.peerIface) ∧
  LinkAdmission.Admitted records.configuration.linkPolicies records.sourceCase.mac.physicalIface true
    (records.packet .outbound) ∧
  LinkAdmission.Admitted records.configuration.linkPolicies records.sourceCase.peerIface false
    (records.packet .inbound)

instance (records : Records) : Decidable (PhysicalChecks records) := by
  unfold PhysicalChecks
  infer_instance

lemma captured_permitted_physical_programs_and_bindings :
    PhysicalChecks protectedCase ∧ PhysicalChecks unprotectedAllowed := by
  exact of_decide_eq_true rfl

lemma observed_physical_packet_is_supported (records : Records) (base : Deployment)
    (direction : Direction) :
    (records.deployment base).Supported ((records.deployment base).Observe (records.packet direction)) := by
  refine ⟨rfl, ?_⟩
  intro _ established
  change ("" : String) = "established" at established
  exact False.elim ((by decide : ("" : String) ≠ "established") established)

lemma native_physical_program_acceptance (records : Records) (base : Deployment)
    (wire : MultiProtocolExecution.Step records.configuration records.physicalReady .linkTransmit records.wired)
    (describes : records.physicalFrame.Describes records.physicalReady.frame)
    (checks : PhysicalChecks records) :
    (records.deployment base).PhysicalBoundaryAccepts records.sender.id .outbound
      ((records.deployment base).Observe (records.packet .outbound)) ∧
    (records.deployment base).PhysicalBoundaryAccepts records.receiver.id .inbound
      ((records.deployment base).Observe (records.packet .inbound)) := by
  obtain ⟨mac, ifaceMember, peerMember, senderMember, receiverMember, name, nativeName,
    owner, peerName, peerNativeName, peerOwner, peerMAC, outAllow, inAllow⟩ := checks
  constructor
  · exact ⟨records.inventory, rfl, records.sourceCase.mac.physicalIface, ifaceMember,
      Or.inl ⟨records.sourceCase.mac, mac, rfl⟩, name, nativeName,
      records.sender, senderMember, rfl, owner, records.physicalFrame,
      .outbound records.physicalReady records.wired records.physicalFrame wire describes,
      rfl, observed_physical_packet_is_supported records base .outbound, outAllow⟩
  · exact ⟨records.inventory, rfl, records.sourceCase.peerIface, peerMember,
      Or.inl peerMAC, peerName, peerNativeName, records.receiver, receiverMember,
      rfl, peerOwner, records.physicalFrame,
      .inbound records.physicalReady records.wired records.physicalFrame wire describes,
      rfl, observed_physical_packet_is_supported records base .inbound, inAllow⟩

theorem protected_frames_are_observed_at_both_physical_boundaries (base : Deployment) :
    (protectedCase.deployment base).PhysicalBoundaryAccepts protectedCase.sender.id .outbound
      ((protectedCase.deployment base).Observe (protectedCase.packet .outbound)) ∧
    (protectedCase.deployment base).PhysicalBoundaryAccepts protectedCase.receiver.id .inbound
      ((protectedCase.deployment base).Observe (protectedCase.packet .inbound)) :=
  native_physical_program_acceptance protectedCase base protected_native_MACsec_and_wire_steps.2
    captured_frames_describe_actual_native_output.1 captured_permitted_physical_programs_and_bindings.1

theorem protection_disabled_plaintext_is_observed_at_both_boundaries (base : Deployment) :
    (unprotectedAllowed.deployment base).PhysicalBoundaryAccepts unprotectedAllowed.sender.id .outbound
      ((unprotectedAllowed.deployment base).Observe (unprotectedAllowed.packet .outbound)) ∧
    (unprotectedAllowed.deployment base).PhysicalBoundaryAccepts unprotectedAllowed.receiver.id .inbound
      ((unprotectedAllowed.deployment base).Observe (unprotectedAllowed.packet .inbound)) :=
  native_physical_program_acceptance unprotectedAllowed base protect_off_native_MACsec_and_wire_steps.2
    captured_frames_describe_actual_native_output.2.1 captured_permitted_physical_programs_and_bindings.2

end TDN.Imported.BoundaryMACsec
