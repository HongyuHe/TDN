import TDN.Deployments.Perimeter_MacsecCases

namespace TDN.Deployments.BoundaryMACsec
open Compliance Requirements Requirements.Msc MultiProtocolForwarding

def PriorLinkTransit (_d : Deployment) (inventory : PacketProcessing.Inventory)
    (iface : Nat) (direction : Direction) : Prop :=
  (∃ next ∈ inventory.ifaces,
    if direction = .inbound then inventory.configuration.bridge iface next
    else inventory.configuration.bridge next iface) ∨
  ∃ carrier ∈ inventory.configuration.carriers, carrier.virtualIface = iface

def PriorLinkCapable (d : Deployment) (interface : String) (direction : Direction)
    (traffic : Traffic) : Prop :=
  ∃ inventory, d.processing = some inventory ∧
    ∃ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface ∧
      ((PacketIsEthernet traffic.packet ∧ PriorLinkTransit d inventory iface direction) ∨
       (PacketMKA traffic.packet ∧
        ∃ endpoint ∈ inventory.mkaPeers,
          (if direction = .outbound then endpoint.sourceIface = iface
            else endpoint.destinationIface = iface) ∧
          ∃ bytes, traffic.packet.payloadBytes = some bytes ∧ 36 ≤ bytes.length ∧
            PacketSource.field bytes 8 8 = endpoint.actorSCI ∧
            traffic.packet.source = endpoint.actorSCI / 65536) ∨
       (PacketMACsec traffic.packet ∧
        ∃ mac ∈ inventory.configuration.macIfaces, mac.physicalIface = iface ∧
          ∃ association bytes, traffic.packet.payloadBytes = some bytes ∧
            MACsecPayload association bytes ∧
            (PacketSource.field bytes 0 1 / 32 % 2 = 0 →
              traffic.packet.source = association.sci / 65536) ∧
            if direction = .outbound then
              mac.transmitAssociation = some association ∧
                mac.settings.controlledPortEnabled = true ∧
                mac.settings.protectFrames = true ∧ mac.settings.encryptFrames = true ∧
                mac.settings.confidentialityOffset = 0
            else association ∈ mac.receiveAssociations ∧ mac.validateStrict = true))

instance (records : Records) : DecidableRel records.configuration.bridge := by
  intro first second
  change Decidable ((first, second) ∈ ([] : List (Nat × Nat)))
  infer_instance

lemma prior_link_capability_omits_actual_protect_off_plaintext (base : Deployment) :
    ¬ PriorLinkCapable (unprotectedAllowed.deployment base) unprotectedAllowed.sender.id .outbound
      ((unprotectedAllowed.deployment base).Observe (unprotectedAllowed.packet .outbound)) := by
  rintro ⟨inventory, present, iface, member, name, capable⟩
  have identity : inventory = unprotectedAllowed.inventory := Option.some.inj present.symm
  subst inventory
  have unique : ∀ iface ∈ unprotectedAllowed.inventory.ifaces,
      unprotectedAllowed.ifaceName iface = unprotectedAllowed.sender.id → iface = 3 := by
    exact of_decide_eq_true rfl
  have same := unique iface member name
  subst iface
  rcases capable with ethernet | mka | macsec
  · have absent : ¬ PriorLinkTransit (unprotectedAllowed.deployment base)
        unprotectedAllowed.inventory 3 .outbound := by
      simp [PriorLinkTransit, Records.inventory, Records.configuration, dataPlaneModelFromRecords]
    exact absent ethernet.2
  · have notMKA : ¬ PacketMKA (unprotectedAllowed.packet .outbound) := by decide
    exact notMKA mka.1
  · have notMACsec : ¬ PacketMACsec (unprotectedAllowed.packet .outbound) := by decide
    exact notMACsec macsec.1

lemma first_ready_observation_stops_before_actual_protect_off_output :
    ¬ FirstReadyRun unprotectedAllowed.configuration
      (unprotectedAllowed.sourceCase.egressReady unprotectedAllowed.configuration) unprotectedAllowed.physicalReady := by
  intro run
  have same := first_ready_run_from_ready_is_identity unprotectedAllowed.configuration rfl run
  have ifaces : (2 : Nat) = 3 := congrArg MultiProtocolForwarding.State.iface same
  omega

lemma recorded_physical_parent_recognition_retains_actual_plaintext (base : Deployment) :
    (unprotectedAllowed.deployment base).AcceptsAt unprotectedAllowed.sender.id .outbound .link
      ((unprotectedAllowed.deployment base).Observe (unprotectedAllowed.packet .outbound)) ∧
    (unprotectedAllowed.deployment base).AcceptsAt unprotectedAllowed.receiver.id .inbound .link
      ((unprotectedAllowed.deployment base).Observe (unprotectedAllowed.packet .inbound)) := by
  have parents : ∀ interface ∈ [unprotectedAllowed.sender, unprotectedAllowed.receiver],
      ∀ iface ∈ unprotectedAllowed.inventory.ifaces, unprotectedAllowed.ifaceName iface = interface.id →
        ∃ mac ∈ unprotectedAllowed.configuration.macIfaces, mac.physicalIface = iface := by
    exact of_decide_eq_true rfl
  constructor
  · exact physical_MACsec_boundary_admission_is_link_admission _ _ rfl _
      (parents _ (by simp)) _ _ (protection_disabled_plaintext_is_observed_at_both_boundaries base).1
  · exact physical_MACsec_boundary_admission_is_link_admission _ _ rfl _
      (parents _ (by simp)) _ _ (protection_disabled_plaintext_is_observed_at_both_boundaries base).2

def senderDevice : Device := devices[1]

theorem actual_protect_off_capture_violates_PF4 (base : Deployment)
    (required : Bool) (internal : String → Bool) (localOuter : String → String) :
    ¬ msc_boundary_interface_filtering (unprotectedAllowed.deployment base) required internal localOuter := by
  apply admitted_plaintext_at_MACsec_boundary_violates_requirement
    (unprotectedAllowed.deployment base) rfl unprotectedAllowed.sender
    (captured_permitted_physical_programs_and_bindings.2.2.2.2.1) senderDevice
    (by simp [Records.deployment, devices, senderDevice]) rfl rfl rfl rfl .outbound
    ((unprotectedAllowed.deployment base).Observe (unprotectedAllowed.packet .outbound))
  · change (unprotectedAllowed.deployment base).BoundaryAccepts unprotectedAllowed.sender.id .outbound _
    exact Or.inr (Or.inr (protection_disabled_plaintext_is_observed_at_both_boundaries base).1)
  · exact of_decide_eq_true rfl
  · simp [ApprovedControl, Records.deployment]

lemma protect_off_filtered_attempt_has_a_real_native_prefix :
    (lts unprotectedDenied.configuration).MTr unprotectedDenied.sourceCase.entry
      [.receive, .route, .forwardFilter, .forwardWithoutEncap, .forwardWithoutEncap] unprotectedDenied.physicalReady := by
  have routed := (routed_MACsec_case_reaches_logical_output unprotectedDenied.sourceCase
    unprotectedDenied.configuration ⟨fun _ => 64, fun _ => 64⟩ rfl
    (captured_routes_and_source_payload_are_nonempty unprotectedDenied (by simp)).1).1
  have plain : MultiProtocolForwarding.Step unprotectedDenied.configuration
      (unprotectedDenied.sourceCase.egressReady unprotectedDenied.configuration) .forwardWithoutEncap unprotectedDenied.physicalReady :=
    .unprotectedMACsec unprotectedDenied.sourceCase.mac (by exact of_decide_eq_true rfl)
      rfl rfl rfl (Or.inl rfl)
  exact (Cslib.LTS.MTr.append_iff _).mpr
    ⟨unprotectedDenied.sourceCase.egressReady unprotectedDenied.configuration, routed, .stepL plain .refl⟩

theorem physical_egress_filter_rejects_the_plaintext_attempt (base : Deployment) :
    ¬ (unprotectedDenied.deployment base).PhysicalBoundaryAccepts unprotectedDenied.sender.id .outbound
      ((unprotectedDenied.deployment base).Observe (unprotectedDenied.packet .outbound)) := by
  apply rejected_physical_program_excludes_boundary_admission _ unprotectedDenied.inventory rfl
  exact of_decide_eq_true rfl

end TDN.Deployments.BoundaryMACsec
