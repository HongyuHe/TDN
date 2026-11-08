import TDN.Evidence.OuterGrayBaselineChecks

namespace TDN.Imported.BoundaryHookCounterexamples
open Compliance Targets Targets.Complete OuterGrayNativeModel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data innerInterface : Interface from "../../data/evidence/continuation/BoundaryHookCounterexamples.json" ["innerInterface"]
tdn_data innerDevice : Device from "../../data/evidence/continuation/BoundaryHookCounterexamples.json" ["innerDevice"]
tdn_data innerIface : Nat from "../../data/evidence/continuation/BoundaryHookCounterexamples.json" ["innerIface"]
tdn_data innerPacket : PacketPolicy.Packet from "../../data/evidence/continuation/BoundaryHookCounterexamples.json" ["innerPacket"]
tdn_data innerPolicy : InterfacePolicy from "../../data/evidence/continuation/BoundaryHookCounterexamples.json" ["innerPolicy"]
tdn_data outerInterface : Interface from "../../data/evidence/continuation/BoundaryHookCounterexamples.json" ["outerInterface"]
tdn_data outerDevice : Device from "../../data/evidence/continuation/BoundaryHookCounterexamples.json" ["outerDevice"]
tdn_data outerIface : Nat from "../../data/evidence/continuation/BoundaryHookCounterexamples.json" ["outerIface"]
tdn_data outerPacket : PacketPolicy.Packet from "../../data/evidence/continuation/BoundaryHookCounterexamples.json" ["outerPacket"]
tdn_data outerPolicy : InterfacePolicy from "../../data/evidence/continuation/BoundaryHookCounterexamples.json" ["outerPolicy"]

tdn_data wrongPortPacket : PacketPolicy.Packet from "../../data/evidence/continuation/BoundaryHookCounterexamples.json" ["wrongPortPacket"]

deriving instance DecidableEq for Device

def records := OuterGrayBaseline.records

lemma inner_plaintext_is_raw_forward_admitted :
    Filter.evaluate (innerPolicy.rules.map PacketPolicy.Rule.toFilter)
      innerPolicy.defaultVerdict innerPacket = .allow := by
  exact of_decide_eq_true rfl

lemma inner_plaintext_is_supported (base : Deployment) :
    (records.deployment base).Supported ((records.deployment base).Observe innerPacket) := by
  refine ⟨rfl, ?_⟩
  intro _ established
  exact False.elim ((by decide : ("new" : String) ≠ "established") established)

lemma inner_plaintext_has_actual_Gray_outbound_context (base : Deployment) :
    (records.deployment base).HookContext innerInterface.id .outbound .forward innerPacket := by
  refine ⟨records.inventory, rfl, innerIface, ?_, rfl, innerInterface, ?_, rfl, rfl, ?_⟩
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact ⟨Or.inr (Or.inr (Or.inl rfl)), rfl⟩

lemma inner_plaintext_is_accepted_at_Gray_forward_hook (base : Deployment) :
    (records.deployment base).AcceptsAt innerInterface.id .outbound .forward
      ((records.deployment base).Observe innerPacket) := by
  refine ⟨inner_plaintext_is_supported base,
    inner_plaintext_has_actual_Gray_outbound_context base, ?_⟩
  refine ⟨innerPolicy, ?_, rfl, rfl, rfl, ?_, inner_plaintext_is_raw_forward_admitted⟩
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl

lemma inner_plaintext_is_not_permitted_boundary_tunnel (base : Deployment) :
    ¬ (records.deployment base).PermittedTunnelTraffic
      ((records.deployment base).Observe innerPacket) := by
  have protocol : ¬ IPsecProtocol ((records.deployment base).Observe innerPacket) := by
    change ¬ (innerPacket.protocol = "esp" ∨ PacketIKE innerPacket ∨ PacketUDPESP innerPacket)
    exact of_decide_eq_true rfl
  have mka : ¬ PacketMKA innerPacket := by exact of_decide_eq_true rfl
  have macsec : ¬ PacketMACsec innerPacket := by exact of_decide_eq_true rfl
  rintro (((ip | udp) | linkMKA | linkMACsec) | ⟨source, destination, binding, member, _⟩)
  · exact protocol ip
  · rcases udp with ⟨binding, member, _⟩ | ⟨binding, member, _⟩ | ⟨binding, member, _⟩
    all_goals cases member
  · exact mka linkMKA
  · exact macsec linkMACsec
  · cases member

lemma outer_pre_encryption_is_raw_forward_admitted :
    Filter.evaluate (outerPolicy.rules.map PacketPolicy.Rule.toFilter)
      outerPolicy.defaultVerdict outerPacket = .allow := by
  exact of_decide_eq_true rfl

lemma outer_pre_encryption_is_supported (base : Deployment) :
    (records.deployment base).Supported ((records.deployment base).Observe outerPacket) := by
  refine ⟨rfl, ?_⟩
  intro _ established
  exact False.elim ((by decide : ("new" : String) ≠ "established") established)

lemma outer_pre_encryption_has_actual_Black_outbound_context (base : Deployment) :
    (records.deployment base).HookContext outerInterface.id .outbound .forward outerPacket := by
  refine ⟨records.inventory, rfl, outerIface, ?_, rfl, outerInterface, ?_, rfl, rfl, ?_⟩
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact ⟨Or.inr (Or.inr (Or.inl rfl)), rfl⟩

lemma outer_pre_encryption_is_accepted_at_Black_forward_hook (base : Deployment) :
    (records.deployment base).AcceptsAt outerInterface.id .outbound .forward
      ((records.deployment base).Observe outerPacket) := by
  refine ⟨outer_pre_encryption_is_supported base,
    outer_pre_encryption_has_actual_Black_outbound_context base, ?_⟩
  refine ⟨outerPolicy, ?_, rfl, rfl, rfl, ?_, outer_pre_encryption_is_raw_forward_admitted⟩
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl

lemma outer_pre_encryption_destination_is_Inner (base : Deployment) :
    ((records.deployment base).Observe outerPacket).destinationDevice = some "V31B_I_B1" := by
  rfl

lemma outer_pre_encryption_destination_is_not_intended_Outer_peer (base : Deployment) :
    ¬ (records.deployment base).IntendedPacketPeerAt outerInterface.id outerDevice.id
      ((records.deployment base).Observe outerPacket) := by
  rintro (peer | mka)
  · rcases peer with ⟨destination, assigned, intended⟩ | ⟨binding, member, _⟩
    · have same : destination = "V31B_I_B1" :=
        Option.some.inj (assigned.symm.trans (outer_pre_encryption_destination_is_Inner base))
      subst destination
      exact (show ¬ (records.deployment base).intendedPeer outerDevice.id "V31B_I_B1" from
        by exact of_decide_eq_true rfl) intended
    · cases member
  · obtain ⟨endpoint, member, _⟩ := mka
    cases member

def prior_msc_boundary_interface_filtering (d : Deployment) (outerFirewallRequired : Bool)
    (firewallInternal : String → Bool) (localOuter : String → String) : Prop :=
  d.AddressInventoryCoherent ∧ d.ProcessingCoherent ∧ d.UDPBindingsCoherent ∧
  ∀ interface ∈ d.interfaces, d.Relevant interface.device → ∀ device ∈ d.devices, d.Relevant device.id → interface.device = device.id →
    ((device.layer = some .outer ∧ interface.zone = .black) ∨
      (device.layer = some .inner ∧ interface.zone = .gray) ∨
      (device.layer = some .inner ∧ interface.zone = .red) ∨
      (device.kind = .outerFirewall ∧ outerFirewallRequired = true)) →
    d.PolicyCoverage interface ∧ ∀ direction traffic, d.Accepts interface.id direction traffic →
      (device.layer = some .outer → interface.zone = .black →
        ((device.kind = .vpn → d.IPsecTraffic traffic ∨
          ApprovedControl d device.id traffic) ∧
        (device.kind = .macsec → PacketMACsec traffic.packet ∨
          ApprovedControl d device.id traffic) ∧
        (direction = .outbound → d.IntendedPacketPeerAt interface.id device.id traffic))) ∧
      (device.layer = some .inner → interface.zone = .gray →
        d.PermittedTunnelTraffic traffic ∨ AOApprovedControl d device.id traffic) ∧
      (device.layer = some .inner → interface.zone = .red →
        d.redService device.id traffic.packet.source traffic.packet.sourcePort ∨
        d.redService device.id traffic.packet.destination traffic.packet.destinationPort) ∧
      (device.kind = .outerFirewall → outerFirewallRequired = true →
        (d.PermittedTunnelTraffic traffic ∨ ApprovedControl d device.id traffic) ∧
        (direction = .inbound → ¬ ApprovedControl d device.id traffic →
          if firewallInternal interface.id then
            LocalOuterAddress d device.id (localOuter device.id) traffic.packet.source
          else LocalOuterAddress d device.id (localOuter device.id) traffic.packet.destination))


theorem prior_boundary_spec_rejects_the_valid_pre_encryption_hook
    (base : Deployment) (required : Bool) (internal : String → Bool)
    (localOuter : String → String) :
    ¬ prior_msc_boundary_interface_filtering (records.deployment base) required internal localOuter := by
  intro complete
  have statement := complete.2.2.2 innerInterface
    (by exact of_decide_eq_true rfl) (Or.inl rfl) innerDevice
    (by exact of_decide_eq_true rfl) (Or.inl rfl) rfl
    (Or.inr (Or.inl ⟨rfl, rfl⟩))
  have allowed := (statement.2 .outbound ((records.deployment base).Observe innerPacket)
    ⟨.forward, inner_plaintext_is_accepted_at_Gray_forward_hook base⟩).2.1 rfl rfl
  rcases allowed with tunnel | approved
  · exact inner_plaintext_is_not_permitted_boundary_tunnel base tunnel
  · exact approved.1.2

lemma wrong_service_port_is_raw_forward_admitted :
    Filter.evaluate (innerPolicy.rules.map PacketPolicy.Rule.toFilter)
      innerPolicy.defaultVerdict wrongPortPacket = .allow := by
  exact of_decide_eq_true rfl

lemma wrong_service_port_has_actual_selected_reqid :
    wrongPortPacket.outboundPolicies =
      (Execution.selectedAssociations (records.configuration.ip.outbound innerIface)
        wrongPortPacket).map Execution.Association.id := by
  exact of_decide_eq_true rfl

lemma wrong_service_port_is_supported (base : Deployment) :
    (records.deployment base).Supported ((records.deployment base).Observe wrongPortPacket) := by
  refine ⟨rfl, ?_⟩
  intro _ established
  exact False.elim ((by decide : ("new" : String) ≠ "established") established)

lemma wrong_service_port_has_actual_Gray_outbound_context (base : Deployment) :
    (records.deployment base).HookContext innerInterface.id .outbound .forward wrongPortPacket := by
  refine ⟨records.inventory, rfl, innerIface, ?_, rfl, innerInterface, ?_, rfl, rfl, ?_⟩
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact ⟨Or.inr (Or.inr (Or.inl rfl)), rfl⟩

lemma wrong_service_port_is_accepted_at_Gray_forward_hook (base : Deployment) :
    (records.deployment base).AcceptsAt innerInterface.id .outbound .forward
      ((records.deployment base).Observe wrongPortPacket) := by
  refine ⟨wrong_service_port_is_supported base,
    wrong_service_port_has_actual_Gray_outbound_context base, ?_⟩
  refine ⟨innerPolicy, ?_, rfl, rfl, rfl, ?_, wrong_service_port_is_raw_forward_admitted⟩
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl

end TDN.Imported.BoundaryHookCounterexamples
