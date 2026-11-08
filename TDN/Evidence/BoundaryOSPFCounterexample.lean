import TDN.Evidence.BoundaryBaselineControlChecks
import TDN.Evidence.BoundaryTransformCases

namespace TDN.Imported.BoundaryOSPFCounterexample
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryNativeModel BoundaryTransformCases

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data flow : BoundaryControlFlow from "../../data/evidence/continuation/BoundaryOSPFCounterexample.json" ["flow"]

tdn_data interface : Interface from "../../data/evidence/continuation/BoundaryOSPFCounterexample.json" ["interface"]
tdn_data iface : Nat from "../../data/evidence/continuation/BoundaryOSPFCounterexample.json" ["port"]
tdn_data packet : PacketPolicy.Packet from "../../data/evidence/continuation/BoundaryOSPFCounterexample.json" ["packet"]
tdn_data policy : InterfacePolicy from "../../data/evidence/continuation/BoundaryOSPFCounterexample.json" ["policy"]

def priorPacketClass (packet : PacketPolicy.Packet) : TrafficClass :=
  if PacketService packet ∈ ["logging", "authentication", "administration"]
    then .management
  else if PacketService packet ∈ ["time", "dns", "dhcp"] ∨ PacketIKE packet ∨ PacketMKA packet ∨ PacketARP packet ∨
    packet.protocol ∈ ["icmp", "icmpv6", "ndp"] then .control
  else .protectedData

lemma prior_OSPF_classification_was_protected_data :
    priorPacketClass packet = .protectedData := by rfl

lemma prior_OSPF_classification_excluded_control_approval :
    priorPacketClass packet ≠ .control := by
  exact of_decide_eq_true rfl

lemma OSPF_has_actual_outside_INPUT_context (base : Deployment) :
    (BoundaryBaseline.deployment base).HookContext interface.id .inbound .input packet := by
  refine ⟨BoundaryBaseline.records.inventory, rfl, iface, ?_, rfl, interface, ?_, rfl, rfl, ?_⟩
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · exact ⟨Or.inl ⟨rfl, rfl⟩, rfl, rfl, rfl⟩

theorem OSPF_is_admitted_by_recorded_local_INPUT (base : Deployment) :
    (BoundaryBaseline.deployment base).AcceptsAt interface.id .inbound .input
      ((BoundaryBaseline.deployment base).Observe packet) := by
  refine ⟨fresh_observed_packet_is_supported _ packet rfl,
    OSPF_has_actual_outside_INPUT_context base, ?_⟩
  refine ⟨policy, ?_, rfl, rfl, rfl, ?_, ?_⟩
  · exact of_decide_eq_true rfl
  · exact of_decide_eq_true rfl
  · change Filter.evaluate (policy.rules.map PacketPolicy.Rule.toFilter) policy.defaultVerdict packet = .allow
    exact of_decide_eq_true rfl

lemma corrected_OSPF_classification_is_control : PacketClass packet = .control :=
  ospf_packet_class packet rfl

theorem declared_local_OSPF_is_approved (base : Deployment) :
    ApprovedControl (BoundaryBaseline.deployment base) interface.device
      ((BoundaryBaseline.deployment base).Observe packet) := by
  refine ⟨ospf_observation_is_control _ packet rfl corrected_OSPF_classification_is_control
    (BoundaryBaseline.control_observations_checked base).2.1
    (BoundaryBaseline.control_observations_checked base).2.2, ?_⟩
  change BoundaryControlApproval BoundaryBaseline.controls interface.device
    ((BoundaryBaseline.deployment base).Observe packet)
  refine ⟨flow, ?_, ?_⟩
  · exact of_decide_eq_true rfl
  · exact ⟨rfl, rfl, rfl, rfl, ⟨Or.inl ⟨rfl, rfl⟩, rfl, rfl, rfl⟩⟩

lemma same_OSPF_tuple_with_forwarding_interfaces_is_not_approved (base : Deployment) :
    ¬ (BoundaryBaseline.deployment base).policyApproved interface.device
      ((BoundaryBaseline.deployment base).Observe { packet with egress := "inside" }) := by
  change ¬ BoundaryControlApproval BoundaryBaseline.controls interface.device
    ((BoundaryBaseline.deployment base).Observe { packet with egress := "inside" })
  rintro ⟨record, member, matched⟩
  have localHooks : ∀ record ∈ BoundaryBaseline.controls,
      record.hook = .input ∨ record.hook = .output := by
    exact of_decide_eq_true rfl
  have atHook := matched.2.2.2.2
  rcases localHooks record member with hook | hook
  · rw [hook] at atHook
    have empty := atHook.2.2.1
    change ("inside" : String) = "" at empty
    contradiction
  · rw [hook] at atHook
    have empty := atHook.2.2.1
    change ("outside" : String) = "" at empty
    contradiction

end TDN.Imported.BoundaryOSPFCounterexample
