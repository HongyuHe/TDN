import TDN.Deployments.DeviceCheckDefaults
import TDN.Import.CompiledDecide
import TDN.Deployments.Perimeter_BaselineControlChecks
import TDN.Deployments.Perimeter_EncapsulationTestVectors

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.Perimeter_OspfCounterexample
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel Perimeter_EncapsulationTestVectors

set_option maxRecDepth 1000000

load_network_records flow : BoundaryControlFlow from "../../data/evidence/continuation/Perimeter_OSPFCounterexample.json" ["flow"]

load_network_records interface : Interface from "../../data/evidence/continuation/Perimeter_OSPFCounterexample.json" ["interface"]
load_network_records iface : Nat from "../../data/evidence/continuation/Perimeter_OSPFCounterexample.json" ["port"]
load_network_records packet : PacketPolicy.Packet from "../../data/evidence/continuation/Perimeter_OSPFCounterexample.json" ["packet"]
load_network_records policy : InterfacePolicy from "../../data/evidence/continuation/Perimeter_OSPFCounterexample.json" ["policy"]

def priorPacketClass (packet : PacketPolicy.Packet) : TrafficClass :=
  if PacketService packet ∈ ["logging", "authentication", "administration"]
    then .management
  else if PacketService packet ∈ ["time", "dns", "dhcp"] ∨ PacketIKE packet ∨ PacketMKA packet ∨ PacketARP packet ∨
    packet.protocol ∈ ["icmp", "icmpv6", "ndp"] then .control
  else .protectedData

lemma prior_ospf_classification_was_protected_data :
    priorPacketClass packet = .protectedData := by rfl

lemma prior_ospf_classification_excluded_control_approval :
    priorPacketClass packet ≠ .control := by
  native_decide

lemma ospf_has_actual_outside_input_context (base : Deployment) :
    (Perimeter_Baseline.deployment base).HookContext interface.id .inbound .input packet := by
  refine ⟨Perimeter_Baseline.records.inventory, rfl, iface, ?_, rfl, interface, ?_, rfl, rfl, ?_⟩
  · native_decide
  · close_check_with emptyDeploymentForChecks; native_decide
  · exact ⟨Or.inl ⟨rfl, rfl⟩, rfl, rfl, rfl⟩

theorem ospf_is_admitted_by_recorded_local_input (base : Deployment) :
    (Perimeter_Baseline.deployment base).PermitsAtHook interface.id .inbound .input
      ((Perimeter_Baseline.deployment base).Observe packet) := by
  refine ⟨fresh_observed_packet_is_supported _ packet rfl,
    ospf_has_actual_outside_input_context base, ?_⟩
  refine ⟨policy, ?_, rfl, rfl, rfl, ?_, ?_⟩
  · close_check_with emptyDeploymentForChecks; native_decide
  · unfold_check_parameters; native_decide
  · change Filter.evaluate (policy.rules.map PacketPolicy.PacketAclRule.toFilter) policy.defaultVerdict packet = .allow
    native_decide

lemma corrected_ospf_classification_is_control : PacketClass packet = .control :=
  ospf_packet_class packet rfl

theorem declared_local_ospf_is_approved (base : Deployment) :
    ApprovedControl (Perimeter_Baseline.deployment base) interface.device
      ((Perimeter_Baseline.deployment base).Observe packet) := by
  refine ⟨ospf_observation_is_control _ packet rfl corrected_ospf_classification_is_control
    (Perimeter_Baseline.control_observations_checked base).2.1
    (Perimeter_Baseline.control_observations_checked base).2.2, ?_⟩
  change BoundaryControlApproval Perimeter_Baseline.controls interface.device
    ((Perimeter_Baseline.deployment base).Observe packet)
  refine ⟨flow, ?_, ?_⟩
  · native_decide
  · exact ⟨rfl, rfl, rfl, rfl, ⟨Or.inl ⟨rfl, rfl⟩, rfl, rfl, rfl⟩⟩

lemma same_ospf_tuple_with_forwarding_interfaces_is_not_approved (base : Deployment) :
    ¬ (Perimeter_Baseline.deployment base).policyApproved interface.device
      ((Perimeter_Baseline.deployment base).Observe { packet with egress := "inside" }) := by
  change ¬ BoundaryControlApproval Perimeter_Baseline.controls interface.device
    ((Perimeter_Baseline.deployment base).Observe { packet with egress := "inside" })
  rintro ⟨record, member, matched⟩
  have localHooks : ∀ record ∈ Perimeter_Baseline.controls,
      record.hook = .input ∨ record.hook = .output := by
    native_decide
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

end TDN.Deployments.Perimeter_OspfCounterexample
