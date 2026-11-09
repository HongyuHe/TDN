import TDN.Requirements.VerifiedThirdPartyServiceDisabling
import TDN.Deployments.SnapshotProof_Addressing

namespace TDN.Deployments.SnapshotProof_ThirdPartyServices
open Compliance Requirements Requirements.Msc

def vendorPacket : PacketPolicy.Packet :=
  { SnapshotProof_Addressing.packet with
    source := 30, destination := 99, protocol := "tcp",
    sourcePort := 12000, destinationPort := 9000, ingress := "port-O" }

def feature (enabled : Bool) : ThirdPartyFeature :=
  ⟨"OUTER-A", "vendor-telemetry", true, enabled, fun traffic => traffic.packet = vendorPacket⟩

abbrev deployment := SnapshotProof_Addressing.deployment

theorem blocking_model_RG037 (base : Deployment) (processing : PacketProcessing.Inventory) :
    msc_outer_third_party_services (deployment base processing) (fun _ => false) [feature true] := by
  apply third_party_services_from_disabled_features_and_rule_checks
  · simp
  · intro item member _ _ _ traffic emitted
    simp only [List.mem_singleton] at member
    subst item
    have packet : traffic.packet = vendorPacket := emitted
    simp [packet, vendorPacket]
  · simp [deployment, SnapshotProof_Addressing.deployment, SnapshotProof_Addressing.policies, SnapshotProof_Addressing.interfaces]
  · intro item member _ _ _ iface _ _ policy present _ _ rule inRules _ traffic emitted
    simp only [List.mem_singleton] at member
    subst item
    have packet : traffic.packet = vendorPacket := emitted
    simp only [deployment, SnapshotProof_Addressing.deployment, SnapshotProof_Addressing.policies,
      List.mem_flatMap] at present
    obtain ⟨source, _, selected⟩ := present
    simp only [List.mem_cons, List.not_mem_nil, or_false] at selected
    rcases selected with rfl | rfl | rfl | rfl
    all_goals
      simp only [SnapshotProof_Addressing.rules, List.mem_cons, List.not_mem_nil, or_false] at inRules
      rcases inRules with rfl | rfl
      all_goals simp [PacketPolicy.Rule.toFilter, PacketPolicy.MatchCondition.matchesPacket, vendorPacket, packet]

theorem disabled_model_RG037 (base : Deployment) (processing : PacketProcessing.Inventory) :
    msc_outer_third_party_services (deployment base processing) (fun _ => true) [feature false] := by
  apply third_party_services_from_disabled_features_and_rule_checks
  · simp [feature]
  · simp
  · simp [deployment, SnapshotProof_Addressing.deployment, SnapshotProof_Addressing.policies, SnapshotProof_Addressing.interfaces]
  · simp

lemma nonempty_feature_has_actual_emission (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    ∃ item ∈ [feature true], item.canContactThirdParty = true ∧
      item.emittedTraffic ((deployment base processing).Observe vendorPacket) := by
  exact ⟨feature true, by simp, rfl, rfl⟩

lemma unrelated_protected_packet_is_admitted (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (deployment base processing).Accepts "port-O" .outbound
      ((deployment base processing).Observe SnapshotProof_Addressing.packet) :=
  SnapshotProof_Addressing.intended_protected_packet_is_accepted base processing

lemma vendor_packet_is_blocked (base : Deployment) (processing : PacketProcessing.Inventory) :
    ¬ (deployment base processing).Accepts "port-O" .outbound
      ((deployment base processing).Observe vendorPacket) := by
  have complete := blocking_model_RG037 base processing
  exact complete (feature true) (by simp) (Or.inl rfl)
    ⟨⟨"OUTER-A", "A", .vpn, some .outer, SnapshotProof_Addressing.level, true⟩,
      by simp [deployment, SnapshotProof_Addressing.deployment, SnapshotProof_Addressing.devices], rfl, rfl⟩
    rfl (SnapshotProof_Addressing.interface "port-O" "OUTER-A" 30)
    (by simp [deployment, SnapshotProof_Addressing.deployment, SnapshotProof_Addressing.interfaces])
    (Or.inl rfl) rfl _ rfl

def badRule : PacketPolicy.Rule :=
  ⟨[.sourceRange 30 30, .destinationRange 99 99, .protocol "tcp"], .allow⟩

lemma admitting_vendor_rule_violates_exclusion :
    badRule.toFilter.accepts vendorPacket = true ∧
    ¬ badRule.toFilter.accepts vendorPacket = false := by
  decide

lemma objective_enabled_mutation_fails (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    ¬ msc_outer_third_party_services (deployment base processing) (fun _ => true) [feature true] := by
  intro complete
  have invalid := complete (feature true) (by simp) (Or.inl rfl)
    ⟨⟨"OUTER-A", "A", .vpn, some .outer, SnapshotProof_Addressing.level, true⟩,
      by simp [deployment, SnapshotProof_Addressing.deployment, SnapshotProof_Addressing.devices], rfl, rfl⟩ rfl
  exact Bool.noConfusion invalid

end TDN.Deployments.SnapshotProof_ThirdPartyServices
