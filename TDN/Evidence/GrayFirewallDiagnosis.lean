import TDN.Evidence.NativeForwardEligibility
import TDN.Evidence.BoundaryBaselineData
import TDN.Evidence.BoundarySharedData
import TDN.Targets.GrayFirewallRules
import TDN.Targets.GrayFirewallCounterexample
import TDN.Targets.GrayForwardAllowance

namespace TDN.Imported.GrayFirewallDiagnosis
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryForwardCases NativeForwardEligibility

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option synthInstance.maxSize 2048

deriving instance DecidableEq for Device

instance instDecidableRegisteredReachableSourceForDiagnosis
    (records : Records) (services : List ServiceRegistration)
    (endpoints : List RedServiceEndpoint) (base : Deployment)
    (controls : List BoundaryControlFlow) (interface : String) :
    DecidablePred ((BoundaryNativeModel.registeredDeployment records services endpoints base controls).reachableSource interface) := by
  change DecidablePred (records.reachableSource interface)
  infer_instance

tdn_data sharedReply : ForwardCase from "../../data/evidence/continuation/GrayFirewallDiagnosis.json" ["sharedReply"]
tdn_data sharedPair : InnerIPsecPair from "../../data/evidence/continuation/GrayFirewallDiagnosis.json" ["sharedPair"]
tdn_data sharedGuard : PacketPolicy.Rule from "../../data/evidence/continuation/GrayFirewallDiagnosis.json" ["sharedReplyGuard"]
tdn_data baselineESP : ForwardCase from "../../data/evidence/continuation/GrayFirewallDiagnosis.json" ["baselineESP"]
tdn_data baselinePair : InnerIPsecPair from "../../data/evidence/continuation/GrayFirewallDiagnosis.json" ["baselinePair"]
tdn_data baselineGuard : PacketPolicy.Rule from "../../data/evidence/continuation/GrayFirewallDiagnosis.json" ["baselineESPGuard"]

def RequiredFormChecks (sample : ForwardCase) (records : Records) (d : Deployment)
    (name : String) (direction : Direction) (pair : InnerIPsecPair) (rule : PacketPolicy.Rule) : Prop :=
  pair.Bound d ∧
    (∀ first ∈ d.devices, ∀ second ∈ d.devices, first.id = second.id → first = second) ∧
    (∀ device ∈ d.devices, device.id = sample.interface.device →
      device.kind = .grayFirewall ∧ device.layer = none) ∧
    GrayIPsecObservationChecks d ∧
    GrayIPsecRuleChecks d sample.interface name direction [pair] rule ∧
    PacketAtHook name direction .forward (sample.packet records) ∧
    rule.toFilter.accepts (sample.packet records) = true

instance (sample : ForwardCase) (records : Records) (d : Deployment)
    (name : String) (direction : Direction) (pair : InnerIPsecPair) (rule : PacketPolicy.Rule)
    [DecidableRel d.intendedPeer] [DecidablePred (d.reachableSource sample.interface.id)] :
    Decidable (RequiredFormChecks sample records d name direction pair rule) := by
  dsimp only [RequiredFormChecks, PacketAtHook, HookDirection]
  infer_instance

lemma checked_form_satisfies_requirement (sample : ForwardCase) (records : Records)
    (d : Deployment) (name : String) (direction : Direction) (pair : InnerIPsecPair) (rule : PacketPolicy.Rule)
    (coherent : d.AddressInventoryCoherent) (carrier : d.carrierBindings = [])
    (checks : RequiredFormChecks sample records d name direction pair rule) :
    GrayFirewallRestrictions d sample.interface direction (d.Observe (sample.packet records)) ∧
      GrayPolicyAllowance d sample.interface (d.Observe (sample.packet records)) := by
  obtain ⟨bound, identifiers, roles, observations, guard, context, matched⟩ := checks
  apply checked_Gray_IPsec_rule_is_safe d sample.interface name direction .forward [pair]
    (by intro record member; have same : record = pair := List.mem_singleton.mp member; exact same ▸ bound)
    identifiers roles carrier coherent observations rule guard _ _
    context matched
  exact BoundaryTransformCases.fresh_observed_packet_is_supported d _ rfl

lemma shared_address_inventory (base : Deployment) :
    (BoundaryShared.deployment base).AddressInventoryCoherent := by
  apply address_inventory_from_checked_records (BoundaryShared.deployment base) rfl
  apply gray_workstation_role_is_empty (BoundaryShared.deployment base)
  · exact of_decide_eq_true rfl
  · rfl

lemma baseline_address_inventory (base : Deployment) :
    (BoundaryBaseline.deployment base).AddressInventoryCoherent := by
  apply address_inventory_from_checked_records (BoundaryBaseline.deployment base) rfl
  apply gray_workstation_role_is_empty (BoundaryBaseline.deployment base)
  · exact of_decide_eq_true rfl
  · rfl

theorem shared_IKE_reply_is_eligible (base : Deployment) :
    (BoundaryShared.deployment base).PacketEligibleAt sharedReply.interface .inbound .forward
      ((BoundaryShared.deployment base).Observe (sharedReply.packet BoundaryShared.records)) := by
  apply checked_forward_context_is_eligible sharedReply BoundaryShared.records
    (BoundaryShared.deployment base) rfl rfl .inbound
  exact of_decide_eq_true rfl

theorem shared_IKE_reply_has_required_allowance (base : Deployment) :
    GrayFirewallRestrictions (BoundaryShared.deployment base) sharedReply.interface .inbound
        ((BoundaryShared.deployment base).Observe (sharedReply.packet BoundaryShared.records)) ∧
      GrayPolicyAllowance (BoundaryShared.deployment base) sharedReply.interface
        ((BoundaryShared.deployment base).Observe (sharedReply.packet BoundaryShared.records)) := by
  letI : DecidableRel (BoundaryShared.deployment base).intendedPeer := by
    intro source destination
    change Decidable (∃ tunnel ∈ BoundaryShared.records.tunnels,
      tunnel.sender = source ∧ tunnel.receiver = destination)
    infer_instance
  letI : DecidablePred ((BoundaryShared.deployment base).reachableSource sharedReply.interface.id) := by
    change DecidablePred (BoundaryShared.records.reachableSource sharedReply.interface.id)
    infer_instance
  apply checked_form_satisfies_requirement sharedReply BoundaryShared.records
    (BoundaryShared.deployment base) "g1" .inbound sharedPair sharedGuard
    (shared_address_inventory base) rfl
  exact of_decide_eq_true rfl

theorem shared_IKE_reply_is_denied (base : Deployment) :
    ¬ (BoundaryShared.deployment base).AcceptsAt sharedReply.interface.id .inbound .forward
      ((BoundaryShared.deployment base).Observe (sharedReply.packet BoundaryShared.records)) := by
  apply checked_forward_hook_is_denied
  exact of_decide_eq_true rfl

theorem baseline_same_interface_ESP_is_eligible (base : Deployment) :
    (BoundaryBaseline.deployment base).PacketEligibleAt baselineESP.interface .inbound .forward
      ((BoundaryBaseline.deployment base).Observe (baselineESP.packet BoundaryBaseline.records)) := by
  apply checked_forward_context_is_eligible baselineESP BoundaryBaseline.records
    (BoundaryBaseline.deployment base) rfl rfl .inbound
  exact of_decide_eq_true rfl

theorem baseline_same_interface_ESP_fails_required_source_check (base : Deployment) :
    ¬ (BoundaryBaseline.deployment base).reachableSource baselineESP.interface.id
      (baselineESP.packet BoundaryBaseline.records).source := by
  change ¬ BoundaryBaseline.records.reachableSource baselineESP.interface.id
    (baselineESP.packet BoundaryBaseline.records).source
  exact of_decide_eq_true rfl

theorem baseline_same_interface_ESP_fails_inbound_restrictions (base : Deployment) :
    ¬ GrayFirewallRestrictions (BoundaryBaseline.deployment base) baselineESP.interface .inbound
      ((BoundaryBaseline.deployment base).Observe (baselineESP.packet BoundaryBaseline.records)) := by
  intro restrictions
  exact baseline_same_interface_ESP_fails_required_source_check base (restrictions.2.2.2.1 rfl)

theorem baseline_same_interface_ESP_is_denied (base : Deployment) :
    ¬ (BoundaryBaseline.deployment base).AcceptsAt baselineESP.interface.id .inbound .forward
      ((BoundaryBaseline.deployment base).Observe (baselineESP.packet BoundaryBaseline.records)) := by
  apply checked_forward_hook_is_denied
  exact of_decide_eq_true rfl


theorem baseline_same_interface_ESP_is_outbound_eligible (base : Deployment) :
    (BoundaryBaseline.deployment base).PacketEligibleAt baselineESP.interface .outbound .forward
      ((BoundaryBaseline.deployment base).Observe (baselineESP.packet BoundaryBaseline.records)) := by
  apply checked_forward_context_is_eligible baselineESP BoundaryBaseline.records
    (BoundaryBaseline.deployment base) rfl rfl .outbound
  exact of_decide_eq_true rfl

theorem baseline_same_interface_ESP_has_current_outbound_allowance (base : Deployment) :
    GrayFirewallRestrictions (BoundaryBaseline.deployment base) baselineESP.interface .outbound
        ((BoundaryBaseline.deployment base).Observe (baselineESP.packet BoundaryBaseline.records)) ∧
      GrayPolicyAllowance (BoundaryBaseline.deployment base) baselineESP.interface
        ((BoundaryBaseline.deployment base).Observe (baselineESP.packet BoundaryBaseline.records)) := by
  letI : DecidableRel (BoundaryBaseline.deployment base).intendedPeer := by
    intro source destination
    change Decidable (∃ tunnel ∈ BoundaryBaseline.records.tunnels,
      tunnel.sender = source ∧ tunnel.receiver = destination)
    infer_instance
  letI : DecidablePred ((BoundaryBaseline.deployment base).reachableSource baselineESP.interface.id) := by
    change DecidablePred (BoundaryBaseline.records.reachableSource baselineESP.interface.id)
    infer_instance
  apply checked_form_satisfies_requirement baselineESP BoundaryBaseline.records
    (BoundaryBaseline.deployment base) "s1" .outbound baselinePair baselineGuard
    (baseline_address_inventory base) rfl
  exact of_decide_eq_true rfl

theorem baseline_same_interface_ESP_is_outbound_denied (base : Deployment) :
    ¬ (BoundaryBaseline.deployment base).AcceptsAt baselineESP.interface.id .outbound .forward
      ((BoundaryBaseline.deployment base).Observe (baselineESP.packet BoundaryBaseline.records)) := by
  apply checked_forward_hook_is_denied
  exact of_decide_eq_true rfl


theorem before_repair_shared_reply_fixture_refutes_complete_spec (base : Deployment) :
    ¬ msc_gray_firewall_allowlist_before_forward_source_check (BoundaryShared.deployment base) true := by
  apply missing_required_Gray_allowance_refutes_complete_spec (BoundaryShared.deployment base)
    rfl sharedReply.interface
  · exact of_decide_eq_true rfl
  · unfold Deployment.IsDevice
    exact of_decide_eq_true rfl
  · exact shared_IKE_reply_is_eligible base
  · exact (shared_IKE_reply_has_required_allowance base).1
  · exact (shared_IKE_reply_has_required_allowance base).2
  · exact shared_IKE_reply_is_denied base

theorem before_repair_baseline_outbound_fixture_refutes_complete_spec (base : Deployment) :
    ¬ msc_gray_firewall_allowlist_before_forward_source_check (BoundaryBaseline.deployment base) true := by
  apply missing_required_Gray_allowance_refutes_complete_spec (BoundaryBaseline.deployment base)
    rfl baselineESP.interface
  · exact of_decide_eq_true rfl
  · unfold Deployment.IsDevice
    exact of_decide_eq_true rfl
  · exact baseline_same_interface_ESP_is_outbound_eligible base
  · exact (baseline_same_interface_ESP_has_current_outbound_allowance base).1
  · exact (baseline_same_interface_ESP_has_current_outbound_allowance base).2
  · exact baseline_same_interface_ESP_is_outbound_denied base


theorem shared_reply_retains_actual_incoming_source_permission (base : Deployment) :
    (BoundaryShared.deployment base).GrayForwardPermission sharedReply.interface .forward
      ((BoundaryShared.deployment base).Observe (sharedReply.packet BoundaryShared.records)) := by
  letI : ∀ interface, DecidablePred ((BoundaryShared.deployment base).reachableSource interface) := by
    intro interface
    change DecidablePred (BoundaryShared.records.reachableSource interface)
    infer_instance
  intro _
  exact of_decide_eq_true rfl

theorem baseline_bad_source_has_no_forward_permission (base : Deployment) :
    ¬ (BoundaryBaseline.deployment base).GrayForwardPermission baselineESP.interface .forward
      ((BoundaryBaseline.deployment base).Observe (baselineESP.packet BoundaryBaseline.records)) := by
  letI : ∀ interface, DecidablePred ((BoundaryBaseline.deployment base).reachableSource interface) := by
    intro interface
    change DecidablePred (BoundaryBaseline.records.reachableSource interface)
    infer_instance
  have excluded : ¬ (BoundaryBaseline.deployment base).ForwardIngressSourceAllowed
      baselineESP.interface.device (baselineESP.packet BoundaryBaseline.records) := by
    exact of_decide_eq_true rfl
  intro permission
  exact excluded (permission rfl)

end TDN.Imported.GrayFirewallDiagnosis
