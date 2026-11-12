import TDN.Deployments.NativeCheckDefaults
import TDN.Import.NativeDecide
import TDN.Deployments.DeviceForwardingEligibility
import TDN.Deployments.Perimeter_BaselineData
import TDN.Deployments.Perimeter_SharedData
import TDN.Requirements.GrayFirewallAllowlistSpec
import TDN.Requirements.GrayFirewallBypassCounterexample
import TDN.Requirements.PermittedGrayForwardingFlows

namespace TDN.Deployments.GrayFirewallDiagnosis
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_ForwardCases DeviceForwardingEligibility

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option synthInstance.maxSize 2048

deriving instance DecidableEq for Device

local instance (base : Deployment) :
    DecidableRel (Perimeter_Shared.deployment base).intendedPeer := by
  intro source destination
  change Decidable (∃ tunnel ∈ Perimeter_Shared.records.tunnels,
    tunnel.sender = source ∧ tunnel.receiver = destination)
  infer_instance

local instance (base : Deployment) :
    DecidableRel (Perimeter_Baseline.deployment base).intendedPeer := by
  intro source destination
  change Decidable (∃ tunnel ∈ Perimeter_Baseline.records.tunnels,
    tunnel.sender = source ∧ tunnel.receiver = destination)
  infer_instance

local instance (base : Deployment) (interface : String) :
    DecidablePred ((Perimeter_Shared.deployment base).reachableSource interface) := by
  change DecidablePred (Perimeter_Shared.records.reachableSource interface)
  infer_instance

local instance (base : Deployment) (interface : String) :
    DecidablePred ((Perimeter_Baseline.deployment base).reachableSource interface) := by
  change DecidablePred (Perimeter_Baseline.records.reachableSource interface)
  infer_instance

instance instDecidableRegisteredReachableSourceForDiagnosis
    (records : Records) (services : List ServiceRegistration)
    (endpoints : List RedServiceEndpoint) (base : Deployment)
    (controls : List BoundaryControlFlow) (interface : String) :
    DecidablePred ((Perimeter_DeviceModel.registeredDeployment records services endpoints base controls).reachableSource interface) := by
  change DecidablePred (records.reachableSource interface)
  infer_instance

load_network_records sharedReply : ForwardCase from "../../data/evidence/continuation/GrayFirewallDiagnosis.json" ["sharedReply"]
load_network_records sharedPair : InnerIPsecPair from "../../data/evidence/continuation/GrayFirewallDiagnosis.json" ["sharedPair"]
load_network_records sharedGuard : PacketPolicy.Rule from "../../data/evidence/continuation/GrayFirewallDiagnosis.json" ["sharedReplyGuard"]
load_network_records baselineESP : ForwardCase from "../../data/evidence/continuation/GrayFirewallDiagnosis.json" ["baselineESP"]
load_network_records baselinePair : InnerIPsecPair from "../../data/evidence/continuation/GrayFirewallDiagnosis.json" ["baselinePair"]
load_network_records baselineGuard : PacketPolicy.Rule from "../../data/evidence/continuation/GrayFirewallDiagnosis.json" ["baselineESPGuard"]

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
  exact Perimeter_TransformCases.fresh_observed_packet_is_supported d _ rfl

lemma shared_address_inventory (base : Deployment) :
    (Perimeter_Shared.deployment base).AddressInventoryCoherent := by
  apply address_inventory_from_checked_records (Perimeter_Shared.deployment base) rfl
  apply gray_workstation_role_is_empty (Perimeter_Shared.deployment base)
  · unfold_check_parameters; native_decide
  · rfl

lemma baseline_address_inventory (base : Deployment) :
    (Perimeter_Baseline.deployment base).AddressInventoryCoherent := by
  apply address_inventory_from_checked_records (Perimeter_Baseline.deployment base) rfl
  apply gray_workstation_role_is_empty (Perimeter_Baseline.deployment base)
  · unfold_check_parameters; native_decide
  · rfl

theorem shared_IKE_reply_is_eligible (base : Deployment) :
    (Perimeter_Shared.deployment base).PacketEligibleAt sharedReply.interface .inbound .forward
      ((Perimeter_Shared.deployment base).Observe (sharedReply.packet Perimeter_Shared.records)) := by
  apply checked_forward_context_is_eligible sharedReply Perimeter_Shared.records
    (Perimeter_Shared.deployment base) rfl rfl .inbound
  unfold_check_parameters; native_decide

theorem shared_IKE_reply_has_required_allowance (base : Deployment) :
    GrayFirewallRestrictions (Perimeter_Shared.deployment base) sharedReply.interface .inbound
        ((Perimeter_Shared.deployment base).Observe (sharedReply.packet Perimeter_Shared.records)) ∧
      GrayPolicyAllowance (Perimeter_Shared.deployment base) sharedReply.interface
        ((Perimeter_Shared.deployment base).Observe (sharedReply.packet Perimeter_Shared.records)) := by
  apply checked_form_satisfies_requirement sharedReply Perimeter_Shared.records
    (Perimeter_Shared.deployment base) "g1" .inbound sharedPair sharedGuard
    (shared_address_inventory base) rfl
  close_check_with emptyDeploymentForChecks; native_decide

theorem shared_IKE_reply_is_denied (base : Deployment) :
    ¬ (Perimeter_Shared.deployment base).AcceptsAt sharedReply.interface.id .inbound .forward
      ((Perimeter_Shared.deployment base).Observe (sharedReply.packet Perimeter_Shared.records)) := by
  apply checked_forward_hook_is_denied
  unfold_check_parameters; native_decide

theorem baseline_same_interface_ESP_is_eligible (base : Deployment) :
    (Perimeter_Baseline.deployment base).PacketEligibleAt baselineESP.interface .inbound .forward
      ((Perimeter_Baseline.deployment base).Observe (baselineESP.packet Perimeter_Baseline.records)) := by
  apply checked_forward_context_is_eligible baselineESP Perimeter_Baseline.records
    (Perimeter_Baseline.deployment base) rfl rfl .inbound
  unfold_check_parameters; native_decide

theorem baseline_same_interface_ESP_fails_required_source_check (base : Deployment) :
    ¬ (Perimeter_Baseline.deployment base).reachableSource baselineESP.interface.id
      (baselineESP.packet Perimeter_Baseline.records).source := by
  change ¬ Perimeter_Baseline.records.reachableSource baselineESP.interface.id
    (baselineESP.packet Perimeter_Baseline.records).source
  native_decide

theorem baseline_same_interface_ESP_fails_inbound_restrictions (base : Deployment) :
    ¬ GrayFirewallRestrictions (Perimeter_Baseline.deployment base) baselineESP.interface .inbound
      ((Perimeter_Baseline.deployment base).Observe (baselineESP.packet Perimeter_Baseline.records)) := by
  intro restrictions
  exact baseline_same_interface_ESP_fails_required_source_check base (restrictions.2.2.2.1 rfl)

theorem baseline_same_interface_ESP_is_denied (base : Deployment) :
    ¬ (Perimeter_Baseline.deployment base).AcceptsAt baselineESP.interface.id .inbound .forward
      ((Perimeter_Baseline.deployment base).Observe (baselineESP.packet Perimeter_Baseline.records)) := by
  apply checked_forward_hook_is_denied
  unfold_check_parameters; native_decide


theorem baseline_same_interface_ESP_is_outbound_eligible (base : Deployment) :
    (Perimeter_Baseline.deployment base).PacketEligibleAt baselineESP.interface .outbound .forward
      ((Perimeter_Baseline.deployment base).Observe (baselineESP.packet Perimeter_Baseline.records)) := by
  apply checked_forward_context_is_eligible baselineESP Perimeter_Baseline.records
    (Perimeter_Baseline.deployment base) rfl rfl .outbound
  unfold_check_parameters; native_decide

theorem baseline_same_interface_ESP_has_current_outbound_allowance (base : Deployment) :
    GrayFirewallRestrictions (Perimeter_Baseline.deployment base) baselineESP.interface .outbound
        ((Perimeter_Baseline.deployment base).Observe (baselineESP.packet Perimeter_Baseline.records)) ∧
      GrayPolicyAllowance (Perimeter_Baseline.deployment base) baselineESP.interface
        ((Perimeter_Baseline.deployment base).Observe (baselineESP.packet Perimeter_Baseline.records)) := by
  apply checked_form_satisfies_requirement baselineESP Perimeter_Baseline.records
    (Perimeter_Baseline.deployment base) "s1" .outbound baselinePair baselineGuard
    (baseline_address_inventory base) rfl
  close_check_with emptyDeploymentForChecks; native_decide

theorem baseline_same_interface_ESP_is_outbound_denied (base : Deployment) :
    ¬ (Perimeter_Baseline.deployment base).AcceptsAt baselineESP.interface.id .outbound .forward
      ((Perimeter_Baseline.deployment base).Observe (baselineESP.packet Perimeter_Baseline.records)) := by
  apply checked_forward_hook_is_denied
  unfold_check_parameters; native_decide


theorem before_repair_shared_reply_fixture_refutes_complete_spec (base : Deployment) :
    ¬ msc_gray_firewall_allowlist_before_forward_source_check (Perimeter_Shared.deployment base) true := by
  apply missing_required_Gray_allowance_refutes_complete_spec (Perimeter_Shared.deployment base)
    rfl sharedReply.interface
  · close_check_with emptyDeploymentForChecks; native_decide
  · unfold Deployment.IsDevice
    unfold_check_parameters; native_decide
  · exact shared_IKE_reply_is_eligible base
  · exact (shared_IKE_reply_has_required_allowance base).1
  · exact (shared_IKE_reply_has_required_allowance base).2
  · exact shared_IKE_reply_is_denied base

theorem before_repair_baseline_outbound_fixture_refutes_complete_spec (base : Deployment) :
    ¬ msc_gray_firewall_allowlist_before_forward_source_check (Perimeter_Baseline.deployment base) true := by
  apply missing_required_Gray_allowance_refutes_complete_spec (Perimeter_Baseline.deployment base)
    rfl baselineESP.interface
  · close_check_with emptyDeploymentForChecks; native_decide
  · unfold Deployment.IsDevice
    unfold_check_parameters; native_decide
  · exact baseline_same_interface_ESP_is_outbound_eligible base
  · exact (baseline_same_interface_ESP_has_current_outbound_allowance base).1
  · exact (baseline_same_interface_ESP_has_current_outbound_allowance base).2
  · exact baseline_same_interface_ESP_is_outbound_denied base


theorem shared_reply_retains_actual_incoming_source_permission (base : Deployment) :
    (Perimeter_Shared.deployment base).GrayForwardPermission sharedReply.interface .forward
      ((Perimeter_Shared.deployment base).Observe (sharedReply.packet Perimeter_Shared.records)) := by
  intro _
  close_check_with emptyDeploymentForChecks; native_decide

theorem baseline_bad_source_has_no_forward_permission (base : Deployment) :
    ¬ (Perimeter_Baseline.deployment base).GrayForwardPermission baselineESP.interface .forward
      ((Perimeter_Baseline.deployment base).Observe (baselineESP.packet Perimeter_Baseline.records)) := by
  letI : ∀ interface, DecidablePred ((Perimeter_Baseline.deployment base).reachableSource interface) := by
    intro interface
    change DecidablePred (Perimeter_Baseline.records.reachableSource interface)
    infer_instance
  have excluded : ¬ (Perimeter_Baseline.deployment base).ForwardIngressSourceAllowed
      baselineESP.interface.device (baselineESP.packet Perimeter_Baseline.records) := by
    unfold_check_parameters; native_decide
  intro permission
  exact excluded (permission rfl)

end TDN.Deployments.GrayFirewallDiagnosis
