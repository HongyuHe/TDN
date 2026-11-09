import TDN.Deployments.Perimeter_SharedData
import TDN.Deployments.Perimeter_ForwardCases

namespace TDN.Deployments.Perimeter_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel Perimeter_ForwardCases

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records redHTTP : ForwardCase from "../../data/evidence/continuation/BoundaryApplicationShared.json" ["redHTTP"]
load_network_records redWrongPort : ForwardCase from "../../data/evidence/continuation/BoundaryApplicationShared.json" ["redWrongPort"]
load_network_records firewallInside : ForwardCase from "../../data/evidence/continuation/BoundaryApplicationShared.json" ["firewallInside"]
load_network_records firewallOutsideOutput : ForwardCase from "../../data/evidence/continuation/BoundaryApplicationShared.json" ["firewallOutsideOutput"]
load_network_records firewallOutsideInput : ForwardCase from "../../data/evidence/continuation/BoundaryApplicationShared.json" ["firewallOutsideInput"]
load_network_records firewallWrongSource : ForwardCase from "../../data/evidence/continuation/BoundaryApplicationShared.json" ["firewallWrongSource"]

lemma local_hook_checks (base : Deployment) :
    ForwardHookChecks redHTTP records (deployment base) .inbound ∧
      ForwardHookChecks redWrongPort records (deployment base) .inbound ∧
      ForwardHookChecks firewallInside records (deployment base) .inbound ∧
      ForwardHookChecks firewallOutsideOutput records (deployment base) .outbound ∧
      ForwardHookChecks firewallOutsideInput records (deployment base) .inbound ∧
      ForwardHookChecks firewallWrongSource records (deployment base) .inbound := by
  exact of_decide_eq_true rfl

lemma redHTTP_ordered_allowance (base : Deployment) :
    ∀ policy ∈ (deployment base).policies, policy.interface = redHTTP.interface.id →
      policy.direction = .inbound → policy.hook = .forward →
        Filter.evaluate (policy.rules.map PacketPolicy.Rule.toFilter)
          policy.defaultVerdict (redHTTP.packet records) = .allow := by
  exact of_decide_eq_true rfl

lemma firewallInside_ordered_allowance (base : Deployment) :
    ∀ policy ∈ (deployment base).policies, policy.interface = firewallInside.interface.id →
      policy.direction = .inbound → policy.hook = .forward →
        Filter.evaluate (policy.rules.map PacketPolicy.Rule.toFilter)
          policy.defaultVerdict (firewallInside.packet records) = .allow := by
  exact of_decide_eq_true rfl

lemma firewallOutsideOutput_ordered_allowance (base : Deployment) :
    ∀ policy ∈ (deployment base).policies, policy.interface = firewallOutsideOutput.interface.id →
      policy.direction = .outbound → policy.hook = .forward →
        Filter.evaluate (policy.rules.map PacketPolicy.Rule.toFilter)
          policy.defaultVerdict (firewallOutsideOutput.packet records) = .allow := by
  exact of_decide_eq_true rfl

lemma firewallOutsideInput_ordered_allowance (base : Deployment) :
    ∀ policy ∈ (deployment base).policies, policy.interface = firewallOutsideInput.interface.id →
      policy.direction = .inbound → policy.hook = .forward →
        Filter.evaluate (policy.rules.map PacketPolicy.Rule.toFilter)
          policy.defaultVerdict (firewallOutsideInput.packet records) = .allow := by
  exact of_decide_eq_true rfl

lemma redWrongPort_ordered_denial (base : Deployment) :
    ∀ policy ∈ (deployment base).policies, policy.interface = redWrongPort.interface.id →
      policy.direction = .inbound → policy.hook = .forward →
        Filter.evaluate (policy.rules.map PacketPolicy.Rule.toFilter)
          policy.defaultVerdict (redWrongPort.packet records) = .deny := by
  exact of_decide_eq_true rfl

lemma firewallWrongSource_ordered_denial (base : Deployment) :
    ∀ policy ∈ (deployment base).policies, policy.interface = firewallWrongSource.interface.id →
      policy.direction = .inbound → policy.hook = .forward →
        Filter.evaluate (policy.rules.map PacketPolicy.Rule.toFilter)
          policy.defaultVerdict (firewallWrongSource.packet records) = .deny := by
  exact of_decide_eq_true rfl

end TDN.Deployments.Perimeter_Shared
