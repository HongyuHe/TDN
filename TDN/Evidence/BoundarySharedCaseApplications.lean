import TDN.Evidence.BoundarySharedCases
import TDN.Evidence.BoundarySharedInventory

namespace TDN.Imported.BoundaryShared
open Compliance Targets Targets.Complete OuterGrayNativeModel BoundaryNativeModel BoundaryForwardCases

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem redHTTP_is_accepted_at_actual_forward_hook (base : Deployment) :
    (deployment base).AcceptsAt redHTTP.interface.id .inbound .forward
      ((deployment base).Observe (redHTTP.packet records)) :=
  checked_forward_context_is_accepted redHTTP records (deployment base) rfl rfl rfl interface_ids_unique
    .inbound (local_hook_checks base).1 (redHTTP_ordered_allowance base)

theorem firewallInside_is_accepted_at_actual_forward_hook (base : Deployment) :
    (deployment base).AcceptsAt firewallInside.interface.id .inbound .forward
      ((deployment base).Observe (firewallInside.packet records)) :=
  checked_forward_context_is_accepted firewallInside records (deployment base) rfl rfl rfl interface_ids_unique
    .inbound (local_hook_checks base).2.2.1 (firewallInside_ordered_allowance base)

theorem firewallOutsideOutput_is_accepted_at_actual_forward_hook (base : Deployment) :
    (deployment base).AcceptsAt firewallOutsideOutput.interface.id .outbound .forward
      ((deployment base).Observe (firewallOutsideOutput.packet records)) :=
  checked_forward_context_is_accepted firewallOutsideOutput records (deployment base) rfl rfl rfl interface_ids_unique
    .outbound (local_hook_checks base).2.2.2.1 (firewallOutsideOutput_ordered_allowance base)

theorem firewallOutsideInput_is_accepted_at_actual_forward_hook (base : Deployment) :
    (deployment base).AcceptsAt firewallOutsideInput.interface.id .inbound .forward
      ((deployment base).Observe (firewallOutsideInput.packet records)) :=
  checked_forward_context_is_accepted firewallOutsideInput records (deployment base) rfl rfl rfl interface_ids_unique
    .inbound (local_hook_checks base).2.2.2.2.1 (firewallOutsideInput_ordered_allowance base)

theorem redWrongPort_has_real_context_and_is_denied (base : Deployment) :
    (deployment base).SupportedAt redWrongPort.interface .inbound (redWrongPort.context records)
        ((deployment base).Observe (redWrongPort.packet records)) ∧
      ¬ (deployment base).AcceptsAt redWrongPort.interface.id .inbound .forward
        ((deployment base).Observe (redWrongPort.packet records)) :=
  ⟨checked_forward_context_is_supported redWrongPort records (deployment base) rfl rfl .inbound
      (local_hook_checks base).2.1,
    checked_forward_hook_is_denied (deployment base) redWrongPort.interface.id .inbound
      ((deployment base).Observe (redWrongPort.packet records)) (redWrongPort_ordered_denial base)⟩

theorem firewallWrongSource_has_real_context_and_is_denied (base : Deployment) :
    (deployment base).SupportedAt firewallWrongSource.interface .inbound (firewallWrongSource.context records)
        ((deployment base).Observe (firewallWrongSource.packet records)) ∧
      ¬ (deployment base).AcceptsAt firewallWrongSource.interface.id .inbound .forward
        ((deployment base).Observe (firewallWrongSource.packet records)) :=
  ⟨checked_forward_context_is_supported firewallWrongSource records (deployment base) rfl rfl .inbound
      (local_hook_checks base).2.2.2.2.2,
    checked_forward_hook_is_denied (deployment base) firewallWrongSource.interface.id .inbound
      ((deployment base).Observe (firewallWrongSource.packet records)) (firewallWrongSource_ordered_denial base)⟩

lemma concrete_inventories_are_nonempty :
    services ≠ [] ∧ redEndpoints ≠ [] ∧ peers ≠ [] ∧ controls ≠ [] ∧
      records.interfaces ≠ [] ∧ records.inventory.ifaces ≠ [] := by
  exact of_decide_eq_true rfl

end TDN.Imported.BoundaryShared
