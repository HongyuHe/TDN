import TDN.Deployments.Perimeter_SharedTestVectors
import TDN.Deployments.Perimeter_SharedInventory

namespace TDN.Deployments.Perimeter_Shared
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel Perimeter_DeviceModel Perimeter_ForwardingTestVectors

set_option maxRecDepth 1000000

theorem red_http_is_accepted_at_actual_forward_hook (base : Deployment) :
    (deployment base).PermitsAtHook redHTTP.interface.id .inbound .forward
      ((deployment base).Observe (redHTTP.packet records)) :=
  checked_forward_context_is_accepted redHTTP records (deployment base) rfl rfl rfl interface_ids_unique
    .inbound (local_hook_checks base).1 (red_http_ordered_allowance base)

theorem firewall_inside_is_accepted_at_actual_forward_hook (base : Deployment) :
    (deployment base).PermitsAtHook firewallInside.interface.id .inbound .forward
      ((deployment base).Observe (firewallInside.packet records)) :=
  checked_forward_context_is_accepted firewallInside records (deployment base) rfl rfl rfl interface_ids_unique
    .inbound (local_hook_checks base).2.2.1 (firewall_inside_ordered_allowance base)

theorem firewall_outside_output_is_accepted_at_actual_forward_hook (base : Deployment) :
    (deployment base).PermitsAtHook firewallOutsideOutput.interface.id .outbound .forward
      ((deployment base).Observe (firewallOutsideOutput.packet records)) :=
  checked_forward_context_is_accepted firewallOutsideOutput records (deployment base) rfl rfl rfl interface_ids_unique
    .outbound (local_hook_checks base).2.2.2.1 (firewall_outside_output_ordered_allowance base)

theorem firewall_outside_input_is_accepted_at_actual_forward_hook (base : Deployment) :
    (deployment base).PermitsAtHook firewallOutsideInput.interface.id .inbound .forward
      ((deployment base).Observe (firewallOutsideInput.packet records)) :=
  checked_forward_context_is_accepted firewallOutsideInput records (deployment base) rfl rfl rfl interface_ids_unique
    .inbound (local_hook_checks base).2.2.2.2.1 (firewall_outside_input_ordered_allowance base)

theorem red_wrong_port_has_real_context_and_is_denied (base : Deployment) :
    (deployment base).SupportedAt redWrongPort.interface .inbound (redWrongPort.context records)
        ((deployment base).Observe (redWrongPort.packet records)) ∧
      ¬ (deployment base).PermitsAtHook redWrongPort.interface.id .inbound .forward
        ((deployment base).Observe (redWrongPort.packet records)) :=
  ⟨checked_forward_context_is_supported redWrongPort records (deployment base) rfl rfl .inbound
      (local_hook_checks base).2.1,
    checked_forward_hook_is_denied (deployment base) redWrongPort.interface.id .inbound
      ((deployment base).Observe (redWrongPort.packet records)) (red_wrong_port_ordered_denial base)⟩

theorem firewall_wrong_source_has_real_context_and_is_denied (base : Deployment) :
    (deployment base).SupportedAt firewallWrongSource.interface .inbound (firewallWrongSource.context records)
        ((deployment base).Observe (firewallWrongSource.packet records)) ∧
      ¬ (deployment base).PermitsAtHook firewallWrongSource.interface.id .inbound .forward
        ((deployment base).Observe (firewallWrongSource.packet records)) :=
  ⟨checked_forward_context_is_supported firewallWrongSource records (deployment base) rfl rfl .inbound
      (local_hook_checks base).2.2.2.2.2,
    checked_forward_hook_is_denied (deployment base) firewallWrongSource.interface.id .inbound
      ((deployment base).Observe (firewallWrongSource.packet records)) (firewall_wrong_source_ordered_denial base)⟩

lemma concrete_inventories_are_nonempty :
    services ≠ [] ∧ redEndpoints ≠ [] ∧ peers ≠ [] ∧ controls ≠ [] ∧
      records.interfaces ≠ [] ∧ records.inventory.ifaces ≠ [] := by
  native_decide

end TDN.Deployments.Perimeter_Shared
