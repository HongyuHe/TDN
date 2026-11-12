import TDN.Import.NativeDecide
import TDN.Deployments.OuterTunnelNoBypass_BaselineNetworkData
import TDN.Deployments.MtuSizing_DeploymentCoverage

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.OuterTunnelNoBypass_BaselineNetwork
open Compliance Requirements OuterToGray_DeviceModel MtuSizing_Records

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma captured_iface_names_nodup : records.ifaceNames.Nodup := by
  native_decide

lemma captured_structure (base : Deployment) :
    ProcessingStructuralChecks (records.deployment base) records.inventory := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · unfold_check_parameters; native_decide
  · unfold_check_parameters; native_decide
  · unfold_check_parameters; native_decide
  · unfold_check_parameters; native_decide
  · exact indexed_iface_names_unique records.ifaceNames records.nativeIfaces.length rfl captured_iface_names_nodup
  · unfold_check_parameters; native_decide
  · native_decide
  · native_decide
  · native_decide

lemma captured_interface_selection :
    ∀ interface ∈ records.interfaces, records.ifaceIndex interface ∈ records.inventory.ifaces ∧
      records.ifaceName (records.ifaceIndex interface) = interface.id := by
  native_decide

lemma captured_chain_match_conditions :
    ∀ iface ∈ records.inventory.ifaces, DeviceProgramAtoms records.inventory iface := by
  native_decide

lemma captured_source_bindings : SourceBindingChecks records entries networks := by
  native_decide

lemma captured_network_sources : NetworkSourceChecks entries roles records.componentName networks flows := by
  native_decide

lemma captured_bridge_policies : BridgePolicyChecks records linkPolicies := by
  native_decide

lemma captured_tunnels : RecordedTunnelChecks records installations := by
  native_decide

lemma captured_physical_endpoints :
    ∀ edge ∈ records.links, edge.1 ∈ records.inventory.ifaces ∧ edge.2 ∈ records.inventory.ifaces := by
  native_decide

lemma captured_bridge_endpoints :
    ∀ edge ∈ records.bridges, edge.1 ∈ records.inventory.ifaces ∧ edge.2 ∈ records.inventory.ifaces := by
  native_decide

lemma captured_devices_unique :
    ∀ first ∈ records.components, ∀ second ∈ records.components, first.id = second.id → first = second := by
  have unique : (records.components.map Device.id).Nodup := by native_decide
  exact (List.nodup_map_iff_inj_on (unique.of_map Device.id)).mp unique

lemma captured_interfaces_unique : InterfaceIDsUnique records.interfaces :=
  interface_ids_unique_from_nodup records.interfaces
    (by change records.ifaceNames.Nodup; exact captured_iface_names_nodup)

lemma captured_tunnels_unique :
    ∀ first ∈ records.tunnels, ∀ second ∈ records.tunnels, first.id = second.id → first = second := by
  have unique : (records.tunnels.map Tunnel.id).Nodup := by native_decide
  exact (List.nodup_map_iff_inj_on (unique.of_map Tunnel.id)).mp unique

lemma captured_networks_nonempty : networks ≠ [] := by
  native_decide

end TDN.Deployments.OuterTunnelNoBypass_BaselineNetwork
