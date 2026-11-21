import TDN.Deployments.SnapshotProof_GrayFirewall
import TDN.Deployments.SnapshotProof_GrayFirewallReuse
import TDN.Deployments.SnapshotProof_HeaderFiltering
import TDN.Deployments.SnapshotProof_LinkHeaderFiltering

namespace TDN.Deployments.OuterToGray_Compatibility
open Compliance

lemma gray_firewall_forward_context (base : Deployment) (processing : PacketProcessing.Inventory)
    (packet : PacketPolicy.Packet) (direction : Direction)
    (selected : if direction = .inbound then packet.ingress = "port-G" else packet.egress = "port-G") :
    (SnapshotProof_GrayFirewall.deployment base processing).HookContext
      "port-G" direction .forward packet := by
  refine ⟨SnapshotProof_GrayFirewall.inventory processing, rfl, 3,
    by simp [SnapshotProof_GrayFirewall.inventory], rfl,
    SnapshotProof_GrayFirewall.interface "port-G" "node-G" 90,
    by simp [SnapshotProof_GrayFirewall.deployment, SnapshotProof_GrayFirewall.interfaces], rfl, rfl, ?_⟩
  simpa [PacketAtHook, HookDirection, SnapshotProof_GrayFirewall.inventory,
    SnapshotProof_GrayFirewall.ifaceName] using selected

lemma rejected_wrong_level_esp_has_context (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (SnapshotProof_GrayFirewall.deployment base processing).HookContext "port-G" .inbound .forward
      { SnapshotProof_GrayFirewall.packet with destination := 40 } :=
  gray_firewall_forward_context base processing _ .inbound rfl

lemma rejected_workstation_traffic_has_context (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (SnapshotProof_GrayFirewall.deployment base processing).HookContext "port-G" .outbound .forward
      { SnapshotProof_GrayFirewall.packet with source := 100, destination := 10 } :=
  gray_firewall_forward_context base processing _ .outbound rfl

lemma rejected_gre_has_context (base : Deployment) (processing : PacketProcessing.Inventory) :
    (SnapshotProof_HeaderFiltering.deployment base processing).HookContext "out" .inbound .input
      { SnapshotProof_HeaderFiltering.packet with protocol := "gre" } := by
  refine ⟨DevicePipelineInventoryChecks.inventory processing, rfl, 1,
    by simp [DevicePipelineInventoryChecks.inventory], rfl,
    { id := "out", device := "router", zone := .black, address := some 20,
      physical := true, managementNetwork := false, mtu := some 1500 },
    by simp [SnapshotProof_HeaderFiltering.deployment, DevicePipelineInventoryChecks.deployment,
      DevicePipelineInventoryChecks.interfaces], rfl, rfl, ?_⟩
  simp [PacketAtHook, HookDirection, DevicePipelineInventoryChecks.inventory,
    DevicePipelineInventoryChecks.name, SnapshotProof_HeaderFiltering.packet]

lemma table_driven_context_inventories_are_nonempty (processing : PacketProcessing.Inventory) :
    (SnapshotProof_GrayFirewall.inventory processing).ifaces ≠ [] ∧
    (SnapshotProof_GrayFirewallReuse.inventory processing).ifaces ≠ [] ∧
    (DevicePipelineInventoryChecks.inventory processing).ifaces ≠ [] ∧
    (SnapshotProof_LinkHeaderFiltering.inventory processing).ifaces ≠ [] ∧
    (SnapshotProof_LinkHeaderFiltering.installedInventory processing).ifaces ≠ [] := by
  simp [SnapshotProof_GrayFirewall.inventory,
    SnapshotProof_GrayFirewallReuse.inventory,
    DevicePipelineInventoryChecks.inventory, SnapshotProof_LinkHeaderFiltering.inventory,
    SnapshotProof_LinkHeaderFiltering.installedInventory]

end TDN.Deployments.OuterToGray_Compatibility
