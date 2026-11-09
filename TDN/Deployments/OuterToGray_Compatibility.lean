import TDN.Deployments.SnapshotProof_GrayFirewall
import TDN.Deployments.SnapshotProof_GrayFirewallReuse
import TDN.Deployments.SnapshotProof_Addressing
import TDN.Deployments.SnapshotProof_LinkAddressing
import TDN.Deployments.SnapshotProof_ThirdPartyServices
import TDN.Deployments.SnapshotProof_HeaderFiltering
import TDN.Deployments.SnapshotProof_LinkHeaderFiltering

namespace TDN.Deployments.OuterToGray_Compatibility
open Compliance

lemma addressing_forward_context (base : Deployment) (processing : PacketProcessing.Inventory)
    (packet : PacketPolicy.Packet) (egress : packet.egress = "port-O") :
    (SnapshotProof_Addressing.deployment base processing).HookContext "port-O" .outbound .forward packet := by
  refine ⟨SnapshotProof_Addressing.inventory processing, rfl, 3,
    by simp [SnapshotProof_Addressing.inventory], rfl,
    SnapshotProof_Addressing.interface "port-O" "OUTER-A" 30,
    by simp [SnapshotProof_Addressing.deployment, SnapshotProof_Addressing.interfaces], rfl, rfl, ?_⟩
  simp [PacketAtHook, HookDirection, SnapshotProof_Addressing.inventory, SnapshotProof_Addressing.ifaceName, egress]

lemma rejected_cross_level_ESP_has_context (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (SnapshotProof_Addressing.deployment base processing).HookContext "port-O" .outbound .forward
      { SnapshotProof_Addressing.packet with destination := 40 } :=
  addressing_forward_context base processing _ rfl

lemma rejected_vendor_emission_has_context (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (SnapshotProof_ThirdPartyServices.deployment base processing).HookContext
      "port-O" .outbound .forward SnapshotProof_ThirdPartyServices.vendorPacket :=
  addressing_forward_context base processing _ rfl

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

lemma rejected_wrong_level_ESP_has_context (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (SnapshotProof_GrayFirewall.deployment base processing).HookContext "port-G" .inbound .forward
      { SnapshotProof_GrayFirewall.packet with destination := 40 } :=
  gray_firewall_forward_context base processing _ .inbound rfl

lemma rejected_workstation_traffic_has_context (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (SnapshotProof_GrayFirewall.deployment base processing).HookContext "port-G" .outbound .forward
      { SnapshotProof_GrayFirewall.packet with source := 100, destination := 10 } :=
  gray_firewall_forward_context base processing _ .outbound rfl

lemma rejected_cross_level_Ethernet_has_context (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (SnapshotProof_LinkAddressing.deployment base processing).HookContext "port-O" .outbound .link
      { SnapshotProof_LinkAddressing.packet with destination := 404 } := by
  refine ⟨SnapshotProof_LinkAddressing.inventory processing, rfl, 3,
    by simp [SnapshotProof_LinkAddressing.inventory, SnapshotProof_Addressing.inventory], rfl,
    SnapshotProof_LinkAddressing.interface "port-O" "OUTER-A" 30 303,
    by simp [SnapshotProof_LinkAddressing.deployment, SnapshotProof_LinkAddressing.interfaces], rfl, rfl, ?_⟩
  simp [PacketAtHook, HookDirection, SnapshotProof_LinkAddressing.inventory, SnapshotProof_Addressing.inventory,
    SnapshotProof_Addressing.ifaceName, SnapshotProof_LinkAddressing.packet]

lemma rejected_GRE_has_context (base : Deployment) (processing : PacketProcessing.Inventory) :
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
    (SnapshotProof_Addressing.inventory processing).ifaces ≠ [] ∧
    (SnapshotProof_GrayFirewall.inventory processing).ifaces ≠ [] ∧
    (SnapshotProof_GrayFirewallReuse.inventory processing).ifaces ≠ [] ∧
    (SnapshotProof_LinkAddressing.inventory processing).ifaces ≠ [] ∧
    (DevicePipelineInventoryChecks.inventory processing).ifaces ≠ [] ∧
    (SnapshotProof_LinkHeaderFiltering.inventory processing).ifaces ≠ [] ∧
    (SnapshotProof_LinkHeaderFiltering.installedInventory processing).ifaces ≠ [] := by
  simp [SnapshotProof_Addressing.inventory, SnapshotProof_GrayFirewall.inventory,
    SnapshotProof_GrayFirewallReuse.inventory, SnapshotProof_LinkAddressing.inventory,
    DevicePipelineInventoryChecks.inventory, SnapshotProof_LinkHeaderFiltering.inventory,
    SnapshotProof_LinkHeaderFiltering.installedInventory]

end TDN.Deployments.OuterToGray_Compatibility
