import TDN.Evidence.CompleteGrayFirewall
import TDN.Evidence.CompleteGrayFirewallReuse
import TDN.Evidence.CompleteAddressing
import TDN.Evidence.CompleteLinkAddressing
import TDN.Evidence.CompleteThirdPartyApplications
import TDN.Evidence.CompleteHeaderFiltering
import TDN.Evidence.CompleteLinkHeaderFiltering

namespace TDN.Imported.OuterGrayCompatibility
open Compliance

lemma addressing_forward_context (base : Deployment) (processing : PacketProcessing.Inventory)
    (packet : PacketPolicy.Packet) (egress : packet.egress = "port-O") :
    (CompleteAddressing.deployment base processing).HookContext "port-O" .outbound .forward packet := by
  refine ⟨CompleteAddressing.inventory processing, rfl, 3,
    by simp [CompleteAddressing.inventory], rfl,
    CompleteAddressing.interface "port-O" "OUTER-A" 30,
    by simp [CompleteAddressing.deployment, CompleteAddressing.interfaces], rfl, rfl, ?_⟩
  simp [PacketAtHook, HookDirection, CompleteAddressing.inventory, CompleteAddressing.ifaceName, egress]

lemma rejected_cross_level_ESP_has_context (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (CompleteAddressing.deployment base processing).HookContext "port-O" .outbound .forward
      { CompleteAddressing.packet with destination := 40 } :=
  addressing_forward_context base processing _ rfl

lemma rejected_vendor_emission_has_context (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (CompleteThirdPartyApplications.deployment base processing).HookContext
      "port-O" .outbound .forward CompleteThirdPartyApplications.vendorPacket :=
  addressing_forward_context base processing _ rfl

lemma gray_firewall_forward_context (base : Deployment) (processing : PacketProcessing.Inventory)
    (packet : PacketPolicy.Packet) (direction : Direction)
    (selected : if direction = .inbound then packet.ingress = "port-G" else packet.egress = "port-G") :
    (CompleteGrayFirewall.deployment base processing).HookContext
      "port-G" direction .forward packet := by
  refine ⟨CompleteGrayFirewall.inventory processing, rfl, 3,
    by simp [CompleteGrayFirewall.inventory], rfl,
    CompleteGrayFirewall.interface "port-G" "node-G" 90,
    by simp [CompleteGrayFirewall.deployment, CompleteGrayFirewall.interfaces], rfl, rfl, ?_⟩
  simpa [PacketAtHook, HookDirection, CompleteGrayFirewall.inventory,
    CompleteGrayFirewall.ifaceName] using selected

lemma rejected_wrong_level_ESP_has_context (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (CompleteGrayFirewall.deployment base processing).HookContext "port-G" .inbound .forward
      { CompleteGrayFirewall.packet with destination := 40 } :=
  gray_firewall_forward_context base processing _ .inbound rfl

lemma rejected_workstation_traffic_has_context (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (CompleteGrayFirewall.deployment base processing).HookContext "port-G" .outbound .forward
      { CompleteGrayFirewall.packet with source := 100, destination := 10 } :=
  gray_firewall_forward_context base processing _ .outbound rfl

lemma rejected_cross_level_Ethernet_has_context (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (CompleteLinkAddressing.deployment base processing).HookContext "port-O" .outbound .link
      { CompleteLinkAddressing.packet with destination := 404 } := by
  refine ⟨CompleteLinkAddressing.inventory processing, rfl, 3,
    by simp [CompleteLinkAddressing.inventory, CompleteAddressing.inventory], rfl,
    CompleteLinkAddressing.interface "port-O" "OUTER-A" 30 303,
    by simp [CompleteLinkAddressing.deployment, CompleteLinkAddressing.interfaces], rfl, rfl, ?_⟩
  simp [PacketAtHook, HookDirection, CompleteLinkAddressing.inventory, CompleteAddressing.inventory,
    CompleteAddressing.ifaceName, CompleteLinkAddressing.packet]

lemma rejected_GRE_has_context (base : Deployment) (processing : PacketProcessing.Inventory) :
    (CompleteHeaderFiltering.deployment base processing).HookContext "out" .inbound .input
      { CompleteHeaderFiltering.packet with protocol := "gre" } := by
  refine ⟨ProcessingInventoryChecks.inventory processing, rfl, 1,
    by simp [ProcessingInventoryChecks.inventory], rfl,
    { id := "out", device := "router", zone := .black, address := some 20,
      physical := true, managementNetwork := false, mtu := some 1500 },
    by simp [CompleteHeaderFiltering.deployment, ProcessingInventoryChecks.deployment,
      ProcessingInventoryChecks.interfaces], rfl, rfl, ?_⟩
  simp [PacketAtHook, HookDirection, ProcessingInventoryChecks.inventory,
    ProcessingInventoryChecks.name, CompleteHeaderFiltering.packet]

lemma finite_context_inventories_are_nonempty (processing : PacketProcessing.Inventory) :
    (CompleteAddressing.inventory processing).ifaces ≠ [] ∧
    (CompleteGrayFirewall.inventory processing).ifaces ≠ [] ∧
    (CompleteGrayFirewallReuse.inventory processing).ifaces ≠ [] ∧
    (CompleteLinkAddressing.inventory processing).ifaces ≠ [] ∧
    (ProcessingInventoryChecks.inventory processing).ifaces ≠ [] ∧
    (CompleteLinkHeaderFiltering.inventory processing).ifaces ≠ [] ∧
    (CompleteLinkHeaderFiltering.installedInventory processing).ifaces ≠ [] := by
  simp [CompleteAddressing.inventory, CompleteGrayFirewall.inventory,
    CompleteGrayFirewallReuse.inventory, CompleteLinkAddressing.inventory,
    ProcessingInventoryChecks.inventory, CompleteLinkHeaderFiltering.inventory,
    CompleteLinkHeaderFiltering.installedInventory]

end TDN.Imported.OuterGrayCompatibility
