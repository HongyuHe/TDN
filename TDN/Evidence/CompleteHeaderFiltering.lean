import TDN.Targets.LinkHeaderFiltering
import TDN.Evidence.ProcessingInventoryChecks

namespace TDN.Imported.CompleteHeaderFiltering
open Compliance Targets Targets.Complete Targets.PolicyDerivation

def level : SecurityLevel := ⟨"secret", ∅, ∅, ∅⟩

def deployment (base : Deployment) (processing : PacketProcessing.Inventory) : Deployment :=
  { ProcessingInventoryChecks.deployment base processing with
    devices := [⟨"router", "site", .vpn, some .outer, level, true⟩],
    services := [], managementExchanges := [], managementHistory := [],
    grayWorkstation := fun _ => False, dropIPv4Options := fun _ => false }

theorem routed_ipv4_RG038 (base : Deployment) (processing : PacketProcessing.Inventory) :
    msc_ip_header_and_multicast_filtering (deployment base processing) (fun _ => false) := by
  apply ip_and_link_header_filtering_from_inventory_and_rule_atoms (deployment base processing)
    (ProcessingInventoryChecks.inventory processing) (fun _ => false)
  · intro _
    rfl
  · rfl
  · rfl
  · funext component
    simp [deployment, grayWorkstationRole, Deployment.IsDevice]
  · rfl
  · rfl
  · funext port address
    simp [deployment, ProcessingInventoryChecks.deployment, ProcessingInventoryChecks.inventory,
      nativeLocalAddress, ProcessingInventoryChecks.interfaces]
  · rfl
  · rfl
  · simp [LinkPolicyRecordChecks, Deployment.LinkPath, ProcessingInventoryChecks.inventory]
  · simp [LinkHeaderPolicyChecks, ProcessingInventoryChecks.inventory, LinkAdmission.lookup]
  · intro interface member endpoint endpointMember
    simp [ProcessingInventoryChecks.inventory] at endpointMember

def packet : PacketPolicy.Packet :=
  { source := 10, destination := 20, protocol := "esp", ingress := "in", egress := "out",
    sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 5, inboundPolicies := [],
    outboundPolicies := [], connectionState := "new" }

lemma permitted_esp_is_accepted (base : Deployment) (processing : PacketProcessing.Inventory) :
    (deployment base processing).Accepts "out" .inbound
      ((deployment base processing).Observe packet) := by
  refine ⟨.input, ⟨rfl, ?_⟩, ?_⟩
  · change (deployment base processing).ManagementMetadataBound packet
    simp [Deployment.ManagementMetadataBound, PacketClass, PacketService, PacketIKE,
      PacketMKA, PacketARP, packet]
  · simp [deployment, ProcessingInventoryChecks.deployment, ProcessingInventoryChecks.policies,
      ProcessingInventoryChecks.interfaces, ProcessingInventoryChecks.rules,
      InterfacePolicy.Accepts, PacketPolicy.Rule.toFilter, Filter.evaluate,
      PacketPolicy.Atom.holds, Deployment.Observe, packet]

lemma gre_is_rejected (base : Deployment) (processing : PacketProcessing.Inventory) :
    ¬ (deployment base processing).Accepts "out" .inbound
      ((deployment base processing).Observe { packet with protocol := "gre" }) := by
  rintro ⟨hook, _, accepts⟩
  cases hook with
  | link =>
    exact routed_port_has_no_link_operation (deployment base processing)
      (ProcessingInventoryChecks.inventory processing) rfl "out"
      (by intro port _ _; simp [RoutedPort, ProcessingInventoryChecks.inventory]) .inbound _ accepts
  | input | output | forward =>
    simp [deployment, ProcessingInventoryChecks.deployment, ProcessingInventoryChecks.policies,
      ProcessingInventoryChecks.interfaces, ProcessingInventoryChecks.rules,
      InterfacePolicy.Accepts, PacketPolicy.Rule.toFilter, Filter.evaluate,
      PacketPolicy.Atom.holds, Deployment.Observe, packet] at accepts

lemma multicast_range_fails_guard :
    ¬ RuleUnicastGuard
      ⟨[.sourceRange 0 100, .destinationRange (224 * 2^24) (239 * 2^24), .protocol "esp"], .allow⟩ := by
  decide

lemma unknown_protocol_fails_guard :
    ¬ RuleHeaderGuard ⟨[.sourceRange 0 100, .destinationRange 0 100, .protocol "gre"], .allow⟩ := by
  decide

def ipv6Rule : PacketPolicy.Rule :=
  ⟨[.sourceRange (2^128) (2^128 + 100), .destinationRange (2^128) (2^128 + 100),
    .protocol "ipv6", .ipv6NextHeaders [50, 6, 17, 58]], .allow⟩

lemma ipv6_rule_checked : RuleHeaderGuard ipv6Rule ∧ RuleUnicastGuard ipv6Rule := by decide

lemma unapproved_ipv6_header_fails_guard :
    ¬ RuleHeaderGuard
      ⟨[.sourceRange (2^128) (2^128 + 100), .destinationRange (2^128) (2^128 + 100),
        .protocol "ipv6", .ipv6NextHeaders [50, 43]], .allow⟩ := by
  decide

lemma selected_options_need_actual_atom (base : Deployment) (processing : PacketProcessing.Inventory) :
    headerPoliciesChecked { deployment base processing with dropIPv4Options := fun _ => true } = false := by
  rfl

end TDN.Imported.CompleteHeaderFiltering
