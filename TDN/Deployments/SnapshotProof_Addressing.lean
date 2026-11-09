import TDN.Requirements.VerifiedAddressingCompliance

namespace TDN.Deployments.SnapshotProof_Addressing
open Requirements Requirements.Msc Compliance

def level : SecurityLevel := ⟨"secret", ∅, ∅, ∅⟩
def otherLevel : SecurityLevel := ⟨"top-secret", ∅, ∅, ∅⟩

def devices : List Device :=
  [⟨"INNER-A", "A", .vpn, some .inner, level, true⟩,
   ⟨"INNER-B", "B", .vpn, some .inner, level, true⟩,
   ⟨"INNER-C", "C", .vpn, some .inner, otherLevel, true⟩,
   ⟨"OUTER-A", "A", .vpn, some .outer, level, true⟩]

def interface (id owner : String) (address : Nat) : Interface :=
  { id := id, device := owner, zone := .gray, address := some address,
    physical := true, managementNetwork := false }

def interfaces : List Interface :=
  [interface "port-A" "INNER-A" 10, interface "port-B" "INNER-B" 20,
    interface "port-C" "INNER-C" 40, interface "port-O" "OUTER-A" 30]

def ranges : List (Addressing.Range SecurityLevel) :=
  [⟨10, 20, level⟩, ⟨40, 40, otherLevel⟩]

def pairs : List IntendedAddressPair :=
  [⟨10, 20, level⟩, ⟨20, 10, level⟩]

def rules : List PacketPolicy.Rule :=
  [⟨[.sourceRange 10 10, .destinationRange 20 20, .protocol "esp"], .allow⟩,
   ⟨[.sourceRange 20 20, .destinationRange 10 10, .protocol "esp"], .allow⟩]

def policies : List InterfacePolicy :=
  interfaces.flatMap fun iface =>
    [⟨iface.id, .inbound, rules, .deny, .input⟩,
     ⟨iface.id, .outbound, rules, .deny, .output⟩,
     ⟨iface.id, .inbound, rules, .deny, .forward⟩,
     ⟨iface.id, .outbound, rules, .deny, .forward⟩]

def ifaceName (iface : Nat) : String :=
  if iface = 0 then "port-A" else if iface = 1 then "port-B" else if iface = 2 then "port-C" else "port-O"

def componentName (iface : Nat) : String :=
  if iface = 0 then "INNER-A" else if iface = 1 then "INNER-B" else if iface = 2 then "INNER-C" else "OUTER-A"

def inventory (base : PacketProcessing.Inventory) : PacketProcessing.Inventory :=
  { base with
    ifaces := [0, 1, 2, 3]
    ifaceName := ifaceName
    componentName := componentName
    configuration := { base.configuration with
      ip := { base.configuration.ip with owner := fun iface => iface, interfaceName := ifaceName }
      macIfaces := [], bridge := fun _ _ => False, carriers := [], linkPolicies := [] }
    mkaPeers := [] }

def deployment (base : Deployment) (processing : PacketProcessing.Inventory) : Deployment :=
  { base with
    devices := devices, interfaces := interfaces, policies := policies,
    services := [], udpBindings := [], managementExchanges := [], managementHistory := [],
    grayWorkstation := fun _ => False, processing := some (inventory processing),
    intendedPeer := fun first second =>
      (first = "INNER-A" ∧ second = "INNER-B") ∨
      (first = "INNER-B" ∧ second = "INNER-A") }

def endpoints : List Requirements.DeriveEndpointInputOutputRules.EndpointPair :=
  [⟨.internet, "INNER-A", "INNER-B", 10, 20⟩,
   ⟨.internet, "INNER-B", "INNER-A", 20, 10⟩]

theorem full_routed_RG014 (base : Deployment) (processing : PacketProcessing.Inventory) :
    msc_gray_addressing_for_level_filtering (deployment base processing) ranges pairs := by
  apply gray_addressing_from_ip_and_link_endpoint_rules
    (deployment base processing) ranges pairs endpoints (inventory processing) rfl
  · rfl
  · funext component
    simp [deployment, grayWorkstationRole, Deployment.IsDevice, devices]
  · rfl
  · decide
  · unfold Addressing.Separated ranges
    decide
  · simp [pairs, ranges, Addressing.Owns, Addressing.Contains]
  · intro iface member gray innerLayer
    simp only [deployment, interfaces, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl <;>
      simp_all [deployment, interface, devices, Deployment.IsLayer,
        ranges, Addressing.Owns, Addressing.Contains]
  · simp [endpoints, Requirements.DeriveEndpointInputOutputRules.EndpointPair.Bound,
      Requirements.DeriveEndpointInputOutputRules.AddressView.read, deployment, devices,
      interfaces, interface, pairs, Deployment.IsLayer,
      Requirements.DeriveEndpointInputOutputRules.SameLevelComponents]
  · intro iface member _ _
    simp only [deployment, interfaces, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl <;>
      simp [Requirements.DeriveEndpointInputOutputRules.admissionPrograms, deployment,
        policies, interfaces, rules, inventory, interface, LinkAdmission.lookup,
        Requirements.DeriveEndpointInputOutputRules.ProgramRuleChecks,
        Requirements.DeriveEndpointInputOutputRules.RuleEndpointGuard, endpoints,
        Requirements.DeriveEndpointInputOutputRules.AddressView.RuleGuard,
        Requirements.DeriveEndpointInputOutputRules.EthernetTypeAtom,
        DeriveDataPlaneFromDeviceRecords.RuleIPGuard, DeriveDataPlaneFromDeviceRecords.IPProtocolAtom]

def packet : PacketPolicy.Packet :=
  { source := 10, destination := 20, protocol := "esp", ingress := "port-A", egress := "port-O",
    sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 5, matchedInboundPolicyIds := [],
    matchedOutboundPolicyIds := [], connectionState := "new" }

lemma intended_protected_packet_is_accepted (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (deployment base processing).Accepts "port-O" .outbound
      ((deployment base processing).Observe packet) := by
  refine ⟨.forward, ?_, ?_, ?_⟩
  · refine ⟨rfl, ?_⟩
    change (deployment base processing).ManagementMetadataBound packet
    simp [Deployment.ManagementMetadataBound, packet, PacketClass, PacketService, PacketIKE,
      PacketMKA, PacketARP]
  · refine ⟨inventory processing, rfl, 3, by simp [inventory], rfl,
      interface "port-O" "OUTER-A" 30, by simp [deployment, interfaces], rfl, rfl, ?_⟩
    simp [PacketAtHook, HookDirection, inventory, ifaceName, packet, Deployment.Observe]
  · simp [deployment, policies, interfaces, interface,
      InterfacePolicy.Accepts, rules, PacketPolicy.Rule.toFilter, Filter.evaluate, packet,
      Deployment.Observe, PacketPolicy.MatchCondition.matchesPacket]

lemma cross_level_packet_is_rejected (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    ¬ (deployment base processing).Accepts "port-O" .outbound
      ((deployment base processing).Observe { packet with destination := 40 }) := by
  rintro ⟨hook, _, _, admitted⟩
  cases hook with
  | link =>
    exact DeriveDataPlaneFromDeviceRecords.routed_iface_has_no_link_operation
      (deployment base processing) (inventory processing) rfl "port-O"
      (by intro iface _ _; simp [DeriveDataPlaneFromDeviceRecords.RoutedIface, inventory])
      .outbound _ admitted
  | input | output | forward =>
    simp [deployment, policies, interfaces, interface, InterfacePolicy.Accepts, rules,
      PacketPolicy.Rule.toFilter, Filter.evaluate, packet, Deployment.Observe,
      PacketPolicy.MatchCondition.matchesPacket] at admitted

end TDN.Deployments.SnapshotProof_Addressing
