import TDN.Deployments.SnapshotProof_Addressing

namespace TDN.Deployments.SnapshotProof_LinkAddressing
open Compliance Requirements Requirements.Msc Requirements.DeriveEndpointInputOutputRules

abbrev level := SnapshotProof_Addressing.level
abbrev otherLevel := SnapshotProof_Addressing.otherLevel

def interface (name owner : String) (address linkAddress : Nat) : Interface :=
  { id := name, device := owner, zone := .gray, address := some address,
    linkAddress := some linkAddress, physical := true, managementNetwork := false }

def interfaces : List Interface :=
  [interface "port-A" "INNER-A" 10 101, interface "port-B" "INNER-B" 20 202,
   interface "port-C" "INNER-C" 40 404, interface "port-O" "OUTER-A" 30 303]

def linkRules : List PacketPolicy.Rule :=
  [⟨[.sourceRange 101 101, .destinationRange 202 202, .protocol "ethernet", .etherTypes [35045]], .allow⟩,
   ⟨[.sourceRange 202 202, .destinationRange 101 101, .protocol "ethernet", .etherTypes [35045]], .allow⟩]

def linkProgram : LinkAdmission.Program := ⟨linkRules, .deny⟩

def inventory (base : PacketProcessing.Inventory) : PacketProcessing.Inventory :=
  { SnapshotProof_Addressing.inventory base with
    configuration := { (SnapshotProof_Addressing.inventory base).configuration with
      bridge := fun first second => (first = 0 ∧ second = 3) ∨ (first = 3 ∧ second = 0),
      linkPolicies := [(3, ⟨linkProgram, linkProgram⟩)] } }

def deployment (base : Deployment) (processing : PacketProcessing.Inventory) : Deployment :=
  { SnapshotProof_Addressing.deployment base processing with
    interfaces := interfaces, processing := some (inventory processing) }

def ranges : List (Addressing.Range SecurityLevel) :=
  SnapshotProof_Addressing.ranges ++ [⟨101, 202, level⟩, ⟨404, 404, otherLevel⟩]

def pairs : List IntendedAddressPair :=
  SnapshotProof_Addressing.pairs ++ [⟨101, 202, level⟩, ⟨202, 101, level⟩]

def endpoints : List EndpointPair :=
  [⟨.internet, "INNER-A", "INNER-B", 10, 20⟩,
   ⟨.internet, "INNER-B", "INNER-A", 20, 10⟩,
   ⟨.link, "INNER-A", "INNER-B", 101, 202⟩,
   ⟨.link, "INNER-B", "INNER-A", 202, 101⟩]

theorem complete_link_model_RG014 (base : Deployment) (processing : PacketProcessing.Inventory) :
    msc_gray_addressing_for_level_filtering (deployment base processing) ranges pairs := by
  apply gray_addressing_from_ip_and_link_endpoint_rules
    (deployment base processing) ranges pairs endpoints (inventory processing) rfl
  · rfl
  · funext component
    simp [deployment, SnapshotProof_Addressing.deployment, grayWorkstationRole,
      Deployment.IsDevice, SnapshotProof_Addressing.devices]
  · rfl
  · decide
  · unfold Addressing.Separated ranges
    decide
  · simp [pairs, ranges, SnapshotProof_Addressing.pairs, SnapshotProof_Addressing.ranges,
      Addressing.Owns, Addressing.Contains]
  · intro iface member gray inner
    simp only [deployment, interfaces, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl <;>
      simp_all [deployment, SnapshotProof_Addressing.deployment, interface, Deployment.IsLayer,
        SnapshotProof_Addressing.devices, ranges, SnapshotProof_Addressing.ranges,
        Addressing.Owns, Addressing.Contains]
  · simp [endpoints, EndpointPair.Bound, AddressView.read, SameLevelComponents,
      deployment, SnapshotProof_Addressing.deployment, SnapshotProof_Addressing.devices,
      interfaces, interface, pairs, SnapshotProof_Addressing.pairs, Deployment.IsLayer]
  · intro iface member _ _
    simp only [deployment, interfaces, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl <;>
      simp [admissionPrograms, deployment, SnapshotProof_Addressing.deployment,
        SnapshotProof_Addressing.policies, SnapshotProof_Addressing.interfaces, SnapshotProof_Addressing.interface,
        SnapshotProof_Addressing.rules, inventory, SnapshotProof_Addressing.inventory, interface,
        LinkAdmission.lookup, linkProgram, linkRules, ProgramRuleChecks, RuleEndpointGuard,
        endpoints, AddressView.RuleGuard, EthernetTypeAtom, DeriveDataPlaneFromDeviceRecords.RuleIPGuard,
        DeriveDataPlaneFromDeviceRecords.IPProtocolAtom]

def packet : PacketPolicy.Packet :=
  { source := 101, destination := 202, protocol := "ethernet",
    ingress := "", egress := "port-O", etherType := some 35045,
    sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 0,
    matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "" }

lemma same_level_Ethernet_is_fully_admitted (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (deployment base processing).Accepts "port-O" .outbound
      ((deployment base processing).Observe packet) := by
  refine ⟨.link, ⟨rfl, ?_⟩, ?_, ?_, ?_⟩
  · change (deployment base processing).ManagementMetadataBound packet
    simp [Deployment.ManagementMetadataBound, packet, PacketClass, PacketService, PacketIKE,
      PacketMKA, PacketARP]
  · refine ⟨inventory processing, rfl, 3, by simp [inventory, SnapshotProof_Addressing.inventory], rfl,
      interface "port-O" "OUTER-A" 30 303, by simp [deployment, interfaces], rfl, rfl, ?_⟩
    simp [PacketAtHook, HookDirection, inventory, SnapshotProof_Addressing.inventory,
      SnapshotProof_Addressing.ifaceName, packet, Deployment.Observe]
  · refine ⟨inventory processing, rfl, 3, by simp [inventory, SnapshotProof_Addressing.inventory], rfl, Or.inl ?_⟩
    refine ⟨⟨rfl, rfl⟩, Or.inl ⟨0, by simp [inventory, SnapshotProof_Addressing.inventory], ?_⟩⟩
    simp [inventory]
  · refine ⟨inventory processing, rfl, 3, by simp [inventory, SnapshotProof_Addressing.inventory], rfl,
      ⟨linkProgram, linkProgram⟩, rfl, ?_⟩
    change linkProgram.Accepts packet
    decide

lemma link_addresses_bind_intended_Inner_peers (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    (deployment base processing).PacketOwner packet 101 = some "INNER-A" ∧
    (deployment base processing).PacketOwner packet 202 = some "INNER-B" ∧
    (deployment base processing).SameLevelInner ((deployment base processing).Observe packet) := by
  refine ⟨rfl, rfl, ?_⟩
  refine ⟨⟨"INNER-A", "A", .vpn, some .inner, level, true⟩,
    by simp [deployment, SnapshotProof_Addressing.deployment, SnapshotProof_Addressing.devices],
    ⟨"INNER-B", "B", .vpn, some .inner, level, true⟩,
    by simp [deployment, SnapshotProof_Addressing.deployment, SnapshotProof_Addressing.devices],
    rfl, rfl, rfl, Or.inl ⟨rfl, rfl⟩, Or.inl ?_⟩
  exact ⟨rfl, rfl,
    ⟨interface "port-A" "INNER-A" 10 101, by simp [deployment, interfaces], rfl, rfl, rfl⟩,
    interface "port-B" "INNER-B" 20 202, by simp [deployment, interfaces], rfl, rfl, rfl⟩

lemma cross_level_Ethernet_is_rejected (base : Deployment)
    (processing : PacketProcessing.Inventory) :
    ¬ (deployment base processing).Accepts "port-O" .outbound
      ((deployment base processing).Observe {packet with destination := 404}) := by
  rintro ⟨hook, _, _, admitted⟩
  cases hook with
  | link =>
    obtain ⟨_, actual, same, iface, member, name, policy, selected, admitted⟩ := admitted
    have equal : actual = inventory processing := Option.some.inj same.symm
    subst actual
    simp only [inventory, SnapshotProof_Addressing.inventory, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl <;>
      simp [inventory, SnapshotProof_Addressing.inventory, LinkAdmission.lookup] at selected
    subst policy
    simp [LinkAdmission.Program.Accepts, linkProgram, linkRules, packet, Deployment.Observe,
      Filter.evaluate, PacketPolicy.Rule.toFilter, PacketPolicy.MatchCondition.matchesPacket] at admitted
  | input | output | forward =>
    simp [deployment, SnapshotProof_Addressing.deployment, SnapshotProof_Addressing.policies,
      SnapshotProof_Addressing.interfaces, SnapshotProof_Addressing.interface, SnapshotProof_Addressing.rules,
      InterfacePolicy.Accepts, packet, Deployment.Observe, Filter.evaluate,
      PacketPolicy.Rule.toFilter, PacketPolicy.MatchCondition.matchesPacket] at admitted

end TDN.Deployments.SnapshotProof_LinkAddressing
