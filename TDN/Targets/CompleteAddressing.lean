import TDN.Targets.CompleteSpecifications
import TDN.Targets.InventoryDerivation
import TDN.Targets.PolicyDerivation
import TDN.Targets.EndpointRuleDerivation

namespace TDN.Targets.Complete
open Compliance

def RangeExcludesInner (d : Deployment) (low high : Nat) : Prop :=
  ∀ device ∈ d.devices, device.layer = some .inner →
    ∀ interface ∈ d.interfaces, interface.device = device.id →
      match interface.address with
      | none => True
      | some address => address < low ∨ high < address

instance (d : Deployment) (low high : Nat) : Decidable (RangeExcludesInner d low high) := by
  unfold RangeExcludesInner
  have (interface : Interface) : Decidable (match interface.address with
      | none => True | some address => address < low ∨ high < address) := by
    cases interface.address <;> infer_instance
  infer_instance

def RuleAddressExclusion (d : Deployment) : PacketPolicy.Atom → Prop
  | .sourceRange low high | .destinationRange low high => RangeExcludesInner d low high
  | _ => False

instance (d : Deployment) (atom : PacketPolicy.Atom) :
    Decidable (RuleAddressExclusion d atom) := by
  cases atom <;> unfold RuleAddressExclusion <;> infer_instance

def RulePeerGuard (d : Deployment) (pairs : List IntendedAddressPair)
    (rule : PacketPolicy.Rule) : Prop :=
  RuleNamesPair pairs rule ∨ ∃ atom ∈ rule.atoms, RuleAddressExclusion d atom

instance (d : Deployment) (pairs : List IntendedAddressPair) (rule : PacketPolicy.Rule) :
    Decidable (RulePeerGuard d pairs rule) := by
  unfold RulePeerGuard
  infer_instance

def PairEndpoints (d : Deployment) (pair : IntendedAddressPair) : Prop :=
  ∃ source ∈ d.devices, ∃ destination ∈ d.devices,
    source.layer = some .inner ∧ destination.layer = some .inner ∧
    source.level = pair.level ∧ destination.level = pair.level ∧
    d.intendedPeer source.id destination.id ∧
    (∃ interface ∈ d.interfaces, interface.device = source.id ∧
      interface.zone = .gray ∧ interface.address = some pair.source) ∧
    ∃ interface ∈ d.interfaces, interface.device = destination.id ∧
      interface.zone = .gray ∧ interface.address = some pair.destination

lemma exclusion_cannot_match_inner_endpoints
    (d : Deployment) (rule : PacketPolicy.Rule) (traffic : Traffic)
    (supported : d.Supported traffic) (ip : traffic.packet.protocol ≠ "ethernet")
    (endpoints : InnerEndpoints d traffic)
    (exclusion : ∃ atom ∈ rule.atoms, RuleAddressExclusion d atom)
    (matched : rule.toFilter.accepts traffic.packet = true) : False := by
  obtain ⟨source, destination, sourceName, destinationName, sourceInner, destinationInner⟩ := endpoints
  have sourceOwner : d.PacketOwner traffic.packet traffic.packet.source = some source := by
    exact (congrArg Traffic.sourceDevice supported.1).symm.trans sourceName
  have destinationOwner : d.PacketOwner traffic.packet traffic.packet.destination = some destination := by
    exact (congrArg Traffic.destinationDevice supported.1).symm.trans destinationName
  obtain ⟨sourceInterface, sourcePresent, sourceDevice, sourceAddress⟩ :=
    packet_owner_has_interface d traffic.packet traffic.packet.source source sourceOwner
  obtain ⟨destinationInterface, destinationPresent, destinationDevice, destinationAddress⟩ :=
    packet_owner_has_interface d traffic.packet traffic.packet.destination destination destinationOwner
  simp only [Interface.PacketAddress, ip, false_and, ↓reduceIte] at sourceAddress destinationAddress
  obtain ⟨sourceNode, sourceMember, sourceId, sourceLayer⟩ := sourceInner
  obtain ⟨destinationNode, destinationMember, destinationId, destinationLayer⟩ := destinationInner
  obtain ⟨atom, atomMember, excluded⟩ := exclusion
  have matchesAtom := PacketPolicy.matching_atom matched atomMember
  cases atom <;> simp only [RuleAddressExclusion] at excluded
  case sourceRange low high =>
    have outside := excluded sourceNode sourceMember sourceLayer
      sourceInterface sourcePresent (sourceDevice.trans sourceId.symm)
    simp only [sourceAddress] at outside
    change low ≤ traffic.packet.source ∧ traffic.packet.source ≤ high at matchesAtom
    omega
  case destinationRange low high =>
    have outside := excluded destinationNode destinationMember destinationLayer
      destinationInterface destinationPresent (destinationDevice.trans destinationId.symm)
    simp only [destinationAddress] at outside
    change low ≤ traffic.packet.destination ∧ traffic.packet.destination ≤ high at matchesAtom
    omega

lemma guarded_policy_accepts_intended_pair (d : Deployment) (pairs : List IntendedAddressPair)
    (policy : InterfacePolicy) (traffic : Traffic)
    (fallback : policy.defaultVerdict = .deny)
    (guards : ∀ rule ∈ policy.rules, rule.verdict = .allow → RulePeerGuard d pairs rule)
    (supported : d.Supported traffic) (ip : traffic.packet.protocol ≠ "ethernet")
    (endpoints : InnerEndpoints d traffic) (accepted : policy.Accepts traffic) :
    IntendedPair pairs traffic.packet := by
  unfold InterfacePolicy.Accepts at accepted
  rw [fallback] at accepted
  obtain ⟨rule, member, matched, allow⟩ :=
    Filter.allowed_has_matching_allow (policy.rules.map PacketPolicy.Rule.toFilter) traffic.packet accepted
  obtain ⟨sourceRule, present, same⟩ := List.mem_map.mp member
  subst rule
  rcases guards sourceRule present allow with named | excluded
  · exact named_pair_rule_matches_intended named matched
  · exact False.elim
      (exclusion_cannot_match_inner_endpoints d sourceRule traffic supported ip endpoints excluded matched)

lemma intended_pair_has_same_level (d : Deployment) (pairs : List IntendedAddressPair)
    (coherent : d.AddressInventoryCoherent)
    (bindings : ∀ pair ∈ pairs, PairEndpoints d pair)
    (traffic : Traffic) (supported : d.Supported traffic)
    (ip : traffic.packet.protocol ≠ "ethernet")
    (intended : IntendedPair pairs traffic.packet) : d.SameLevelInner traffic := by
  obtain ⟨pair, present, sourceAddress, destinationAddress⟩ := intended
  obtain ⟨source, sourceMember, destination, destinationMember, sourceLayer, destinationLayer,
    sourceLevel, destinationLevel, peer, firstInterface, secondInterface⟩ := bindings pair present
  obtain ⟨sourceInterface, sourcePresent, sourceOwner, sourceGray, sourceAssigned⟩ := firstInterface
  obtain ⟨destinationInterface, destinationPresent, destinationOwner,
    destinationGray, destinationAssigned⟩ := secondInterface
  have owners : ∀ address, ∀ first ∈ d.interfaces, ∀ second ∈ d.interfaces,
      first.PacketAddress traffic.packet = some address →
      second.PacketAddress traffic.packet = some address → first.device = second.device := by
    intro address first firstMember second secondMember firstAddress secondAddress
    simp only [Interface.PacketAddress, ip, false_and, ↓reduceIte] at firstAddress secondAddress
    exact coherent.2.2.1 first firstMember second secondMember address firstAddress secondAddress
  have sourcePacket : sourceInterface.PacketAddress traffic.packet = some traffic.packet.source := by
    simpa [Interface.PacketAddress, ip, sourceAddress] using sourceAssigned
  have destinationPacket : destinationInterface.PacketAddress traffic.packet = some traffic.packet.destination := by
    simpa [Interface.PacketAddress, ip, destinationAddress] using destinationAssigned
  have sourceMetadata : traffic.sourceDevice = some source.id :=
    (congrArg Traffic.sourceDevice supported.1).trans
      ((packet_owner_of_interface d traffic.packet sourceInterface sourcePresent _
        sourcePacket (owners _)).trans (congrArg some sourceOwner))
  have destinationMetadata : traffic.destinationDevice = some destination.id :=
    (congrArg Traffic.destinationDevice supported.1).trans
      ((packet_owner_of_interface d traffic.packet destinationInterface destinationPresent _
        destinationPacket (owners _)).trans (congrArg some destinationOwner))
  refine ⟨source, sourceMember, destination, destinationMember, sourceLayer, destinationLayer,
    sourceLevel.trans destinationLevel.symm, peer, Or.inl ?_⟩
  exact ⟨sourceMetadata, destinationMetadata,
    ⟨sourceInterface, sourcePresent, sourceOwner, sourceGray, sourcePacket⟩,
    destinationInterface, destinationPresent, destinationOwner, destinationGray, destinationPacket⟩

end TDN.Targets.Complete

namespace TDN.Targets.Complete
open Compliance

theorem gray_addressing_from_inventory_ranges_and_local_rule_checks
    (d : Deployment) (ranges : List (Addressing.Range SecurityLevel))
    (pairs : List IntendedAddressPair) (inventory : PacketProcessing.Inventory)
    (processing : d.processing = some inventory)
    (addressChecks : addressRecordsChecked d = true)
    (workstations : d.grayWorkstation = grayWorkstationRole d)
    (indices : policyIndicesChecked d = true)
    (valid : ∀ range ∈ ranges, range.low ≤ range.high)
    (separated : Addressing.Separated ranges)
    (peers : ∀ pair ∈ pairs, Addressing.Owns ranges pair.source pair.level ∧
      Addressing.Owns ranges pair.destination pair.level)
    (interfaceRanges : ∀ interface ∈ d.interfaces, interface.zone = .gray →
      d.IsLayer interface.device .inner →
        ∃ device ∈ d.devices, device.id = interface.device ∧ ∃ address,
          interface.address = some address ∧ Addressing.Owns ranges address device.level)
    (bindings : ∀ pair ∈ pairs, PairEndpoints d pair)
    (fallback : ∀ policy ∈ d.policies, policy.defaultVerdict = .deny)
    (guards : ∀ policy ∈ d.policies, ∀ rule ∈ policy.rules,
      rule.verdict = .allow → RulePeerGuard d pairs rule)
    (ipGuards : ∀ policy ∈ d.policies, ∀ rule ∈ policy.rules,
      rule.verdict = .allow → PolicyDerivation.RuleIPGuard rule)
    (routed : ∀ interface ∈ d.interfaces,
      (d.IsLayer interface.device .outer ∨ d.IsDevice interface.device .grayFirewall) →
      interface.zone = .gray →
      ∀ port ∈ inventory.ports, inventory.portName port = interface.id →
        PolicyDerivation.RoutedPort inventory port) :
    msc_gray_addressing_for_level_filtering d ranges pairs := by
  have coherent := address_inventory_from_checked_records d addressChecks workstations
  have acceptedPairs : ∀ interface ∈ d.interfaces,
      (d.IsLayer interface.device .outer ∨ d.IsDevice interface.device .grayFirewall) →
      interface.zone = .gray → ∀ direction traffic,
      d.Accepts interface.id direction traffic → InnerEndpoints d traffic →
      IntendedPair pairs traffic.packet ∧ d.SameLevelInner traffic := by
    intro interface present role gray direction traffic accepted endpoints
    obtain ⟨ip, policy, member, _, _, admits⟩ :=
      PolicyDerivation.routed_acceptance_has_ip_policy d inventory processing
        interface.id direction traffic (routed interface present role gray) fallback ipGuards accepted
    have supported := accepted_traffic_supported d interface.id direction traffic accepted
    have intended := guarded_policy_accepts_intended_pair d pairs policy traffic
      (fallback policy member) (guards policy member) supported ip endpoints admits
    exact ⟨intended, intended_pair_has_same_level d pairs coherent bindings traffic supported ip intended⟩
  refine ⟨coherent, valid, ?_, peers, ?_, ?_⟩
  · intro address first second a b
    exact Addressing.separated_ranges_unique_label separated a b
  · intro interface member _ zone innerLayer
    exact interfaceRanges interface member zone innerLayer
  · intro device member _ kind
    have role : d.IsLayer device.id .outer ∨ d.IsDevice device.id .grayFirewall := by
      rcases kind with outerLayer | firewall
      · exact Or.inl ⟨device, member, rfl, outerLayer⟩
      · exact Or.inr ⟨device, member, rfl, firewall⟩
    constructor
    · intro interface present _ owner gray
      refine ⟨policy_coverage_from_checked_indices d indices interface present, ?_⟩
      intro direction traffic accepted endpoints
      exact (acceptedPairs interface present (owner ▸ role) gray
        direction traffic accepted endpoints).2
    · intro interface present _ owner gray direction traffic accepted endpoints
      exact (acceptedPairs interface present (owner ▸ role) gray
        direction traffic accepted endpoints).1

end TDN.Targets.Complete

namespace TDN.Targets.Complete
open Compliance EndpointRuleDerivation

theorem gray_addressing_from_ip_and_link_endpoint_rules
    (d : Deployment) (ranges : List (Addressing.Range SecurityLevel))
    (pairs : List IntendedAddressPair) (endpoints : List EndpointPair)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (addressChecks : addressRecordsChecked d = true)
    (workstations : d.grayWorkstation = grayWorkstationRole d)
    (indices : policyIndicesChecked d = true)
    (valid : ∀ range ∈ ranges, range.low ≤ range.high)
    (separated : Addressing.Separated ranges)
    (peers : ∀ pair ∈ pairs, Addressing.Owns ranges pair.source pair.level ∧
      Addressing.Owns ranges pair.destination pair.level)
    (interfaceRanges : ∀ interface ∈ d.interfaces, interface.zone = .gray →
      d.IsLayer interface.device .inner →
      ∃ device ∈ d.devices, device.id = interface.device ∧ ∃ address,
        interface.address = some address ∧ Addressing.Owns ranges address device.level)
    (bindings : ∀ endpoint ∈ endpoints, endpoint.Bound d ∧
      (d.IsLayer endpoint.source .inner → d.IsLayer endpoint.destination .inner →
        SameLevelComponents d endpoint.source endpoint.destination) ∧
      ∃ pair ∈ pairs, pair.source = endpoint.sourceAddress ∧ pair.destination = endpoint.destinationAddress)
    (ruleChecks : ∀ interface ∈ d.interfaces,
      (d.IsLayer interface.device .outer ∨ d.IsDevice interface.device .grayFirewall) →
      interface.zone = .gray →
      ∀ program ∈ admissionPrograms d inventory interface.id,
        ProgramRuleChecks (RuleEndpointGuard d (fun node => d.IsLayer node .inner) endpoints) program) :
    msc_gray_addressing_for_level_filtering d ranges pairs := by
  have coherent := address_inventory_from_checked_records d addressChecks workstations
  have acceptedPairs : ∀ interface ∈ d.interfaces,
      (d.IsLayer interface.device .outer ∨ d.IsDevice interface.device .grayFirewall) →
      interface.zone = .gray → ∀ direction traffic,
      d.Accepts interface.id direction traffic → InnerEndpoints d traffic →
      IntendedPair pairs traffic.packet ∧ d.SameLevelInner traffic := by
    intro interface member role gray direction traffic accepted innerEndpoints
    obtain ⟨source, destination, sourceMetadata, destinationMetadata, sourceInner, destinationInner⟩ :=
      innerEndpoints
    obtain ⟨endpoint, endpointMember, rule, guard, sourceAtom, destinationAtom, matched⟩ :=
      accepted_endpoints_have_named_pair d inventory present (fun node => d.IsLayer node .inner)
        endpoints interface.id (ruleChecks interface member role gray) direction traffic accepted
        source destination sourceMetadata destinationMetadata sourceInner destinationInner
    have records := bindings endpoint endpointMember
    have supported := accepted_traffic_supported d interface.id direction traffic accepted
    obtain ⟨sourceId, destinationId, _, _⟩ :=
      matched_bound_pair_recovers_metadata d coherent endpoint records.1 rule guard
        sourceAtom destinationAtom traffic supported matched
    have sourceEq := Option.some.inj (sourceMetadata.symm.trans sourceId)
    have destinationEq := Option.some.inj (destinationMetadata.symm.trans destinationId)
    refine ⟨?_, matched_same_level_pair_is_inner_traffic d coherent endpoint records.1
      (records.2.1 (sourceEq ▸ sourceInner) (destinationEq ▸ destinationInner))
      rule guard sourceAtom destinationAtom traffic supported matched⟩
    obtain ⟨pair, pairMember, sourceAddress, destinationAddress⟩ := records.2.2
    have sourceBounds := PacketPolicy.matching_atom matched sourceAtom
    have destinationBounds := PacketPolicy.matching_atom matched destinationAtom
    change endpoint.sourceAddress ≤ traffic.packet.source ∧
      traffic.packet.source ≤ endpoint.sourceAddress at sourceBounds
    change endpoint.destinationAddress ≤ traffic.packet.destination ∧
      traffic.packet.destination ≤ endpoint.destinationAddress at destinationBounds
    exact ⟨pair, pairMember, by omega, by omega⟩
  refine ⟨coherent, valid, ?_, peers, ?_, ?_⟩
  · intro address first second firstOwner secondOwner
    exact Addressing.separated_ranges_unique_label separated firstOwner secondOwner
  · intro interface member _ gray inner
    exact interfaceRanges interface member gray inner
  · intro device member _ role
    have actual : d.IsLayer device.id .outer ∨ d.IsDevice device.id .grayFirewall := by
      rcases role with outer | firewall
      · exact Or.inl ⟨device, member, rfl, outer⟩
      · exact Or.inr ⟨device, member, rfl, firewall⟩
    constructor
    · intro interface present _ owner gray
      refine ⟨policy_coverage_from_checked_indices d indices interface present, ?_⟩
      intro direction traffic accepted endpoints
      exact (acceptedPairs interface present (owner ▸ actual) gray direction traffic accepted endpoints).2
    · intro interface present _ owner gray direction traffic accepted endpoints
      exact (acceptedPairs interface present (owner ▸ actual) gray direction traffic accepted endpoints).1

end TDN.Targets.Complete
