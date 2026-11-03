import TDN.Targets.InventoryDerivation
import TDN.Targets.PolicyDerivation

namespace TDN.Targets.EndpointRuleDerivation
open Compliance

inductive AddressView where
  | internet | link
  deriving DecidableEq

def AddressView.read (view : AddressView) (interface : Interface) : Option Nat :=
  match view with
  | .internet => interface.address
  | .link => interface.linkAddress

def EthernetTypeAtom : PacketPolicy.Atom → Prop
  | .etherTypes _ => True
  | _ => False

instance (atom : PacketPolicy.Atom) : Decidable (EthernetTypeAtom atom) := by
  cases atom <;> unfold EthernetTypeAtom <;> infer_instance

def AddressView.RuleGuard (view : AddressView) (rule : PacketPolicy.Rule) : Prop :=
  match view with
  | .internet => PolicyDerivation.RuleIPGuard rule
  | .link => .protocol "ethernet" ∈ rule.atoms ∧ ∃ atom ∈ rule.atoms, EthernetTypeAtom atom

instance (view : AddressView) (rule : PacketPolicy.Rule) :
    Decidable (view.RuleGuard rule) := by
  cases view <;> unfold AddressView.RuleGuard <;> infer_instance

lemma matching_rule_selects_address_view (view : AddressView) (rule : PacketPolicy.Rule)
    (guard : view.RuleGuard rule) (packet : PacketPolicy.Packet)
    (matched : rule.toFilter.accepts packet = true) (interface : Interface) :
    interface.PacketAddress packet = view.read interface := by
  cases view with
  | internet =>
    have ip := PolicyDerivation.ip_rule_cannot_match_ethernet rule packet guard matched
    simp [Interface.PacketAddress, AddressView.read, ip]
  | link =>
    obtain ⟨protocolAtom, atom, member, typed⟩ := guard
    have ethernet : packet.protocol = "ethernet" :=
      PacketPolicy.matching_atom matched protocolAtom
    have matchesAtom := PacketPolicy.matching_atom matched member
    cases atom <;> simp only [EthernetTypeAtom] at typed
    case etherTypes values =>
      obtain ⟨value, typeEq, _⟩ := matchesAtom
      simp [Interface.PacketAddress, AddressView.read, ethernet, typeEq]

structure EndpointPair where
  view : AddressView
  source : String
  destination : String
  sourceAddress : Nat
  destinationAddress : Nat
  deriving DecidableEq

def EndpointPair.Bound (pair : EndpointPair) (d : Deployment) : Prop :=
  (∃ interface ∈ d.interfaces, interface.device = pair.source ∧
    interface.zone = .gray ∧ pair.view.read interface = some pair.sourceAddress) ∧
  ∃ interface ∈ d.interfaces, interface.device = pair.destination ∧
    interface.zone = .gray ∧ pair.view.read interface = some pair.destinationAddress

instance (pair : EndpointPair) (d : Deployment) : Decidable (pair.Bound d) := by
  unfold EndpointPair.Bound
  infer_instance

def RangeExcludesNodes (d : Deployment) (nodes : String → Prop)
    (view : AddressView) (low high : Nat) : Prop :=
  ∀ interface ∈ d.interfaces, nodes interface.device →
    match view.read interface with
    | none => True
    | some address => address < low ∨ high < address

instance (d : Deployment) (nodes : String → Prop) [DecidablePred nodes]
    (view : AddressView) (low high : Nat) :
    Decidable (RangeExcludesNodes d nodes view low high) := by
  unfold RangeExcludesNodes
  have (interface : Interface) : Decidable (match view.read interface with
      | none => True | some address => address < low ∨ high < address) := by
    cases view.read interface <;> infer_instance
  infer_instance

def RangeExclusionAtom (d : Deployment) (nodes : String → Prop)
    (view : AddressView) : PacketPolicy.Atom → Prop
  | .sourceRange low high | .destinationRange low high =>
      RangeExcludesNodes d nodes view low high
  | _ => False

instance (d : Deployment) (nodes : String → Prop) [DecidablePred nodes]
    (view : AddressView) (atom : PacketPolicy.Atom) :
    Decidable (RangeExclusionAtom d nodes view atom) := by
  cases atom <;> unfold RangeExclusionAtom <;> infer_instance

def RuleEndpointGuard (d : Deployment) (nodes : String → Prop)
    (pairs : List EndpointPair) (rule : PacketPolicy.Rule) : Prop :=
  (∃ pair ∈ pairs, pair.view.RuleGuard rule ∧
    .sourceRange pair.sourceAddress pair.sourceAddress ∈ rule.atoms ∧
    .destinationRange pair.destinationAddress pair.destinationAddress ∈ rule.atoms) ∨
  ∃ view ∈ [AddressView.internet, .link], view.RuleGuard rule ∧
    ∃ atom ∈ rule.atoms, RangeExclusionAtom d nodes view atom

instance (d : Deployment) (nodes : String → Prop) [DecidablePred nodes]
    (pairs : List EndpointPair) (rule : PacketPolicy.Rule) :
    Decidable (RuleEndpointGuard d nodes pairs rule) := by
  unfold RuleEndpointGuard
  infer_instance

lemma address_inventory_owner_uniqueness (d : Deployment)
    (coherent : d.AddressInventoryCoherent) (packet : PacketPolicy.Packet)
    (address : Nat) (first : Interface) (firstMember : first ∈ d.interfaces)
    (second : Interface) (secondMember : second ∈ d.interfaces)
    (firstAddress : first.PacketAddress packet = some address)
    (secondAddress : second.PacketAddress packet = some address) :
    first.device = second.device := by
  unfold Interface.PacketAddress at firstAddress secondAddress
  split at firstAddress
  · rename_i link
    simp only [link] at secondAddress
    exact coherent.2.1 first firstMember second secondMember address firstAddress secondAddress
  · rename_i ip
    simp only [ip, ↓reduceIte] at secondAddress
    exact coherent.2.2.1 first firstMember second secondMember address firstAddress secondAddress

lemma matched_bound_pair_recovers_metadata (d : Deployment)
    (coherent : d.AddressInventoryCoherent) (pair : EndpointPair) (bound : pair.Bound d)
    (rule : PacketPolicy.Rule) (guard : pair.view.RuleGuard rule)
    (sourceAtom : .sourceRange pair.sourceAddress pair.sourceAddress ∈ rule.atoms)
    (destinationAtom : .destinationRange pair.destinationAddress pair.destinationAddress ∈ rule.atoms)
    (traffic : Traffic) (supported : d.Supported traffic)
    (matched : rule.toFilter.accepts traffic.packet = true) :
    traffic.sourceDevice = some pair.source ∧ traffic.destinationDevice = some pair.destination ∧
    (∃ interface ∈ d.interfaces, interface.device = pair.source ∧
      interface.zone = .gray ∧ interface.PacketAddress traffic.packet = some traffic.packet.source) ∧
    ∃ interface ∈ d.interfaces, interface.device = pair.destination ∧
      interface.zone = .gray ∧ interface.PacketAddress traffic.packet = some traffic.packet.destination := by
  obtain ⟨source, sourceMember, sourceOwner, sourceGray, sourceAddress⟩ := bound.1
  obtain ⟨destination, destinationMember, destinationOwner, destinationGray, destinationAddress⟩ := bound.2
  have sourceBounds := PacketPolicy.matching_atom matched sourceAtom
  have destinationBounds := PacketPolicy.matching_atom matched destinationAtom
  change pair.sourceAddress ≤ traffic.packet.source ∧ traffic.packet.source ≤ pair.sourceAddress at sourceBounds
  change pair.destinationAddress ≤ traffic.packet.destination ∧ traffic.packet.destination ≤ pair.destinationAddress at destinationBounds
  have sourceEq : traffic.packet.source = pair.sourceAddress := by omega
  have destinationEq : traffic.packet.destination = pair.destinationAddress := by omega
  have sourcePacket : source.PacketAddress traffic.packet = some traffic.packet.source := by
    rw [matching_rule_selects_address_view pair.view rule guard traffic.packet matched source, sourceEq]
    exact sourceAddress
  have destinationPacket : destination.PacketAddress traffic.packet = some traffic.packet.destination := by
    rw [matching_rule_selects_address_view pair.view rule guard traffic.packet matched destination, destinationEq]
    exact destinationAddress
  refine ⟨?_, ?_, ⟨source, sourceMember, sourceOwner, sourceGray, sourcePacket⟩,
    destination, destinationMember, destinationOwner, destinationGray, destinationPacket⟩
  · exact (congrArg Traffic.sourceDevice supported.1).trans
      ((packet_owner_of_interface d traffic.packet source sourceMember _ sourcePacket
        (address_inventory_owner_uniqueness d coherent traffic.packet _)).trans
          (congrArg some sourceOwner))
  · exact (congrArg Traffic.destinationDevice supported.1).trans
      ((packet_owner_of_interface d traffic.packet destination destinationMember _ destinationPacket
        (address_inventory_owner_uniqueness d coherent traffic.packet _)).trans
          (congrArg some destinationOwner))

lemma exclusion_cannot_match_node_endpoints (d : Deployment) (nodes : String → Prop)
    (view : AddressView) (rule : PacketPolicy.Rule) (guard : view.RuleGuard rule)
    (traffic : Traffic) (supported : d.Supported traffic)
    (source destination : String)
    (sourceMetadata : traffic.sourceDevice = some source)
    (destinationMetadata : traffic.destinationDevice = some destination)
    (sourceNode : nodes source) (destinationNode : nodes destination)
    (exclusion : ∃ atom ∈ rule.atoms, RangeExclusionAtom d nodes view atom)
    (matched : rule.toFilter.accepts traffic.packet = true) : False := by
  have sourceOwner : d.PacketOwner traffic.packet traffic.packet.source = some source :=
    (congrArg Traffic.sourceDevice supported.1).symm.trans sourceMetadata
  have destinationOwner : d.PacketOwner traffic.packet traffic.packet.destination = some destination :=
    (congrArg Traffic.destinationDevice supported.1).symm.trans destinationMetadata
  obtain ⟨sourceInterface, sourceMember, sourceDevice, sourceAddress⟩ :=
    packet_owner_has_interface d traffic.packet traffic.packet.source source sourceOwner
  obtain ⟨destinationInterface, destinationMember, destinationDevice, destinationAddress⟩ :=
    packet_owner_has_interface d traffic.packet traffic.packet.destination destination destinationOwner
  rw [matching_rule_selects_address_view view rule guard traffic.packet matched sourceInterface] at sourceAddress
  rw [matching_rule_selects_address_view view rule guard traffic.packet matched destinationInterface] at destinationAddress
  obtain ⟨atom, member, excluded⟩ := exclusion
  have matchesAtom := PacketPolicy.matching_atom matched member
  cases atom <;> simp only [RangeExclusionAtom] at excluded
  case sourceRange low high =>
    have outside := excluded sourceInterface sourceMember (sourceDevice ▸ sourceNode)
    simp only [sourceAddress] at outside
    change low ≤ traffic.packet.source ∧ traffic.packet.source ≤ high at matchesAtom
    omega
  case destinationRange low high =>
    have outside := excluded destinationInterface destinationMember (destinationDevice ▸ destinationNode)
    simp only [destinationAddress] at outside
    change low ≤ traffic.packet.destination ∧ traffic.packet.destination ≤ high at matchesAtom
    omega

lemma guarded_rule_preserves_endpoint_relation (d : Deployment)
    (coherent : d.AddressInventoryCoherent) (nodes : String → Prop)
    (relation : String → String → Prop) (pairs : List EndpointPair)
    (bindings : ∀ pair ∈ pairs, pair.Bound d ∧ relation pair.source pair.destination)
    (rule : PacketPolicy.Rule) (guard : RuleEndpointGuard d nodes pairs rule)
    (traffic : Traffic) (supported : d.Supported traffic)
    (source destination : String)
    (sourceMetadata : traffic.sourceDevice = some source)
    (destinationMetadata : traffic.destinationDevice = some destination)
    (sourceNode : nodes source) (destinationNode : nodes destination)
    (matched : rule.toFilter.accepts traffic.packet = true) :
    relation source destination := by
  rcases guard with ⟨pair, member, view, sourceAtom, destinationAtom⟩ |
    ⟨view, _, checked, atom, member, exclusion⟩
  · have records := bindings pair member
    obtain ⟨actualSource, actualDestination, _, _⟩ :=
      matched_bound_pair_recovers_metadata d coherent pair records.1 rule view
        sourceAtom destinationAtom traffic supported matched
    have sourceEq := Option.some.inj (sourceMetadata.symm.trans actualSource)
    have destinationEq := Option.some.inj (destinationMetadata.symm.trans actualDestination)
    exact sourceEq.symm ▸ destinationEq.symm ▸ records.2
  · exact False.elim (exclusion_cannot_match_node_endpoints d nodes view rule checked
      traffic supported source destination sourceMetadata destinationMetadata
      sourceNode destinationNode ⟨atom, member, exclusion⟩ matched)

end TDN.Targets.EndpointRuleDerivation

namespace TDN.Targets.EndpointRuleDerivation
open Compliance

def admissionPrograms (d : Deployment) (inventory : PacketProcessing.Inventory) (interface : String) :
    List LinkAdmission.Program :=
  (d.policies.filter (fun policy => policy.interface == interface)).map (fun policy => ⟨policy.rules, policy.defaultVerdict⟩) ++
  (inventory.ports.filter (fun port => inventory.portName port == interface)).flatMap (fun port =>
    match LinkAdmission.lookup inventory.configuration.linkPolicies port with
    | none => []
    | some policy => [policy.inbound, policy.outbound])

lemma admitted_packet_has_inventory_program (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : String) (direction : Direction) (traffic : Traffic)
    (accepted : d.Accepts interface direction traffic) :
    ∃ program ∈ admissionPrograms d inventory interface, program.Accepts traffic.packet := by
  obtain ⟨hook, _, admission⟩ := accepted
  by_cases link : hook = .link
  · subst hook
    obtain ⟨_, actual, same, port, member, name, policy, selected, admits⟩ := admission
    have actualEq : actual = inventory := Option.some.inj (same.symm.trans present)
    subst actual
    refine ⟨if direction = .outbound then policy.outbound else policy.inbound, ?_, by simpa using admits⟩
    apply List.mem_append_right
    apply List.mem_flatMap.mpr
    refine ⟨port, List.mem_filter.mpr ⟨member, by simpa using name⟩, ?_⟩
    simp only [selected]
    cases direction <;> simp
  · simp only [link, ↓reduceIte] at admission
    obtain ⟨policy, member, name, _, _, _, admits⟩ := admission
    refine ⟨⟨policy.rules, policy.defaultVerdict⟩, ?_, admits⟩
    exact List.mem_append_left _ (List.mem_map.mpr ⟨policy, List.mem_filter.mpr ⟨member, by simpa using name⟩, rfl⟩)

def ProgramRuleChecks (guard : PacketPolicy.Rule → Prop) (program : LinkAdmission.Program) : Prop :=
  program.fallback = .deny ∧ ∀ rule ∈ program.rules, rule.verdict = .allow → guard rule

instance (guard : PacketPolicy.Rule → Prop) [DecidablePred guard]
    (program : LinkAdmission.Program) : Decidable (ProgramRuleChecks guard program) := by
  unfold ProgramRuleChecks
  infer_instance

lemma admitted_packet_has_checked_rule (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (guard : PacketPolicy.Rule → Prop) (interface : String)
    (checks : ∀ program ∈ admissionPrograms d inventory interface, ProgramRuleChecks guard program)
    (direction : Direction) (traffic : Traffic)
    (accepted : d.Accepts interface direction traffic) :
    ∃ rule, guard rule ∧ rule.toFilter.accepts traffic.packet = true := by
  obtain ⟨program, member, admits⟩ :=
    admitted_packet_has_inventory_program d inventory present interface direction traffic accepted
  have checked := checks program member
  change Filter.evaluate (program.rules.map PacketPolicy.Rule.toFilter) program.fallback
    traffic.packet = .allow at admits
  rw [checked.1] at admits
  obtain ⟨rule, ruleMember, matched, allow⟩ := Filter.allowed_has_matching_allow
    (program.rules.map PacketPolicy.Rule.toFilter) traffic.packet admits
  obtain ⟨source, sourceMember, same⟩ := List.mem_map.mp ruleMember
  subst rule
  exact ⟨source, checked.2 source sourceMember allow, matched⟩

lemma accepted_endpoints_have_named_pair (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (nodes : String → Prop) (pairs : List EndpointPair) (interface : String)
    (checks : ∀ program ∈ admissionPrograms d inventory interface,
      ProgramRuleChecks (RuleEndpointGuard d nodes pairs) program)
    (direction : Direction) (traffic : Traffic)
    (accepted : d.Accepts interface direction traffic)
    (source destination : String)
    (sourceMetadata : traffic.sourceDevice = some source)
    (destinationMetadata : traffic.destinationDevice = some destination)
    (sourceNode : nodes source) (destinationNode : nodes destination) :
    ∃ pair ∈ pairs, ∃ rule, pair.view.RuleGuard rule ∧
      .sourceRange pair.sourceAddress pair.sourceAddress ∈ rule.atoms ∧
      .destinationRange pair.destinationAddress pair.destinationAddress ∈ rule.atoms ∧
      rule.toFilter.accepts traffic.packet = true := by
  obtain ⟨rule, guard, matched⟩ := admitted_packet_has_checked_rule d inventory present
    (RuleEndpointGuard d nodes pairs) interface checks direction traffic accepted
  rcases guard with ⟨pair, member, view, sourceAtom, destinationAtom⟩ |
    ⟨view, _, viewGuard, exclusion⟩
  · exact ⟨pair, member, rule, view, sourceAtom, destinationAtom, matched⟩
  · exact False.elim (exclusion_cannot_match_node_endpoints d nodes view rule viewGuard
      traffic (accepted_traffic_supported d interface direction traffic accepted)
      source destination sourceMetadata destinationMetadata sourceNode destinationNode
      exclusion matched)

lemma accepted_endpoints_preserve_local_relation (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (coherent : d.AddressInventoryCoherent) (nodes : String → Prop)
    (relation : String → String → Prop) (pairs : List EndpointPair)
    (bindings : ∀ pair ∈ pairs, pair.Bound d ∧ relation pair.source pair.destination) (interface : String)
    (checks : ∀ program ∈ admissionPrograms d inventory interface,
      ProgramRuleChecks (RuleEndpointGuard d nodes pairs) program)
    (direction : Direction) (traffic : Traffic)
    (accepted : d.Accepts interface direction traffic)
    (source destination : String)
    (sourceMetadata : traffic.sourceDevice = some source)
    (destinationMetadata : traffic.destinationDevice = some destination)
    (sourceNode : nodes source) (destinationNode : nodes destination) :
    relation source destination := by
  obtain ⟨rule, guard, matched⟩ := admitted_packet_has_checked_rule d inventory present
    (RuleEndpointGuard d nodes pairs) interface checks direction traffic accepted
  exact guarded_rule_preserves_endpoint_relation d coherent nodes relation pairs bindings rule
    guard traffic (accepted_traffic_supported d interface direction traffic accepted)
    source destination sourceMetadata destinationMetadata sourceNode destinationNode matched

end TDN.Targets.EndpointRuleDerivation

namespace TDN.Targets.EndpointRuleDerivation
open Compliance

def SameLevelComponents (d : Deployment) (source destination : String) : Prop :=
  ∃ first ∈ d.devices, ∃ second ∈ d.devices,
    first.id = source ∧ second.id = destination ∧
    first.layer = some .inner ∧ second.layer = some .inner ∧
    first.level = second.level ∧ d.intendedPeer source destination

lemma matched_same_level_pair_is_inner_traffic (d : Deployment)
    (coherent : d.AddressInventoryCoherent) (pair : EndpointPair) (bound : pair.Bound d)
    (peers : SameLevelComponents d pair.source pair.destination)
    (rule : PacketPolicy.Rule) (guard : pair.view.RuleGuard rule)
    (sourceAtom : .sourceRange pair.sourceAddress pair.sourceAddress ∈ rule.atoms)
    (destinationAtom : .destinationRange pair.destinationAddress pair.destinationAddress ∈ rule.atoms)
    (traffic : Traffic) (supported : d.Supported traffic)
    (matched : rule.toFilter.accepts traffic.packet = true) : d.SameLevelInner traffic := by
  obtain ⟨first, firstMember, second, secondMember, firstId, secondId,
    firstLayer, secondLayer, sameLevel, peer⟩ := peers
  obtain ⟨sourceMetadata, destinationMetadata, sourceInterface, destinationInterface⟩ :=
    matched_bound_pair_recovers_metadata d coherent pair bound rule guard sourceAtom
      destinationAtom traffic supported matched
  refine ⟨first, firstMember, second, secondMember, firstLayer, secondLayer, sameLevel, ?_, Or.inl ?_⟩
  · simpa [firstId, secondId] using peer
  · rw [firstId, secondId]
    exact ⟨sourceMetadata, destinationMetadata, sourceInterface, destinationInterface⟩

end TDN.Targets.EndpointRuleDerivation
