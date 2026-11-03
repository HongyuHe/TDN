import TDN.Targets.CompleteSpecifications
import TDN.Targets.ProcessingInventoryDerivation
import TDN.Targets.PolicyDerivation

namespace TDN.Targets.Complete
open Compliance PolicyDerivation

def IPv4SourceAtom : PacketPolicy.Atom → Prop
  | .sourceRange _ high => high < 2^32
  | _ => False

def IPv4DestinationAtom : PacketPolicy.Atom → Prop
  | .destinationRange _ high => high < 2^32
  | _ => False

def IPv4ProtocolAtom : PacketPolicy.Atom → Prop
  | .protocol name => name ∈ ["tcp", "udp", "esp", "icmp"]
  | _ => False

def IPv6SourceAtom : PacketPolicy.Atom → Prop
  | .sourceRange low high => 2^128 ≤ low ∧ high < 2^129
  | _ => False

def IPv6DestinationAtom : PacketPolicy.Atom → Prop
  | .destinationRange low high => 2^128 ≤ low ∧ high < 2^129
  | _ => False

def IPv6ProtocolAtom : PacketPolicy.Atom → Prop
  | .ipv6NextHeaders values => ∀ value ∈ values, value ∈ [50, 6, 17, 58]
  | _ => False

def UnicastDestinationAtom : PacketPolicy.Atom → Prop
  | .destinationRange low high =>
      high < 224 * 2^24 ∨
      (240 * 2^24 ≤ low ∧ high < 2^32) ∨
      (2^128 ≤ low ∧ high < 2^128 + 255 * 2^120)
  | _ => False

instance (atom : PacketPolicy.Atom) : Decidable (IPv4SourceAtom atom) := by
  cases atom <;> unfold IPv4SourceAtom <;> infer_instance
instance (atom : PacketPolicy.Atom) : Decidable (IPv4DestinationAtom atom) := by
  cases atom <;> unfold IPv4DestinationAtom <;> infer_instance
instance (atom : PacketPolicy.Atom) : Decidable (IPv4ProtocolAtom atom) := by
  cases atom <;> unfold IPv4ProtocolAtom <;> infer_instance
instance (atom : PacketPolicy.Atom) : Decidable (IPv6SourceAtom atom) := by
  cases atom <;> unfold IPv6SourceAtom <;> infer_instance
instance (atom : PacketPolicy.Atom) : Decidable (IPv6DestinationAtom atom) := by
  cases atom <;> unfold IPv6DestinationAtom <;> infer_instance
instance (atom : PacketPolicy.Atom) : Decidable (IPv6ProtocolAtom atom) := by
  cases atom <;> unfold IPv6ProtocolAtom <;> infer_instance
instance (atom : PacketPolicy.Atom) : Decidable (UnicastDestinationAtom atom) := by
  cases atom <;> unfold UnicastDestinationAtom <;> infer_instance

def IPv6WireProtocolAtom : PacketPolicy.Atom → Prop
  | .protocol name => name ∉ ["macsec", "mka", "arp", "ethernet"]
  | _ => False

instance (atom : PacketPolicy.Atom) : Decidable (IPv6WireProtocolAtom atom) := by
  cases atom <;> unfold IPv6WireProtocolAtom <;> infer_instance

def RuleHeaderGuard (rule : PacketPolicy.Rule) : Prop :=
  ((∃ atom ∈ rule.atoms, IPv4SourceAtom atom) ∧
    (∃ atom ∈ rule.atoms, IPv4DestinationAtom atom) ∧
    ∃ atom ∈ rule.atoms, IPv4ProtocolAtom atom) ∨
  ((∃ atom ∈ rule.atoms, IPv6SourceAtom atom) ∧
    (∃ atom ∈ rule.atoms, IPv6DestinationAtom atom) ∧
    (∃ atom ∈ rule.atoms, IPv6ProtocolAtom atom) ∧
    ∃ atom ∈ rule.atoms, IPv6WireProtocolAtom atom)

instance (rule : PacketPolicy.Rule) : Decidable (RuleHeaderGuard rule) := by
  unfold RuleHeaderGuard
  infer_instance

def RuleUnicastGuard (rule : PacketPolicy.Rule) : Prop :=
  ∃ atom ∈ rule.atoms, UnicastDestinationAtom atom

instance (rule : PacketPolicy.Rule) : Decidable (RuleUnicastGuard rule) := by
  unfold RuleUnicastGuard
  infer_instance

lemma source_bound_v4 (rule : PacketPolicy.Rule) (packet : PacketPolicy.Packet)
    (guard : ∃ atom ∈ rule.atoms, IPv4SourceAtom atom)
    (matched : rule.toFilter.accepts packet = true) : packet.source < 2^32 := by
  obtain ⟨atom, member, bound⟩ := guard
  have holds := PacketPolicy.matching_atom matched member
  cases atom <;> simp only [IPv4SourceAtom] at bound
  case sourceRange low high =>
    change low ≤ packet.source ∧ packet.source ≤ high at holds
    omega

lemma destination_bound_v4 (rule : PacketPolicy.Rule) (packet : PacketPolicy.Packet)
    (guard : ∃ atom ∈ rule.atoms, IPv4DestinationAtom atom)
    (matched : rule.toFilter.accepts packet = true) : packet.destination < 2^32 := by
  obtain ⟨atom, member, bound⟩ := guard
  have holds := PacketPolicy.matching_atom matched member
  cases atom <;> simp only [IPv4DestinationAtom] at bound
  case destinationRange low high =>
    change low ≤ packet.destination ∧ packet.destination ≤ high at holds
    omega

lemma source_bound_v6 (rule : PacketPolicy.Rule) (packet : PacketPolicy.Packet)
    (guard : ∃ atom ∈ rule.atoms, IPv6SourceAtom atom)
    (matched : rule.toFilter.accepts packet = true) :
    2^128 ≤ packet.source ∧ packet.source < 2^129 := by
  obtain ⟨atom, member, bound⟩ := guard
  have holds := PacketPolicy.matching_atom matched member
  cases atom <;> simp only [IPv6SourceAtom] at bound
  case sourceRange low high =>
    change low ≤ packet.source ∧ packet.source ≤ high at holds
    constructor <;> omega

lemma destination_bound_v6 (rule : PacketPolicy.Rule) (packet : PacketPolicy.Packet)
    (guard : ∃ atom ∈ rule.atoms, IPv6DestinationAtom atom)
    (matched : rule.toFilter.accepts packet = true) :
    2^128 ≤ packet.destination ∧ packet.destination < 2^129 := by
  obtain ⟨atom, member, bound⟩ := guard
  have holds := PacketPolicy.matching_atom matched member
  cases atom <;> simp only [IPv6DestinationAtom] at bound
  case destinationRange low high =>
    change low ≤ packet.destination ∧ packet.destination ≤ high at holds
    constructor <;> omega

lemma guarded_rule_has_permitted_header (rule : PacketPolicy.Rule)
    (packet : PacketPolicy.Packet) (guard : RuleHeaderGuard rule)
    (matched : rule.toFilter.accepts packet = true) :
    (PacketIPVersion packet = some 4 ∧ PacketIPProtocol packet ∈ [6, 17, 50, 1]) ∨
      (PacketIPVersion packet = some 6 ∧ packet.ipv6NextHeader ∈ [50, 6, 17, 58]) := by
  rcases guard with ⟨source, destination, atom, member, protocol⟩ |
      ⟨source, destination, ⟨atom, member, protocol⟩, wire⟩
  · have sourceBound := source_bound_v4 rule packet source matched
    have destinationBound := destination_bound_v4 rule packet destination matched
    have holds := PacketPolicy.matching_atom matched member
    cases atom <;> simp only [IPv4ProtocolAtom] at protocol
    case protocol name =>
      change packet.protocol = name at holds
      simp only [List.mem_cons, List.not_mem_nil, or_false] at protocol
      rcases protocol with rfl | rfl | rfl | rfl
      all_goals
        left
        simp [PacketIPVersion, PacketIPProtocol, holds, sourceBound, destinationBound]
  · have sourceBound := source_bound_v6 rule packet source matched
    have destinationBound := destination_bound_v6 rule packet destination matched
    have holds := PacketPolicy.matching_atom matched member
    cases atom <;> simp only [IPv6ProtocolAtom] at protocol
    case ipv6NextHeaders values =>
      change packet.ipv6NextHeader ∈ values at holds
      right
      refine ⟨?_, protocol _ holds⟩
      have notSpecial : packet.protocol ∉ ["macsec", "mka", "arp", "ethernet"] := by
        obtain ⟨wireAtom, wireMember, wireGuard⟩ := wire
        have wireHolds := PacketPolicy.matching_atom matched wireMember
        cases wireAtom <;> simp only [IPv6WireProtocolAtom] at wireGuard
        case protocol name =>
          change packet.protocol = name at wireHolds
          exact wireHolds ▸ wireGuard
      have sourceLarge : ¬ packet.source < 2^32 := by omega
      simp [PacketIPVersion, notSpecial, sourceBound, destinationBound, sourceLarge]

lemma unicast_rule_is_not_multicast (rule : PacketPolicy.Rule)
    (packet : PacketPolicy.Packet) (guard : RuleUnicastGuard rule)
    (headers : PacketIPVersion packet = some 4 ∨ PacketIPVersion packet = some 6)
    (matched : rule.toFilter.accepts packet = true) : PacketMulticast packet = false := by
  obtain ⟨atom, member, bound⟩ := guard
  have holds := PacketPolicy.matching_atom matched member
  cases atom <;> simp only [UnicastDestinationAtom] at bound
  case destinationRange low high =>
    change low ≤ packet.destination ∧ packet.destination ≤ high at holds
    rcases headers with version | version
    · simp only [PacketMulticast, version]
      simp only [decide_eq_false_iff_not]
      rcases bound with below | above | encoded <;> omega
    · simp only [PacketMulticast, version]
      simp only [decide_eq_false_iff_not]
      rcases bound with below | above | encoded <;> omega

end TDN.Targets.Complete

namespace TDN.Targets.Complete
open Compliance PolicyDerivation

instance (device : Device) (interface : Interface) :
    Decidable (HeaderFilterApplies device interface) := by
  unfold HeaderFilterApplies
  infer_instance

def HeaderRuleChecks (d : Deployment) (device : Device) (interface : Interface)
    (rule : PacketPolicy.Rule) : Prop :=
  RuleHeaderGuard rule ∧
    (device.layer = some .outer → interface.zone = .black → RuleUnicastGuard rule) ∧
    (device.kind = .vpn → device.layer = some .outer →
      d.dropIPv4Options device.id = true → .ipv4HeaderWords 5 ∈ rule.atoms)

instance (d : Deployment) (device : Device) (interface : Interface) (rule : PacketPolicy.Rule) :
    Decidable (HeaderRuleChecks d device interface rule) := by
  unfold HeaderRuleChecks
  exact instDecidableAnd

def HeaderInterfacePolicyCheck (d : Deployment) (device : Device) (interface : Interface)
    (policy : InterfacePolicy) : Prop :=
  policy.defaultVerdict = .deny ∧
    ∀ rule ∈ policy.rules, rule.verdict = .allow → HeaderRuleChecks d device interface rule

instance (d : Deployment) (device : Device) (interface : Interface) (policy : InterfacePolicy) :
    Decidable (HeaderInterfacePolicyCheck d device interface policy) := by
  unfold HeaderInterfacePolicyCheck
  infer_instance

def HeaderPolicyChecks (d : Deployment) : Prop :=
  ∀ interface ∈ d.interfaces, ∀ device ∈ d.devices,
    interface.device = device.id → HeaderFilterApplies device interface →
    ∀ policy ∈ d.policies, policy.interface = interface.id → policy.direction = .inbound →
      HeaderInterfacePolicyCheck d device interface policy

instance (d : Deployment) : Decidable (HeaderPolicyChecks d) := by
  unfold HeaderPolicyChecks
  infer_instance

def headerPoliciesChecked (d : Deployment) : Bool := decide (HeaderPolicyChecks d)

theorem ip_header_filtering_from_inventory_and_rule_atoms (d : Deployment)
    (inventory : PacketProcessing.Inventory) (objective : String → Bool)
    (objectiveDefinition : ∀ component, objective component = d.dropIPv4Options component)
    (present : d.processing = some inventory)
    (addressChecked : addressRecordsChecked d = true)
    (workstationDefinition : d.grayWorkstation = grayWorkstationRole d)
    (processingChecked : processingInventoryChecked d inventory = true)
    (lengthDefinition : (fun packet payload =>
      inventory.configuration.networkBytes (.datagram packet) payload) =
        (fun packet _ => packet.networkBytes))
    (localAddressDefinition : inventory.configuration.ip.localAddress = nativeLocalAddress d inventory)
    (indicesChecked : policyIndicesChecked d = true)
    (rulesChecked : headerPoliciesChecked d = true)
    (linkPolicies : d.LinkPoliciesComplete)
    (routed : ∀ interface ∈ d.interfaces, ∀ device ∈ d.devices,
      interface.device = device.id → HeaderFilterApplies device interface →
      ∀ port ∈ inventory.ports, inventory.portName port = interface.id → RoutedPort inventory port) :
    msc_ip_header_and_multicast_filtering d objective := by
  have address := address_inventory_from_checked_records d addressChecked workstationDefinition
  have processing := processing_coherence_from_record_checks d inventory present processingChecked
    lengthDefinition localAddressDefinition
  have checks : HeaderPolicyChecks d := of_decide_eq_true rulesChecked
  refine ⟨objectiveDefinition, address, processing, linkPolicies, ?_⟩
  intro interface member _ device deviceMember _ owner applies
  refine ⟨policy_coverage_from_checked_indices d indicesChecked interface member, ?_⟩
  intro traffic accepted
  have acceptedBase : d.Accepts interface.id .inbound traffic := accepted
  have supported := accepted_traffic_supported d interface.id .inbound traffic acceptedBase
  obtain ⟨policy, policyMember, name, direction, admits⟩ :=
    routed_acceptance_has_policy d inventory present interface.id .inbound traffic
      (routed interface member device deviceMember owner applies) acceptedBase
  obtain ⟨fallback, guards⟩ :=
    checks interface member device deviceMember owner applies policy policyMember name direction
  obtain ⟨rule, ruleMember, matched, allows⟩ :=
    policy_acceptance_has_matching_rule policy traffic fallback admits
  obtain ⟨headerGuard, unicastGuard, optionGuard⟩ := guards rule ruleMember allows
  have header := guarded_rule_has_permitted_header rule traffic.packet headerGuard matched
  have version : traffic.ipVersion = PacketIPVersion traffic.packet := by
    rw [supported.1]
    rfl
  have protocol : traffic.ipProtocol = PacketIPProtocol traffic.packet := by
    rw [supported.1]
    rfl
  have multicast : traffic.multicast = PacketMulticast traffic.packet := by
    rw [supported.1]
    rfl
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro outer black
    apply Or.inl
    rw [multicast]
    exact unicast_rule_is_not_multicast rule traffic.packet (unicastGuard outer black)
      (header.elim (fun v => Or.inl v.1) (fun v => Or.inr v.1)) matched
  · intro _ ipv4
    rw [version] at ipv4
    rw [protocol]
    rcases header with v4 | v6
    · exact v4.2
    · simp [v6.1] at ipv4
  · intro _ ipv6
    rw [version] at ipv6
    rcases header with v4 | v6
    · simp [v4.1] at ipv6
    · exact v6.2
  · intro vpn outer _ selected
    exact PacketPolicy.matching_atom matched
      (optionGuard vpn outer ((objectiveDefinition device.id).symm.trans selected))

end TDN.Targets.Complete
