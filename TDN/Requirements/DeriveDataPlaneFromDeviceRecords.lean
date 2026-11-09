import TDN.Requirements.MscComplianceSchema

namespace TDN.Requirements.DeriveDataPlaneFromDeviceRecords
open Compliance

lemma non_ethernet_has_no_link_operation (d : Deployment) (interface : String)
    (direction : Direction) (traffic : Traffic)
    (notEthernet : traffic.packet.protocol ≠ "ethernet") :
    ¬ d.LinkOperation interface direction traffic := by
  rintro ⟨⟨inventory, _, iface, _, _, operation⟩, _⟩
  rcases operation with ethernet | mka | macsec
  · exact notEthernet ethernet.1.1
  · exact notEthernet mka.1.1.1
  · exact notEthernet macsec.1.1.1

lemma ip_acceptance_has_policy (d : Deployment) (interface : String)
    (direction : Direction) (traffic : Traffic)
    (notEthernet : traffic.packet.protocol ≠ "ethernet")
    (accepted : d.Accepts interface direction traffic) :
    ∃ policy ∈ d.policies,
      policy.interface = interface ∧ policy.direction = direction ∧ policy.Accepts traffic := by
  obtain ⟨hook, _, _, accepted⟩ := accepted
  by_cases link : hook = .link
  · subst hook
    have operation : d.LinkOperation interface direction traffic := accepted
    exact False.elim
      (non_ethernet_has_no_link_operation d interface direction traffic notEthernet operation)
  · simp only [link, ↓reduceIte] at accepted
    obtain ⟨policy, member, iface, direction, _, _, admits⟩ := accepted
    exact ⟨policy, member, iface, direction, admits⟩

lemma policy_denies_if_allow_rules_miss (policy : InterfacePolicy) (traffic : Traffic)
    (fallback : policy.defaultVerdict = .deny)
    (misses : ∀ rule ∈ policy.rules, rule.verdict = .allow →
      rule.toFilter.accepts traffic.packet = false) :
    ¬ policy.Accepts traffic := by
  intro accepted
  unfold InterfacePolicy.Accepts at accepted
  rw [fallback] at accepted
  obtain ⟨rule, member, matched, allow⟩ :=
    Filter.allowed_has_matching_allow (policy.rules.map PacketPolicy.Rule.toFilter)
      traffic.packet accepted
  obtain ⟨source, present, same⟩ := List.mem_map.mp member
  subst rule
  have denied := misses source present allow
  exact Bool.noConfusion (matched.symm.trans denied)

end TDN.Requirements.DeriveDataPlaneFromDeviceRecords

namespace TDN.Requirements.DeriveDataPlaneFromDeviceRecords
open Compliance

def RoutedIface (inventory : PacketProcessing.Inventory) (iface : Nat) : Prop :=
  (∀ mac ∈ inventory.configuration.macIfaces, mac.physicalIface ≠ iface) ∧
  (∀ next ∈ inventory.ifaces,
    ¬ inventory.configuration.bridge iface next ∧ ¬ inventory.configuration.bridge next iface) ∧
  (∀ carrier ∈ inventory.configuration.carriers, carrier.virtualIface ≠ iface) ∧
  (∀ endpoint ∈ inventory.mkaPeers,
    endpoint.sourceIface ≠ iface ∧ endpoint.destinationIface ≠ iface)

lemma routed_iface_has_no_link_operation (d : Deployment) (inventory : PacketProcessing.Inventory)
    (present : d.processing = some inventory) (interface : String)
    (ifaces : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface → RoutedIface inventory iface)
    (direction : Direction) (traffic : Traffic) :
    ¬ d.LinkOperation interface direction traffic := by
  rintro ⟨⟨actual, same, iface, member, name, operation⟩, _⟩
  have equal : actual = inventory := Option.some.inj (same.symm.trans present)
  subst actual
  obtain ⟨macs, bridges, carriers, mkaPeers⟩ := ifaces iface member name
  rcases operation with ethernet | mka | macsec
  · rcases ethernet.2 with ⟨next, nextMember, bridge⟩ | ⟨carrier, carrierMember, virtual⟩ |
        ⟨mac, macMember, physical⟩
    · cases direction with
      | inbound => exact (bridges next nextMember).1 bridge
      | outbound => exact (bridges next nextMember).2 bridge
    · exact carriers carrier carrierMember virtual
    · exact macs mac macMember physical
  · obtain ⟨endpoint, endpointMember, side, _⟩ := mka.2
    cases direction with
    | inbound => exact (mkaPeers endpoint endpointMember).2 side
    | outbound => exact (mkaPeers endpoint endpointMember).1 side
  · obtain ⟨mac, macMember, physical, _⟩ := macsec.2
    exact macs mac macMember physical

def IPProtocolAtom : PacketPolicy.MatchCondition → Prop
  | .protocol name => name ≠ "ethernet"
  | _ => False

instance (atom : PacketPolicy.MatchCondition) : Decidable (IPProtocolAtom atom) := by
  cases atom <;> unfold IPProtocolAtom <;> infer_instance

def RuleIPGuard (rule : PacketPolicy.Rule) : Prop :=
  ∃ atom ∈ rule.atoms, IPProtocolAtom atom

instance (rule : PacketPolicy.Rule) : Decidable (RuleIPGuard rule) := by
  unfold RuleIPGuard
  infer_instance

lemma ip_rule_cannot_match_ethernet (rule : PacketPolicy.Rule) (packet : PacketPolicy.Packet)
    (guard : RuleIPGuard rule) (matched : rule.toFilter.accepts packet = true) :
    packet.protocol ≠ "ethernet" := by
  obtain ⟨atom, present, guarded⟩ := guard
  have atomMatches := PacketPolicy.matching_atom matched present
  cases atom <;> simp only [IPProtocolAtom] at guarded
  case protocol name =>
    change packet.protocol = name at atomMatches
    exact atomMatches ▸ guarded

lemma routed_acceptance_has_ip_policy (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : String) (direction : Direction) (traffic : Traffic)
    (ifaces : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface → RoutedIface inventory iface)
    (fallback : ∀ policy ∈ d.policies, policy.defaultVerdict = .deny)
    (guards : ∀ policy ∈ d.policies, ∀ rule ∈ policy.rules,
      rule.verdict = .allow → RuleIPGuard rule)
    (accepted : d.Accepts interface direction traffic) :
    traffic.packet.protocol ≠ "ethernet" ∧ ∃ policy ∈ d.policies,
      policy.interface = interface ∧ policy.direction = direction ∧ policy.Accepts traffic := by
  obtain ⟨hook, _, _, admission⟩ := accepted
  by_cases link : hook = .link
  · subst hook
    exact False.elim (routed_iface_has_no_link_operation d inventory present
      interface ifaces direction traffic admission)
  · simp only [link, ↓reduceIte] at admission
    obtain ⟨policy, member, name, direction, _, _, admits⟩ := admission
    have allows := admits
    unfold InterfacePolicy.Accepts at allows
    rw [fallback policy member] at allows
    obtain ⟨rule, ruleMember, matchesRule, allow⟩ :=
      Filter.allowed_has_matching_allow (policy.rules.map PacketPolicy.Rule.toFilter) traffic.packet allows
    obtain ⟨original, originalMember, same⟩ := List.mem_map.mp ruleMember
    subst rule
    exact ⟨ip_rule_cannot_match_ethernet original traffic.packet
      (guards policy member original originalMember allow) matchesRule,
      policy, member, name, direction, admits⟩

end TDN.Requirements.DeriveDataPlaneFromDeviceRecords

namespace TDN.Requirements.DeriveDataPlaneFromDeviceRecords
open Compliance

lemma routed_acceptance_has_policy (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : String) (direction : Direction) (traffic : Traffic)
    (ifaces : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface → RoutedIface inventory iface)
    (accepted : d.Accepts interface direction traffic) :
    ∃ policy ∈ d.policies, policy.interface = interface ∧
      policy.direction = direction ∧ policy.Accepts traffic := by
  obtain ⟨hook, _, _, admission⟩ := accepted
  by_cases link : hook = .link
  · subst hook
    exact False.elim (routed_iface_has_no_link_operation d inventory present
      interface ifaces direction traffic admission)
  · simp only [link, ↓reduceIte] at admission
    obtain ⟨policy, member, name, direction, _, _, admits⟩ := admission
    exact ⟨policy, member, name, direction, admits⟩

lemma policy_acceptance_has_matching_rule (policy : InterfacePolicy) (traffic : Traffic)
    (fallback : policy.defaultVerdict = .deny) (accepted : policy.Accepts traffic) :
    ∃ rule ∈ policy.rules, rule.toFilter.accepts traffic.packet = true ∧ rule.verdict = .allow := by
  unfold InterfacePolicy.Accepts at accepted
  rw [fallback] at accepted
  obtain ⟨rule, member, matched, allow⟩ :=
    Filter.allowed_has_matching_allow (policy.rules.map PacketPolicy.Rule.toFilter)
      traffic.packet accepted
  obtain ⟨source, present, same⟩ := List.mem_map.mp member
  subst rule
  exact ⟨source, present, matched, allow⟩

end TDN.Requirements.DeriveDataPlaneFromDeviceRecords
