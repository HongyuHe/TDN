import TDN.Requirements.RedEnclaveNoBypassSpec

namespace TDN.Requirements.Msc
open Compliance

lemma routed_acceptance_has_local_matching_rule (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : String) (direction : Direction) (traffic : Traffic)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface →
      DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface)
    (fallback : ∀ policy ∈ d.policies, policy.interface = interface → policy.defaultVerdict = .deny)
    (accepted : d.Accepts interface direction traffic) :
    ∃ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface ∧
      ∃ hook, PacketAtHook (inventory.configuration.ip.interfaceName iface) direction hook traffic.packet ∧
      ∃ policy ∈ d.policies, policy.interface = interface ∧ policy.direction = direction ∧
      policy.hook = hook ∧
      ∃ rule ∈ policy.rules, rule.verdict = .allow ∧ rule.toFilter.accepts traffic.packet = true := by
  obtain ⟨hook, supported, context, admission⟩ := accepted
  by_cases link : hook = .link
  · subst hook
    exact False.elim (DeriveDataPlaneFromDeviceRecords.routed_iface_has_no_link_operation d inventory present
      interface routed direction traffic admission)
  · simp only [link, ↓reduceIte] at admission
    obtain ⟨policy, member, name, policyDirection, policyHook, unique, allows⟩ := admission
    obtain ⟨rule, ruleMember, matched, allow⟩ :=
      DeriveDataPlaneFromDeviceRecords.policy_acceptance_has_matching_rule policy traffic
        (fallback policy member name) allows
    obtain ⟨actual, same, iface, ifaceMember, ifaceName, record, _, _, _, atHook⟩ := context
    have sameInventory : actual = inventory := Option.some.inj (same.symm.trans present)
    subst actual
    exact ⟨iface, ifaceMember, ifaceName, hook, atHook,
      policy, member, name, policyDirection, policyHook, rule, ruleMember, allow, matched⟩

theorem Red_admission_from_local_rule_checks (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (endpoints : List RedServiceEndpoint)
    (bound : ∀ endpoint ∈ endpoints, endpoint.Bound d)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface)
    (checks : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      ∀ policy ∈ d.policies, policy.interface = interface.id →
        policy.defaultVerdict = .deny ∧ ∀ rule ∈ policy.rules, rule.verdict = .allow →
          RedBoundaryRule interface.device (inventory.configuration.ip.interfaceName iface)
            policy.direction endpoints rule)
    (direction : Direction) (traffic : Traffic)
    (accepted : d.Accepts interface.id direction traffic) :
    d.redService interface.device traffic.packet.source (TransportServicePort traffic.packet true) ∨
      d.redService interface.device traffic.packet.destination (TransportServicePort traffic.packet false) := by
  have fallback : ∀ policy ∈ d.policies, policy.interface = interface.id →
      policy.defaultVerdict = .deny := by
    intro policy member name
    obtain ⟨hook, _, context, _⟩ := accepted
    obtain ⟨actual, same, iface, ifaceMember, ifaceName, _⟩ := context
    have sameInventory : actual = inventory := Option.some.inj (same.symm.trans present)
    subst actual
    exact (checks iface ifaceMember ifaceName policy member name).1
  obtain ⟨iface, ifaceMember, ifaceName, hook, context, policy, member, name, policyDirection,
    policyHook, rule, ruleMember, allow, matched⟩ :=
    routed_acceptance_has_local_matching_rule d inventory present interface.id direction traffic
      routed fallback accepted
  have ruleChecks := (checks iface ifaceMember ifaceName policy member name).2 rule ruleMember allow
  rw [policyDirection] at ruleChecks
  exact matching_Red_boundary_rule d interface.device
    (inventory.configuration.ip.interfaceName iface) direction hook endpoints bound rule ruleChecks
    traffic.packet context matched

def DevicePolicyAtom (direction : Direction) : PacketPolicy.MatchCondition → Prop
  | .inboundPolicy _ => direction = .inbound
  | .outboundPolicy _ => direction = .outbound
  | _ => False

instance (direction : Direction) (atom : PacketPolicy.MatchCondition) :
    Decidable (DevicePolicyAtom direction atom) := by
  cases atom <;> unfold DevicePolicyAtom <;> infer_instance

def DeviceProtocolRule (name : String) (direction : Direction) (rule : PacketPolicy.Rule) : Prop :=
  RuleMissesHook name direction rule ∨ IPsecRule rule ∨
    ∃ atom ∈ rule.atoms, DevicePolicyAtom direction atom

instance (name : String) (direction : Direction) (rule : PacketPolicy.Rule) :
    Decidable (DeviceProtocolRule name direction rule) := by
  unfold DeviceProtocolRule
  infer_instance

lemma matching_native_protocol_rule (name : String) (direction : Direction)
    (hook : PacketProcessing.Hook) (rule : PacketPolicy.Rule)
    (checks : DeviceProtocolRule name direction rule)
    (packet : PacketPolicy.Packet) (context : PacketAtHook name direction hook packet)
    (matched : rule.toFilter.accepts packet = true) :
    IPsecPacket packet ∨
      if direction = .inbound then packet.matchedInboundPolicyIds ≠ [] else packet.matchedOutboundPolicyIds ≠ [] := by
  rcases checks with misses | protocol | ⟨atom, member, guard⟩
  · exact False.elim (hook_mismatch_cannot_match name direction hook packet context rule misses matched)
  · exact Or.inl (IPsec_rule_has_IPsec_packet rule packet protocol matched)
  · have holds := PacketPolicy.matching_atom matched member
    cases atom <;> simp only [DevicePolicyAtom] at guard
    case inboundPolicy requestId =>
      subst direction
      refine Or.inr ?_
      change packet.matchedInboundPolicyIds ≠ []
      intro empty
      simpa [PacketPolicy.MatchCondition.matchesPacket, empty] using holds
    case outboundPolicy requestId =>
      subst direction
      refine Or.inr ?_
      change packet.matchedOutboundPolicyIds ≠ []
      intro empty
      simpa [PacketPolicy.MatchCondition.matchesPacket, empty] using holds

end TDN.Requirements.Msc
