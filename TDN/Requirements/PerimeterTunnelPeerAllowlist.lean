import TDN.Requirements.ExtractConfiguredTunnelPeers
import TDN.Requirements.DerivePerimeterContext

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding

def OutboundPeerRule (device name : String) (peers : List BoundaryPeer)
    (rule : PacketPolicy.Rule) : Prop :=
  RuleMissesHook name .outbound rule ∨
    (∃ atom ∈ rule.atoms, DevicePolicyAtom .outbound atom) ∨
    ∃ record ∈ peers, record.source = device ∧
      .destinationRange record.destinationAddress record.destinationAddress ∈ rule.atoms ∧
      DeriveDataPlaneFromDeviceRecords.RuleIPGuard rule

instance (device name : String) (peers : List BoundaryPeer) (rule : PacketPolicy.Rule) :
    Decidable (OutboundPeerRule device name peers rule) := by
  unfold OutboundPeerRule
  infer_instance

lemma matching_outbound_peer_rule (device name : String) (peers : List BoundaryPeer)
    (hook : PacketProcessing.Hook) (packet : PacketPolicy.Packet)
    (context : PacketAtHook name .outbound hook packet)
    (rule : PacketPolicy.Rule) (checks : OutboundPeerRule device name peers rule)
    (matched : rule.toFilter.accepts packet = true) :
    (∃ record ∈ peers, record.source = device ∧ packet.destination = record.destinationAddress ∧
      packet.protocol ≠ "ethernet") ∨ ∃ requestId, requestId ∈ packet.matchedOutboundPolicyIds := by
  rcases checks with misses | ⟨atom, member, native⟩ | ⟨record, member, owner, address, guard⟩
  · exact False.elim (hook_mismatch_cannot_match name .outbound hook packet context rule misses matched)
  · have holds := PacketPolicy.matching_atom matched member
    cases atom <;> simp only [DevicePolicyAtom] at native
    case inboundPolicy requestId => cases native
    case outboundPolicy requestId => exact Or.inr ⟨requestId, holds⟩
  · have interval := PacketPolicy.matching_atom matched address
    change record.destinationAddress ≤ packet.destination ∧ packet.destination ≤ record.destinationAddress at interval
    exact Or.inl ⟨record, member, owner, by omega,
      DeriveDataPlaneFromDeviceRecords.ip_rule_cannot_match_ethernet rule packet guard matched⟩

lemma admitted_native_packet_has_peer_or_outbound_annotation (d : Deployment)
    (inventory : PacketProcessing.Inventory) (present : d.processing = some inventory)
    (interface : Interface) (peers : List BoundaryPeer)
    (routed : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      DeriveDataPlaneFromDeviceRecords.RoutedIface inventory iface)
    (checks : ∀ iface ∈ inventory.ifaces, inventory.ifaceName iface = interface.id →
      ∀ policy ∈ d.policies, policy.interface = interface.id →
        policy.defaultVerdict = .deny ∧ (policy.direction = .outbound → ∀ rule ∈ policy.rules, rule.verdict = .allow →
          OutboundPeerRule interface.device (inventory.configuration.ip.interfaceName iface) peers rule))
    (traffic : Traffic) (accepted : d.Accepts interface.id .outbound traffic) :
    (∃ record ∈ peers, record.source = interface.device ∧
      traffic.packet.destination = record.destinationAddress ∧ traffic.packet.protocol ≠ "ethernet") ∨
      ∃ requestId, requestId ∈ traffic.packet.matchedOutboundPolicyIds := by
  have fallback : ∀ policy ∈ d.policies, policy.interface = interface.id →
      policy.defaultVerdict = .deny := by
    obtain ⟨_, _, ⟨actual, same, iface, member, name, _⟩, admission⟩ := accepted
    have identity : actual = inventory := Option.some.inj (same.symm.trans present)
    subst actual
    intro policy policyMember policyName
    exact (checks iface member name policy policyMember policyName).1
  obtain ⟨iface, member, name, hook, context, policy, policyMember, policyName,
    policyDirection, _, rule, ruleMember, allow, matched⟩ :=
    routed_acceptance_has_local_matching_rule d inventory present interface.id .outbound traffic
      routed fallback accepted
  exact matching_outbound_peer_rule interface.device _ peers hook traffic.packet context rule
    ((checks iface member name policy policyMember policyName).2 policyDirection rule ruleMember allow) matched

end TDN.Requirements.Msc
