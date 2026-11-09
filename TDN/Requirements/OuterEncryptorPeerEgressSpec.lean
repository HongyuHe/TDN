import TDN.Models.IpHeaderAclGuards

namespace TDN.Requirements
open PacketPolicy

def PeerOutputGuard (peer : Nat) (rule : Rule) : Prop :=
  .egress "lo" ∈ rule.atoms ∨ .destinationRange peer peer ∈ rule.atoms

instance (peer : Nat) (rule : Rule) : Decidable (PeerOutputGuard peer rule) := by
  unfold PeerOutputGuard
  infer_instance

theorem accepted_nonloopback_output_has_peer_destination (rules : List Rule) (peer : Nat)
    (checked : ∀ rule ∈ rules, rule.verdict = .allow → PeerOutputGuard peer rule)
    (packet : Packet) (accepted : Accepts rules packet) (external : packet.egress ≠ "lo") :
    packet.destination = peer := by
  have property : packet.egress ≠ "lo" → packet.destination = peer := by
    apply TDN.Filter.default_deny_sound (rules.map Rule.toFilter)
      (fun p => p.egress ≠ "lo" → p.destination = peer) ?_ packet accepted
    intro target member allow candidate matched outside
    obtain ⟨rule, present, rfl⟩ := List.mem_map.mp member
    rcases checked rule present allow with loopback | destination
    · exact False.elim (outside (matching_atom matched loopback))
    · have bounds := matching_atom matched destination
      change peer ≤ candidate.destination ∧ candidate.destination ≤ peer at bounds
      omega
  exact property external

theorem nonpeer_local_output_is_blocked (rules : List Rule) (peer : Nat)
    (checked : ∀ rule ∈ rules, rule.verdict = .allow → PeerOutputGuard peer rule)
    (packet : Packet) (external : packet.egress ≠ "lo") (thirdParty : packet.destination ≠ peer) :
    TDN.Filter.evaluate (rules.map Rule.toFilter) .deny packet = .deny := by
  cases verdict : TDN.Filter.evaluate (rules.map Rule.toFilter) .deny packet with
  | deny => rfl
  | allow => exact False.elim (thirdParty
      (accepted_nonloopback_output_has_peer_destination rules peer checked packet verdict external))

end TDN.Requirements
