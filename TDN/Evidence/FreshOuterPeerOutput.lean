import TDN.Import.Command
import TDN.Targets.PeerOutput
import TDN.Evidence.FreshSharedExecution

namespace TDN.Imported.FreshOuterPeerOutput

/-- Complete Outer inventory and the corresponding raw SAD/configured peer
endpoint addresses from the shared native execution import. -/
tdn_data outerPeers : List (Nat × Nat) from "../../evidence/lean/FreshOuterPeerOutput.json" ["TDN.Imported.FreshOuterPeerOutput.outerPeers"]

def rules (device : Nat) : List PacketPolicy.Rule :=
  (Execution.deviceAt FreshSharedExecution.devices device).outputRules

lemma actual_defaults : ∀ row ∈ outerPeers,
    (Execution.deviceAt FreshSharedExecution.devices row.1).outputFallback = .deny := by decide

lemma peer_rule_checks : ∀ row ∈ outerPeers, ∀ rule ∈ rules row.1,
    rule.verdict = .allow → Targets.PeerOutputGuard row.2 rule := by decide

/-- OR10's local-output subclause. Forwarded traffic and additional interface
protocol clauses are accounted separately; no requirement approval is assumed. -/
theorem every_external_local_output_targets_the_actual_peer (row : Nat × Nat)
    (member : row ∈ outerPeers) (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((rules row.1).map PacketPolicy.Rule.toFilter)
      (Execution.deviceAt FreshSharedExecution.devices row.1).outputFallback packet = .allow)
    (external : packet.egress ≠ "lo") : packet.destination = row.2 := by
  rw [actual_defaults row member] at accepted
  exact Targets.accepted_nonloopback_output_has_peer_destination (rules row.1) row.2
    (peer_rule_checks row member) packet accepted external

/-- PF6's blocking alternative for locally generated contacts. Every destination
other than the recorded Outer peer is denied on non-loopback output under the
captured OUTPUT hook semantics and fixed policy. -/
theorem locally_generated_third_party_contacts_are_blocked (row : Nat × Nat)
    (member : row ∈ outerPeers) (packet : PacketPolicy.Packet)
    (external : packet.egress ≠ "lo") (thirdParty : packet.destination ≠ row.2) :
    Filter.evaluate ((rules row.1).map PacketPolicy.Rule.toFilter)
      (Execution.deviceAt FreshSharedExecution.devices row.1).outputFallback packet = .deny := by
  rw [actual_defaults row member]
  exact Targets.nonpeer_local_output_is_blocked (rules row.1) row.2
    (peer_rule_checks row member) packet external thirdParty

end TDN.Imported.FreshOuterPeerOutput
