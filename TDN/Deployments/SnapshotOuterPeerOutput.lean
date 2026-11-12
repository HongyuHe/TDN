import TDN.Import.SnapshotLoader
import TDN.Requirements.OuterEncryptorPeerEgressSpec
import TDN.Deployments.ProfileShared_DataPlane

namespace TDN.Deployments.SnapshotOuterPeerOutput

load_network_records outerPeers : List (Nat × Nat) from "../../data/evidence/SnapshotOuterPeerOutput.json" ["TDN.Deployments.SnapshotOuterPeerOutput.outerPeers"]

def rules (device : Nat) : List PacketPolicy.Rule :=
  (DataPlaneForwarding.deviceAt ProfileShared_DataPlane.devices device).outputRules

lemma actual_defaults : ∀ row ∈ outerPeers,
    (DataPlaneForwarding.deviceAt ProfileShared_DataPlane.devices row.1).outputFallback = .deny := by native_decide

lemma peer_rule_checks : ∀ row ∈ outerPeers, ∀ rule ∈ rules row.1,
    rule.verdict = .allow → Requirements.PeerOutputGuard row.2 rule := by native_decide

theorem every_external_local_output_targets_the_actual_peer (row : Nat × Nat)
    (member : row ∈ outerPeers) (packet : PacketPolicy.Packet)
    (accepted : Filter.evaluate ((rules row.1).map PacketPolicy.Rule.toFilter)
      (DataPlaneForwarding.deviceAt ProfileShared_DataPlane.devices row.1).outputFallback packet = .allow)
    (external : packet.egress ≠ "lo") : packet.destination = row.2 := by
  rw [actual_defaults row member] at accepted
  exact Requirements.accepted_nonloopback_output_has_peer_destination (rules row.1) row.2
    (peer_rule_checks row member) packet accepted external

theorem locally_generated_third_party_contacts_are_blocked (row : Nat × Nat)
    (member : row ∈ outerPeers) (packet : PacketPolicy.Packet)
    (external : packet.egress ≠ "lo") (thirdParty : packet.destination ≠ row.2) :
    Filter.evaluate ((rules row.1).map PacketPolicy.Rule.toFilter)
      (DataPlaneForwarding.deviceAt ProfileShared_DataPlane.devices row.1).outputFallback packet = .deny := by
  rw [actual_defaults row member]
  exact Requirements.nonpeer_local_output_is_blocked (rules row.1) row.2
    (peer_rule_checks row member) packet external thirdParty

end TDN.Deployments.SnapshotOuterPeerOutput
