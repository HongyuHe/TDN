import TDN.Targets.PeerInteroperability
import TDN.Evidence.FreshRecordedOperations
import TDN.Evidence.FreshPairingInnerMacsecOuterIpsecForwardVLAN0
import TDN.Evidence.FreshPairingInnerMacsecOuterIpsecReverseVLAN0

namespace TDN.Imported.FreshRecordedOperations

def issuanceAt (index : Fin 4) : RecordedOperations.Issuance :=
  issuances[index.val]'(by change index.val < 4; exact index.isLt)

def peerIssuance (index : Fin 4) : RecordedOperations.Issuance :=
  issuanceAt ([1, 0, 3, 2][index.val]!)

lemma peer_issuer_coverage : ∀ index : Fin 4,
    (([peerIssuance index].map RecordedOperations.Issuance.signer).toFinset ⊆
      (issuanceAt index).loadedAuthorities.toFinset) := by
  unfold peerIssuance issuanceAt issuances
  decide

/-- Each logical A/B site has the actual opposite site's signing CA loaded for
its layer. The enterprise case declares these logical sites. Independent
administrators, revocation completeness and all trust policies remain separate. -/
theorem actual_peer_signing_ca_is_available (index : Fin 4) :
    (peerIssuance index).signer ∈ (issuanceAt index).loadedAuthorities := by
  exact Targets.peer_issuers_available_from_loaded_coverage
    [peerIssuance index] RecordedOperations.Issuance.signer
    (issuanceAt index).loadedAuthorities (peer_issuer_coverage index)
    (peerIssuance index) (by simp)

end TDN.Imported.FreshRecordedOperations

namespace TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN0

/-- The checked nonempty useful trace ends at the receiving Red endpoint and
restores its original opaque Ethernet header through MACsec, L2TP and ESP. -/
theorem actual_peer_restores_original_ethernet :
    usefulState30.phase = .delivered ∧
    usefulState30.frame.body.originalEthernet = usefulState0.frame.body.originalEthernet := by
  refine ⟨rfl, ?_⟩
  have restored := Targets.successful_ethernet_peer_restores_header config
    positive_mixed_delivery (show usefulState0.frame.body = .ethernet _ from rfl)
    (show usefulState30.frame.body = .ethernet _ from rfl)
  exact congrArg some restored

end TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN0

namespace TDN.Imported.PairingInnerMacsecOuterIpsec.ReverseVLAN0

/-- The checked nonempty useful trace ends at the receiving Red endpoint and
restores its original opaque Ethernet header through MACsec, L2TP and ESP. -/
theorem actual_peer_restores_original_ethernet :
    usefulState30.phase = .delivered ∧
    usefulState30.frame.body.originalEthernet = usefulState0.frame.body.originalEthernet := by
  refine ⟨rfl, ?_⟩
  have restored := Targets.successful_ethernet_peer_restores_header config
    positive_mixed_delivery (show usefulState0.frame.body = .ethernet _ from rfl)
    (show usefulState30.frame.body = .ethernet _ from rfl)
  exact congrArg some restored

end TDN.Imported.PairingInnerMacsecOuterIpsec.ReverseVLAN0
