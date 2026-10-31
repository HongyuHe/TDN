import TDN.Targets.PeerInteroperability
import TDN.Evidence.FreshPairingInnerMacsecOuterIpsecForwardVLAN0
import TDN.Evidence.FreshPairingInnerMacsecOuterIpsecReverseVLAN0

namespace TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN0

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

theorem actual_peer_restores_original_ethernet :
    usefulState30.phase = .delivered ∧
    usefulState30.frame.body.originalEthernet = usefulState0.frame.body.originalEthernet := by
  refine ⟨rfl, ?_⟩
  have restored := Targets.successful_ethernet_peer_restores_header config
    positive_mixed_delivery (show usefulState0.frame.body = .ethernet _ from rfl)
    (show usefulState30.frame.body = .ethernet _ from rfl)
  exact congrArg some restored

end TDN.Imported.PairingInnerMacsecOuterIpsec.ReverseVLAN0
