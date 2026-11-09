import TDN.Requirements.TunnelPeerCryptoInteropSpec
import TDN.Deployments.TunnelMatrix_InnerMacsec_OuterIpsec_Fwd_VLAN0
import TDN.Deployments.TunnelMatrix_InnerMacsec_OuterIpsec_Rev_VLAN0

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec.ForwardVLAN0

theorem actual_peer_restores_original_ethernet :
    usefulState30.datapathStage = .delivered ∧
    usefulState30.frame.body.originalEthernet = usefulState0.frame.body.originalEthernet := by
  refine ⟨rfl, ?_⟩
  have restored := Requirements.successful_ethernet_peer_restores_header config
    positive_mixed_delivery (show usefulState0.frame.body = .ethernet _ from rfl)
    (show usefulState30.frame.body = .ethernet _ from rfl)
  exact congrArg some restored

end TDN.Deployments.PairingInnerMacsecOuterIpsec.ForwardVLAN0

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec.ReverseVLAN0

theorem actual_peer_restores_original_ethernet :
    usefulState30.datapathStage = .delivered ∧
    usefulState30.frame.body.originalEthernet = usefulState0.frame.body.originalEthernet := by
  refine ⟨rfl, ?_⟩
  have restored := Requirements.successful_ethernet_peer_restores_header config
    positive_mixed_delivery (show usefulState0.frame.body = .ethernet _ from rfl)
    (show usefulState30.frame.body = .ethernet _ from rfl)
  exact congrArg some restored

end TDN.Deployments.PairingInnerMacsecOuterIpsec.ReverseVLAN0
