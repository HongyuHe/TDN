import TDN.Requirements.OuterTunnelCarrierSpec
import TDN.Deployments.TunnelMatrix_InnerMacsec_OuterIpsec_Integrated_Fwd_VLAN0
import TDN.Deployments.TunnelMatrix_InnerMacsec_OuterIpsec_Integrated_Rev_VLAN0

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec.ForwardVlan0

theorem actual_carrier_precedes_outer_encryption :
    (∃ carrier, usefulState6.frame.body =
      LayeredFrame.Body.carrier carrier usefulState5.frame.body) ∧
    usefulState8.frame.body = usefulState6.frame.body ∧
    MultiProtocolForwarding.TunnelForwardingStep config usefulState8 .encryptIPsec usefulState9 :=
  ⟨Requirements.carrier_step_wraps_the_exact_input_body config useful_step5, rfl, useful_step8⟩

theorem actual_carrier_preserves_inner_protection :
    usefulState6.frame.body.protectionLayers = usefulState5.frame.body.protectionLayers ∧
    usefulState6.frame.body.originalEthernet = usefulState5.frame.body.originalEthernet :=
  Requirements.carrier_step_preserves_existing_protection config useful_step5

end TDN.Deployments.PairingInnerMacsecOuterIpsec.ForwardVlan0

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec.ReverseVlan0

theorem actual_carrier_precedes_outer_encryption :
    (∃ carrier, usefulState6.frame.body =
      LayeredFrame.Body.carrier carrier usefulState5.frame.body) ∧
    usefulState8.frame.body = usefulState6.frame.body ∧
    MultiProtocolForwarding.TunnelForwardingStep config usefulState8 .encryptIPsec usefulState9 :=
  ⟨Requirements.carrier_step_wraps_the_exact_input_body config useful_step5, rfl, useful_step8⟩

end TDN.Deployments.PairingInnerMacsecOuterIpsec.ReverseVlan0
