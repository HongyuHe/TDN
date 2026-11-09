import TDN.Requirements.OuterTunnelCarrierSpec
import TDN.Deployments.TunnelMatrix_InnerMacsec_OuterIpsec_Fwd_VLAN0
import TDN.Deployments.TunnelMatrix_InnerMacsec_OuterIpsec_Rev_VLAN0

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec.ForwardVLAN0

theorem actual_carrier_precedes_outer_encryption :
    (∃ carrier, usefulState6.frame.body =
      LayeredFrame.Body.carrier carrier usefulState5.frame.body) ∧
    usefulState8.frame.body = usefulState6.frame.body ∧
    MultiProtocolForwarding.Step config usefulState8 .encryptIPsec usefulState9 :=
  ⟨Requirements.carrier_step_wraps_the_exact_input_body config usefulStep5, rfl, usefulStep8⟩

theorem actual_carrier_preserves_inner_protection :
    usefulState6.frame.body.protectionLayers = usefulState5.frame.body.protectionLayers ∧
    usefulState6.frame.body.originalEthernet = usefulState5.frame.body.originalEthernet :=
  Requirements.carrier_step_preserves_existing_protection config usefulStep5

end TDN.Deployments.PairingInnerMacsecOuterIpsec.ForwardVLAN0

namespace TDN.Deployments.PairingInnerMacsecOuterIpsec.ReverseVLAN0

theorem actual_carrier_precedes_outer_encryption :
    (∃ carrier, usefulState6.frame.body =
      LayeredFrame.Body.carrier carrier usefulState5.frame.body) ∧
    usefulState8.frame.body = usefulState6.frame.body ∧
    MultiProtocolForwarding.Step config usefulState8 .encryptIPsec usefulState9 :=
  ⟨Requirements.carrier_step_wraps_the_exact_input_body config usefulStep5, rfl, usefulStep8⟩

end TDN.Deployments.PairingInnerMacsecOuterIpsec.ReverseVLAN0
