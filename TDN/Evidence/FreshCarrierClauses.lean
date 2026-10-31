import TDN.Targets.CarrierClauses
import TDN.Evidence.FreshPairingInnerMacsecOuterIpsecForwardVLAN0
import TDN.Evidence.FreshPairingInnerMacsecOuterIpsecReverseVLAN0

namespace TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN0

/-- The retained useful path encapsulates the existing MACsec body, then applies
Outer ESP to that unchanged carrier. The full useful delivery is already checked
in positive_mixed_delivery with the actual bridge and IP policy configuration. -/
theorem actual_carrier_precedes_outer_encryption :
    (∃ carrier, usefulState6.frame.body =
      LayeredFrame.Body.carrier carrier usefulState5.frame.body) ∧
    usefulState8.frame.body = usefulState6.frame.body ∧
    MultiProtocolExecution.Step config usefulState8 .encryptIPsec usefulState9 :=
  ⟨Targets.carrier_step_wraps_the_exact_input_body config usefulStep5, rfl, usefulStep8⟩

theorem actual_carrier_preserves_inner_protection :
    usefulState6.frame.body.protectionLayers = usefulState5.frame.body.protectionLayers ∧
    usefulState6.frame.body.originalEthernet = usefulState5.frame.body.originalEthernet :=
  Targets.carrier_step_preserves_existing_protection config usefulStep5

end TDN.Imported.PairingInnerMacsecOuterIpsec.ForwardVLAN0

namespace TDN.Imported.PairingInnerMacsecOuterIpsec.ReverseVLAN0

theorem actual_carrier_precedes_outer_encryption :
    (∃ carrier, usefulState6.frame.body =
      LayeredFrame.Body.carrier carrier usefulState5.frame.body) ∧
    usefulState8.frame.body = usefulState6.frame.body ∧
    MultiProtocolExecution.Step config usefulState8 .encryptIPsec usefulState9 :=
  ⟨Targets.carrier_step_wraps_the_exact_input_body config usefulStep5, rfl, usefulStep8⟩

end TDN.Imported.PairingInnerMacsecOuterIpsec.ReverseVLAN0
