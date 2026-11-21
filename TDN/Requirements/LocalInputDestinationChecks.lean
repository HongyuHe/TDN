import TDN.Models.MultiProtocolForwarding

namespace TDN.MultiProtocolForwarding
open LayeredFrame

def LocalInputDestinationChecked (configuration : TunnelForwardingModel) (state : TunnelForwardingState) : Prop :=
  state.datapathStage = .localInput → ∀ header,
    configuration.visibleHeader state.frame = some header →
    configuration.ip.localAddress state.iface header.destination

lemma step_preserves_local_input_destination {configuration : TunnelForwardingModel} {before after : TunnelForwardingState}
    {operation : TunnelForwardingAction} (step : TunnelForwardingStep configuration before operation after)
    (valid : LocalInputDestinationChecked configuration before) :
    LocalInputDestinationChecked configuration after := by
  cases step <;> simp_all [LocalInputDestinationChecked]

end TDN.MultiProtocolForwarding
