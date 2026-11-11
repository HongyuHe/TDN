import TDN.Models.MultiProtocolForwarding

namespace TDN.MultiProtocolForwarding
open LayeredFrame

def LocalInputDestinationChecked (configuration : Config) (state : State) : Prop :=
  state.datapathStage = .localInput → ∀ header,
    configuration.visibleHeader state.frame = some header →
    configuration.ip.localAddress state.iface header.destination

lemma step_preserves_local_input_destination {configuration : Config} {before after : State}
    {operation : Action} (step : Step configuration before operation after)
    (valid : LocalInputDestinationChecked configuration before) :
    LocalInputDestinationChecked configuration after := by
  cases step <;> simp_all [LocalInputDestinationChecked]

end TDN.MultiProtocolForwarding
