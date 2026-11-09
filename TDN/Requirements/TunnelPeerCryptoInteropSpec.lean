import TDN.Models.MultiProtocolEncryptionEvents

namespace TDN.Requirements
open MultiProtocolForwarding LayeredFrame

theorem successful_ethernet_peer_restores_header (config : Config)
    {first last : State} {actions : List Action} {sent received : EthernetHeader}
    (execution : (lts config).MTr first actions last)
    (sourceBody : first.frame.body = .ethernet sent)
    (destinationBody : last.frame.body = .ethernet received) :
    received = sent := by
  have equal := all_traces_preserve_original_ethernet config execution
  rw [sourceBody, destinationBody] at equal
  exact Option.some.inj equal

end TDN.Requirements
