import TDN.Semantics.PacketProcessing

namespace TDN.Execution

instance (rules : List PacketPolicy.Rule) (fallback : Filter.Verdict) (packet : PacketPolicy.Packet) :
    Decidable (accepts rules fallback packet) := by
  unfold accepts
  infer_instance

instance (association : SecurityAssociation) (policy : Association) :
    Decidable (StateBindsPolicy association policy) := by
  unfold StateBindsPolicy
  infer_instance

end TDN.Execution
