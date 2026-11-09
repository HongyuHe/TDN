import TDN.Models.RawPacketDecodeAndHooks

namespace TDN.DataPlaneForwarding

instance (rules : List PacketPolicy.Rule) (fallback : Filter.Verdict) (packet : PacketPolicy.Packet) :
    Decidable (accepts rules fallback packet) := by
  unfold accepts
  infer_instance

instance (association : InstalledSA) (policy : IpsecPolicy) :
    Decidable (saMatchesPolicy association policy) := by
  unfold saMatchesPolicy
  infer_instance

end TDN.DataPlaneForwarding
