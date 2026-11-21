import TDN.Models.RawPacketDecodeAndHooks

namespace TDN.DataPlaneForwarding

instance (rules : List PacketPolicy.PacketAclRule) (fallback : Filter.Verdict) (packet : PacketPolicy.Packet) :
    Decidable (TDN.PacketPolicy.AclAllows rules fallback packet) := by
  unfold TDN.PacketPolicy.AclAllows
  infer_instance

instance (association : InstalledSa) (policy : IpsecPolicy) :
    Decidable (saMatchesPolicy association policy) := by
  unfold saMatchesPolicy
  infer_instance

end TDN.DataPlaneForwarding
