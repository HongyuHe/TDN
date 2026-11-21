import TDN.Models.RawPacketDecodeAndHooks

namespace TDN.MultiProtocolForwarding

def TunnelForwardingModel.withLocalAddresses (configuration : TunnelForwardingModel) (addresses : Nat → Nat → Prop) : TunnelForwardingModel :=
  { configuration with ip := { configuration.ip with localAddress := addresses } }

lemma local_address_projection_preserves_policy_packet (configuration : TunnelForwardingModel)
    (addresses : Nat → Nat → Prop) (context : PacketProcessing.Context) :
    context.Packet (configuration.withLocalAddresses addresses) = context.Packet configuration := by
  cases context.hook <;> rfl

lemma local_address_projection_preserves_input_admission (configuration : TunnelForwardingModel)
    (addresses : Nat → Nat → Prop) (state : MultiProtocolForwarding.TunnelForwardingState) :
    PacketProcessing.InputAdmitted (configuration.withLocalAddresses addresses) state ↔
      PacketProcessing.InputAdmitted configuration state := by
  rfl

lemma local_address_projection_preserves_forward_decision (configuration : TunnelForwardingModel)
    (addresses : Nat → Nat → Prop) (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate
        (((configuration.withLocalAddresses addresses).ip.forwardRules iface).map PacketPolicy.PacketAclRule.toFilter)
        ((configuration.withLocalAddresses addresses).ip.forwardFallback iface)
        (context.Packet (configuration.withLocalAddresses addresses)) =
      Filter.evaluate ((configuration.ip.forwardRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (configuration.ip.forwardFallback iface) (context.Packet configuration) := by
  rw [local_address_projection_preserves_policy_packet]
  rfl

lemma local_address_projection_preserves_input_decision (configuration : TunnelForwardingModel)
    (addresses : Nat → Nat → Prop) (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate
        (((configuration.withLocalAddresses addresses).ip.inputRules iface).map PacketPolicy.PacketAclRule.toFilter)
        ((configuration.withLocalAddresses addresses).ip.inputFallback iface)
        (context.Packet (configuration.withLocalAddresses addresses)) =
      Filter.evaluate ((configuration.ip.inputRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (configuration.ip.inputFallback iface) (context.Packet configuration) := by
  rw [local_address_projection_preserves_policy_packet]
  rfl

lemma local_address_projection_preserves_output_decision (configuration : TunnelForwardingModel)
    (addresses : Nat → Nat → Prop) (context : PacketProcessing.Context) (iface : Nat) :
    Filter.evaluate
        (((configuration.withLocalAddresses addresses).ip.outputRules iface).map PacketPolicy.PacketAclRule.toFilter)
        ((configuration.withLocalAddresses addresses).ip.outputFallback iface)
        (context.Packet (configuration.withLocalAddresses addresses)) =
      Filter.evaluate ((configuration.ip.outputRules iface).map PacketPolicy.PacketAclRule.toFilter)
        (configuration.ip.outputFallback iface) (context.Packet configuration) := by
  rw [local_address_projection_preserves_policy_packet]
  rfl

end TDN.MultiProtocolForwarding
