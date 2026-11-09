import TDN.Models.MultiProtocolForwarding

namespace TDN.LayeredFrame

def Body.IPsecOnly (known : DataPlaneForwarding.TunnelSAStamp → Prop) : Body → Prop
  | .datagram _ | .ethernet _ => True
  | .ipsec association body => known association ∧ body.IPsecOnly known ∧
      body.visibleHeader.isSome = true
  | .macsec _ _ | .carrier _ _ => False

end TDN.LayeredFrame

namespace TDN.MultiProtocolForwarding
open LayeredFrame

lemma Config.visible_implies_body_header {configuration : Config} {frame : Frame}
    {header : PacketPolicy.Packet} (visible : configuration.visibleHeader frame = some header) :
    frame.body.visibleHeader.isSome = true := by
  cases mode : configuration.headerProcessing with
  | none => simpa only [Config.visibleHeader, mode, Option.isSome_some] using
      congrArg Option.isSome visible
  | some processing =>
    cases shape : frame.body.visibleHeader with
    | none => simp [Config.visibleHeader, mode, Frame.visibleHeader, shape] at visible
    | some nominal => rfl

lemma step_preserves_IPsec_body_shape {configuration : Config}
    (noMAC : configuration.macIfaces = []) (noCarriers : configuration.carriers = [])
    (known : DataPlaneForwarding.TunnelSAStamp → Prop)
    (installed : ∀ iface policy association,
      policy ∈ configuration.ip.egressPolicies iface → association ∈ configuration.ip.egressSAs iface →
      DataPlaneForwarding.saMatchesPolicy association policy → known (policy.seal association))
    {before after : State} {action : Action} (step : Step configuration before action after)
    (shape : before.frame.body.IPsecOnly known) : after.frame.body.IPsecOnly known := by
  cases step with
  | receive => exact shape
  | route => simpa only [Config.forwardedFrame_body] using shape
  | routeLocalOutput => exact shape
  | forwardFilter => exact shape
  | outputFilter => exact shape
  | encryptIPsec policy association datapathStage visible selected member bound =>
    simp only [Config.ipsecFrame_body, Body.IPsecOnly]
    exact ⟨installed _ policy association (DataPlaneForwarding.matched_policy_is_configured selected).1 member bound,
      shape, Config.visible_implies_body_header visible⟩
  | routeOuterPacket => exact shape
  | forwardWithoutEncap => exact shape
  | decryptIPsec policy association contents header datapathStage encrypted configured member bound visible selected tracking =>
    rw [encrypted] at shape
    simpa only [Config.restoredFrame_body] using shape.2.1
  | inputFilter => exact shape
  | deliver => exact shape
  | deliverEthernet => exact shape
  | linkTransmit => exact shape
  | bridge => exact shape
  | bridgeOutput => exact shape
  | encryptMACsec iface association configured => simp only [noMAC, List.not_mem_nil] at configured
  | unprotectedMACsec iface configured => simp only [noMAC, List.not_mem_nil] at configured
  | decryptMACsec iface association transmitted contents configured =>
    simp only [noMAC, List.not_mem_nil] at configured
  | uncheckedMACsec iface configured => simp only [noMAC, List.not_mem_nil] at configured
  | encapsulate iface configured => simp only [noCarriers, List.not_mem_nil] at configured
  | decapsulate iface contents configured => simp only [noCarriers, List.not_mem_nil] at configured
  | drop => exact shape

end TDN.MultiProtocolForwarding
