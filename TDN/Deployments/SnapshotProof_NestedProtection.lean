import TDN.Deployments.NestedProtection_BaselineSampleTrace
import TDN.Deployments.NestedProtection_MixedSampleTrace
import TDN.Deployments.InnerTunnelNoBypass_IPsecSampleTrace

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MultiProtocolForwarding

theorem snapshot_RG007_mixed_with_captured_bridge_policy (independentKeys : String → String → Prop)
    (independent : IndependentLayerKeys independentKeys) :
    msc_nested_layer_protection deployment forwarding flows (fun start _ _ payload => flowAt start payload) independentKeys ∧
    ∀ first last, (first,last) ∈ records.bridges → ∀ frame : LinkAdmission.Frame,
      SplitBridgeAdmitted first last frame ↔
        (capturedBridgeChain (configuration.ip.owner first)).Accepts
          (frame.Packet (configuration.ip.interfaceName first) (configuration.ip.interfaceName last)) :=
  ⟨snapshot_RG007_mixed_nested_layer_protection independentKeys independent,
    fun first last edge frame => split_bridge_policies_match_captured_chain first last edge frame⟩

end TDN.Deployments.NestedProtection_Mixed
