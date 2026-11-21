import TDN.Deployments.NestedProtection_BaselineSampleTrace
import TDN.Deployments.NestedProtection_HybridIpsecMacsecSampleTrace
import TDN.Deployments.InnerTunnelNoBypass_IpsecSampleTrace

namespace TDN.Deployments.NestedProtection_HybridIpsecMacsec
open Compliance Requirements Requirements.Msc MultiProtocolForwarding

theorem snapshot_rg007_hybrid_ipsec_macsec_with_captured_bridge_policy (independentKeys : String → String → Prop)
    (independent : IndependentLayerKeys independentKeys) :
    nested_layer_protection deployment forwarding flows (fun start _ _ payload => flowAt start payload) independentKeys ∧
    ∀ first last, (first,last) ∈ records.bridges → ∀ frame : LinkAdmission.EthernetFrame,
      SplitBridgeAdmitted first last frame ↔
        (capturedBridgeChain (configuration.ip.owner first)).PermitsPacket
          (frame.Packet (configuration.ip.interfaceName first) (configuration.ip.interfaceName last)) :=
  ⟨snapshot_rg007_hybrid_ipsec_macsec_nested_layer_protection independentKeys independent,
    fun first last edge frame => split_bridge_policies_match_captured_chain first last edge frame⟩

end TDN.Deployments.NestedProtection_HybridIpsecMacsec
