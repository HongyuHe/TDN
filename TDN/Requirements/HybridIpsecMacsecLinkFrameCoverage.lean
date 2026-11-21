import TDN.Requirements.HybridIpsecMacsecFlowPolicyChecks

namespace TDN.Requirements.Msc
open Compliance LayeredFrame MultiProtocolForwarding DataPlaneForwarding

def LinkPathMACsecFramed (configuration : TunnelForwardingModel) (state : MultiProtocolForwarding.TunnelForwardingState) : Prop :=
  configuration.LinkPath state.iface →
    ∃ association body, state.frame.body = .macsec association body

structure HybridIpsecMacsecFlowLinkChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : HybridIpsecMacsecFlowEndpoints) (expectedEncapStack : Nat → List Nat) : Prop where
  noCarriers : binding.configuration.carriers = []
  protectFrames : ∀ iface ∈ binding.configuration.macIfaces, iface.settings.protectFrames = true
  pathStack : ∀ iface, binding.configuration.LinkPath iface → expectedEncapStack iface = [2,1]
  logicalOutside : ∀ iface ∈ binding.configuration.macIfaces, ¬ binding.configuration.LinkPath iface.logicalIface
  physicalSources : ∀ first last, binding.configuration.physicalLink first last →
    binding.configuration.LinkPath last → binding.configuration.LinkPath first
  routeOutside : ∀ frame header route,
    frame.HeadersCoherent → binding.configuration.visibleHeader frame = some header →
    FlowMixedBody binding selected.flow selected.RemoteHeader (· = selected.innerStamp) (· = selected.outerAssociation) frame.body →
    (frame.body.protectionLayers = [] → selected.PlainAllowed binding.configuration.ip.owner route.egress frame.body) →
    SelectedFibRoute binding.configuration.ip.routes route header → ¬ binding.configuration.LinkPath route.egress

lemma hybrid_ipsec_macsec_step_preserves_link_path_framing {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : HybridIpsecMacsecFlowEndpoints) (expectedEncapStack : Nat → List Nat)
    (checks : HybridIpsecMacsecFlowLinkChecks binding selected expectedEncapStack)
    {before after : MultiProtocolForwarding.TunnelForwardingState} {operation : MultiProtocolForwarding.TunnelForwardingAction}
    (step : MultiProtocolForwarding.TunnelForwardingStep binding.configuration before operation after)
    (safeBefore : HybridIpsecMacsecFlowInvariant binding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation)
      (selected.PlainAllowed binding.configuration.ip.owner) expectedEncapStack selected.destinationLogicalIface before)
    (safeAfter : HybridIpsecMacsecFlowInvariant binding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation)
      (selected.PlainAllowed binding.configuration.ip.owner) expectedEncapStack selected.destinationLogicalIface after)
    (framed : LinkPathMACsecFramed binding.configuration before) :
    LinkPathMACsecFramed binding.configuration after := by
  cases step
  all_goals dsimp only [LinkPathMACsecFramed] at framed ⊢
  all_goals try { simpa only [TunnelForwardingModel.forwarded_frame_body] using framed }
  case route route stage visible selectedRoute entry =>
    exact fun path => False.elim (checks.routeOutside before.frame _ route safeBefore.1.1 visible
      safeBefore.2.1 (by simpa only [TunnelForwardingModel.forwarded_frame_body] using safeAfter.2.2.1) selectedRoute path)
  case routeLocalOutput route stage visible selectedRoute entry =>
    exact fun path => False.elim (checks.routeOutside before.frame _ route safeBefore.1.1 visible
      safeBefore.2.1 safeAfter.2.2.1 selectedRoute path)
  case routeOuterPacket route stage visible selectedRoute entry =>
    exact fun path => False.elim (checks.routeOutside before.frame _ route safeBefore.1.1 visible
      safeBefore.2.1 safeAfter.2.2.1 selectedRoute path)
  case encryptIPsec policy association stage visible matched installed bound =>
    intro path
    have shape := safeAfter.1.2.2.1
    have valid := safeAfter.2.1
    simp only [TunnelForwardingModel.ipsec_frame_body, FlowMixedBody] at valid
    have impossible : (policy.seal association).tag = 2 := by
      have layers : (policy.seal association).tag :: before.frame.body.protectionLayers = [2,1] := by
        simpa only [TunnelForwardingModel.ipsec_frame_body, Body.protectionLayers, checks.pathStack before.iface path] using shape
      exact (List.cons.inj layers).1
    have one := valid.1.2.1
    omega
  case decryptIPsec policy association body header stage encrypted configured installed bound visible matched tracking =>
    intro path
    obtain ⟨transmitted, contents, macsec⟩ := framed path
    rw [macsec] at encrypted
    cases encrypted
  case linkTransmit next stage linked =>
    intro path
    exact framed (checks.physicalSources before.iface next linked path)
  case bridge next stage linked =>
    intro path
    exact framed (Or.inr (Or.inl ⟨next, Or.inl linked⟩))
  case bridgeOutput next stage linked =>
    intro path
    exact framed (Or.inr (Or.inl ⟨next, Or.inl linked⟩))
  case encryptMACsec iface association configured stage logical emits =>
    intro path
    exact ⟨association, before.frame.body, TunnelForwardingModel.macsec_frame_body _ _ _⟩
  case unprotectedMACsec iface configured stage logical enabled unprotected =>
    simp [checks.protectFrames iface configured] at unprotected
  case protectMACsec iface association configured stage logical enabled protection installed limited =>
    have invalid := safeAfter.2.1
    cases mode : binding.configuration.headerProcessing <;>
      simp only [TunnelForwardingModel.macsecPduFrame, mode, TunnelFrame.pushHeader, FlowMixedBody] at invalid
  case decryptMACsec iface association transmitted body configured stage physical encrypted installed spi =>
    intro path
    exact False.elim (checks.logicalOutside iface configured path)
  case validateMACsec iface association transmitted encryptFrames offset body configured stage physical encrypted installed spi =>
    intro path
    exact False.elim (checks.logicalOutside iface configured path)
  case uncheckedMACsec iface configured stage physical unchecked =>
    intro path
    exact False.elim (checks.logicalOutside iface configured path)
  all_goals simp_all only [checks.noCarriers, List.not_mem_nil]

end TDN.Requirements.Msc
