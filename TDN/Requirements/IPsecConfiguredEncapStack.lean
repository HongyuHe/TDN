import TDN.Requirements.IPsecLayerBoundaryChecks

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding LayeredFrame

def protectionLayerTag : Layer → Nat
  | .inner => 1
  | .outer => 2

def IPsecStampHasConfiguredLayer {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (association : DataPlaneForwarding.TunnelSAStamp) : Prop :=
  ∃ tunnel ∈ d.tunnels, tunnel.id = binding.ipsecTunnel association ∧
    protectionLayerTag tunnel.layer = association.tag

def IPsecBodyHasConfiguredLayers {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) : Body → Prop
  | .datagram _ | .ethernet _ => True
  | .ipsec association body =>
      IPsecStampHasConfiguredLayer binding d association ∧ IPsecBodyHasConfiguredLayers binding d body
  | .macsec _ _ | .macsecPdu _ _ _ _ | .carrier _ _ => False

structure IPsecEncapLayerChecks {S A : Type} (binding : DeviceExecutionBinding S A) (d : Deployment) : Prop where
  noMACsec : binding.configuration.macIfaces = []
  noCarriers : binding.configuration.carriers = []
  installedLayers : ∀ iface policy association,
    policy ∈ binding.configuration.ip.egressPolicies iface →
    association ∈ binding.configuration.ip.egressSAs iface →
    DataPlaneForwarding.saMatchesPolicy association policy →
    IPsecStampHasConfiguredLayer binding d (policy.seal association)
  uniqueLayers : ∀ first ∈ d.tunnels, ∀ second ∈ d.tunnels,
    first.id = second.id → first.layer = second.layer

lemma ipsec_step_preserves_configured_layers {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (checks : IPsecEncapLayerChecks binding d)
    {before after : MultiProtocolForwarding.State} {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before operation after)
    (valid : IPsecBodyHasConfiguredLayers binding d before.frame.body) :
    IPsecBodyHasConfiguredLayers binding d after.frame.body := by
  cases step
  all_goals try simpa only [Config.forwardedFrame_body] using valid
  case encryptIPsec policy association stage visible selected installed bound =>
    have configured := (List.mem_filter.mp selected).1
    have layer := checks.installedLayers before.iface policy association configured installed bound
    cases mode : binding.configuration.headerProcessing <;>
      simpa only [Config.ipsecFrame, mode, Frame.pushHeader, IPsecBodyHasConfiguredLayers] using And.intro layer valid
  case decryptIPsec policy association body header stage encrypted configured installed bound visible selected tracking =>
    rw [encrypted] at valid
    simpa only [Config.restoredFrame_body] using valid.2
  all_goals simp_all only [checks.noMACsec, checks.noCarriers, List.not_mem_nil]

lemma empty_ipsec_stack_has_no_named_layers {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (body : Body) (valid : IPsecBodyHasConfiguredLayers binding d body)
    (empty : body.protectionLayers = []) : binding.LayerIds body = [] := by
  cases body <;> simp_all [IPsecBodyHasConfiguredLayers, Body.protectionLayers, DeviceExecutionBinding.LayerIds]

lemma single_inner_ipsec_stack_has_configured_name {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (body : Body) (valid : IPsecBodyHasConfiguredLayers binding d body)
    (single : body.protectionLayers = [1]) :
    ∃ tunnel ∈ d.tunnels, tunnel.layer = .inner ∧ binding.LayerIds body = [tunnel.id] := by
  cases body with
  | datagram header | ethernet header => simp [Body.protectionLayers] at single
  | macsec association body | macsecPdu association encryptFrames offset body | carrier endpoint body => exact False.elim valid
  | ipsec association body =>
    have same : association.tag = 1 ∧ body.protectionLayers = [] := by
      simpa only [Body.protectionLayers, List.cons.injEq, List.nil_append] using single
    obtain ⟨tunnel, member, name, tag⟩ := valid.1
    have layer : tunnel.layer = .inner := by
      cases selected : tunnel.layer <;> simp_all [protectionLayerTag]
    refine ⟨tunnel, member, layer, ?_⟩
    simp only [DeviceExecutionBinding.LayerIds, empty_ipsec_stack_has_no_named_layers binding d body valid.2 same.2, name]

lemma single_inner_ipsec_stack_has_no_outer_name {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (checks : IPsecEncapLayerChecks binding d) (body : Body)
    (valid : IPsecBodyHasConfiguredLayers binding d body) (single : body.protectionLayers = [1])
    (outer : Tunnel) (member : outer ∈ d.tunnels) (layer : outer.layer = .outer) :
    outer.id ∉ binding.LayerIds body := by
  obtain ⟨inner, stored, selected, names⟩ := single_inner_ipsec_stack_has_configured_name binding d body valid single
  rw [names]
  intro present
  have same := List.mem_singleton.mp present
  have layers := checks.uniqueLayers outer member inner stored same
  simp [layer, selected] at layers

end TDN.Requirements.Msc
