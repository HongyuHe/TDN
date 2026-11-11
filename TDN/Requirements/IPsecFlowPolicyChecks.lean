import TDN.Requirements.IPsecFlowTunnelNames
import TDN.Models.DecidableAclInstances

namespace TDN.Requirements.Msc
open Compliance LayeredFrame MultiProtocolForwarding DataPlaneForwarding

structure IPsecFlowEndpoints where
  flow : Flow
  originDomain : Nat
  sourceInnerOwner : Nat
  sourceHostOwner : Nat
  destinationInnerOwner : Nat
  destinationHostOwner : Nat
  innerStamp : TunnelSAStamp
  outerStamp : TunnelSAStamp
  remoteLow : Nat
  remoteHigh : Nat

def IPsecFlowEndpoints.SourceSide (selected : IPsecFlowEndpoints) (owner : Nat) : Prop :=
  owner = selected.sourceInnerOwner ∨ owner = selected.sourceHostOwner

def IPsecFlowEndpoints.DestinationSide (selected : IPsecFlowEndpoints) (owner : Nat) : Prop :=
  owner = selected.destinationInnerOwner ∨ owner = selected.destinationHostOwner

def IPsecFlowEndpoints.RemoteHeader (selected : IPsecFlowEndpoints) : Option PacketPolicy.Packet → Prop
  | none => False
  | some header => selected.remoteLow ≤ header.destination ∧ header.destination ≤ selected.remoteHigh

def IPsecFlowEndpoints.AllowedStamp (selected : IPsecFlowEndpoints) (stamp : TunnelSAStamp) : Prop :=
  stamp = selected.innerStamp ∨ stamp = selected.outerStamp

def IPsecFlowEndpoints.PlainAllowed (selected : IPsecFlowEndpoints) (owner : Nat → Nat)
    (iface : Nat) (body : Body) : Prop :=
  selected.SourceSide (owner iface) ∨
    (selected.DestinationSide (owner iface) ∧ selected.RemoteHeader body.originalHeader)

def IPsecFlowEndpoints.OutgoingPolicy (selected : IPsecFlowEndpoints) (owner : Nat)
    (expectedEncapStack : List Nat) (policy : IpsecPolicy) (association : InstalledSA) : Prop :=
  (policy.tag = 1 ∧ expectedEncapStack = [1] ∧
    (selected.SourceSide owner → policy.seal association = selected.innerStamp ∧
      selected.remoteLow ≤ policy.destinationLow ∧ policy.destinationHigh ≤ selected.remoteHigh) ∧
    (selected.DestinationSide owner →
      policy.destinationHigh < selected.remoteLow ∨ selected.remoteHigh < policy.destinationLow)) ∨
  (policy.tag = 2 ∧ expectedEncapStack = [2, 1] ∧
    (policy.matches (outerHeader selected.innerStamp.sender selected.innerStamp.receiver "esp" 0 0) = true →
      policy.seal association = selected.outerStamp))

def IPsecFlowEndpoints.IncomingPolicy (selected : IPsecFlowEndpoints) (owner : Nat)
    (expectedEncapStack : List Nat) (policy : IpsecPolicy) (association : InstalledSA) : Prop :=
  (policy.tag = 1 ∧ expectedEncapStack = [1] ∧
    (policy.seal association = selected.innerStamp → selected.DestinationSide owner)) ∨
  (policy.tag = 2 ∧ expectedEncapStack = [2, 1])

structure IPsecFlowPolicyChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : IPsecFlowEndpoints) (expectedEncapStack : Nat → List Nat) : Prop where
  innerTag : selected.innerStamp.tag = 1
  outerTag : selected.outerStamp.tag = 2
  innerName : binding.ipsecTunnel selected.innerStamp = selected.flow.innerTunnel
  outerName : binding.ipsecTunnel selected.outerStamp = selected.flow.outerTunnel
  outgoing : ∀ iface policy association,
    policy ∈ binding.configuration.ip.egressPolicies iface →
    association ∈ binding.configuration.ip.egressSAs iface → saMatchesPolicy association policy →
    (expectedEncapStack iface).head? = some policy.tag → selected.OutgoingPolicy (binding.configuration.ip.owner iface) (expectedEncapStack iface) policy association
  incoming : ∀ iface policy association,
    policy ∈ binding.configuration.ip.ingressPolicies iface →
    association ∈ binding.configuration.ip.ingressSAs iface → saMatchesPolicy association policy →
    (expectedEncapStack iface).head? = some policy.tag → selected.IncomingPolicy (binding.configuration.ip.owner iface) (expectedEncapStack iface) policy association

lemma plain_ipsec_flow_visible_header {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : IPsecFlowEndpoints) (processing : HeaderProcessing)
    (mode : binding.configuration.headerProcessing = some processing)
    (frame : LayeredFrame.Frame) (header : PacketPolicy.Packet)
    (coherent : frame.HeadersCoherent) (visible : binding.configuration.visibleHeader frame = some header)
    (valid : FlowIPsecBody binding selected.flow selected.RemoteHeader selected.AllowedStamp frame.body)
    (empty : frame.body.protectionLayers = []) :
    ∃ original, frame.body.originalHeader = some original ∧ HeaderIdentity header original := by
  have actual : frame.visibleHeader = some header := by simpa only [Config.visibleHeader, mode] using visible
  obtain ⟨nominal, nominalVisible, identity⟩ := LayeredFrame.Frame.coherent_visible coherent header actual
  cases body : frame.body with
  | datagram packet =>
    have same : packet = nominal := by simpa only [body, Body.visibleHeader, Option.some.injEq] using nominalVisible
    exact ⟨packet, rfl, same ▸ identity⟩
  | ethernet packet => simp only [body, Body.visibleHeader, reduceCtorEq] at nominalVisible
  | ipsec stamp contents => simp only [body, Body.protectionLayers, List.cons_ne_nil] at empty
  | macsec | macsecPdu | carrier => simp only [body, FlowIPsecBody] at valid

lemma ipsec_flow_outgoing_policy_named {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : IPsecFlowEndpoints) (expectedEncapStack : Nat → List Nat)
    (checks : IPsecFlowPolicyChecks binding selected expectedEncapStack)
    (processing : HeaderProcessing) (mode : binding.configuration.headerProcessing = some processing)
    (iface : Nat) (frame : LayeredFrame.Frame) (header : PacketPolicy.Packet) (policy : IpsecPolicy) (association : InstalledSA)
    (coherent : frame.HeadersCoherent) (visible : binding.configuration.visibleHeader frame = some header)
    (matched : policy ∈ lookupSpdPolicies (binding.configuration.ip.egressPolicies iface) header)
    (installed : association ∈ binding.configuration.ip.egressSAs iface) (bound : saMatchesPolicy association policy)
    (valid : FlowIPsecBody binding selected.flow selected.RemoteHeader selected.AllowedStamp frame.body)
    (plain : frame.body.protectionLayers = [] → selected.PlainAllowed binding.configuration.ip.owner iface frame.body)
    (stack : policy.tag :: frame.body.protectionLayers = expectedEncapStack iface) :
    FlowIPsecStamp binding selected.flow selected.RemoteHeader (policy.seal association) selected.AllowedStamp frame.body := by
  have configured := matched_policy_is_configured matched
  rcases checks.outgoing iface policy association configured.1 installed bound
    (by rw [← stack]; rfl) with inner | outer
  · have empty : frame.body.protectionLayers = [] := by
      rw [inner.1, inner.2.1] at stack
      exact (List.cons.inj stack).2
    obtain ⟨original, originalHeader, identity⟩ := plain_ipsec_flow_visible_header binding selected processing mode
      frame header coherent visible valid empty
    have ranges := configured.2
    simp only [IpsecPolicy.matches, decide_eq_true_eq] at ranges
    have destination := identity.destination
    have sourceSide : selected.SourceSide (binding.configuration.ip.owner iface) := by
      rcases plain empty with source | ⟨destinationSide, remote⟩
      · exact source
      · have disjoint := inner.2.2.2 destinationSide
        simp only [originalHeader, IPsecFlowEndpoints.RemoteHeader] at remote
        rcases disjoint with before | after <;> omega
    obtain ⟨stamp, lower, upper⟩ := inner.2.2.1 sourceSide
    refine ⟨Or.inl stamp, Or.inl ⟨inner.1, ?_, ?_⟩⟩
    · simpa only [stamp] using checks.innerName
    · simp only [originalHeader, IPsecFlowEndpoints.RemoteHeader]
      omega
  · have layers : frame.body.protectionLayers = [1] := by
      rw [outer.1, outer.2.1] at stack
      exact (List.cons.inj stack).2
    have stamp : ∃ contents, frame.body = .ipsec selected.innerStamp contents := by
      cases body : frame.body with
      | datagram | ethernet => simp [body, Body.protectionLayers] at layers
      | ipsec association contents =>
        have tag : association.tag = 1 := by
          have shaped : association.tag :: contents.protectionLayers = [1] := by simpa only [body, Body.protectionLayers] using layers
          exact (List.cons.inj shaped).1
        have currentValid : FlowIPsecBody binding selected.flow selected.RemoteHeader selected.AllowedStamp (.ipsec association contents) := by simpa only [body] using valid
        have validStamp := currentValid.1.1
        rcases validStamp with same | same
        · exact ⟨contents, by simpa only [same] using body⟩
        · have impossible : association.tag = 2 := same ▸ checks.outerTag
          omega
      | macsec | macsecPdu | carrier => simp only [body, FlowIPsecBody] at valid
    obtain ⟨contents, body⟩ := stamp
    have actual : frame.visibleHeader = some header := by simpa only [Config.visibleHeader, mode] using visible
    obtain ⟨nominal, nominalVisible, identity⟩ := LayeredFrame.Frame.coherent_visible coherent header actual
    have same : outerHeader selected.innerStamp.sender selected.innerStamp.receiver "esp" 0 0 = nominal := by
      simpa only [body, Body.visibleHeader, Option.some.injEq] using nominalVisible
    have nominalMatched : policy.matches (outerHeader selected.innerStamp.sender selected.innerStamp.receiver "esp" 0 0) = true := by
      simpa only [IpsecPolicy.matches, identity.source, identity.destination, ← same] using configured.2
    have selectedStamp := outer.2.2 nominalMatched
    exact ⟨Or.inr selectedStamp, Or.inr ⟨outer.1, by simpa only [selectedStamp] using checks.outerName⟩⟩

lemma ipsec_flow_incoming_plain_destination {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : IPsecFlowEndpoints) (expectedEncapStack : Nat → List Nat)
    (checks : IPsecFlowPolicyChecks binding selected expectedEncapStack)
    (iface : Nat) (policy : IpsecPolicy) (association : InstalledSA) (body : Body)
    (configured : policy ∈ binding.configuration.ip.ingressPolicies iface)
    (installed : association ∈ binding.configuration.ip.ingressSAs iface) (bound : saMatchesPolicy association policy)
    (valid : FlowIPsecBody binding selected.flow selected.RemoteHeader selected.AllowedStamp (.ipsec (policy.seal association) body))
    (stack : policy.tag :: body.protectionLayers = expectedEncapStack iface) (empty : body.protectionLayers = []) :
    selected.PlainAllowed binding.configuration.ip.owner iface body := by
  rcases checks.incoming iface policy association configured installed bound
    (by rw [← stack]; rfl) with inner | outer
  · have stamp : policy.seal association = selected.innerStamp := by
      rcases valid.1.1 with selectedInner | selectedOuter
      · exact selectedInner
      · have tag := congrArg TunnelSAStamp.tag selectedOuter
        simp [IpsecPolicy.seal, inner.1, checks.outerTag] at tag
    have remote : selected.RemoteHeader body.originalHeader := by
      rcases valid.1.2 with innerValid | outerValid
      · exact innerValid.2.2
      · simp [IpsecPolicy.seal, inner.1] at outerValid
    exact Or.inr ⟨inner.2.2 stamp, remote⟩
  · simp [empty, outer.1, outer.2] at stack

end TDN.Requirements.Msc
