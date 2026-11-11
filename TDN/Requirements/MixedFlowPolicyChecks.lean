import TDN.Requirements.MixedFlowTunnelNames
import TDN.Requirements.IPsecFlowPolicyChecks

namespace TDN.Requirements.Msc
open Compliance LayeredFrame MultiProtocolForwarding DataPlaneForwarding

structure MixedFlowEndpoints where
  flow : Flow
  originDomain : Nat
  sourceInnerOwner : Nat
  sourceHostOwner : Nat
  destinationInnerOwner : Nat
  destinationHostOwner : Nat
  innerStamp : TunnelSAStamp
  outerAssociation : MACsecAssociation
  destinationLogicalIface : Nat
  remoteLow : Nat
  remoteHigh : Nat

def MixedFlowEndpoints.SourceSide (selected : MixedFlowEndpoints) (owner : Nat) : Prop :=
  owner = selected.sourceInnerOwner ∨ owner = selected.sourceHostOwner

def MixedFlowEndpoints.DestinationSide (selected : MixedFlowEndpoints) (owner : Nat) : Prop :=
  owner = selected.destinationInnerOwner ∨ owner = selected.destinationHostOwner

def MixedFlowEndpoints.RemoteHeader (selected : MixedFlowEndpoints) : Option PacketPolicy.Packet → Prop
  | none => False
  | some header => selected.remoteLow ≤ header.destination ∧ header.destination ≤ selected.remoteHigh

def MixedFlowEndpoints.PlainAllowed (selected : MixedFlowEndpoints) (owner : Nat → Nat)
    (iface : Nat) (body : Body) : Prop :=
  selected.SourceSide (owner iface) ∨
    (selected.DestinationSide (owner iface) ∧ selected.RemoteHeader body.originalHeader)

def MixedFlowEndpoints.OutgoingPolicy (selected : MixedFlowEndpoints) (owner : Nat)
    (expectedEncapStack : List Nat) (policy : IpsecPolicy) (association : InstalledSA) : Prop :=
  policy.tag = 1 ∧ expectedEncapStack = [1] ∧
    (selected.SourceSide owner → policy.seal association = selected.innerStamp ∧
      selected.remoteLow ≤ policy.destinationLow ∧ policy.destinationHigh ≤ selected.remoteHigh) ∧
    (selected.DestinationSide owner →
      policy.destinationHigh < selected.remoteLow ∨ selected.remoteHigh < policy.destinationLow)

def MixedFlowEndpoints.IncomingPolicy (selected : MixedFlowEndpoints) (owner : Nat)
    (expectedEncapStack : List Nat) (policy : IpsecPolicy) (association : InstalledSA) : Prop :=
  policy.tag = 1 ∧ expectedEncapStack = [1] ∧
    (policy.seal association = selected.innerStamp → selected.DestinationSide owner)

structure MixedFlowPolicyChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : MixedFlowEndpoints) (expectedEncapStack : Nat → List Nat) : Prop where
  innerTag : selected.innerStamp.tag = 1
  outerTag : selected.outerAssociation.tag = 2
  innerName : binding.ipsecTunnel selected.innerStamp = selected.flow.innerTunnel
  outerName : binding.macsecTunnel selected.outerAssociation = selected.flow.outerTunnel
  outgoing : ∀ iface policy association,
    policy ∈ binding.configuration.ip.egressPolicies iface →
    association ∈ binding.configuration.ip.egressSAs iface → saMatchesPolicy association policy →
    (expectedEncapStack iface).head? = some policy.tag →
    selected.OutgoingPolicy (binding.configuration.ip.owner iface) (expectedEncapStack iface) policy association
  incoming : ∀ iface policy association,
    policy ∈ binding.configuration.ip.ingressPolicies iface →
    association ∈ binding.configuration.ip.ingressSAs iface → saMatchesPolicy association policy →
    (expectedEncapStack iface).head? = some policy.tag →
    selected.IncomingPolicy (binding.configuration.ip.owner iface) (expectedEncapStack iface) policy association
  routes : ∀ route ∈ binding.configuration.ip.routes,
    route.egress = selected.destinationLogicalIface →
    selected.innerStamp.receiver < route.destPrefixLow ∨ route.destPrefixHigh < selected.innerStamp.receiver
  macTransmit : ∀ iface ∈ binding.configuration.macIfaces, ∀ association,
    iface.transmitAssociation = some association →
    iface.logicalIface = selected.destinationLogicalIface ∨ association = selected.outerAssociation
  macLogicalStack : ∀ iface ∈ binding.configuration.macIfaces, expectedEncapStack iface.logicalIface = [1]

lemma plain_mixed_flow_visible_header {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : MixedFlowEndpoints) (processing : HeaderProcessing)
    (mode : binding.configuration.headerProcessing = some processing)
    (frame : LayeredFrame.Frame) (header : PacketPolicy.Packet)
    (coherent : frame.HeadersCoherent) (visible : binding.configuration.visibleHeader frame = some header)
    (valid : FlowMixedBody binding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation) frame.body)
    (empty : frame.body.protectionLayers = []) :
    ∃ original, frame.body.originalHeader = some original ∧ HeaderIdentity header original := by
  have actual : frame.visibleHeader = some header := by simpa only [Config.visibleHeader, mode] using visible
  obtain ⟨nominal, nominalVisible, identity⟩ := LayeredFrame.Frame.coherent_visible coherent header actual
  cases body : frame.body with
  | datagram packet =>
    have same : packet = nominal := by simpa only [body, Body.visibleHeader, Option.some.injEq] using nominalVisible
    exact ⟨packet, rfl, same ▸ identity⟩
  | ethernet packet => simp only [body, Body.visibleHeader, reduceCtorEq] at nominalVisible
  | ipsec | macsec => simp only [body, Body.protectionLayers, List.cons_ne_nil] at empty
  | macsecPdu | carrier => simp only [body, FlowMixedBody] at valid

lemma mixed_flow_outgoing_policy_named {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : MixedFlowEndpoints) (expectedEncapStack : Nat → List Nat)
    (checks : MixedFlowPolicyChecks binding selected expectedEncapStack)
    (processing : HeaderProcessing) (mode : binding.configuration.headerProcessing = some processing)
    (iface : Nat) (frame : LayeredFrame.Frame) (header : PacketPolicy.Packet) (policy : IpsecPolicy) (association : InstalledSA)
    (coherent : frame.HeadersCoherent) (visible : binding.configuration.visibleHeader frame = some header)
    (matched : policy ∈ lookupSpdPolicies (binding.configuration.ip.egressPolicies iface) header)
    (installed : association ∈ binding.configuration.ip.egressSAs iface) (bound : saMatchesPolicy association policy)
    (valid : FlowMixedBody binding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation) frame.body)
    (plain : frame.body.protectionLayers = [] → selected.PlainAllowed binding.configuration.ip.owner iface frame.body)
    (stack : policy.tag :: frame.body.protectionLayers = expectedEncapStack iface) :
    FlowMixedIPsecStamp binding selected.flow selected.RemoteHeader (· = selected.innerStamp)
      (policy.seal association) frame.body := by
  have configured := matched_policy_is_configured matched
  obtain ⟨tag, ifaceStack, sourcePolicy, destinationPolicy⟩ := checks.outgoing iface policy association
    configured.1 installed bound (by rw [← stack]; rfl)
  have empty : frame.body.protectionLayers = [] := by
    rw [tag, ifaceStack] at stack
    exact (List.cons.inj stack).2
  obtain ⟨original, originalHeader, identity⟩ := plain_mixed_flow_visible_header binding selected processing mode
    frame header coherent visible valid empty
  have ranges := configured.2
  simp only [IpsecPolicy.matches, decide_eq_true_eq] at ranges
  have destination := identity.destination
  have sourceSide : selected.SourceSide (binding.configuration.ip.owner iface) := by
    rcases plain empty with source | ⟨destinationSide, remote⟩
    · exact source
    · have disjoint := destinationPolicy destinationSide
      simp only [originalHeader, MixedFlowEndpoints.RemoteHeader] at remote
      rcases disjoint with before | after <;> omega
  obtain ⟨stamp, lower, upper⟩ := sourcePolicy sourceSide
  refine ⟨stamp, tag, ?_, ?_⟩
  · simpa only [stamp] using checks.innerName
  · simp only [originalHeader, MixedFlowEndpoints.RemoteHeader]
    omega

lemma mixed_flow_incoming_plain_destination {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : MixedFlowEndpoints) (expectedEncapStack : Nat → List Nat)
    (checks : MixedFlowPolicyChecks binding selected expectedEncapStack)
    (iface : Nat) (policy : IpsecPolicy) (association : InstalledSA) (body : Body)
    (configured : policy ∈ binding.configuration.ip.ingressPolicies iface)
    (installed : association ∈ binding.configuration.ip.ingressSAs iface) (bound : saMatchesPolicy association policy)
    (valid : FlowMixedBody binding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation) (.ipsec (policy.seal association) body))
    (stack : policy.tag :: body.protectionLayers = expectedEncapStack iface) (_empty : body.protectionLayers = []) :
    selected.PlainAllowed binding.configuration.ip.owner iface body := by
  have incoming := checks.incoming iface policy association configured installed bound (by rw [← stack]; rfl)
  exact Or.inr ⟨incoming.2.2 valid.1.1, valid.1.2.2.2⟩

lemma mixed_flow_inner_body_is_selected_ipsec {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : MixedFlowEndpoints) (body : Body)
    (valid : FlowMixedBody binding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation) body)
    (layers : body.protectionLayers = [1]) : ∃ contents, body = .ipsec selected.innerStamp contents := by
  cases body with
  | datagram | ethernet => simp only [Body.protectionLayers, reduceCtorEq] at layers
  | ipsec association contents => exact ⟨contents, by rw [valid.1.1]⟩
  | macsec association contents =>
    have tag := (List.cons.inj layers).1
    rw [valid.1.2.1] at tag
    contradiction
  | macsecPdu | carrier => exact False.elim valid

lemma mixed_flow_routes_preserve_direction {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : MixedFlowEndpoints) (expectedEncapStack : Nat → List Nat)
    (checks : MixedFlowPolicyChecks binding selected expectedEncapStack)
    (processing : HeaderProcessing) (mode : binding.configuration.headerProcessing = some processing)
    (frame : LayeredFrame.Frame) (header : PacketPolicy.Packet) (route : FibRoute)
    (coherent : frame.HeadersCoherent) (visible : binding.configuration.visibleHeader frame = some header)
    (valid : FlowMixedBody binding selected.flow selected.RemoteHeader
      (· = selected.innerStamp) (· = selected.outerAssociation) frame.body)
    (layers : frame.body.protectionLayers = [1])
    (chosen : SelectedFibRoute binding.configuration.ip.routes route header) :
    route.egress ≠ selected.destinationLogicalIface := by
  intro wrong
  obtain ⟨contents, body⟩ := mixed_flow_inner_body_is_selected_ipsec binding selected frame.body valid layers
  have actual : frame.visibleHeader = some header := by simpa only [Config.visibleHeader, mode] using visible
  obtain ⟨nominal, nominalVisible, identity⟩ := LayeredFrame.Frame.coherent_visible coherent header actual
  have same : outerHeader selected.innerStamp.sender selected.innerStamp.receiver "esp" 0 0 = nominal := by
    simpa only [body, Body.visibleHeader, Option.some.injEq] using nominalVisible
  have destination : header.destination = selected.innerStamp.receiver := by
    rw [identity.destination, ← same]
    rfl
  have matched := chosen.2.1
  have disjoint := checks.routes route chosen.1 wrong
  rcases disjoint with lower | upper <;> simp only [FibRoute.matches, destination] at matched <;> omega

lemma mixed_flow_macsec_transmit_is_selected {S A : Type} (binding : DeviceExecutionBinding S A)
    (selected : MixedFlowEndpoints) (expectedEncapStack : Nat → List Nat)
    (checks : MixedFlowPolicyChecks binding selected expectedEncapStack)
    (iface : MACIface) (association : MACsecAssociation) (state : MultiProtocolForwarding.State)
    (configured : iface ∈ binding.configuration.macIfaces) (stage : state.datapathStage = .egressReady)
    (logical : state.iface = iface.logicalIface) (emits : fullMACsecTransmit iface association state.frame.body)
    (layout : state.frame.body.protectionLayers = expectedEncapStack state.iface)
    (guarded : InnerMACsecEgressGuard selected.destinationLogicalIface state) :
    FlowMixedMACsecStamp binding selected.flow (· = selected.outerAssociation) association := by
  have layers : state.frame.body.protectionLayers = [1] :=
    layout.trans (by rw [logical]; exact checks.macLogicalStack iface configured)
  have same : association = selected.outerAssociation := by
    rcases checks.macTransmit iface configured association emits.1 with wrong | same
    · exact False.elim ((guarded layers (logical.trans wrong)).2.2.2 stage)
    · exact same
  exact ⟨same, same ▸ checks.outerTag, same ▸ checks.outerName⟩

end TDN.Requirements.Msc
