import TDN.Requirements.InnerOuterTunnelCompositionSpec
import TDN.Models.MultiProtocolBoundaryDecryption

namespace TDN.Requirements
open MultiProtocolForwarding

def mixedTunnelBoundary (c : MultiProtocolForwarding.Config) (expectedEncapStack : Nat → List Nat)
    (inside outside : List Nat) (tag component : Nat) :
    TunnelBoundaryView MultiProtocolForwarding.State MultiProtocolForwarding.Action where
  system := RestrictedExecution.within (MultiProtocolForwarding.lts c)
    (fun state => c.ip.owner state.iface = component)
  outboundEntry := fun state => state.datapathStage = .received ∧ state.iface ∈ inside ∧
    MultiProtocolForwarding.EncapStackConsistent c expectedEncapStack state
  outboundExit := fun state => state.datapathStage = .egressReady ∧ state.iface ∈ outside
  inboundEntry := fun state => state.datapathStage = .received ∧ state.iface ∈ outside ∧
    state.authenticated = []
  inboundExit := fun state => state.datapathStage = .egressReady ∧ state.iface ∈ inside
  outboundProtected := fun state => tag ∈ state.frame.body.protectionLayers
  inboundDecryptionOccurred := fun before actions after =>
    TraceEvents.Contains (MultiProtocolForwarding.lts c) before actions after
      (fun left action right => BoundaryDecryption c tag left action right ∧
        c.ip.owner left.iface = component ∧ left.frame.payload = before.frame.payload)
  splitTunnelExit := fun state => state.datapathStage = .egressReady ∧ state.iface ∈ outside ∧
    tag ∉ state.frame.body.protectionLayers

theorem mixed_tunnel_boundary_from_local_checks (c : MultiProtocolForwarding.Config)
    (expectedEncapStack : Nat → List Nat) (inside outside : List Nat) (tag component : Nat)
    (conditions : MultiProtocolForwarding.LocalConditions c expectedEncapStack)
    (carrierCheck : CarrierInputCheck c expectedEncapStack tag)
    (ipTags : ∀ entry, c.ip.owner entry = component →
      ∀ policy ∈ c.ip.ingressPolicies entry, policy.tag = tag)
    (macTags : ∀ iface ∈ c.macIfaces, c.ip.owner iface.physicalIface = component →
      ∀ association ∈ iface.receiveAssociations, association.tag = tag)
    (insideCheck : ∀ iface ∈ inside, tag ∉ expectedEncapStack iface)
    (outsideCheck : ∀ iface ∈ outside, tag ∈ expectedEncapStack iface) :
    BoundaryNoBypass (mixedTunnelBoundary c expectedEncapStack inside outside tag component) := by
  refine ⟨?_, ?_, ?_⟩
  · intro start finish actions entry run exitIface
    obtain ⟨received, member, invariant⟩ := entry
    obtain ⟨ready, outsideMember⟩ := exitIface
    have final := MultiProtocolForwarding.all_traces_preserve_stack c expectedEncapStack conditions
      (RestrictedExecution.project_trace _ _ run) invariant
    have stack : finish.frame.body.protectionLayers = expectedEncapStack finish.iface := by
      simpa only [ready] using final.2
    change tag ∈ finish.frame.body.protectionLayers
    rw [stack]
    exact outsideCheck finish.iface outsideMember
  · intro start finish actions entry run exitIface
    obtain ⟨received, member, empty⟩ := entry
    obtain ⟨ready, insideMember⟩ := exitIface
    exact inbound_crossing_has_actual_boundary_decryption c expectedEncapStack tag component conditions
      carrierCheck ipTags macTags run received empty (outsideCheck start.iface member)
      ready (insideCheck finish.iface insideMember)
  · intro start finish actions entry run bypass
    obtain ⟨received, member, invariant⟩ := entry
    obtain ⟨ready, outsideMember, missing⟩ := bypass
    have final := MultiProtocolForwarding.all_traces_preserve_stack c expectedEncapStack conditions
      (RestrictedExecution.project_trace _ _ run) invariant
    have stack : finish.frame.body.protectionLayers = expectedEncapStack finish.iface := by
      simpa only [ready] using final.2
    exact missing (stack ▸ outsideCheck finish.iface outsideMember)

end TDN.Requirements
