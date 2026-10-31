import TDN.Targets.LayeredRequirements
import TDN.Semantics.MultiProtocolAuthentication

namespace TDN.Targets
open MultiProtocolExecution

/-- Outbound bodies come from the surrounding protected-payload execution.
Inbound bodies are arbitrary and carry no initial local authentication assertion. -/
def mixedTunnelBoundary (c : MultiProtocolExecution.Config) (layout : Nat → List Nat)
    (inside outside : List Nat) (tag component : Nat) :
    TunnelBoundaryView MultiProtocolExecution.State MultiProtocolExecution.Action where
  system := RestrictedExecution.within (MultiProtocolExecution.lts c)
    (fun state => c.ip.owner state.port = component)
  outboundEntry := fun state => state.phase = .received ∧ state.port ∈ inside ∧
    MultiProtocolExecution.StackInvariant c layout state
  outboundExit := fun state => state.phase = .ready ∧ state.port ∈ outside
  inboundEntry := fun state => state.phase = .received ∧ state.port ∈ outside ∧
    state.authenticated = []
  inboundExit := fun state => state.phase = .ready ∧ state.port ∈ inside
  outboundProtected := fun state => tag ∈ state.frame.body.protectionLayers
  inboundDecryptionOccurred := fun before actions after =>
    TraceEvents.Contains (MultiProtocolExecution.lts c) before actions after
      (fun left action right => BoundaryDecryption c tag left action right ∧
        c.ip.owner left.port = component ∧ left.frame.payload = before.frame.payload)
  splitTunnelExit := fun state => state.phase = .ready ∧ state.port ∈ outside ∧
    tag ∉ state.frame.body.protectionLayers

/-- The same local route, hook and association checks establish outward protection
and require an actual local receiving operation on every arbitrary inward traversal. -/
theorem mixed_tunnel_boundary_from_local_checks (c : MultiProtocolExecution.Config)
    (layout : Nat → List Nat) (inside outside : List Nat) (tag component : Nat)
    (conditions : MultiProtocolExecution.LocalConditions c layout)
    (carrierCheck : CarrierInputCheck c layout tag)
    (ipTags : ∀ entry, c.ip.owner entry = component →
      ∀ policy ∈ c.ip.inbound entry, policy.tag = tag)
    (macTags : ∀ port ∈ c.macPorts, c.ip.owner port.physicalPort = component →
      ∀ association ∈ port.receiveAssociations, association.tag = tag)
    (insideCheck : ∀ port ∈ inside, tag ∉ layout port)
    (outsideCheck : ∀ port ∈ outside, tag ∈ layout port) :
    BoundaryNoBypass (mixedTunnelBoundary c layout inside outside tag component) := by
  refine ⟨?_, ?_, ?_⟩
  · intro start finish actions entry run exitPort
    obtain ⟨received, member, invariant⟩ := entry
    obtain ⟨ready, outsideMember⟩ := exitPort
    have final := MultiProtocolExecution.all_executions_preserve_stack c layout conditions
      (RestrictedExecution.project_trace _ _ run) invariant
    have stack : finish.frame.body.protectionLayers = layout finish.port := by
      simpa only [ready] using final.2
    change tag ∈ finish.frame.body.protectionLayers
    rw [stack]
    exact outsideCheck finish.port outsideMember
  · intro start finish actions entry run exitPort
    obtain ⟨received, member, empty⟩ := entry
    obtain ⟨ready, insideMember⟩ := exitPort
    exact inbound_crossing_has_actual_boundary_decryption c layout tag component conditions
      carrierCheck ipTags macTags run received empty (outsideCheck start.port member)
      ready (insideCheck finish.port insideMember)
  · intro start finish actions entry run bypass
    obtain ⟨received, member, invariant⟩ := entry
    obtain ⟨ready, outsideMember, missing⟩ := bypass
    have final := MultiProtocolExecution.all_executions_preserve_stack c layout conditions
      (RestrictedExecution.project_trace _ _ run) invariant
    have stack : finish.frame.body.protectionLayers = layout finish.port := by
      simpa only [ready] using final.2
    exact missing (stack ▸ outsideCheck finish.port outsideMember)

end TDN.Targets
