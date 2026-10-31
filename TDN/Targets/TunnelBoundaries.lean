import TDN.Targets.LayeredRequirements
import TDN.Semantics.RestrictedExecution
import TDN.Semantics.ExecutionAuthentication

namespace TDN.Targets
open Execution

def operationalTunnelBoundary (c : Config) (layout : Nat → List Nat)
    (inside outside : List Nat) (tag component : Nat) : TunnelBoundaryView Execution.State Action where
  system := RestrictedExecution.within (lts c) (fun s => c.owner s.port = component)
  outboundEntry := fun s => s.phase = .received ∧ s.port ∈ inside ∧ s.frame.tags = layout s.port
  outboundExit := fun s => s.phase = .ready ∧ s.port ∈ outside
  inboundEntry := fun s => s.phase = .received ∧ s.port ∈ outside ∧ s.authenticated = []
  inboundExit := fun s => s.phase = .ready ∧ s.port ∈ inside
  outboundProtected := fun s => tag ∈ s.frame.tags
  inboundDecryptionOccurred := fun before actions after =>
    TraceEvents.Contains (lts c) before actions after
      (fun left action right => action = .decrypt ∧
        left.frame.tags = tag :: right.frame.tags ∧ left.frame.payload = before.frame.payload ∧
        c.owner left.port = component)
  splitTunnelExit := fun s => s.phase = .ready ∧ s.port ∈ outside ∧ tag ∉ s.frame.tags

theorem tunnel_boundary_from_local_stack_checks (c : Config) (layout : Nat → List Nat)
    (inside outside : List Nat) (tag component : Nat)
    (conditions : LocalStackConditions c layout)
    (inboundTags : ∀ port, c.owner port = component → ∀ a ∈ c.inbound port, a.tag = tag)
    (insideCheck : ∀ port ∈ inside, tag ∉ layout port)
    (outsideCheck : ∀ port ∈ outside, tag ∈ layout port) :
    BoundaryNoBypass (operationalTunnelBoundary c layout inside outside tag component) := by
  have initial : ∀ s : Execution.State, s.phase = .received → s.frame.tags = layout s.port →
      StackInvariant c layout s := by
    intro s phase shape
    simpa [StackInvariant, phase] using shape
  refine ⟨?_, ?_, ?_⟩
  · intro start finish actions entry run exitPort
    obtain ⟨phase, member, shape⟩ := entry
    obtain ⟨ready, outsideMember⟩ := exitPort
    have projected := RestrictedExecution.project_trace (lts c) (fun s => c.owner s.port = component) run
    have stack := transmitted_stack c layout conditions projected (initial start phase shape) ready
    change tag ∈ finish.frame.tags
    rw [stack]
    exact outsideCheck finish.port outsideMember
  · intro start finish actions entry run exitPort
    obtain ⟨phase, member, authentication⟩ := entry
    obtain ⟨ready, insideMember⟩ := exitPort
    exact inbound_crossing_requires_local_decryption c layout tag component conditions inboundTags
      run phase authentication (outsideCheck start.port member) ready
      (insideCheck finish.port insideMember)
  · intro start finish actions entry run bypass
    obtain ⟨phase, member, shape⟩ := entry
    obtain ⟨ready, outsideMember, missing⟩ := bypass
    have projected := RestrictedExecution.project_trace (lts c) (fun s => c.owner s.port = component) run
    have stack := transmitted_stack c layout conditions projected (initial start phase shape) ready
    rw [stack] at missing
    exact missing (outsideCheck finish.port outsideMember)

theorem inner_tunnel_requirements_from_local_checks
    (c : Config) (layout : Nat → List Nat) (inside outside : List Nat) (component : Nat)
    (conditions : LocalStackConditions c layout)
    (inboundTags : ∀ port, c.owner port = component → ∀ a ∈ c.inbound port, a.tag = 1)
    (insideCheck : ∀ port ∈ inside, 1 ∉ layout port)
    (outsideCheck : ∀ port ∈ outside, 1 ∈ layout port)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool)
    (settings : ∀ item ∈ components,
      (item.mechanism = .ipsec → item.espTunnelMode = true ∧ item.associatedIPTunnel = true) ∧
      (outboundMACObjective = true → item.outboundMACPolicy = true) ∧
      (inboundMACObjective = true → item.inboundMACPolicy = true)) :
    msc_inner_tunnel_no_bypass
      (operationalTunnelBoundary c layout inside outside 1 component)
      components outboundMACObjective inboundMACObjective :=
  ⟨tunnel_boundary_from_local_stack_checks c layout inside outside 1 component
    conditions inboundTags insideCheck outsideCheck, settings⟩

theorem outer_tunnel_requirements_from_local_checks
    (c : Config) (layout : Nat → List Nat) (inside outside : List Nat) (component : Nat)
    (conditions : LocalStackConditions c layout)
    (inboundTags : ∀ port, c.owner port = component → ∀ a ∈ c.inbound port, a.tag = 2)
    (insideCheck : ∀ port ∈ inside, 2 ∉ layout port ∧ 1 ∈ layout port)
    (outsideCheck : ∀ port ∈ outside, 2 ∈ layout port)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool)
    (settings : ∀ item ∈ components,
      (item.mechanism = .ipsec → item.espTunnelMode = true) ∧
      (outboundMACObjective = true → item.outboundMACPolicy = true) ∧
      (inboundMACObjective = true → item.inboundMACPolicy = true)) :
    msc_outer_tunnel_no_bypass
      (operationalTunnelBoundary c layout inside outside 2 component)
      components outboundMACObjective inboundMACObjective
      (operationalTunnelBoundary c layout inside outside 2 component).outboundEntry
      (fun state => 1 ∈ state.frame.tags) := by
  refine ⟨tunnel_boundary_from_local_stack_checks c layout inside outside 2 component
    conditions inboundTags (fun port member => (insideCheck port member).1) outsideCheck, ?_, settings⟩
  intro state entry
  obtain ⟨phase, member, shape⟩ := entry
  rw [shape]
  exact (insideCheck state.port member).2

end TDN.Targets
