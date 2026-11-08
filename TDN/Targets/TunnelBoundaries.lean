import TDN.Targets.LayeredRequirements
import TDN.Semantics.RestrictedExecution
import TDN.Semantics.ExecutionAuthentication

namespace TDN.Targets
open Execution

def operationalTunnelBoundary (c : Environment) (expectedEncapStack : Nat → List Nat)
    (inside outside : List Nat) (tag component : Nat) : TunnelBoundaryView Execution.State Action where
  system := RestrictedExecution.within (lts c) (fun s => c.owner s.iface = component)
  outboundEntry := fun s => s.datapathStage = .received ∧ s.iface ∈ inside ∧ s.frame.tags = expectedEncapStack s.iface
  outboundExit := fun s => s.datapathStage = .ready ∧ s.iface ∈ outside
  inboundEntry := fun s => s.datapathStage = .received ∧ s.iface ∈ outside ∧ s.authenticated = []
  inboundExit := fun s => s.datapathStage = .ready ∧ s.iface ∈ inside
  outboundProtected := fun s => tag ∈ s.frame.tags
  inboundDecryptionOccurred := fun before actions after =>
    TraceEvents.Contains (lts c) before actions after
      (fun left action right => action = .decrypt ∧
        left.frame.tags = tag :: right.frame.tags ∧ left.frame.payload = before.frame.payload ∧
        c.owner left.iface = component)
  splitTunnelExit := fun s => s.datapathStage = .ready ∧ s.iface ∈ outside ∧ tag ∉ s.frame.tags

theorem tunnel_boundary_from_local_stack_checks (c : Environment) (expectedEncapStack : Nat → List Nat)
    (inside outside : List Nat) (tag component : Nat)
    (conditions : LocalStackConditions c expectedEncapStack)
    (inboundTags : ∀ iface, c.owner iface = component → ∀ a ∈ c.inbound iface, a.tag = tag)
    (insideCheck : ∀ iface ∈ inside, tag ∉ expectedEncapStack iface)
    (outsideCheck : ∀ iface ∈ outside, tag ∈ expectedEncapStack iface) :
    BoundaryNoBypass (operationalTunnelBoundary c expectedEncapStack inside outside tag component) := by
  have initial : ∀ s : Execution.State, s.datapathStage = .received → s.frame.tags = expectedEncapStack s.iface →
      StackInvariant c expectedEncapStack s := by
    intro s datapathStage shape
    simpa [StackInvariant, datapathStage] using shape
  refine ⟨?_, ?_, ?_⟩
  · intro start finish actions entry run exitIface
    obtain ⟨datapathStage, member, shape⟩ := entry
    obtain ⟨ready, outsideMember⟩ := exitIface
    have projected := RestrictedExecution.project_trace (lts c) (fun s => c.owner s.iface = component) run
    have stack := transmitted_stack c expectedEncapStack conditions projected (initial start datapathStage shape) ready
    change tag ∈ finish.frame.tags
    rw [stack]
    exact outsideCheck finish.iface outsideMember
  · intro start finish actions entry run exitIface
    obtain ⟨datapathStage, member, authentication⟩ := entry
    obtain ⟨ready, insideMember⟩ := exitIface
    exact inbound_crossing_requires_local_decryption c expectedEncapStack tag component conditions inboundTags
      run datapathStage authentication (outsideCheck start.iface member) ready
      (insideCheck finish.iface insideMember)
  · intro start finish actions entry run bypass
    obtain ⟨datapathStage, member, shape⟩ := entry
    obtain ⟨ready, outsideMember, missing⟩ := bypass
    have projected := RestrictedExecution.project_trace (lts c) (fun s => c.owner s.iface = component) run
    have stack := transmitted_stack c expectedEncapStack conditions projected (initial start datapathStage shape) ready
    rw [stack] at missing
    exact missing (outsideCheck finish.iface outsideMember)

theorem inner_tunnel_requirements_from_local_checks
    (c : Environment) (expectedEncapStack : Nat → List Nat) (inside outside : List Nat) (component : Nat)
    (conditions : LocalStackConditions c expectedEncapStack)
    (inboundTags : ∀ iface, c.owner iface = component → ∀ a ∈ c.inbound iface, a.tag = 1)
    (insideCheck : ∀ iface ∈ inside, 1 ∉ expectedEncapStack iface)
    (outsideCheck : ∀ iface ∈ outside, 1 ∈ expectedEncapStack iface)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool)
    (settings : ∀ item ∈ components,
      (item.mechanism = .ipsec → item.espTunnelMode = true ∧ item.associatedIPTunnel = true) ∧
      (outboundMACObjective = true → item.outboundMACPolicy = true) ∧
      (inboundMACObjective = true → item.inboundMACPolicy = true)) :
    msc_inner_tunnel_no_bypass
      (operationalTunnelBoundary c expectedEncapStack inside outside 1 component)
      components outboundMACObjective inboundMACObjective :=
  ⟨tunnel_boundary_from_local_stack_checks c expectedEncapStack inside outside 1 component
    conditions inboundTags insideCheck outsideCheck, settings⟩

theorem outer_tunnel_requirements_from_local_checks
    (c : Environment) (expectedEncapStack : Nat → List Nat) (inside outside : List Nat) (component : Nat)
    (conditions : LocalStackConditions c expectedEncapStack)
    (inboundTags : ∀ iface, c.owner iface = component → ∀ a ∈ c.inbound iface, a.tag = 2)
    (insideCheck : ∀ iface ∈ inside, 2 ∉ expectedEncapStack iface ∧ 1 ∈ expectedEncapStack iface)
    (outsideCheck : ∀ iface ∈ outside, 2 ∈ expectedEncapStack iface)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool)
    (settings : ∀ item ∈ components,
      (item.mechanism = .ipsec → item.espTunnelMode = true) ∧
      (outboundMACObjective = true → item.outboundMACPolicy = true) ∧
      (inboundMACObjective = true → item.inboundMACPolicy = true)) :
    msc_outer_tunnel_no_bypass
      (operationalTunnelBoundary c expectedEncapStack inside outside 2 component)
      components outboundMACObjective inboundMACObjective
      (operationalTunnelBoundary c expectedEncapStack inside outside 2 component).outboundEntry
      (fun state => 1 ∈ state.frame.tags) := by
  refine ⟨tunnel_boundary_from_local_stack_checks c expectedEncapStack inside outside 2 component
    conditions inboundTags (fun iface member => (insideCheck iface member).1) outsideCheck, ?_, settings⟩
  intro state entry
  obtain ⟨datapathStage, member, shape⟩ := entry
  rw [shape]
  exact (insideCheck state.iface member).2

end TDN.Targets
