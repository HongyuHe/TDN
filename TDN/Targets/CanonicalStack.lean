import TDN.Targets.CanonicalHeaders
import TDN.Semantics.HeaderedEvents

namespace TDN.Compliance
open MultiProtocolExecution LayeredFrame

lemma NativeExecutionBinding.source_initial_red_stack {S A : Type}
    (binding : NativeExecutionBinding S A) (d : Deployment)
    (expectedEncapStack : Nat → List Nat)
    (sourceLayouts : ∀ iface network, binding.sourceEntry iface = some network → expectedEncapStack iface = [])
    (state : MultiProtocolExecution.State) (source : binding.SourceInitial d state)
    (network : String) (origin : binding.origin state.frame.originDomain = .red network) :
    HeaderedStackInvariant binding.configuration expectedEncapStack state := by
  have coherent := binding.source_initial_headers d state source
  have plain := source.2.1
  have sourceShape := source.2.2.2
  rw [origin] at sourceShape
  obtain ⟨datapathStage, entry, _⟩ := sourceShape
  have stack := sourceLayouts state.iface network entry
  refine ⟨coherent, ?_, ?_⟩
  · rcases plain with ⟨header, body⟩ | ⟨header, body⟩ <;> simp [body, CarrierBodies]
  · simp only [datapathStage]
    rcases plain with ⟨header, body⟩ | ⟨header, body⟩ <;>
      simp [body, Body.protectionLayers, stack]

theorem reachable_stack_from_local_steps {S A : Type}
    (model : ExecutionModel S A) (faithful : model.Faithful)
    (expectedEncapStack : Nat → List Nat)
    (conditions : HeaderedLocalConditions model.native.configuration expectedEncapStack)
    (processing : HeaderProcessing)
    (mode : model.native.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing)
    {start finish : S} {actions : List A} (run : model.system.MTr start actions finish)
    (initial : HeaderedStackInvariant model.native.configuration expectedEncapStack (model.native.state start)) :
    HeaderedStackInvariant model.native.configuration expectedEncapStack (model.native.state finish) := by
  have preserved : model.system.TrInv
      (fun state => HeaderedStackInvariant model.native.configuration expectedEncapStack (model.native.state state)) := by
    intro before action after step invariant
    have exactStep := faithful before action after step
    cases projection : model.native.action action with
    | none =>
      rw [projection] at exactStep
      rw [← exactStep.1]
      exact invariant
    | some native =>
      rw [projection] at exactStep
      exact headered_step_preserves_stack conditions processing mode bounds exactStep.1.1 invariant
  exact Cslib.LTS.mtrInv_of_trInv preserved start actions finish run initial

end TDN.Compliance

namespace TDN.Targets.CanonicalExecution
open Compliance MultiProtocolExecution

theorem canonical_red_reachable_stack {S A : Type}
    (prototype : NativeExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (expectedEncapStack : Nat → List Nat)
    (conditions : HeaderedLocalConditions prototype.configuration expectedEncapStack)
    (processing : HeaderProcessing)
    (mode : prototype.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing)
    (sourceLayouts : ∀ iface network, prototype.sourceEntry iface = some network → expectedEncapStack iface = [])
    (start finish : State ifaces) (actions : List (Action ifaces))
    (initialized : (model prototype ifaces d history).initial start)
    (network : String) (origin : prototype.origin start.native.frame.originDomain = .red network)
    (run : (model prototype ifaces d history).system.MTr start actions finish) :
    HeaderedStackInvariant prototype.configuration expectedEncapStack finish.native := by
  exact reachable_stack_from_local_steps (model prototype ifaces d history)
    (canonical_model_faithful prototype ifaces d history) expectedEncapStack conditions processing mode bounds run
    ((binding prototype ifaces).source_initial_red_stack d expectedEncapStack sourceLayouts
      start.native initialized.1 network origin)

end TDN.Targets.CanonicalExecution
