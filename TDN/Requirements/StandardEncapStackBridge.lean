import TDN.Requirements.StandardParsedHeaderBridge
import TDN.Models.HeaderAwareEncryptionOrder

namespace TDN.Compliance
open MultiProtocolForwarding LayeredFrame

lemma DeviceExecutionBinding.source_initial_red_stack {S A : Type}
    (binding : DeviceExecutionBinding S A) (d : Deployment)
    (expectedEncapStack : Nat → List Nat)
    (sourceLayouts : ∀ iface network, binding.sourceEntry iface = some network → expectedEncapStack iface = [])
    (state : MultiProtocolForwarding.TunnelForwardingState) (source : binding.SourceInitial d state)
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
    (model : ForwardingModel S A) (faithful : model.Faithful)
    (expectedEncapStack : Nat → List Nat)
    (conditions : HeaderedLocalConditions model.deviceDataPlane.configuration expectedEncapStack)
    (processing : HeaderProcessing)
    (mode : model.deviceDataPlane.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing)
    {start finish : S} {actions : List A} (run : model.ForwardsAlongTrace start actions finish)
    (initial : HeaderedStackInvariant model.deviceDataPlane.configuration expectedEncapStack (model.deviceDataPlane.state start)) :
    HeaderedStackInvariant model.deviceDataPlane.configuration expectedEncapStack (model.deviceDataPlane.state finish) := by
  have preserved : model.system.TrInv
      (fun state => HeaderedStackInvariant model.deviceDataPlane.configuration expectedEncapStack (model.deviceDataPlane.state state)) := by
    intro before action after step invariant
    have exactStep := faithful before action after step
    cases projection : model.deviceDataPlane.action action with
    | none =>
      rw [projection] at exactStep
      rw [← exactStep.1]
      exact invariant
    | some native =>
      rw [projection] at exactStep
      exact headered_step_preserves_stack conditions processing mode bounds exactStep.1.1 invariant
  exact Cslib.LTS.mtrInv_of_trInv preserved start actions finish run initial

end TDN.Compliance

namespace TDN.Requirements.StandardDataPlaneBridge
open Compliance MultiProtocolForwarding

theorem standard_red_reachable_stack {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (expectedEncapStack : Nat → List Nat)
    (conditions : HeaderedLocalConditions prototype.configuration expectedEncapStack)
    (processing : HeaderProcessing)
    (mode : prototype.configuration.headerProcessing = some processing)
    (bounds : HeaderBounds processing)
    (sourceLayouts : ∀ iface network, prototype.sourceEntry iface = some network → expectedEncapStack iface = [])
    (start finish : State ifaces) (actions : List (Action ifaces))
    (initialized : (model prototype ifaces d history).initial start)
    (network : String) (origin : prototype.origin start.deviceState.frame.originDomain = .red network)
    (run : (model prototype ifaces d history).system.MTr start actions finish) :
    HeaderedStackInvariant prototype.configuration expectedEncapStack finish.deviceState := by
  exact reachable_stack_from_local_steps (model prototype ifaces d history)
    (standard_model_faithful prototype ifaces d history) expectedEncapStack conditions processing mode bounds run
    ((binding prototype ifaces).source_initial_red_stack d expectedEncapStack sourceLayouts
      start.deviceState initialized.1 network origin)

end TDN.Requirements.StandardDataPlaneBridge
