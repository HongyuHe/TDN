import TDN.Targets.CanonicalSourceCoverage
import TDN.Semantics.MultiProtocolHeaders

namespace TDN.Compliance

lemma NativeExecutionBinding.source_initial_headers {S A : Type}
    (binding : NativeExecutionBinding S A) (d : Deployment)
    (state : MultiProtocolExecution.State) (source : binding.SourceInitial d state) :
    state.frame.HeadersCoherent := by
  obtain ⟨request, datagrams, datagram, _, _, _, valid, same⟩ := source.2.2.1
  rw [same]
  simpa only [NativeExecutionBinding.SourceState, LayeredFrame.Frame.HeadersCoherent] using
    PacketSource.decoded_source_headers datagram valid.1

theorem reachable_headers_from_local_steps {S A : Type} (model : ExecutionModel S A)
    (faithful : model.Faithful) (processing : MultiProtocolExecution.HeaderProcessing)
    (mode : model.native.configuration.headerProcessing = some processing)
    (bounds : MultiProtocolExecution.HeaderBounds processing)
    {start finish : S} {actions : List A} (run : model.system.MTr start actions finish)
    (initial : (model.native.state start).frame.HeadersCoherent) :
    (model.native.state finish).frame.HeadersCoherent := by
  have preserved : model.system.TrInv
      (fun state => (model.native.state state).frame.HeadersCoherent) := by
    intro before action after step coherent
    have exactStep := faithful before action after step
    cases projection : model.native.action action with
    | none =>
      rw [projection] at exactStep
      rw [← exactStep.1]
      exact coherent
    | some native =>
      rw [projection] at exactStep
      exact MultiProtocolExecution.step_preserves_headers processing mode bounds
        exactStep.1.1 coherent
  exact Cslib.LTS.mtrInv_of_trInv preserved start actions finish run initial

end TDN.Compliance

namespace TDN.Targets.CanonicalExecution
open Compliance

theorem canonical_reachable_headers {S A : Type}
    (prototype : NativeExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (processing : MultiProtocolExecution.HeaderProcessing)
    (mode : prototype.configuration.headerProcessing = some processing)
    (bounds : MultiProtocolExecution.HeaderBounds processing)
    (start finish : State ifaces) (actions : List (Action ifaces))
    (initialized : (model prototype ifaces d history).initial start)
    (run : (model prototype ifaces d history).system.MTr start actions finish) :
    finish.native.frame.HeadersCoherent := by
  exact reachable_headers_from_local_steps (model prototype ifaces d history)
    (canonical_model_faithful prototype ifaces d history) processing mode bounds run
    ((binding prototype ifaces).source_initial_headers d start.native initialized.1)

end TDN.Targets.CanonicalExecution
