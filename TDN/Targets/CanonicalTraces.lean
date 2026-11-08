import TDN.Targets.CanonicalStack
import TDN.Semantics.TraceProjection
import TDN.Semantics.MultiProtocolIdentity

namespace TDN.Compliance

theorem ExecutionModel.project_native_trace {S A : Type} (model : ExecutionModel S A)
    (faithful : model.Faithful)
    {before after : S} {actions : List A} (run : model.system.MTr before actions after) :
    (MultiProtocolExecution.lts model.native.configuration).MTr
      (model.native.state before) (actions.filterMap model.native.action)
      (model.native.state after) := by
  apply TraceProjection.optional_actions model.system
    (MultiProtocolExecution.lts model.native.configuration)
    model.native.state model.native.action _ run
  intro first action last step
  have checked := faithful first action last step
  cases selected : model.native.action action with
  | none =>
    rw [selected] at checked
    exact checked.1
  | some native =>
    rw [selected] at checked
    exact checked.1.1

theorem ExecutionModel.preserves_payload_identity {S A : Type} (model : ExecutionModel S A)
    (faithful : model.Faithful)
    {before after : S} {actions : List A} (run : model.system.MTr before actions after) :
    (model.native.state after).frame.payload = (model.native.state before).frame.payload ∧
    (model.native.state after).frame.originDomain = (model.native.state before).frame.originDomain :=
  MultiProtocolExecution.all_executions_preserve_payload model.native.configuration
    (model.project_native_trace faithful run)

theorem ExecutionModel.preserves_source_headers {S A : Type} (model : ExecutionModel S A)
    (faithful : model.Faithful)
    {before after : S} {actions : List A} (run : model.system.MTr before actions after) :
    (model.native.state after).frame.body.originalHeader =
        (model.native.state before).frame.body.originalHeader ∧
    (model.native.state after).frame.body.originalEthernet =
        (model.native.state before).frame.body.originalEthernet := by
  have native := model.project_native_trace faithful run
  exact ⟨MultiProtocolExecution.all_executions_preserve_original_header
      model.native.configuration native,
    MultiProtocolExecution.all_executions_preserve_original_ethernet
      model.native.configuration native⟩

end TDN.Compliance

namespace TDN.Targets.CanonicalExecution
open Compliance

theorem source_record_preserved {S A : Type} (prototype : NativeExecutionBinding S A)
    (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    {before after : State ifaces} {actions : List (Action ifaces)}
    (run : (model prototype ifaces d history).system.MTr before actions after) :
    after.source = before.source := by
  have stepProjection : (model prototype ifaces d history).system.TrInv
      (fun state => state.source = before.source) := by
    intro first action last step same
    exact step.2.2.1.symm.trans same
  exact Cslib.LTS.mtrInv_of_trInv stepProjection before actions after run rfl

theorem native_execution {S A : Type} (prototype : NativeExecutionBinding S A)
    (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    {before after : State ifaces} {actions : List (Action ifaces)}
    (run : (model prototype ifaces d history).system.MTr before actions after) :
    (MultiProtocolExecution.lts prototype.configuration).MTr
      before.native (actions.map Action.operation) after.native := by
  have projected := (model prototype ifaces d history).project_native_trace
    (canonical_model_faithful prototype ifaces d history) run
  change (MultiProtocolExecution.lts prototype.configuration).MTr
    before.native (actions.filterMap (fun action => some action.operation)) after.native at projected
  have same : actions.filterMap (fun action : Action ifaces => some action.operation) =
      actions.map Action.operation :=
    List.filterMap_eq_map_iff_forall_eq_some.mpr (by intro action member; rfl)
  rw [same] at projected
  exact projected

theorem source_identity_preserved {S A : Type} (prototype : NativeExecutionBinding S A)
    (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    {before after : State ifaces} {actions : List (Action ifaces)}
    (run : (model prototype ifaces d history).system.MTr before actions after) :
    after.native.frame.payload = before.native.frame.payload ∧
    after.native.frame.originDomain = before.native.frame.originDomain ∧
    after.native.frame.body.originalHeader = before.native.frame.body.originalHeader ∧
    after.native.frame.body.originalEthernet = before.native.frame.body.originalEthernet ∧
    after.source = before.source := by
  have payload := (model prototype ifaces d history).preserves_payload_identity
    (canonical_model_faithful prototype ifaces d history) run
  have headers := (model prototype ifaces d history).preserves_source_headers
    (canonical_model_faithful prototype ifaces d history) run
  exact ⟨payload.1, payload.2, headers.1, headers.2, source_record_preserved prototype ifaces d history run⟩

end TDN.Targets.CanonicalExecution
