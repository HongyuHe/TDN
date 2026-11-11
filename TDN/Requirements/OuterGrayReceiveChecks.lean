import TDN.Requirements.IPsecOuterBoundaryChecks

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding LayeredFrame

lemma non_network_event_has_gray_receive_shape (d : Deployment) (genuineControl : PayloadId → Prop)
    (event : NetworkEvent) (other : event.NetworkOperation = false) :
    OuterGrayReceiveShape d genuineControl event := by
  cases event <;> simp_all [NetworkEvent.NetworkOperation, OuterGrayReceiveShape]

lemma ipsec_source_events_have_gray_receive_shape {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (stack : Nat → List Nat) (outer : Nat → Prop) (processing : HeaderProcessing)
    (checks : IPsecOuterBoundaryChecks binding d stack outer processing)
    (genuineControl : PayloadId → Prop) (before : S) :
    ∀ event ∈ binding.SourceEvents before, OuterGrayReceiveShape d genuineControl event := by
  dsimp only [DeviceExecutionBinding.SourceEvents]
  split
  next initial =>
    cases origin : binding.origin (binding.state before).frame.originDomain with
    | red network =>
      dsimp only
      split
      next selected =>
        intro event member
        simp only [List.mem_cons, List.not_mem_nil, or_false] at member
        rcases member with rfl | rfl
        · trivial
        · intro data interface stored relevant name gray owner
          exact False.elim (checks.sourceNotGray _ _ selected.1 interface stored name owner gray)
      next missing => simp
    | management component | control component protocol => simp
  next other => simp

lemma nontransmit_operation_events_have_gray_receive_shape {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (genuineControl : PayloadId → Prop) (before after : S)
    (operation : MultiProtocolForwarding.Action) (other : operation ≠ .linkTransmit) :
    ∀ event ∈ binding.OperationEvents before operation after, OuterGrayReceiveShape d genuineControl event := by
  cases operation <;> simp_all only [DeviceExecutionBinding.OperationEvents]
  all_goals repeat' first
    | split
    | simp_all [OuterGrayReceiveShape]

lemma ipsec_operation_events_have_gray_receive_shape {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (stack : Nat → List Nat) (outer : Nat → Prop) (processing : HeaderProcessing)
    (checks : IPsecOuterBoundaryChecks binding d stack outer processing) (genuineControl : PayloadId → Prop)
    {before after : MultiProtocolForwarding.State} {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before operation after)
    (safe : IPsecOuterBoundaryStateSafe binding d binding.configuration stack outer before) :
    ∀ event ∈ (binding.withProjection id (fun action => some action)).OperationEvents before operation after,
      OuterGrayReceiveShape d genuineControl event := by
  by_cases transmitting : operation = .linkTransmit
  · subst operation
    have safeAfter := ipsec_outer_boundary_state_preserved binding d stack outer processing checks step safe
    cases step with
    | linkTransmit next ready linked =>
      have names : ∀ body, (binding.withProjection (id : MultiProtocolForwarding.State → MultiProtocolForwarding.State)
          (fun action : MultiProtocolForwarding.Action => some action)).LayerIds body = binding.LayerIds body :=
        layer_ids_with_tunnel_names binding _ _
      dsimp only [DeviceExecutionBinding.withProjection] at names
      intro event member
      simp only [DeviceExecutionBinding.OperationEvents, DeviceExecutionBinding.withProjection, id_eq,
        List.mem_cons, List.not_mem_nil, or_false] at member
      rcases member with rfl | rfl | rfl | rfl
      · trivial
      · trivial
      · intro data interface stored relevant name gray component
        have expected := checks.internalInputs _ _ linked interface stored name component gray
        have actual : before.frame.body.protectionLayers = [1] := by
          have invariant := safeAfter.1.2.2
          simpa [expected] using invariant
        simpa only [names] using single_inner_ipsec_stack_has_configured_name binding d _ safeAfter.2.2 actual
      · trivial
  · exact nontransmit_operation_events_have_gray_receive_shape _ d genuineControl before after operation transmitting

def ipsecOuterGrayReceiveChecks {S A : Type} (model : ForwardingModel S A) (d : Deployment)
    (stack : Nat → List Nat) (outer : Nat → Prop) (processing : HeaderProcessing)
    (covered : model.CoversDeployment d)
    (checks : IPsecOuterBoundaryChecks model.native d stack outer processing) : OuterGrayReceiveLocalChecks d model := by
  refine ⟨fun state => IPsecOuterBoundaryStateSafe model.native d model.native.configuration stack outer (model.native.state state), ?_, ?_, ?_⟩
  · intro state initial
    exact ipsec_outer_boundary_state_initialized model.native d stack outer processing checks _
      (covered.2.2.2.1.2.2.2.1 state initial).1
  · intro before action after step safe
    have faithful := covered.2.1 before action after step
    cases selected : model.native.action action with
    | none => rw [selected] at faithful; rw [← faithful.1]; exact safe
    | some operation =>
      rw [selected] at faithful
      exact ipsec_outer_boundary_state_preserved model.native d stack outer processing checks faithful.1.1 safe
  · intro before action after step safe event member
    by_cases network : event.NetworkOperation = true
    · have recorded := List.mem_filter.mpr ⟨member, network⟩
      have faithful := covered.2.1 before action after step
      cases selected : model.native.action action with
      | none => rw [selected] at faithful; rw [faithful.2] at recorded; simp at recorded
      | some operation =>
        rw [selected] at faithful
        rw [faithful.2, DeviceExecutionBinding.RequiredEvents] at recorded
        rcases List.mem_append.mp recorded with source | operationEvent
        · exact ipsec_source_events_have_gray_receive_shape model.native d stack outer processing checks _ before event source
        · have localEvents := ipsec_operation_events_have_gray_receive_shape model.native d stack outer processing checks
            model.GenuineControl faithful.1.1 safe
          have projected : (model.native.withProjection id (fun action => some action)).OperationEvents
              (model.native.state before) operation (model.native.state after) =
              model.native.OperationEvents before operation after := by
            have names : ∀ body, (model.native.withProjection
                (id : MultiProtocolForwarding.State → MultiProtocolForwarding.State)
                (fun action : MultiProtocolForwarding.Action => some action)).LayerIds body =
                model.native.LayerIds body := layer_ids_with_tunnel_names model.native _ _
            dsimp only [DeviceExecutionBinding.withProjection] at names
            simp only [DeviceExecutionBinding.OperationEvents, DeviceExecutionBinding.withProjection, id_eq, names]
          rw [projected] at localEvents
          exact localEvents event operationEvent
    · exact non_network_event_has_gray_receive_shape d model.GenuineControl event (by cases value : event.NetworkOperation <;> simp_all)

end TDN.Requirements.Msc
