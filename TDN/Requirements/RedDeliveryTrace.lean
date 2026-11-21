import TDN.Requirements.IpsecNestedFlowEvents
import TDN.Requirements.DataPlaneToEventTraceBridge

namespace TDN.Requirements.Msc
open Compliance StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

lemma step_to_delivered_emits_event {S A : Type} (prototype : DeviceExecutionBinding S A)
    {before after : TunnelForwardingState} {operation : TunnelForwardingAction} {domain : Nat}
    (step : TunnelForwardingStep prototype.configuration before operation after)
    (done : after.datapathStage = .delivered)
    (recipient : prototype.configuration.ip.ifaceSecurityDomain after.iface = some domain) :
    .deliver ⟨after.frame.originDomain, after.frame.payload⟩ (prototype.domainName domain) [] ∈
      (packetBinding prototype).OperationEvents before operation after := by
  cases step <;> try {simp_all}
  all_goals
    simp_all [packetBinding, DeviceExecutionBinding.withProjection, DeviceExecutionBinding.OperationEvents,
      DeviceExecutionBinding.LayerIds]

lemma delivered_trace_contains_event {S A : Type} (prototype : DeviceExecutionBinding S A)
    (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    {first last : State ifaces} {actions : List (Action ifaces)} {domain : Nat}
    (run : (model prototype ifaces d history).system.MTr first actions last)
    (pending : first.deviceState.datapathStage ≠ .delivered)
    (done : last.deviceState.datapathStage = .delivered)
    (recipient : prototype.configuration.ip.ifaceSecurityDomain last.deviceState.iface = some domain) :
    .deliver ⟨last.deviceState.frame.originDomain, last.deviceState.frame.payload⟩
      (prototype.domainName domain) [] ∈ actions.flatMap (model prototype ifaces d history).events := by
  rcases actions.eq_nil_or_concat' with rfl | ⟨prior, action, rfl⟩
  · cases run
    contradiction
  · let forwarding := model prototype ifaces d history
    obtain ⟨before, _, finalStep⟩ := (Cslib.LTS.MTr.append_iff forwarding.system).mp run
    have step := (Cslib.LTS.MTr.singleton_iff forwarding.system ..).mp finalStep
    obtain ⟨sameBefore, sameAfter, _, accepted⟩ := step
    subst before
    subst last
    simp only [List.flatMap_append, List.flatMap_cons, List.flatMap_nil, List.append_nil]
    apply List.mem_append_right
    change _ ∈ (binding prototype ifaces).RequiredEvents _ _ _
    rw [packet_binding_required_events]
    exact List.mem_append_right _ (step_to_delivered_emits_event prototype accepted.1 done recipient)

theorem injection_precedes_delivered_endpoint {S A : Type} (prototype : DeviceExecutionBinding S A)
    (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    {first last : State ifaces} {actions : List (Action ifaces)} {domain : Nat} {network : String}
    (run : (model prototype ifaces d history).system.MTr first actions last)
    (sourceEvents : (binding prototype ifaces).SourceEvents first =
      [.inject ⟨first.deviceState.frame.originDomain, first.deviceState.frame.payload⟩ network,
       .receive ⟨first.deviceState.frame.originDomain, first.deviceState.frame.payload⟩
         (prototype.ifaceName first.deviceState.iface) [] .protectedData])
    (arrived : first.deviceState.datapathStage = .received)
    (done : last.deviceState.datapathStage = .delivered)
    (recipient : prototype.configuration.ip.ifaceSecurityDomain last.deviceState.iface = some domain) :
    Before ((model prototype ifaces d history).TraceEvents actions)
      (.inject ⟨first.deviceState.frame.originDomain, first.deviceState.frame.payload⟩ network)
      (.deliver ⟨first.deviceState.frame.originDomain, first.deviceState.frame.payload⟩ (prototype.domainName domain) []) := by
  have member := delivered_trace_contains_event prototype ifaces d history run (by simp [arrived]) done recipient
  have identity := (model prototype ifaces d history).preserves_payload_identity
    (standard_model_faithful prototype ifaces d history) run
  change last.deviceState.frame.payload = first.deviceState.frame.payload ∧
    last.deviceState.frame.originDomain = first.deviceState.frame.originDomain at identity
  rw [identity.1, identity.2] at member
  cases actions with
  | nil => cases run; contradiction
  | cons action rest =>
    obtain ⟨next, step, _⟩ := Cslib.LTS.MTr.cons_iff.mp run
    have actionEvents : (model prototype ifaces d history).events action =
        (binding prototype ifaces).SourceEvents first ++
        (binding prototype ifaces).OperationEvents first action.operation next := by
      rw [← step.1, ← step.2.1]
      rfl
    simp only [List.flatMap_cons, actionEvents, sourceEvents, List.cons_append, List.nil_append,
      List.mem_cons, reduceCtorEq, false_or] at member
    have remaining : NetworkEvent.deliver ⟨first.deviceState.frame.originDomain, first.deviceState.frame.payload⟩
        (prototype.domainName domain) [] ∈ (binding prototype ifaces).OperationEvents first action.operation next ++
          rest.flatMap (model prototype ifaces d history).events := by simpa using member
    obtain ⟨middle, later, equal⟩ := List.append_of_mem remaining
    refine ⟨history.Events,
      .receive ⟨first.deviceState.frame.originDomain, first.deviceState.frame.payload⟩
        (prototype.ifaceName first.deviceState.iface) [] .protectedData :: middle, later, ?_⟩
    simp only [ForwardingModel.TraceEvents, List.flatMap_cons, actionEvents, sourceEvents,
      List.cons_append, List.nil_append, List.append_assoc, equal]
    rfl

end TDN.Requirements.Msc
