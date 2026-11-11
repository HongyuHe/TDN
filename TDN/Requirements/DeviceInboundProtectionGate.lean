import TDN.Requirements.InboundProtectionEventGate
import TDN.Requirements.DeviceProtectionLayerEvents

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding

def InboundGateConsistent (guard : PendingInboundProtection → MultiProtocolForwarding.State → Prop)
    (pending : Option PendingInboundProtection) (state : MultiProtocolForwarding.State) : Prop :=
  match pending with
  | none => True
  | some received => guard received state

structure DeviceInboundGateChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : Layer) (target : PayloadId → String → Option String) where
  guard : PendingInboundProtection → MultiProtocolForwarding.State → Prop
  stateSafe : MultiProtocolForwarding.State → Prop
  initialized : ∀ state, binding.SourceInitial d state → stateSafe state
  preserved : ∀ before operation after, MultiProtocolForwarding.Step binding.configuration before operation after →
    stateSafe before → stateSafe after
  step : ∀ before operation after,
    MultiProtocolForwarding.Step binding.configuration before operation after → stateSafe before →
    ∀ pending, InboundGateConsistent guard pending before →
    ∃ next, (inboundProtectionGate d layer target ⟨before.frame.originDomain, before.frame.payload⟩).MTr
      pending ((binding.withProjection id (fun action => some action)).RequiredEvents before operation after) next ∧
      InboundGateConsistent guard next after

lemma model_step_follows_inbound_gate {S A : Type} (model : ForwardingModel S A)
    (d : Deployment) (layer : Layer) (target : PayloadId → String → Option String)
    (checks : DeviceInboundGateChecks model.native d layer target) (faithful : model.Faithful)
    {before after : S} {action : A} (step : model.system.Tr before action after)
    (safe : checks.stateSafe (model.native.state before))
    (pending : Option PendingInboundProtection)
    (consistent : InboundGateConsistent checks.guard pending (model.native.state before)) :
    ∃ next, (inboundProtectionGate d layer target
      ⟨(model.native.state before).frame.originDomain, (model.native.state before).frame.payload⟩).MTr
        pending (model.events action) next ∧ InboundGateConsistent checks.guard next (model.native.state after) := by
  have checked := faithful before action after step
  cases selected : model.native.action action with
  | none =>
    rw [selected] at checked
    refine ⟨pending, gate_run_from_network_filter ?_, ?_⟩
    · rw [checked.2]
      exact .refl
    · rw [← checked.1]
      exact consistent
  | some operation =>
    rw [selected] at checked
    obtain ⟨next, gate, retained⟩ := checks.step _ _ _ checked.1.1 safe pending consistent
    rw [required_events_with_tunnel_names] at gate
    refine ⟨next, gate_run_from_network_filter ?_, retained⟩
    rw [checked.2]
    exact gate

lemma forwarding_events_follow_inbound_gate {S A : Type} (model : ForwardingModel S A)
    (d : Deployment) (layer : Layer) (target : PayloadId → String → Option String)
    (checks : DeviceInboundGateChecks model.native d layer target) (faithful : model.Faithful)
    {start finish : S} {actions : List A} (run : model.system.MTr start actions finish)
    (safe : checks.stateSafe (model.native.state start))
    (pending : Option PendingInboundProtection)
    (consistent : InboundGateConsistent checks.guard pending (model.native.state start)) :
    ∃ next, (inboundProtectionGate d layer target
      ⟨(model.native.state start).frame.originDomain, (model.native.state start).frame.payload⟩).MTr
        pending (actions.flatMap model.events) next ∧
      InboundGateConsistent checks.guard next (model.native.state finish) := by
  induction run generalizing pending with
  | refl => exact ⟨pending, .refl, consistent⟩
  | @stepL before action after rest finish step tail ih =>
    obtain ⟨next, first, nextConsistent⟩ :=
      model_step_follows_inbound_gate model d layer target checks faithful step safe pending consistent
    have safeAfter : checks.stateSafe (model.native.state after) := by
      have checked := faithful before action after step
      cases selected : model.native.action action with
      | none =>
        rw [selected] at checked
        rw [← checked.1]
        exact safe
      | some operation =>
        rw [selected] at checked
        exact checks.preserved _ _ _ checked.1.1 safe
    obtain ⟨last, following, lastConsistent⟩ := ih safeAfter next nextConsistent
    have identity := model.preserves_payload_identity faithful (Cslib.LTS.MTr.stepL step .refl)
    rw [identity.1, identity.2] at following
    exact ⟨last, (Cslib.LTS.MTr.append_iff _).mpr ⟨next, first, following⟩, lastConsistent⟩

lemma neutral_gate_events_preserve_pending {d : Deployment} {layer : Layer}
    {target : PayloadId → String → Option String} {payload : PayloadId}
    (pending : Option PendingInboundProtection) (events : List NetworkEvent)
    (neutral : ∀ event ∈ events, InboundGateNeutral event) :
    (inboundProtectionGate d layer target payload).MTr pending events pending := by
  induction events with
  | nil => exact .refl
  | cons event rest ih =>
    exact .stepL (InboundProtectionGateStep.neutral pending event (neutral event (by simp)))
      (ih (fun next member => neutral next (by simp [member])))

lemma setup_history_preserves_inbound_gate (d : Deployment) (layer : Layer)
    (target : PayloadId → String → Option String) (payload : PayloadId)
    (history : ObservedHistory) (valid : history.Valid) :
    (inboundProtectionGate d layer target payload).MTr none history.Events none := by
  apply neutral_gate_events_preserve_pending
  intro event member
  obtain ⟨record, stored, same⟩ := List.mem_map.mp member
  have setup := (valid.2.1 record stored).2.2.2.2
  rw [← same]
  rcases record with ⟨source, observer, localPosition, component, position, epoch, session, recorded⟩
  cases recorded <;> simp_all [HistoricalEvent.SetupOnly, InboundGateNeutral]

lemma deployment_events_follow_inbound_gate {S A : Type} (model : ForwardingModel S A)
    (d : Deployment) (layer : Layer) (target : PayloadId → String → Option String)
    (covered : model.CoversDeployment d) (checks : DeviceInboundGateChecks model.native d layer target)
    {start finish : S} {actions : List A} (initial : model.initial start)
    (run : model.system.MTr start actions finish) :
    ∃ next, (inboundProtectionGate d layer target
      ⟨(model.native.state start).frame.originDomain, (model.native.state start).frame.payload⟩).MTr
        none (model.TraceEvents actions) next := by
  obtain ⟨next, following, retained⟩ :=
    forwarding_events_follow_inbound_gate model d layer target checks covered.2.1 run
      (checks.initialized _ (covered.2.2.2.1.2.2.2.1 start initial).1) none trivial
  exact ⟨next, (Cslib.LTS.MTr.append_iff _).mpr
    ⟨none, setup_history_preserves_inbound_gate d layer target _ model.history covered.2.2.2.2.1, following⟩⟩

end TDN.Requirements.Msc
