import TDN.Requirements.InboundProtectionEventGuard
import TDN.Requirements.DeviceProtectionLayerEvents

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding

def InboundGuardConsistent (guard : PendingInboundProtection → MultiProtocolForwarding.TunnelForwardingState → Prop)
    (pending : Option PendingInboundProtection) (state : MultiProtocolForwarding.TunnelForwardingState) : Prop :=
  match pending with
  | none => True
  | some received => guard received state

structure DeviceInboundGuardChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : EncryptionLayer) (target : PayloadId → String → Option String) where
  guard : PendingInboundProtection → MultiProtocolForwarding.TunnelForwardingState → Prop
  stateSafe : MultiProtocolForwarding.TunnelForwardingState → Prop
  initialized : ∀ state, binding.SourceInitial d state → stateSafe state
  preserved : ∀ before operation after, MultiProtocolForwarding.TunnelForwardingStep binding.configuration before operation after →
    stateSafe before → stateSafe after
  step : ∀ before operation after,
    MultiProtocolForwarding.TunnelForwardingStep binding.configuration before operation after → stateSafe before →
    ∀ pending, InboundGuardConsistent guard pending before →
    ∃ next, (inboundProtectionGuard d layer target ⟨before.frame.originDomain, before.frame.payload⟩).MTr
      pending ((binding.withProjection id (fun action => some action)).RequiredEvents before operation after) next ∧
      InboundGuardConsistent guard next after

lemma model_step_follows_inbound_guard {S A : Type} (model : ForwardingModel S A)
    (d : Deployment) (layer : EncryptionLayer) (target : PayloadId → String → Option String)
    (checks : DeviceInboundGuardChecks model.deviceDataPlane d layer target) (faithful : model.Faithful)
    {before after : S} {action : A} (step : model.system.Tr before action after)
    (safe : checks.stateSafe (model.deviceDataPlane.state before))
    (pending : Option PendingInboundProtection)
    (consistent : InboundGuardConsistent checks.guard pending (model.deviceDataPlane.state before)) :
    ∃ next, (inboundProtectionGuard d layer target
      ⟨(model.deviceDataPlane.state before).frame.originDomain, (model.deviceDataPlane.state before).frame.payload⟩).MTr
        pending (model.events action) next ∧ InboundGuardConsistent checks.guard next (model.deviceDataPlane.state after) := by
  have checked := faithful before action after step
  cases selected : model.deviceDataPlane.action action with
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

lemma forwarding_events_follow_inbound_guard {S A : Type} (model : ForwardingModel S A)
    (d : Deployment) (layer : EncryptionLayer) (target : PayloadId → String → Option String)
    (checks : DeviceInboundGuardChecks model.deviceDataPlane d layer target) (faithful : model.Faithful)
    {start finish : S} {actions : List A} (run : model.ForwardsAlongTrace start actions finish)
    (safe : checks.stateSafe (model.deviceDataPlane.state start))
    (pending : Option PendingInboundProtection)
    (consistent : InboundGuardConsistent checks.guard pending (model.deviceDataPlane.state start)) :
    ∃ next, (inboundProtectionGuard d layer target
      ⟨(model.deviceDataPlane.state start).frame.originDomain, (model.deviceDataPlane.state start).frame.payload⟩).MTr
        pending (actions.flatMap model.events) next ∧
      InboundGuardConsistent checks.guard next (model.deviceDataPlane.state finish) := by
  induction run generalizing pending with
  | refl => exact ⟨pending, .refl, consistent⟩
  | @stepL before action after rest finish step tail ih =>
    obtain ⟨next, first, nextConsistent⟩ :=
      model_step_follows_inbound_guard model d layer target checks faithful step safe pending consistent
    have safeAfter : checks.stateSafe (model.deviceDataPlane.state after) := by
      have checked := faithful before action after step
      cases selected : model.deviceDataPlane.action action with
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

lemma neutral_guard_events_preserve_pending {d : Deployment} {layer : EncryptionLayer}
    {target : PayloadId → String → Option String} {payload : PayloadId}
    (pending : Option PendingInboundProtection) (events : List NetworkEvent)
    (neutral : ∀ event ∈ events, InboundGuardNeutral event) :
    (inboundProtectionGuard d layer target payload).MTr pending events pending := by
  induction events with
  | nil => exact .refl
  | cons event rest ih =>
    exact .stepL (InboundProtectionGuardStep.neutral pending event (neutral event (by simp)))
      (ih (fun next member => neutral next (by simp [member])))

lemma setup_history_preserves_inbound_guard (d : Deployment) (layer : EncryptionLayer)
    (target : PayloadId → String → Option String) (payload : PayloadId)
    (history : ObservedHistory) (valid : history.Valid) :
    (inboundProtectionGuard d layer target payload).MTr none history.Events none := by
  apply neutral_guard_events_preserve_pending
  intro event member
  obtain ⟨record, stored, same⟩ := List.mem_map.mp member
  have setup := (valid.2.1 record stored).2.2.2.2
  rw [← same]
  rcases record with ⟨source, observer, localPosition, component, position, epoch, session, recorded⟩
  cases recorded <;> simp_all [HistoricalEvent.SetupOnly, InboundGuardNeutral]

lemma deployment_events_follow_inbound_guard {S A : Type} (model : ForwardingModel S A)
    (d : Deployment) (layer : EncryptionLayer) (target : PayloadId → String → Option String)
    (covered : model.CoversDeployment d) (checks : DeviceInboundGuardChecks model.deviceDataPlane d layer target)
    {start finish : S} {actions : List A} (initial : model.initial start)
    (run : model.ForwardsAlongTrace start actions finish) :
    ∃ next, (inboundProtectionGuard d layer target
      ⟨(model.deviceDataPlane.state start).frame.originDomain, (model.deviceDataPlane.state start).frame.payload⟩).MTr
        none (model.TraceEvents actions) next := by
  obtain ⟨next, following, retained⟩ :=
    forwarding_events_follow_inbound_guard model d layer target checks covered.2.1 run
      (checks.initialized _ (covered.2.2.2.1.2.2.2.1 start initial).1) none trivial
  exact ⟨next, (Cslib.LTS.MTr.append_iff _).mpr
    ⟨none, setup_history_preserves_inbound_guard d layer target _ model.history covered.validHistory, following⟩⟩

end TDN.Requirements.Msc
