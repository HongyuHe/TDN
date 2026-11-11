import TDN.Requirements.ProtectionLayerEventPayloads
import TDN.Requirements.CoreMscRequirements

namespace TDN.Requirements.Msc
open Compliance

structure PendingInboundProtection where
  component : String
  layers : List String
  deriving DecidableEq

def MatchingInboundDecryption (d : Deployment) (layer : Layer)
    (pending : PendingInboundProtection) (tunnel : String) : Prop :=
  ∃ configured ∈ d.tunnels, configured.id = tunnel ∧ configured.layer = layer ∧
    configured.receiver = pending.component ∧ tunnel ∈ pending.layers

def InboundGateNeutral : NetworkEvent → Prop
  | .receive .. | .transmit .. => False
  | _ => True

inductive InboundProtectionGateStep (d : Deployment) (layer : Layer)
    (target : PayloadId → String → Option String) (payload : PayloadId) :
    Option PendingInboundProtection → NetworkEvent → Option PendingInboundProtection → Prop
  | receiveProtected (iface component : String) (layers : List String) (trafficClass : TrafficClass)
      (selected : target payload iface = some component) :
      InboundProtectionGateStep d layer target payload none (.receive payload iface layers trafficClass)
        (some ⟨component, layers⟩)
  | receiveOther (pending : Option PendingInboundProtection) (iface : String)
      (layers : List String) (trafficClass : TrafficClass) (other : target payload iface = none) :
      InboundProtectionGateStep d layer target payload pending (.receive payload iface layers trafficClass) pending
  | transmit (iface : String) (layers : List String) (trafficClass : TrafficClass) :
      InboundProtectionGateStep d layer target payload none (.transmit payload iface layers trafficClass) none
  | decrypt (pending : PendingInboundProtection) (tunnel : String)
      (matched : MatchingInboundDecryption d layer pending tunnel) :
      InboundProtectionGateStep d layer target payload (some pending) (.decrypt payload tunnel) none
  | neutral (pending : Option PendingInboundProtection) (event : NetworkEvent)
      (ignored : InboundGateNeutral event) :
      InboundProtectionGateStep d layer target payload pending event pending

def inboundProtectionGate (d : Deployment) (layer : Layer)
    (target : PayloadId → String → Option String) (payload : PayloadId) :
    Cslib.LTS (Option PendingInboundProtection) NetworkEvent :=
  ⟨InboundProtectionGateStep d layer target payload⟩

lemma inbound_gate_receive_shape {d : Deployment} {layer : Layer}
    {target : PayloadId → String → Option String} {payload observed : PayloadId}
    {before after : Option PendingInboundProtection} {iface component : String}
    {layers : List String} {trafficClass : TrafficClass}
    (step : InboundProtectionGateStep d layer target payload before
      (.receive observed iface layers trafficClass) after)
    (selected : target observed iface = some component) :
    observed = payload ∧ before = none ∧ after = some ⟨component, layers⟩ := by
  cases step with
  | receiveProtected iface found layers trafficClass matched =>
    have same := Option.some.inj (matched.symm.trans selected)
    subst found
    exact ⟨rfl, rfl, rfl⟩
  | receiveOther pending iface layers trafficClass other => simp [other] at selected
  | neutral pending event ignored => cases ignored

lemma inbound_gate_transmit_shape {d : Deployment} {layer : Layer}
    {target : PayloadId → String → Option String} {payload observed : PayloadId}
    {before after : Option PendingInboundProtection} {iface : String}
    {layers : List String} {trafficClass : TrafficClass}
    (step : InboundProtectionGateStep d layer target payload before
      (.transmit observed iface layers trafficClass) after) : before = none ∧ after = none := by
  cases step with
  | transmit => exact ⟨rfl, rfl⟩
  | neutral pending event ignored => cases ignored

lemma inbound_gate_release_requires_decrypt {d : Deployment} {layer : Layer}
    {target : PayloadId → String → Option String} {payload : PayloadId}
    {before after : Option PendingInboundProtection} {event : NetworkEvent}
    {pending : PendingInboundProtection}
    (step : InboundProtectionGateStep d layer target payload before event after)
    (current : before = some pending) (changed : after ≠ some pending) :
    ∃ tunnel, MatchingInboundDecryption d layer pending tunnel ∧ event = .decrypt payload tunnel := by
  cases step with
  | receiveProtected | transmit => cases current
  | receiveOther | neutral => exact False.elim (changed current)
  | decrypt received tunnel matched =>
    have same := Option.some.inj current
    subst received
    exact ⟨tunnel, matched, rfl⟩

lemma inbound_gate_release_has_decrypt {d : Deployment} {layer : Layer}
    {target : PayloadId → String → Option String} {payload : PayloadId}
    {pending : PendingInboundProtection} {events : List NetworkEvent}
    (run : (inboundProtectionGate d layer target payload).MTr (some pending) events none) :
    ∃ tunnel, MatchingInboundDecryption d layer pending tunnel ∧ .decrypt payload tunnel ∈ events := by
  obtain ⟨earlier, later, left, event, right, sequence, leading, step, trailing, current, changed⟩ :=
    TraceEvents.changing_predicate_has_event (inboundProtectionGate d layer target payload)
      (fun state => state = some pending) run rfl (by simp)
  obtain ⟨tunnel, matched, same⟩ := inbound_gate_release_requires_decrypt step current changed
  refine ⟨tunnel, matched, ?_⟩
  rw [sequence, same]
  simp

theorem external_receive_before_transmit_has_decrypt {d : Deployment} {layer : Layer}
    {target : PayloadId → String → Option String} {payload : PayloadId}
    {start finish : Option PendingInboundProtection} {earlier middle later : List NetworkEvent}
    {observed : PayloadId} {ingress component egress : String} {received sent : List String}
    {receiveClass sendClass : TrafficClass}
    (run : (inboundProtectionGate d layer target payload).MTr start
      (earlier ++ [.receive observed ingress received receiveClass] ++ middle ++
        [.transmit observed egress sent sendClass] ++ later) finish)
    (selected : target observed ingress = some component) :
    ∃ tunnel ∈ d.tunnels, tunnel.layer = layer ∧ tunnel.receiver = component ∧
      tunnel.id ∈ received ∧ .decrypt observed tunnel.id ∈ middle := by
  have splitRun : (inboundProtectionGate d layer target payload).MTr start
      (earlier ++ .receive observed ingress received receiveClass ::
        (middle ++ .transmit observed egress sent sendClass :: later)) finish := by
    simpa only [List.append_assoc, List.singleton_append, List.cons_append, List.nil_append] using run
  obtain ⟨before, after, leading, receivedStep, suffix⟩ := event_trace_split _ splitRun
  have receivedShape := inbound_gate_receive_shape receivedStep selected
  obtain ⟨left, right, between, sentStep, trailing⟩ := event_trace_split _ suffix
  have sentShape := inbound_gate_transmit_shape sentStep
  have segment : (inboundProtectionGate d layer target payload).MTr
      (some ⟨component, received⟩) middle none := by
    simpa only [receivedShape.2.2, sentShape.1] using between
  obtain ⟨name, ⟨tunnel, member, same, selectedLayer, receiver, present⟩, decrypted⟩ :=
    inbound_gate_release_has_decrypt segment
  subst name
  exact ⟨tunnel, member, selectedLayer, receiver, present, receivedShape.1 ▸ decrypted⟩

lemma stack_neutral_is_gate_neutral (event : NetworkEvent) (neutral : ProtectionLayerNeutral event) :
    InboundGateNeutral event := by
  cases event <;> simp_all [ProtectionLayerNeutral, InboundGateNeutral]

lemma gate_run_from_network_filter {d : Deployment} {layer : Layer}
    {target : PayloadId → String → Option String} {payload : PayloadId} {events : List NetworkEvent}
    {before after : Option PendingInboundProtection}
    (run : (inboundProtectionGate d layer target payload).MTr before
      (events.filter NetworkEvent.NetworkOperation) after) :
    (inboundProtectionGate d layer target payload).MTr before events after := by
  induction events generalizing before with
  | nil => exact run
  | cons event rest ih =>
    cases selected : event.NetworkOperation with
    | false =>
      have tail : (inboundProtectionGate d layer target payload).MTr before
          (rest.filter NetworkEvent.NetworkOperation) after := by
        simpa only [List.filter_cons, selected, Bool.false_eq_true, ↓reduceIte] using run
      exact .stepL (InboundProtectionGateStep.neutral before event
        (stack_neutral_is_gate_neutral event (nonnetwork_event_is_layer_neutral event selected))) (ih tail)
    | true =>
      have whole : (inboundProtectionGate d layer target payload).MTr before
          (event :: rest.filter NetworkEvent.NetworkOperation) after := by
        simpa only [List.filter_cons, selected, ↓reduceIte] using run
      cases whole with
      | stepL step tail => exact .stepL step (ih tail)

end TDN.Requirements.Msc
