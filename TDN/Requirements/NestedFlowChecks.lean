import TDN.Requirements.DeliveredPayloadLayers
import TDN.Requirements.MasterMscRequirementSpecs

namespace TDN.Requirements.Msc
open Compliance

def NestedFlowEventChecks {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (flows : List Flow) (flow : PayloadId → Flow) (remoteDestination : PayloadId → Prop) :
    NetworkEvent → Prop
  | .inject payload network => flow payload ∈ flows ∧ (flow payload).sourceNetwork = network ∧
      model.ProtectedPayload d payload
  | .transmit payload iface layers _ => model.ProtectedPayload d payload →
      ∀ interface ∈ d.interfaces, d.Relevant interface.device → interface.id = iface →
      (interface.zone = .gray → flow payload ∈ flows ∧ layers = [(flow payload).innerTunnel]) ∧
      (interface.zone = .black → flow payload ∈ flows ∧
        layers = [(flow payload).outerTunnel, (flow payload).innerTunnel] ∧ remoteDestination payload)
  | .receive payload iface layers _ => model.ProtectedPayload d payload →
      ∀ interface ∈ d.interfaces, d.Relevant interface.device → interface.id = iface →
      interface.zone = .black → flow payload ∈ flows ∧
        layers = [(flow payload).outerTunnel, (flow payload).innerTunnel] ∧ remoteDestination payload
  | .deliver payload network layers => remoteDestination payload →
      flow payload ∈ flows ∧ network = (flow payload).destinationNetwork ∧ layers = []
  | _ => True

structure NestedFlowChecks {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (flows : List Flow) (flowAt : S → PayloadId → Flow)
    (remoteDestination : S → PayloadId → Prop) (invariant : S → Prop) : Prop where
  sources : ∀ state, model.initial state → invariant state
  forwarding : ∀ before action after, invariant before → model.system.Tr before action after → invariant after
  flowPreserved : ∀ before action after, invariant before → model.system.Tr before action after →
    flowAt before = flowAt after
  destinationPreserved : ∀ before action after, invariant before → model.system.Tr before action after →
    remoteDestination before = remoteDestination after
  packetEvents : ∀ before action after, invariant before → model.system.Tr before action after →
    ∀ event ∈ model.events action,
      NestedFlowEventChecks d model flows (flowAt before) (remoteDestination before) event

lemma nested_flow_forwarding_events_checked {S A : Type} {d : Deployment} {model : ForwardingModel S A}
    {flows : List Flow} {flowAt : S → PayloadId → Flow}
    {remoteDestination : S → PayloadId → Prop} {invariant : S → Prop}
    (checks : NestedFlowChecks d model flows flowAt remoteDestination invariant)
    {start finish : S} {actions : List A} (run : model.system.MTr start actions finish) :
    invariant start → ∀ event ∈ actions.flatMap model.events,
      NestedFlowEventChecks d model flows (flowAt start) (remoteDestination start) event := by
  induction run with
  | refl => intro safe event member; simp at member
  | @stepL first action next rest last step tail ih =>
    intro safe event member
    rcases List.mem_append.mp member with current | remaining
    · exact checks.packetEvents first action next safe step event current
    · have checked := ih (checks.forwarding first action next safe step) event remaining
      rw [← checks.flowPreserved first action next safe step,
        ← checks.destinationPreserved first action next safe step] at checked
      exact checked

lemma history_events_satisfy_nested_flow_checks {S A : Type} (d : Deployment)
    (model : ForwardingModel S A) (flows : List Flow) (flow : PayloadId → Flow)
    (remoteDestination : PayloadId → Prop) (valid : model.history.Valid) :
    ∀ event ∈ model.history.Events, NestedFlowEventChecks d model flows flow remoteDestination event := by
  intro event member
  obtain ⟨record, stored, same⟩ := List.mem_map.mp member
  have setup := (valid.2.1 record stored).2.2.2.2
  rw [← same]
  rcases record with ⟨source, observer, localPosition, component, position, epoch, session, recorded⟩
  cases recorded <;> simp_all [HistoricalEvent.SetupOnly, NestedFlowEventChecks]

lemma nested_flow_trace_events_checked {S A : Type} {d : Deployment} {model : ForwardingModel S A}
    {flows : List Flow} {flowAt : S → PayloadId → Flow}
    {remoteDestination : S → PayloadId → Prop} {invariant : S → Prop}
    (checks : NestedFlowChecks d model flows flowAt remoteDestination invariant)
    (history : model.history.Valid) {start finish : S} {actions : List A}
    (initial : model.initial start) (run : model.system.MTr start actions finish) :
    ∀ event ∈ model.TraceEvents actions,
      NestedFlowEventChecks d model flows (flowAt start) (remoteDestination start) event := by
  intro event member
  rcases List.mem_append.mp member with setup | packet
  · exact history_events_satisfy_nested_flow_checks d model flows _ _ history event setup
  · exact nested_flow_forwarding_events_checked checks run (checks.sources start initial) event packet

end TDN.Requirements.Msc
