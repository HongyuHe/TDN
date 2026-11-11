import TDN.Requirements.NestedFlowChecks

namespace TDN.Requirements.Msc
open Compliance

theorem nested_layer_protection_from_local_checks {S A : Type}
    (d : Deployment) (model : ForwardingModel S A) (flows : List Flow)
    (flowAt : S → PayloadId → Flow) (remoteDestination : S → PayloadId → Prop)
    (invariant : S → Prop) (independentKeys : String → String → Prop)
    (covered : model.CoversDeployment { d with focus := none })
    (services : ArchitectureServices { d with focus := none })
    (validFlows : ∀ flow ∈ flows, flow.Valid { d with focus := none } independentKeys)
    (checks : NestedFlowChecks { d with focus := none } model flows flowAt remoteDestination invariant) :
    msc_nested_layer_protection d model flows (fun start _ _ payload => flowAt start payload) independentKeys := by
  let whole : Deployment := { d with focus := none }
  change CoreReq_msc_nested_layer_protection whole model flows _ independentKeys
  refine ⟨covered, services, validFlows, ?_⟩
  intro start actions finish initial run
  dsimp only
  have checked := nested_flow_trace_events_checked checks covered.2.2.2.2.1 initial run
  have layers := deployment_events_follow_delivery_layers model whole covered initial run
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro payload network injected
    have source := checked (.inject payload network) injected
    exact ⟨source.1, source.2.1⟩
  · intro earlier later payload iface stack trafficClass split classified interface member relevant name
    have transmitted : .transmit payload iface stack trafficClass ∈ model.TraceEvents actions := by
      rw [split]; simp
    obtain ⟨gray, black⟩ := checked _ transmitted classified interface member relevant name
    obtain ⟨samePayload, leadingRun⟩ := delivery_trace_before_transmit layers split
    rw [← samePayload] at leadingRun
    constructor
    · intro zone
      obtain ⟨listed, singleton⟩ := gray zone
      refine ⟨listed, singleton, ?_⟩
      rw [singleton] at leadingRun
      exact event_layers_addition_has_encrypt (delivery_layer_trace_tracks_protection leadingRun)
        (by simp) (by simp)
    · intro zone
      obtain ⟨listed, pair, remote⟩ := black zone
      refine ⟨listed, pair, ?_⟩
      rw [pair] at leadingRun
      exact nested_tunnel_names_require_ordered_encryptions
        (delivery_layer_trace_tracks_protection leadingRun) (by simp [OuterWrapsInner])
  · intro payload iface stack trafficClass received classified interface member relevant name zone
    have result := checked (.receive payload iface stack trafficClass) received
      classified interface member relevant name zone
    exact ⟨result.1, result.2.1⟩
  · intro earlier later payload network stack split injected crossed
    have injectedTrace : .inject payload (flowAt start payload).sourceNetwork ∈ model.TraceEvents actions := by
      rw [split]; simp only [List.mem_append]; exact Or.inl (Or.inl injected)
    have classified : model.ProtectedPayload whole payload := (checked _ injectedTrace).2.2
    have remote : remoteDestination start payload := by
      obtain ⟨interface, member, black, receivedStack, trafficClass, crossing⟩ := crossed
      rcases crossing with sent | received
      · have eventMember : .transmit payload interface.id receivedStack trafficClass ∈ model.TraceEvents actions := by
          rw [split]; simp only [List.mem_append]; exact Or.inl (Or.inl sent)
        exact ((checked _ eventMember classified interface member (Or.inl rfl) rfl).2 black).2.2
      · have eventMember : .receive payload interface.id receivedStack trafficClass ∈ model.TraceEvents actions := by
          rw [split]; simp only [List.mem_append]; exact Or.inl (Or.inl received)
        exact (checked _ eventMember classified interface member (Or.inl rfl) rfl black).2.2
    have delivered : .deliver payload network stack ∈ model.TraceEvents actions := by rw [split]; simp
    obtain ⟨listed, destination, empty⟩ := checked _ delivered remote
    refine ⟨listed, destination, empty, ?_⟩
    obtain ⟨samePayload, leadingRun⟩ := delivery_trace_before_deliver layers split
    rw [← samePayload, empty] at leadingRun
    obtain ⟨interface, member, black, receivedStack, trafficClass, crossing⟩ := crossed
    rcases crossing with sent | received
    · have eventMember : .transmit payload interface.id receivedStack trafficClass ∈ model.TraceEvents actions := by
        rw [split]; simp only [List.mem_append]; exact Or.inl (Or.inl sent)
      have pair := ((checked _ eventMember classified interface member (Or.inl rfl) rfl).2 black).2.1
      obtain ⟨beforeCross, afterCross, crossingSplit⟩ := event_member_has_segments sent
      rw [pair] at crossingSplit
      exact events_before_black_transmit_deliver_after_outer_then_inner leadingRun crossingSplit
    · have eventMember : .receive payload interface.id receivedStack trafficClass ∈ model.TraceEvents actions := by
        rw [split]; simp only [List.mem_append]; exact Or.inl (Or.inl received)
      have pair := (checked _ eventMember classified interface member (Or.inl rfl) rfl black).2.1
      obtain ⟨beforeCross, afterCross, crossingSplit⟩ := event_member_has_segments received
      rw [pair] at crossingSplit
      exact events_before_black_receive_deliver_after_outer_then_inner leadingRun crossingSplit

end TDN.Requirements.Msc
