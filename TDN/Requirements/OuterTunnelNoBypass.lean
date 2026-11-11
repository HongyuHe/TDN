import TDN.Requirements.LayerOutboundEventChecks

namespace TDN.Requirements.Msc
open Compliance

def OuterGrayReceiveShape (d : Deployment) (genuineControl : PayloadId → Prop) : NetworkEvent → Prop
  | .receive payload ingress layers _ => ¬ genuineControl payload →
      ∀ interface ∈ d.interfaces, d.Relevant interface.device → interface.id = ingress →
        interface.zone = .gray → d.IsLayer interface.device .outer →
        ∃ tunnel ∈ d.tunnels, tunnel.layer = .inner ∧ layers = [tunnel.id]
  | _ => True

structure OuterGrayReceiveLocalChecks {S A : Type} (d : Deployment) (model : ForwardingModel S A) where
  safe : S → Prop
  initial : ∀ start, model.initial start → safe start
  preserved : ∀ before action after, model.system.Tr before action after → safe before → safe after
  events : ∀ before action after, model.system.Tr before action after → safe before →
    ∀ event ∈ model.events action, OuterGrayReceiveShape d model.GenuineControl event

lemma forwarding_has_gray_receive_shapes {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (checks : OuterGrayReceiveLocalChecks d model) {start finish : S} {actions : List A}
    (run : model.system.MTr start actions finish) (safe : checks.safe start) :
    ∀ event ∈ actions.flatMap model.events, OuterGrayReceiveShape d model.GenuineControl event := by
  induction run with
  | refl => simp
  | @stepL before action after rest finish step tail ih =>
    intro event member
    rcases List.mem_append.mp member with first | later
    · exact checks.events before action after step safe event first
    · exact ih (checks.preserved before action after step safe) event later

lemma setup_history_has_gray_receive_shapes (d : Deployment) (history : ObservedHistory)
    (valid : history.Valid) (genuineControl : PayloadId → Prop) :
    ∀ event ∈ history.Events, OuterGrayReceiveShape d genuineControl event := by
  intro event member
  obtain ⟨record, stored, same⟩ := List.mem_map.mp member
  have setup := (valid.2.1 record stored).2.2.2.2
  rw [← same]
  rcases record with ⟨source, observer, localPosition, component, position, epoch, session, recorded⟩
  cases recorded <;> simp_all [HistoricalEvent.SetupOnly, OuterGrayReceiveShape]

theorem outer_tunnel_no_bypass_from_local_checks {S A : Type} (d : Deployment)
    (model : ForwardingModel S A) (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool) (receiveComponent : PayloadId → String → Option String)
    (covered : model.CoversDeployment { d with focus := none })
    (outbound : LayerOutboundLocalChecks { d with focus := none } model .outer)
    (inbound : DeviceInboundGateChecks model.native { d with focus := none } .outer receiveComponent)
    (receivers : InboundGateReceiversBound { d with focus := none } model.GenuineControl .outer receiveComponent)
    (configurations : ComponentConfigurationCoverage { d with focus := none } .outer components)
    (parameters : ∀ component ∈ components, ({ d with focus := none } : Deployment).Relevant component.id →
      (component.mechanism = .ipsec → component.espTunnelMode = true) ∧
      (outboundMACObjective = true → component.outboundMACPolicy = true) ∧
      (inboundMACObjective = true → component.inboundMACPolicy = true))
    (gray : OuterGrayReceiveLocalChecks { d with focus := none } model) :
    msc_outer_tunnel_no_bypass d model components outboundMACObjective inboundMACObjective := by
  refine ⟨configurations, ⟨covered, ?_⟩, parameters, ?_⟩
  · intro start actions finish initial run
    obtain ⟨next, gate⟩ := deployment_events_follow_inbound_gate model _ .outer receiveComponent covered inbound initial run
    apply layer_events_have_no_bypass_with_inbound_gate _ .outer model.GenuineControl receiveComponent
      (deployment_events_follow_layers model _ covered initial run) gate receivers
    intro event member
    rcases List.mem_append.mp member with setup | forwarding
    · exact setup_history_has_outbound_boundary_shapes _ model.history covered.2.2.2.2.1 _ .outer event setup
    · exact forwarding_has_outbound_boundary_shapes _ model .outer outbound run
        (outbound.initial start initial) event forwarding
  · intro start actions finish initial run payload ingress layers trafficClass member data interface stored relevant name zone outer
    have shape : OuterGrayReceiveShape { d with focus := none } model.GenuineControl
        (.receive payload ingress layers trafficClass) := by
      rcases List.mem_append.mp member with setup | forwarding
      · exact setup_history_has_gray_receive_shapes _ model.history covered.2.2.2.2.1 _ _ setup
      · exact forwarding_has_gray_receive_shapes _ model gray run (gray.initial start initial) _ forwarding
    exact shape data interface stored relevant name zone outer

end TDN.Requirements.Msc
