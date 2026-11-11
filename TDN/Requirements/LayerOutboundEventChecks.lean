import TDN.Requirements.MasterMscRequirementSpecs
import TDN.Requirements.DeviceInboundProtectionGate

namespace TDN.Requirements.Msc
open Compliance

def LayerOutboundEventShape (d : Deployment) (genuineControl : PayloadId → Prop)
    (layer : Layer) : NetworkEvent → Prop
  | .receive payload iface layers _ =>
      ¬ genuineControl payload → ∀ interface ∈ d.interfaces, interface.id = iface →
        d.IsLayer interface.device layer → interface.zone = InternalZone layer →
        ∀ tunnel ∈ d.tunnels, tunnel.layer = layer → tunnel.id ∉ layers
  | .transmit payload iface layers _ =>
      ¬ genuineControl payload → ∀ interface ∈ d.interfaces, interface.id = iface →
        d.IsLayer interface.device layer →
        (interface.zone = InternalZone layer →
          ∀ tunnel ∈ d.tunnels, tunnel.layer = layer → tunnel.id ∉ layers) ∧
        (interface.zone ≠ InternalZone layer →
          ∃ tunnel ∈ d.tunnels, tunnel.layer = layer ∧ tunnel.sender = interface.device ∧ tunnel.id ∈ layers)
  | _ => True

def InboundGateReceiversBound (d : Deployment) (genuineControl : PayloadId → Prop)
    (layer : Layer) (target : PayloadId → String → Option String) : Prop :=
  ∀ payload, ¬ genuineControl payload → ∀ interface ∈ d.interfaces,
    d.IsLayer interface.device layer → interface.zone = ExternalZone layer →
      target payload interface.id = some interface.device

theorem layer_events_have_no_bypass_with_inbound_gate (d : Deployment) (layer : Layer)
    (genuineControl : PayloadId → Prop) (target : PayloadId → String → Option String)
    {payload : PayloadId} {events : List NetworkEvent} {finalLayers : List String}
    {finalPending : Option PendingInboundProtection}
    (run : (protectionLayerSystem payload).MTr [] events finalLayers)
    (gate : (inboundProtectionGate d layer target payload).MTr none events finalPending)
    (targets : InboundGateReceiversBound d genuineControl layer target)
    (shapes : ∀ event ∈ events, LayerOutboundEventShape d genuineControl layer event) :
    TraceNoBypass d genuineControl layer events := by
  constructor
  · intro earlier middle later observed ingress received receiveClass egress sent sendClass split data
      input inputMember output outputMember inputName outputName sameDevice component
    have firstRun : (protectionLayerSystem payload).MTr []
        (earlier ++ .receive observed ingress received receiveClass ::
          (middle ++ .transmit observed egress sent sendClass :: later)) finalLayers := by
      simpa only [split, List.append_assoc, List.singleton_append, List.cons_append, List.nil_append] using run
    have observedSame := receive_event_has_trace_payload firstRun
    subst observed
    have segment := receive_to_transmit_layer_run (by simpa only [split] using run)
    have receiveMember : .receive payload ingress received receiveClass ∈ events := by rw [split]; simp
    have sendMember : .transmit payload egress sent sendClass ∈ events := by rw [split]; simp
    have receiveShape := shapes _ receiveMember data input inputMember inputName component
    have outputComponent : d.IsLayer output.device layer := sameDevice ▸ component
    have sendShape := shapes _ sendMember data output outputMember outputName outputComponent
    constructor
    · intro inside outside
      obtain ⟨tunnel, member, selectedLayer, sender, present⟩ := sendShape.2 outside
      exact ⟨tunnel, member, selectedLayer, sender.trans sameDevice.symm, present,
        event_layers_addition_has_encrypt segment (receiveShape inside tunnel member selectedLayer) present⟩
    · intro outside inside
      apply external_receive_before_transmit_has_decrypt (by simpa only [split] using gate)
      rw [← inputName]
      exact targets payload data input inputMember component outside
  · intro earlier later observed iface layers trafficClass split data interface member name component external
    have splitRun : (protectionLayerSystem payload).MTr []
        (earlier ++ .transmit observed iface layers trafficClass :: later) finalLayers := by
      simpa only [split, List.append_assoc, List.singleton_append, List.cons_append, List.nil_append] using run
    have observedSame := transmit_event_has_trace_payload splitRun
    subst observed
    have present : .transmit payload iface layers trafficClass ∈ events := by rw [split]; simp
    have shape := shapes _ present data interface member name component
    have different : interface.zone ≠ InternalZone layer := by
      rw [external]
      cases layer <;> decide
    obtain ⟨tunnel, tunnelMember, selectedLayer, sender, encryptedLayer⟩ := shape.2 different
    obtain ⟨before, after, leading, step, trailing⟩ := event_trace_split _ splitRun
    have layerShape := protection_layer_transmit_shape step
    have initialRun : (protectionLayerSystem payload).MTr [] earlier layers := by
      simpa only [layerShape.2.1] using leading
    exact ⟨tunnel, tunnelMember, selectedLayer, sender, encryptedLayer,
      event_layers_addition_has_encrypt initialRun (by simp) encryptedLayer⟩

structure LayerOutboundLocalChecks {S A : Type} (d : Deployment)
    (model : ForwardingModel S A) (layer : Layer) where
  safe : S → Prop
  initial : ∀ start, model.initial start → safe start
  preserved : ∀ before action after, model.system.Tr before action after → safe before → safe after
  events : ∀ before action after, model.system.Tr before action after → safe before →
    ∀ event ∈ model.events action, LayerOutboundEventShape d model.GenuineControl layer event

lemma forwarding_has_outbound_boundary_shapes {S A : Type} (d : Deployment)
    (model : ForwardingModel S A) (layer : Layer) (checks : LayerOutboundLocalChecks d model layer)
    {start finish : S} {actions : List A} (run : model.system.MTr start actions finish)
    (safe : checks.safe start) :
    ∀ event ∈ actions.flatMap model.events, LayerOutboundEventShape d model.GenuineControl layer event := by
  induction run with
  | refl => simp
  | @stepL before action after rest finish step tail ih =>
    intro event member
    rcases List.mem_append.mp member with first | later
    · exact checks.events before action after step safe event first
    · exact ih (checks.preserved before action after step safe) event later

lemma setup_history_has_outbound_boundary_shapes (d : Deployment) (history : ObservedHistory)
    (valid : history.Valid) (genuineControl : PayloadId → Prop) (layer : Layer) :
    ∀ event ∈ history.Events, LayerOutboundEventShape d genuineControl layer event := by
  intro event member
  obtain ⟨record, stored, same⟩ := List.mem_map.mp member
  have setup := (valid.2.1 record stored).2.2.2.2
  rw [← same]
  rcases record with ⟨source, observer, localPosition, component, position, epoch, session, recorded⟩
  cases recorded <;> simp_all [HistoricalEvent.SetupOnly, LayerOutboundEventShape]

theorem inner_tunnel_no_bypass_from_outbound_and_inbound_checks {S A : Type} (d : Deployment)
    (model : ForwardingModel S A) (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool)
    (target : PayloadId → String → Option String)
    (covered : model.CoversDeployment { d with focus := none })
    (outbound : LayerOutboundLocalChecks { d with focus := none } model .inner)
    (inbound : DeviceInboundGateChecks model.native { d with focus := none } .inner target)
    (targets : InboundGateReceiversBound { d with focus := none } model.GenuineControl .inner target)
    (configurations : ComponentConfigurationCoverage { d with focus := none } .inner components)
    (parameters : ∀ component ∈ components, ({ d with focus := none } : Deployment).Relevant component.id →
      (component.mechanism = .ipsec → component.espTunnelMode = true ∧ component.associatedIPTunnel = true) ∧
      (outboundMACObjective = true → component.outboundMACPolicy = true) ∧
      (inboundMACObjective = true → component.inboundMACPolicy = true)) :
    msc_inner_tunnel_no_bypass d model components outboundMACObjective inboundMACObjective := by
  refine ⟨configurations, ⟨covered, ?_⟩, parameters⟩
  intro start actions finish initial run
  obtain ⟨next, gate⟩ := deployment_events_follow_inbound_gate model _ .inner target covered inbound initial run
  apply layer_events_have_no_bypass_with_inbound_gate _ .inner model.GenuineControl target
    (deployment_events_follow_layers model _ covered initial run) gate targets
  intro event member
  rcases List.mem_append.mp member with setup | forwarding
  · exact setup_history_has_outbound_boundary_shapes _ model.history covered.2.2.2.2.1 _ .inner event setup
  · exact forwarding_has_outbound_boundary_shapes _ model .inner outbound run
      (outbound.initial start initial) event forwarding

end TDN.Requirements.Msc
