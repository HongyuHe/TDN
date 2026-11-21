import TDN.Models.MultiProtocolForwarding
import TDN.Models.MultiStepTraceBridge

namespace TDN.IpsecEgress
open DataPlaneForwarding LayeredFrame MultiProtocolForwarding

def body (header : PacketPolicy.Packet) : List EncapHeaderLayer → Body
  | [] => .datagram header
  | layer :: rest => .ipsec layer.authentication (body layer.header rest)

def asTunnelState (s : ForwardingState) : TunnelForwardingState where
  iface := s.iface
  datapathStage := s.datapathStage
  frame := {
    payload := s.frame.payload
    originDomain := s.frame.originDomain
    body := body s.frame.packet s.frame.encapLayers
    activeHeader := some s.frame.packet
    hiddenHeaders := s.frame.encapLayers.map fun layer => some layer.header }
  enteredIface := s.frame.enteredIface
  tracking := s.frame.packet.connectionState
  authenticated := s.authenticated

inductive EgressAction where
  | route | transmit

def EgressAction.tunnel : EgressAction → TunnelForwardingAction
  | .route => .route
  | .transmit => .linkTransmit

def segment (ip : DataPlaneModel) : Cslib.LTS ForwardingState EgressAction where
  Tr s a t := s.frame.encapLayers ≠ [] ∧ match a with
    | .route => s.datapathStage = .encapsulated ∧ ForwardingStep ip s .route t
    | .transmit => ForwardingStep ip s .linkTransmit t

lemma visible_ip_header (model : TunnelForwardingModel) (processing : HeaderProcessing)
    (headers : model.headerProcessing = some processing) (s : ForwardingState) :
    model.visibleHeader (asTunnelState s).frame = some s.frame.packet := by
  cases layers : s.frame.encapLayers <;>
    simp [TunnelForwardingModel.visibleHeader, headers, TunnelFrame.visibleHeader, asTunnelState,
      layers, body, Body.visibleHeader]

lemma egress_step (model : TunnelForwardingModel) (processing : HeaderProcessing)
    (headers : model.headerProcessing = some processing)
    (links : ∀ a b, model.ip.link a b → model.physicalLink a b)
    {s t : ForwardingState} {a : EgressAction} (step : (segment model.ip).Tr s a t) :
    TunnelForwardingStep model (asTunnelState s) a.tunnel (asTunnelState t) := by
  obtain ⟨layers, operation⟩ := step
  cases a with
  | transmit =>
    cases operation with
    | linkTransmit linked => exact .linkTransmit _ rfl (links _ _ linked)
  | route =>
    obtain ⟨stage, route⟩ := operation
    cases route with
    | route => cases stage
    | routeLocalOutput => cases stage
    | routeOuterPacket r chosen entry =>
      exact TunnelForwardingStep.routeOuterPacket r rfl (visible_ip_header model processing headers _) chosen entry

theorem egress_trace (model : TunnelForwardingModel) (processing : HeaderProcessing)
    (headers : model.headerProcessing = some processing)
    (links : ∀ a b, model.ip.link a b → model.physicalLink a b)
    {s t : ForwardingState} {actions : List EgressAction} (run : (segment model.ip).MTr s actions t) :
    (MultiProtocolForwarding.lts model).MTr (asTunnelState s) (actions.map EgressAction.tunnel) (asTunnelState t) :=
  MultiStepTraceBridge.project_forwarding _ _ asTunnelState EgressAction.tunnel
    (fun _ _ _ step => egress_step model processing headers links step) run

end TDN.IpsecEgress
