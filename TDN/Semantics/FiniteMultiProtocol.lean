import TDN.Semantics.MultiProtocolInvariant
import TDN.Semantics.FiniteRoutedExecution

namespace TDN.MultiProtocolExecution
open LayeredFrame

def finiteConfig (devices : List Execution.DeviceData) (ports : List Execution.PortData)
    (routes : List Execution.Route) (links bridges : List (Nat × Nat))
    (macPorts : List MACPort) (carriers : List CarrierPort) : Config :=
  { ip := Execution.finiteConfig devices ports routes links [],
    macPorts := macPorts, carriers := carriers,
    bridge := fun a b => (a, b) ∈ bridges, physicalLink := fun a b => (a, b) ∈ links }

def MACTransmitCheck (ports : List Execution.PortData) (port : MACPort) : Prop :=
  match port.transmitAssociation with
  | none => True
  | some association =>
      association.tag :: (Execution.portAt ports port.logicalPort).stack =
        (Execution.portAt ports port.physicalPort).stack

def CarrierRouteChecks (devices : List Execution.DeviceData) (ports : List Execution.PortData)
    (routes : List Execution.Route) (carriers : List CarrierPort) : Prop :=
  ∀ carrier ∈ carriers, ∀ route ∈ routes, route.ingress = carrier.routingPort →
    route.low ≤ (carrierHeader carrier).destination →
    (carrierHeader carrier).destination ≤ route.high →
    let selected := Execution.selectedAssociations
      (Execution.deviceAt devices (Execution.portAt ports route.egress).owner).outbound
        (carrierHeader carrier)
    (selected = [] → (Execution.portAt ports carrier.routingPort).stack =
      (Execution.portAt ports route.egress).stack) ∧
    (∀ policy ∈ selected, policy.tag :: (Execution.portAt ports carrier.routingPort).stack =
      (Execution.portAt ports route.egress).stack)

instance (ports : List Execution.PortData) (port : MACPort) :
    Decidable (MACTransmitCheck ports port) := by
  unfold MACTransmitCheck
  split <;> infer_instance

instance (devices : List Execution.DeviceData) (ports : List Execution.PortData)
    (routes : List Execution.Route) (carriers : List CarrierPort) :
    Decidable (CarrierRouteChecks devices ports routes carriers) := by
  unfold CarrierRouteChecks
  infer_instance

instance (sender receiver : CarrierPort) : Decidable (CarrierPeers sender receiver) := by
  unfold CarrierPeers
  infer_instance

theorem local_conditions_from_finite_checks (devices : List Execution.DeviceData)
    (ports : List Execution.PortData) (routes : List Execution.Route)
    (links bridges : List (Nat × Nat)) (macPorts : List MACPort) (carriers : List CarrierPort)
    (ipChecks : Execution.LocalStackConditions
      (Execution.finiteConfig devices ports routes links []) (Execution.finiteLayout ports))
    (linkChecks : ∀ edge ∈ links,
      (Execution.portAt ports edge.1).stack = (Execution.portAt ports edge.2).stack)
    (bridgeChecks : ∀ edge ∈ bridges,
      (Execution.portAt ports edge.1).stack = (Execution.portAt ports edge.2).stack)
    (macTransmitChecks : ∀ port ∈ macPorts, MACTransmitCheck ports port)
    (macReceiveChecks : ∀ port ∈ macPorts, ∀ association ∈ port.receiveAssociations,
      association.tag :: (Execution.portAt ports port.logicalPort).stack =
        (Execution.portAt ports port.physicalPort).stack)
    (macRoleChecks : ∀ sender ∈ macPorts, ∀ transmitted,
      sender.transmitAssociation = some transmitted → ∀ receiver ∈ macPorts,
      ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
      transmitted.tag = association.tag)
    (macSecureChecks : ∀ port ∈ macPorts,
      port.settings.protectFrames = true ∧ port.settings.encryptFrames = true ∧
      port.settings.confidentialityOffset = 0 ∧ port.validateStrict = true)
    (carrierOutputChecks : ∀ carrier ∈ carriers,
      (Execution.portAt ports carrier.virtualPort).stack =
        (Execution.portAt ports carrier.routingPort).stack)
    (carrierRoutes : CarrierRouteChecks devices ports routes carriers)
    (carrierPeerChecks : ∀ sender ∈ carriers, ∀ receiver ∈ carriers,
      CarrierPeers sender receiver →
        (Execution.portAt ports sender.virtualPort).stack =
          (Execution.portAt ports receiver.virtualPort).stack) :
    LocalConditions (finiteConfig devices ports routes links bridges macPorts carriers)
      (Execution.finiteLayout ports) := by
  refine ⟨ipChecks, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact fun a b member => linkChecks (a,b) member
  · exact fun a b member => bridgeChecks (a,b) member
  · intro port member association installed
    have checked := macTransmitChecks port member
    simpa only [MACTransmitCheck, installed, Execution.finiteLayout] using checked
  · exact macReceiveChecks
  · exact macRoleChecks
  · exact macSecureChecks
  · exact carrierOutputChecks
  · intro carrier member route chosen ingress
    exact carrierRoutes carrier member route chosen.1 ingress chosen.2.1.1 chosen.2.1.2
  · exact carrierPeerChecks

end TDN.MultiProtocolExecution
