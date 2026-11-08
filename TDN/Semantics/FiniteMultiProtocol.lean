import TDN.Semantics.MultiProtocolInvariant
import TDN.Semantics.FiniteRoutedExecution

namespace TDN.MultiProtocolExecution
open LayeredFrame

def dataPlaneConfigFromRecords (devices : List Execution.DeviceData) (ifaces : List Execution.IfaceData)
    (routes : List Execution.Route) (links bridges : List (Nat × Nat))
    (macIfaces : List MACIface) (carriers : List CarrierIface) : Config :=
  { ip := Execution.dataPlaneConfigFromRecords devices ifaces routes links [],
    macIfaces := macIfaces, carriers := carriers,
    bridge := fun a b => (a, b) ∈ bridges, physicalLink := fun a b => (a, b) ∈ links }

def MACTransmitCheck (ifaces : List Execution.IfaceData) (iface : MACIface) : Prop :=
  match iface.transmitAssociation with
  | none => True
  | some association =>
      association.tag :: (Execution.ifaceAt ifaces iface.logicalIface).stack =
        (Execution.ifaceAt ifaces iface.physicalIface).stack

def CarrierRouteChecks (devices : List Execution.DeviceData) (ifaces : List Execution.IfaceData)
    (routes : List Execution.Route) (carriers : List CarrierIface) : Prop :=
  ∀ carrier ∈ carriers, ∀ route ∈ routes, route.ingress = carrier.routingIface →
    route.low ≤ (carrierHeader carrier).destination →
    (carrierHeader carrier).destination ≤ route.high →
    let selected := Execution.selectedAssociations
      (Execution.deviceAt devices (Execution.ifaceAt ifaces route.egress).owner).outbound
        (carrierHeader carrier)
    (selected = [] → (Execution.ifaceAt ifaces carrier.routingIface).stack =
      (Execution.ifaceAt ifaces route.egress).stack) ∧
    (∀ policy ∈ selected, policy.tag :: (Execution.ifaceAt ifaces carrier.routingIface).stack =
      (Execution.ifaceAt ifaces route.egress).stack)

instance (ifaces : List Execution.IfaceData) (iface : MACIface) :
    Decidable (MACTransmitCheck ifaces iface) := by
  unfold MACTransmitCheck
  split <;> infer_instance

instance (devices : List Execution.DeviceData) (ifaces : List Execution.IfaceData)
    (routes : List Execution.Route) (carriers : List CarrierIface) :
    Decidable (CarrierRouteChecks devices ifaces routes carriers) := by
  unfold CarrierRouteChecks
  infer_instance

instance (sender receiver : CarrierIface) : Decidable (CarrierPeers sender receiver) := by
  unfold CarrierPeers
  infer_instance

theorem local_conditions_from_finite_checks (devices : List Execution.DeviceData)
    (ifaces : List Execution.IfaceData) (routes : List Execution.Route)
    (links bridges : List (Nat × Nat)) (macIfaces : List MACIface) (carriers : List CarrierIface)
    (ipChecks : Execution.LocalStackConditions
      (Execution.dataPlaneConfigFromRecords devices ifaces routes links []) (Execution.expectedEncapStackFromRecords ifaces))
    (linkChecks : ∀ edge ∈ links,
      (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack)
    (bridgeChecks : ∀ edge ∈ bridges,
      (Execution.ifaceAt ifaces edge.1).stack = (Execution.ifaceAt ifaces edge.2).stack)
    (macTransmitChecks : ∀ iface ∈ macIfaces, MACTransmitCheck ifaces iface)
    (macReceiveChecks : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
      association.tag :: (Execution.ifaceAt ifaces iface.logicalIface).stack =
        (Execution.ifaceAt ifaces iface.physicalIface).stack)
    (macRoleChecks : ∀ sender ∈ macIfaces, ∀ transmitted,
      sender.transmitAssociation = some transmitted → ∀ receiver ∈ macIfaces,
      ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
      transmitted.tag = association.tag)
    (macSecureChecks : ∀ iface ∈ macIfaces,
      iface.settings.protectFrames = true ∧ iface.settings.encryptFrames = true ∧
      iface.settings.confidentialityOffset = 0 ∧ iface.validateStrict = true)
    (carrierOutputChecks : ∀ carrier ∈ carriers,
      (Execution.ifaceAt ifaces carrier.virtualIface).stack =
        (Execution.ifaceAt ifaces carrier.routingIface).stack)
    (carrierRoutes : CarrierRouteChecks devices ifaces routes carriers)
    (carrierPeerChecks : ∀ sender ∈ carriers, ∀ receiver ∈ carriers,
      CarrierPeers sender receiver →
        (Execution.ifaceAt ifaces sender.virtualIface).stack =
          (Execution.ifaceAt ifaces receiver.virtualIface).stack) :
    LocalConditions (dataPlaneConfigFromRecords devices ifaces routes links bridges macIfaces carriers)
      (Execution.expectedEncapStackFromRecords ifaces) := by
  refine ⟨rfl, ipChecks, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact fun a b member => linkChecks (a,b) member
  · exact fun a b member => bridgeChecks (a,b) member
  · intro iface member association installed
    have checked := macTransmitChecks iface member
    simpa only [MACTransmitCheck, installed, Execution.expectedEncapStackFromRecords] using checked
  · exact macReceiveChecks
  · exact macRoleChecks
  · exact macSecureChecks
  · exact carrierOutputChecks
  · intro carrier member route chosen ingress
    exact carrierRoutes carrier member route chosen.1 ingress chosen.2.1.1 chosen.2.1.2
  · exact carrierPeerChecks

end TDN.MultiProtocolExecution
