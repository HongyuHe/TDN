import TDN.Models.MultiProtocolEncapPreservation
import TDN.Models.RouteAwareAclChecks

namespace TDN.MultiProtocolForwarding
open LayeredFrame

def dataPlaneModelFromRecords (devices : List DataPlaneForwarding.DeviceData) (ifaces : List DataPlaneForwarding.IfaceData)
    (routes : List DataPlaneForwarding.FibRoute) (links bridges : List (Nat × Nat))
    (macIfaces : List MACIface) (carriers : List CarrierIface) : Config :=
  { ip := DataPlaneForwarding.dataPlaneModelFromRecords devices ifaces routes links [],
    macIfaces := macIfaces, carriers := carriers,
    bridge := fun a b => (a, b) ∈ bridges, physicalLink := fun a b => (a, b) ∈ links }

def MACTransmitCheck (ifaces : List DataPlaneForwarding.IfaceData) (iface : MACIface) : Prop :=
  match iface.transmitAssociation with
  | none => True
  | some association =>
      association.tag :: (DataPlaneForwarding.ifaceAt ifaces iface.logicalIface).stack =
        (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).stack

def CarrierRouteChecks (devices : List DataPlaneForwarding.DeviceData) (ifaces : List DataPlaneForwarding.IfaceData)
    (routes : List DataPlaneForwarding.FibRoute) (carriers : List CarrierIface) : Prop :=
  ∀ carrier ∈ carriers, ∀ route ∈ routes, route.ingress = carrier.routingIface →
    route.destPrefixLow ≤ (carrierHeader carrier).destination →
    (carrierHeader carrier).destination ≤ route.destPrefixHigh →
    let selected := DataPlaneForwarding.lookupSpdPolicies
      (DataPlaneForwarding.deviceAt devices (DataPlaneForwarding.ifaceAt ifaces route.egress).owner).egressPolicies
        (carrierHeader carrier)
    (selected = [] → (DataPlaneForwarding.ifaceAt ifaces carrier.routingIface).stack =
      (DataPlaneForwarding.ifaceAt ifaces route.egress).stack) ∧
    (∀ policy ∈ selected, policy.tag :: (DataPlaneForwarding.ifaceAt ifaces carrier.routingIface).stack =
      (DataPlaneForwarding.ifaceAt ifaces route.egress).stack)

instance (ifaces : List DataPlaneForwarding.IfaceData) (iface : MACIface) :
    Decidable (MACTransmitCheck ifaces iface) := by
  unfold MACTransmitCheck
  split <;> infer_instance

instance (devices : List DataPlaneForwarding.DeviceData) (ifaces : List DataPlaneForwarding.IfaceData)
    (routes : List DataPlaneForwarding.FibRoute) (carriers : List CarrierIface) :
    Decidable (CarrierRouteChecks devices ifaces routes carriers) := by
  unfold CarrierRouteChecks
  infer_instance

instance (sender receiver : CarrierIface) : Decidable (CarrierPeers sender receiver) := by
  unfold CarrierPeers
  infer_instance

theorem local_conditions_from_finite_checks (devices : List DataPlaneForwarding.DeviceData)
    (ifaces : List DataPlaneForwarding.IfaceData) (routes : List DataPlaneForwarding.FibRoute)
    (links bridges : List (Nat × Nat)) (macIfaces : List MACIface) (carriers : List CarrierIface)
    (ipChecks : DataPlaneForwarding.PerHopEncapConditions
      (DataPlaneForwarding.dataPlaneModelFromRecords devices ifaces routes links []) (DataPlaneForwarding.expectedEncapStackFromRecords ifaces))
    (linkChecks : ∀ edge ∈ links,
      (DataPlaneForwarding.ifaceAt ifaces edge.1).stack = (DataPlaneForwarding.ifaceAt ifaces edge.2).stack)
    (bridgeChecks : ∀ edge ∈ bridges,
      (DataPlaneForwarding.ifaceAt ifaces edge.1).stack = (DataPlaneForwarding.ifaceAt ifaces edge.2).stack)
    (macTransmitChecks : ∀ iface ∈ macIfaces, MACTransmitCheck ifaces iface)
    (macReceiveChecks : ∀ iface ∈ macIfaces, ∀ association ∈ iface.receiveAssociations,
      association.tag :: (DataPlaneForwarding.ifaceAt ifaces iface.logicalIface).stack =
        (DataPlaneForwarding.ifaceAt ifaces iface.physicalIface).stack)
    (macRoleChecks : ∀ sender ∈ macIfaces, ∀ transmitted,
      sender.transmitAssociation = some transmitted → ∀ receiver ∈ macIfaces,
      ∀ association ∈ receiver.receiveAssociations, SameMACWireIdentity transmitted association →
      transmitted.tag = association.tag)
    (macSecureChecks : ∀ iface ∈ macIfaces,
      iface.settings.protectFrames = true ∧ iface.settings.encryptFrames = true ∧
      iface.settings.confidentialityOffset = 0 ∧ iface.validateStrict = true)
    (carrierOutputChecks : ∀ carrier ∈ carriers,
      (DataPlaneForwarding.ifaceAt ifaces carrier.virtualIface).stack =
        (DataPlaneForwarding.ifaceAt ifaces carrier.routingIface).stack)
    (carrierRoutes : CarrierRouteChecks devices ifaces routes carriers)
    (carrierPeerChecks : ∀ sender ∈ carriers, ∀ receiver ∈ carriers,
      CarrierPeers sender receiver →
        (DataPlaneForwarding.ifaceAt ifaces sender.virtualIface).stack =
          (DataPlaneForwarding.ifaceAt ifaces receiver.virtualIface).stack) :
    LocalConditions (dataPlaneModelFromRecords devices ifaces routes links bridges macIfaces carriers)
      (DataPlaneForwarding.expectedEncapStackFromRecords ifaces) := by
  refine ⟨rfl, ipChecks, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact fun a b member => linkChecks (a,b) member
  · exact fun a b member => bridgeChecks (a,b) member
  · intro iface member association installed
    have checked := macTransmitChecks iface member
    simpa only [MACTransmitCheck, installed, DataPlaneForwarding.expectedEncapStackFromRecords] using checked
  · exact macReceiveChecks
  · exact macRoleChecks
  · exact macSecureChecks
  · exact carrierOutputChecks
  · intro carrier member route chosen ingress
    exact carrierRoutes carrier member route chosen.1 ingress chosen.2.1.1 chosen.2.1.2
  · exact carrierPeerChecks

end TDN.MultiProtocolForwarding
