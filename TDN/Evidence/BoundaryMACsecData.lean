import TDN.Targets.MACsecWireTrace
import TDN.Targets.PhysicalFrameChecks
import TDN.Targets.MACsecBoundaryPolicy
import TDN.Semantics.FiniteMultiProtocol
import TDN.Import.Command

namespace TDN.Imported.BoundaryMACsec
open Compliance Targets Targets.Complete MultiProtocolExecution

structure Records where
  interfaces : List Interface
  sender : Interface
  receiver : Interface
  ownerNames : List String
  nativeDevices : List Execution.DeviceData
  nativeIfaces : List Execution.IfaceData
  routes : List Execution.Route
  links : List (Nat × Nat)
  macIfaces : List MACIface
  linkPolicies : List (Nat × LinkAdmission.IfacePolicy)
  sourceCase : RoutedMACsecCase
  sourceFrame : LinkAdmission.Frame
  logicalFrame : LinkAdmission.Frame
  physicalFrame : LinkAdmission.Frame
  sourceNetwork : List UInt8
  sourceTransport : List UInt8
  logicalNetwork : List UInt8
  logicalTransport : List UInt8

tdn_data protectedCase : Records from "../../data/evidence/continuation/BoundaryMACsec.json" ["protected"]
tdn_data unprotectedAllowed : Records from "../../data/evidence/continuation/BoundaryMACsec.json" ["unprotectedAllowed"]
tdn_data unprotectedDenied : Records from "../../data/evidence/continuation/BoundaryMACsec.json" ["unprotectedDenied"]

def Records.ifaceName (records : Records) (iface : Nat) : String :=
  (Execution.ifaceAt records.nativeIfaces iface).name

def Records.componentName (records : Records) (owner : Nat) : String :=
  records.ownerNames[owner]?.getD "unlisted-owner"

def Records.configuration (records : Records) : Config :=
  { dataPlaneConfigFromRecords records.nativeDevices records.nativeIfaces records.routes records.links [] records.macIfaces [] with
    headerProcessing := some ⟨fun _ => 64, fun _ => 64⟩
    linkPolicies := records.linkPolicies
    linkEncoding := fun iface _ =>
      if iface ∈ records.macIfaces.map MACIface.physicalIface then some records.physicalFrame else none }

def Records.inventory (records : Records) : PacketProcessing.Inventory :=
  { ifaces := List.range records.nativeIfaces.length
    configuration := records.configuration
    ifaceName := records.ifaceName
    componentName := records.componentName
    mkaPeers := []
    ipsecSizes := []
    macsecTunnel := fun _ => "static-SA-boundary-experiment" }

def devices : List Device :=
  [⟨"R", "source", .other, none, ⟨"test", {}, {}, {}⟩, false⟩,
   ⟨"A", "sender", .macsec, some .outer, ⟨"test", {}, {}, {}⟩, true⟩,
   ⟨"B", "receiver", .macsec, some .outer, ⟨"test", {}, {}, {}⟩, true⟩]

def Records.deployment (records : Records) (base : Deployment) : Deployment :=
  { base with
    processing := some records.inventory
    devices := devices
    interfaces := records.interfaces
    policies := []
    focus := none
    services := []
    managementServices := []
    managementExchanges := []
    managementHistory := []
    udpBindings := []
    carrierBindings := []
    policyApproved := fun _ _ => False
    aoApproved := fun _ _ => False
    intendedPeer := fun source destination => (source, destination) ∈ [("A", "B"), ("B", "A")]
    grayWorkstation := fun _ => False }

def Records.physicalReady (records : Records) : MultiProtocolExecution.State :=
  let ready := records.sourceCase.ready records.configuration
  { ready with
    initialEntry := false
    iface := records.sourceCase.mac.physicalIface
    frame := if records.sourceCase.mac.settings.protectFrames then
      records.configuration.macsecFrame ready.frame
        (records.sourceCase.mac.transmitAssociation.getD ⟨0, 0, 0, 0⟩)
      else ready.frame }

def Records.wired (records : Records) : MultiProtocolExecution.State :=
  { records.physicalReady with
    initialEntry := false
    iface := records.sourceCase.peerIface
    datapathStage := .received
    authenticated := [] }

def Records.packet (records : Records) (direction : Direction) : PacketPolicy.Packet :=
  PhysicalBoundaryPacket records.configuration
    (if direction = .outbound then records.sourceCase.mac.physicalIface else records.sourceCase.peerIface)
    direction records.physicalFrame

end TDN.Imported.BoundaryMACsec
