import TDN.Deployments.NestedProtection_Mixed
import TDN.Requirements.DeviceForwardingTraceCoverage

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

deriving instance DecidableEq for Body

structure ProtectionMove where
  operation : MultiProtocolForwarding.Action
  index : Nat
  saIndex : Nat
  macIndex : Nat
  rxIndex : Nat
  domain : Nat
  sourceIndex : Nat

structure ProtectionPath where
  sourceFlow : SourceFlow
  moves : List ProtectionMove
  destinationIface : Nat
  destinationDomain : Nat
  destinationNetwork : String

load_network_records protectionPaths : List ProtectionPath from "../../data/evidence/nestedProtection/MixedDeliveryPlans.json" ["plans"]

def ProtectionPath.datagram (path : ProtectionPath) : PacketSource.Datagram :=
  let datagrams := match PacketSource.processSource (records.sourceMtu path.sourceFlow.iface) path.sourceFlow.request with
    | .emitted datagrams => datagrams
    | .error _ => []
  datagrams.headD ⟨path.sourceFlow.request.body, [], [], [], []⟩

def ProtectionPath.start (path : ProtectionPath) : MultiProtocolForwarding.State :=
  deviceBinding.SourceState path.sourceFlow.request path.datagram

def ProtectionMove.installation (move : ProtectionMove) : PublicSARecord :=
  records.installations[move.saIndex]?.getD (records.installations.head (by native_decide))

def ProtectionMove.sourceInstallation (move : ProtectionMove) : PublicSARecord :=
  records.installations[move.sourceIndex]?.getD (records.installations.head (by native_decide))

def ProtectionMove.macIface (move : ProtectionMove) : MACIface :=
  records.macIfaces[move.macIndex]?.getD (records.macIfaces.head (by native_decide))

def ProtectionMove.transmitted (move : ProtectionMove) : MACsecAssociation :=
  move.macIface.transmitAssociation.getD ⟨0,0,0,0⟩

def ProtectionMove.receiveAssociation (move : ProtectionMove) : MACsecAssociation :=
  move.macIface.receiveAssociations[move.rxIndex]?.getD ⟨0,0,0,0⟩

def ProtectionMove.route (move : ProtectionMove) : DataPlaneForwarding.FibRoute :=
  records.routes[move.index]?.getD (records.routes.head (by native_decide))

def currentHeader (before : MultiProtocolForwarding.State) : PacketPolicy.Packet :=
  (configuration.visibleHeader before.frame).getD
    { source := 0, destination := 0, protocol := "", ingress := "", egress := "",
      sourcePort := 0, destinationPort := 0, ipv4HeaderWords := 0,
      matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "" }

def currentPolicy (before : MultiProtocolForwarding.State) (inbound : Bool) : DataPlaneForwarding.IpsecPolicy :=
  ((if inbound then configuration.ip.ingressPolicies else configuration.ip.egressPolicies) before.iface).headD
    { id := 0, priority := 0, sourceLow := 0, sourceHigh := 0, destinationLow := 0,
      destinationHigh := 0, sender := 0, receiver := 0, tag := 0, requiredSpi := none }

def bodyContents (body : Body) : Body :=
  match body with
  | .ipsec _ contents | .macsec _ contents => contents
  | _ => body

def ProtectionMove.after (move : ProtectionMove) (before : MultiProtocolForwarding.State) : MultiProtocolForwarding.State :=
  match move.operation with
  | .receive => { before with initialEntry := false, datapathStage := .ingress, enteredIface := before.iface, authenticated := [], tracking := "new" }
  | .route => if before.datapathStage = .encapsulated then
      { before with initialEntry := false, iface := move.route.egress, datapathStage := .egressReady }
    else { before with initialEntry := false, iface := move.route.egress, datapathStage := .routed, frame := configuration.forwardedFrame before.frame }
  | .forwardFilter => { before with initialEntry := false, datapathStage := .filtered }
  | .forwardWithoutEncap => { before with initialEntry := false, datapathStage := .egressReady }
  | .encryptIPsec => { before with initialEntry := false, datapathStage := .encapsulated, frame := configuration.ipsecFrame before.iface before.frame ((currentPolicy before false).seal (move.installation.installation.association)) }
  | .decryptIPsec => { before with initialEntry := false, datapathStage := .ingress, enteredIface := before.iface, frame := configuration.restoredFrame before.frame (bodyContents before.frame.body), authenticated := [(currentPolicy before true).id], tracking := "new" }
  | .encryptMACsec => { before with initialEntry := false, iface := move.macIface.physicalIface, frame := configuration.macsecFrame before.frame move.transmitted }
  | .decryptMACsec => { before with initialEntry := false, iface := move.macIface.logicalIface, frame := configuration.restoredFrame before.frame (bodyContents before.frame.body), authenticated := [] }
  | .linkTransmit => { before with initialEntry := false, iface := move.index, datapathStage := .received, authenticated := [] }
  | .bridge => { before with initialEntry := false, iface := move.index, datapathStage := .egressReady }
  | .inputFilter => { before with initialEntry := false, datapathStage := .localInput }
  | .deliver => { before with initialEntry := false, datapathStage := .delivered }
  | _ => before

def ProtectionPath.state (path : ProtectionPath) (index : Nat) : MultiProtocolForwarding.State :=
  (path.moves.take index).foldl (fun state move => move.after state) path.start

def samplePath (index : Nat) : ProtectionPath :=
  protectionPaths[index]?.getD (protectionPaths.head (by native_decide))

def sampleMove (path step : Nat) : ProtectionMove :=
  (samplePath path).moves[step]?.getD ⟨.drop,0,0,0,0,0,0⟩

lemma namespace_address_records_checked :
    NamespaceAddressChecks records.interfaces records.componentName records.deviceData := by native_decide

lemma imported_local_addresses_are_unchanged (iface address : Nat)
    (present : configuration.ip.owner iface < records.deviceData.length) :
    configuration.ip.localAddress iface address ↔
      address ∈ (DataPlaneForwarding.deviceAt records.deviceData (configuration.ip.owner iface)).localAddresses :=
  namespace_local_addresses_exact records.interfaces records.componentName records.deviceData
    namespace_address_records_checked _ present address

end TDN.Deployments.NestedProtection_Mixed
