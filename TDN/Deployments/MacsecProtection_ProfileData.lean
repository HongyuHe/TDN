import TDN.Requirements.VerifiedMacsecProtectionParameters
import TDN.Requirements.MacsecDeviceModelCoverage
import TDN.Requirements.DeviceRoutingAndFirewallRecords
import TDN.Models.TableDrivenMultiProtocolDataPlane
import TDN.Import.SnapshotLoader

namespace TDN.Deployments.MacsecProtection
open Compliance Requirements Requirements.Msc StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

deriving instance DecidableEq for Device
deriving instance DecidableEq for Tunnel

structure ObservedParameters where
  device : String
  dataDelayProtectionLogged : Bool
  lifetimeMilliseconds : Nat
  normalHelloMilliseconds : Nat
  activeHelloMilliseconds : Nat
  replayWindow : Nat
  replayProtection : Bool
  confidentialityOffset : Nat
  protectFrames : Bool
  encryptFrames : Bool
  controlledPortEnabled : Bool
  receiveValidation : String
  secured : Bool
  sci : String
  transmitAssociationNumber : Nat
  instrumentedBuild : Bool
  daemonSha256 : String
  sourceObservations : List String
  configuredMacsecPolicy : Option Nat
  configuredIntegrityOnly : Option Nat
  publicConfiguration : Option String

load_network_records observedParameters : List ObservedParameters from
  "../../data/evidence/macsecProtection/MkaParametersLive.json" ["parameters"]

def ObservedParameters.parameter (record : ObservedParameters) : MACsecParameters :=
  { device := record.device
    dataDelayProtection := record.dataDelayProtectionLogged
    lifetimeMilliseconds := record.lifetimeMilliseconds
    normalHelloMilliseconds := record.normalHelloMilliseconds
    activeHelloMilliseconds := record.activeHelloMilliseconds
    replayWindow := record.replayWindow
    feasibleReplayWindow := fun _ => True
    confidentialityOffset := record.confidentialityOffset
    mustSecure := record.protectFrames && record.encryptFrames }

def parameters : List MACsecParameters := observedParameters.map ObservedParameters.parameter

structure ProfileRecords where
  ownerNames : List String
  deviceData : List DataPlaneForwarding.DeviceData
  ifaceData : List DataPlaneForwarding.IfaceData
  devices : List Device
  interfaces : List Interface
  routes : List DataPlaneForwarding.FibRoute
  links : List (Nat × Nat)
  macIfaces : List MACIface
  mkaPeers : List PacketProcessing.MKAEndpoint
  tunnels : List Tunnel
  macFrames : List (MACsecAssociation × LinkAdmission.Frame)
  sourceIfaces : List Nat
  sourceAddresses : List Nat
  networks : List RedNetworkIdentity

load_network_records direct : ProfileRecords from
  "../../data/evidence/macsecProtection/MacsecProtectionProfiles.json" ["direct"]
load_network_records routed : ProfileRecords from
  "../../data/evidence/macsecProtection/MacsecProtectionProfiles.json" ["routed"]

def ProfileRecords.ifaceName (records : ProfileRecords) (iface : Nat) : String :=
  (DataPlaneForwarding.ifaceAt records.ifaceData iface).name

def ProfileRecords.componentName (records : ProfileRecords) (owner : Nat) : String :=
  records.ownerNames[owner]?.getD "unlisted-owner"

def ProfileRecords.ifaceIndex (records : ProfileRecords) (interface : Interface) : Nat :=
  (records.ifaceData.findIdx? (fun iface => iface.name == interface.id)).getD 0

def ProfileRecords.macsecTunnel (records : ProfileRecords) (association : MACsecAssociation) : String :=
  if association.keyGeneration = 1 then records.tunnels[0]?.map Tunnel.id |>.getD "unlisted-tunnel"
  else records.tunnels[1]?.map Tunnel.id |>.getD "unlisted-tunnel"

def ProfileRecords.sourceEntry (records : ProfileRecords) (iface : Nat) : Option String :=
  if iface = records.sourceIfaces[0]?.getD 0 then some "red-0"
  else if iface = records.sourceIfaces[1]?.getD 0 then some "red-1"
  else none

def ProfileRecords.configuration (records : ProfileRecords) : Config :=
  let base := dataPlaneModelFromRecords records.deviceData records.ifaceData records.routes
    records.links [] records.macIfaces []
  { base with
    ip := { base.ip with
      egressPolicies := fun _ => [], ingressPolicies := fun _ => [],
      egressSAs := fun _ => [], ingressSAs := fun _ => [],
      localAddress := fun iface address =>
      ∃ interface ∈ records.interfaces,
        interface.device = records.componentName (base.ip.owner iface) ∧ interface.HasLocalAddress address }
    headerProcessing := some ⟨fun _ => 64, fun _ => 64⟩
    linkPolicies := records.macIfaces.map (fun iface =>
      (iface.physicalIface, ⟨⟨[], .allow⟩, ⟨[], .allow⟩⟩))
    linkEncoding := fun _ frame => match frame.body with
      | .macsec association _ => (records.macFrames.find? (fun entry => entry.1 == association)).map Prod.snd
      | _ => none }

def ProfileRecords.inventory (records : ProfileRecords) : PacketProcessing.Inventory :=
  { ifaces := List.range records.ifaceData.length
    configuration := records.configuration
    ifaceName := records.ifaceName
    componentName := records.componentName
    mkaPeers := records.mkaPeers
    macsecTunnel := records.macsecTunnel }

def ProfileRecords.prototype (records : ProfileRecords) :
    DeviceExecutionBinding MultiProtocolForwarding.State MultiProtocolForwarding.Action :=
  { configuration := records.configuration
    state := id
    action := some
    ifaceName := records.ifaceName
    ipsecTunnel := fun _ => "no-IPsec"
    ipsecEpoch := none
    ipsecInstallations := []
    ipsecKeyMaterial := fun _ => none
    macsecTunnel := records.macsecTunnel
    macsecKeyMaterial := fun association => some (List.replicate 16 (UInt8.ofNat association.keyGeneration))
    componentName := records.componentName
    sourceEntry := records.sourceEntry
    sourceProcessing := PacketSource.sourceProcessing (fun _ => 1500)
    keyName := fun generation => "model-key-" ++ toString generation
    domainName := fun domain => if domain = 0 then "red-0" else "red-1"
    origin := fun domain => .red (if domain = 0 then "red-0" else "red-1") }

def ProfileRecords.deployment (records : ProfileRecords) : Deployment :=
  { processing := some records.inventory
    devices := records.devices
    interfaces := records.interfaces
    tunnels := records.tunnels
    networks := records.networks
    centralManagementSite := none
    networkAttachment := fun _ _ _ => False
    policies := nativePolicies records.inventory records.interfaces records.ifaceIndex
    physicalLink := fun first second =>
      ∃ edge ∈ records.links, records.ifaceName edge.1 = first ∧ records.ifaceName edge.2 = second
    storedVPNKey := fun _ _ => False
    certificateAuthenticated := fun _ => false
    preSharedCAKAuthenticated := fun _ => true
    keyManagementCA := fun _ _ => False
    keyManagementGenerator := fun _ _ => False
    innerUsesOuter := fun _ _ => False
    intendedPeer := fun source destination =>
      ∃ tunnel ∈ records.tunnels, tunnel.sender = source ∧ tunnel.receiver = destination
    policyApproved := fun _ _ => False
    aoApproved := fun _ _ => False
    reachableSource := fun _ _ => False
    redService := fun _ _ _ => False
    grayManagementService := fun _ _ => False
    grayWorkstation := fun _ => False
    standaloneEncapsulator := fun _ => False
    authority := ⟨fun _ => False, fun _ => False, fun _ => False,
      fun _ => False, fun _ => False, fun _ => False, fun _ => False⟩ }

def ProfileRecords.model (records : ProfileRecords) :=
  StandardDataPlaneBridge.model records.prototype (List.range records.ifaceData.length)
    records.deployment {}

end TDN.Deployments.MacsecProtection
