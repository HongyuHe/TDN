import TDN.Deployments.MtuSizing_DeploymentCoverage
import TDN.Requirements.MixedNestedFlowEvents

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

deriving instance DecidableEq for Flow
deriving instance DecidableEq for MixedFlowEndpoints
deriving instance DecidableEq for Device
deriving instance DecidableEq for Tunnel

structure AuthenticationSetting where
  device : String
  certificateAuth : Bool
  pskAuth : Bool

structure BridgeRule where
  owner : Nat
  rule : PacketPolicy.Rule

structure Records where
  ownerNames : List String
  ifaceNames : List String
  deviceData : List DataPlaneForwarding.DeviceData
  ifaceData : List DataPlaneForwarding.IfaceData
  components : List Device
  interfaces : List Interface
  networks : List RedNetworkIdentity
  entries : List SourceEntry
  attachments : List RedNetworkAttachment
  sourceFlows : List SourceFlow
  routes : List DataPlaneForwarding.FibRoute
  links : List (Nat × Nat)
  bridges : List (Nat × Nat)
  macIfaces : List MACIface
  staticPeers : List PacketProcessing.MKAEndpoint
  ipsecSizes : List PacketProcessing.IPsecSizeBinding
  installations : List PublicSARecord
  epoch : String
  tunnels : List Tunnel
  ipsecTunnelBindings : List (DataPlaneForwarding.TunnelSAStamp × String)
  macsecTunnelBindings : List (MACsecAssociation × String)
  macMaterials : List (MACsecAssociation × String)
  macFrames : List (MACsecAssociation × LinkAdmission.Frame)
  linkPolicies : List (Nat × LinkAdmission.IfacePolicy)
  bridgeRules : List BridgeRule
  contexts : List MixedFlowEndpoints
  innerOuterUses : List (String × String)
  authentication : List AuthenticationSetting

load_network_records records : Records from "../../data/evidence/nestedProtection/MixedIPsecMACsec.json" ["records"]

def Records.ifaces (records : Records) : List Nat :=
  (List.range records.ifaceData.length).filter (· != 0)

def Records.ifaceName (records : Records) (iface : Nat) : String :=
  records.ifaceNames[iface]?.getD "unlisted-iface"

def Records.componentName (records : Records) (owner : Nat) : String :=
  records.ownerNames[owner]?.getD "unlisted-component"

def Records.ifaceIndex (records : Records) (interface : Interface) : Nat :=
  records.ifaceNames.idxOf interface.id

def Records.ipsecTunnel (records : Records) (association : DataPlaneForwarding.TunnelSAStamp) : String :=
  ((records.ipsecTunnelBindings.find? (fun entry => entry.1 == association)).map Prod.snd).getD "unlisted-IPsec-tunnel"

def Records.macsecTunnel (records : Records) (association : MACsecAssociation) : String :=
  ((records.macsecTunnelBindings.find? (fun entry => entry.1 == association)).map Prod.snd).getD "unlisted-MACsec-tunnel"

def Records.macsecKeyName (records : Records) (generation : Nat) : String :=
  "macsec:" ++ ((records.macMaterials.find? (fun entry => entry.1.keyGeneration == generation)).map Prod.snd).getD "unlisted-key"

def Records.redNetwork (records : Records) (domain : Nat) : String :=
  ((records.entries.find? (fun entry => entry.originDomain == domain)).map SourceEntry.network).getD ""

def Records.sourceMtu (records : Records) (iface : Nat) : Nat :=
  ((records.interfaces.find? (fun interface => interface.id == records.ifaceName iface)).bind Interface.mtu).getD 1500

def Records.configuration (records : Records) : Config :=
  let native := dataPlaneModelFromRecords records.deviceData records.ifaceData records.routes
    records.links records.bridges records.macIfaces []
  { native with
    ip := { native.ip with
      egressSAs := fun iface => directionalStates records.installations (native.ip.owner iface) .outbound
      ingressSAs := fun iface => directionalStates records.installations (native.ip.owner iface) .inbound
      localAddress := fun iface address => ∃ interface ∈ records.interfaces,
        interface.device = records.componentName (native.ip.owner iface) ∧ interface.HasLocalAddress address }
    headerProcessing := some ⟨fun _ => 64, fun _ => 64⟩
    linkPolicies := records.linkPolicies
    linkEncoding := fun _ frame => match frame.body with
      | .macsec association _ => (records.macFrames.find? (fun entry => entry.1 == association)).map Prod.snd
      | _ => none }

def Records.inventory (records : Records) : PacketProcessing.Inventory :=
  { ifaces := records.ifaces, configuration := records.configuration,
    ifaceName := records.ifaceName, componentName := records.componentName,
    mkaPeers := records.staticPeers, ipsecSizes := records.ipsecSizes,
    macsecTunnel := records.macsecTunnel }

def Records.ipsecMaterial (records : Records) (reference : String) : IPsecKeyMaterial :=
  let index := (records.installations.map PublicSARecord.materialReference).idxOf reference + 1
  { transform := capturedTransform, encryptionKey := List.replicate 32 (UInt8.ofNat index),
    salt := List.replicate 4 (UInt8.ofNat index), integrityKey := [] }

def Records.macsecMaterial (records : Records) (association : MACsecAssociation) : Option (List UInt8) :=
  (records.macMaterials.find? (fun entry => entry.1 == association)).map fun entry =>
    List.replicate 32 (UInt8.ofNat ((records.macMaterials.map Prod.snd).idxOf entry.2 + 1))

def Records.prototype (records : Records) : DeviceExecutionBinding Unit Unit :=
  { configuration := records.configuration
    state := fun _ => { iface := 0, datapathStage := .dropped, frame := { payload := 0, originDomain := 0, body := .ethernet ⟨0, 0, 0, []⟩ }, enteredIface := 0, authenticated := [], tracking := "" }
    action := fun _ => none
    ifaceName := records.ifaceName, componentName := records.componentName
    ipsecTunnel := records.ipsecTunnel, macsecTunnel := records.macsecTunnel
    ipsecEpoch := some records.epoch, ipsecInstallations := records.installations.map PublicSARecord.installation
    ipsecKeyMaterial := publicKeyMaterial records.installations records.ipsecMaterial
    macsecKeyMaterial := records.macsecMaterial
    sourceEntry := sourceEntry records.entries
    sourceProcessing := PacketSource.sourceProcessing records.sourceMtu
    keyName := records.macsecKeyName, domainName := records.redNetwork
    origin := fun domain => .red (records.redNetwork domain) }

def Records.deployment (records : Records) : Deployment :=
  { devices := records.components, interfaces := records.interfaces, tunnels := records.tunnels,
    networks := records.networks, redNetworkAttachments := records.attachments,
    processing := some records.inventory, centralManagementSite := none,
    networkAttachment := fun _ _ _ => False,
    policies := nativePolicies records.inventory records.interfaces records.ifaceIndex
    physicalLink := fun first last => ∃ edge ∈ records.links,
      records.ifaceName edge.1 = first ∧ records.ifaceName edge.2 = last
    storedVPNKey := fun _ _ => False
    certificateAuthenticated := fun component =>
      ((records.authentication.find? (fun setting => setting.device == component)).map AuthenticationSetting.certificateAuth).getD false
    preSharedCAKAuthenticated := fun component =>
      ((records.authentication.find? (fun setting => setting.device == component)).map AuthenticationSetting.pskAuth).getD false
    keyManagementCA := fun _ _ => False, keyManagementGenerator := fun _ _ => False
    innerUsesOuter := fun inner outer => (inner, outer) ∈ records.innerOuterUses
    intendedPeer := fun source destination =>
      ∃ tunnel ∈ records.tunnels, tunnel.sender = source ∧ tunnel.receiver = destination
    policyApproved := fun _ _ => False, aoApproved := fun _ _ => False
    reachableSource := fun _ _ => False, redService := fun _ _ _ => False
    grayManagementService := fun _ _ => False, grayWorkstation := fun _ => False
    standaloneEncapsulator := fun _ => False
    authority := ⟨fun _ => False, fun _ => False, fun _ => False, fun _ => False,
      fun _ => False, fun _ => False, fun _ => False⟩ }

abbrev configuration := records.configuration
abbrev deviceBinding := records.prototype
abbrev deployment := records.deployment
abbrev ifaces := records.ifaces
abbrev contexts := records.contexts

def flows : List Flow := contexts.map MixedFlowEndpoints.flow

def expectedEncapStack (iface : Nat) : List Nat :=
  (DataPlaneForwarding.ifaceAt records.ifaceData iface).stack

def contextFor (domain : Nat) : MixedFlowEndpoints :=
  (contexts.find? (fun selected => selected.originDomain == domain)).getD (contexts.head (by native_decide))

def forwarding := StandardDataPlaneBridge.model deviceBinding ifaces deployment {}

instance : DecidableRel configuration.physicalLink := by
  intro first last
  change Decidable ((first,last) ∈ records.links)
  infer_instance

instance : DecidableRel configuration.bridge := by
  intro first last
  change Decidable ((first,last) ∈ records.bridges)
  infer_instance

end TDN.Deployments.NestedProtection_Mixed
