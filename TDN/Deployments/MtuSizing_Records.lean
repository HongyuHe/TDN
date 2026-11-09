import TDN.Deployments.OuterToGray_DeviceModel
import TDN.Requirements.KeyRedactedSaInventory
import TDN.Requirements.NamespaceLocalIpOwnership
import TDN.Models.OriginTransmitterSatisfiesContract
import TDN.Requirements.StandardEthernetWireBridge

namespace TDN.Deployments.MtuSizing_Records
open Compliance Requirements OuterToGray_DeviceModel

structure SourceEntry where
  iface : Nat
  network : String
  originDomain : Nat
  sourceHost : String
  hostIface : Nat
  arrivalPath : List Nat

structure SourceFlow where
  iface : Nat
  domain : Nat
  source : Nat
  destination : Nat

structure SizingRole where
  iface : Nat
  interface : String
  owner : Nat
  device : String
  declaredRole : String
  declaredZone : String
  linkKind : String
  attached : Bool
  managementNetwork : Bool
  originalExternalData : Bool
  mtu : Nat
  role : SizingInterface


def directionalConfiguration (records : Records) (installations : List PublicSARecord) :
    MultiProtocolForwarding.Config :=
  let native := records.configuration
  { native with ip := { native.ip with
      egressSAs := fun iface => directionalStates installations (native.ip.owner iface) .outbound
      ingressSAs := fun iface => directionalStates installations (native.ip.owner iface) .inbound } }


def sourceEntry (entries : List SourceEntry) (iface : Nat) : Option String :=
  (entries.find? (fun entry => entry.iface == iface)).map SourceEntry.network


def sourceMtu (roles : List SizingRole) (iface : Nat) : Nat :=
  ((roles.find? (fun role => role.iface == iface)).map SizingRole.mtu).getD 1500


def requiredSizing (roles : List SizingRole) (iface : Nat) : Bool :=
  roles.any (fun role => role.iface == iface && role.role != .other)


def plaintextLimit (tag : Nat) : Nat := if tag = 1 then 1320 else if tag = 2 then 1400 else 0

def authenticationLimit (requestId : Nat) : Nat :=
  if requestId ∈ [101, 102, 103, 104] then 1320
  else if requestId ∈ [201, 202] then 1400 else 0


def completeConfiguration {Key : Type} (records : Records) (installations : List PublicSARecord)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (codec : IPsecFrameEncoding.Codec Key) :
    MultiProtocolForwarding.Config :=
  { directionalConfiguration records installations with
    linkPolicies := policies
    linkEncoding := fun _ frame => some (IPsecFrameEncoding.linkEncoding codec frame)
    networkBytes := fun body _ => IPsecFrameEncoding.networkLength body }


def completeInventory {Key : Type} (records : Records) (installations : List PublicSARecord)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (codec : IPsecFrameEncoding.Codec Key) :
    PacketProcessing.Inventory :=
  { records.inventory with configuration := completeConfiguration records installations policies codec }


def completeDeployment {Key : Type} (records : Records) (installations : List PublicSARecord)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (codec : IPsecFrameEncoding.Codec Key)
    (networks : List RedNetworkIdentity) (attachments : List RedNetworkAttachment)
    (services : List ServiceRegistration) (base : Deployment) : Deployment :=
  let inventory := completeInventory records installations policies codec
  let observed := records.deployment base
  { observed with
    processing := some inventory
    networks := networks, redNetworkAttachments := attachments, services := services,
    policies := nativePolicies inventory records.interfaces records.ifaceIndex,
    physicalLink := fun first last => ∃ edge ∈ records.links,
      records.ifaceName edge.1 = first ∧ records.ifaceName edge.2 = last }


def settings (roles : List SizingRole) : List PacketSizing :=
  (roles.filter (fun role => role.role != .other)).map fun role =>
    { interface := role.iface, role := role.role, family := .ipv4,
      externalMtu := role.mtu, payloadLimit := role.mtu,
      encodedSize := fun _ => role.mtu, ipv6PmtuConfigured := false,
      innerObjectiveSelected := false, encapsulationOverheadBound := role.mtu,
      outerMtu := 1500, blackMtu := 1500 }


def sourceOrigin (entries : List SourceEntry) (componentName : Nat → String)
    (domain : Nat) : PayloadOrigin :=
  match entries.find? (fun entry => entry.originDomain == domain) with
  | some entry => .red entry.network
  | none =>
    let localDomain := domain - (entries.length + 1)
    let component := componentName (localDomain / 13)
    let protocols := ["icmp", "icmpv6", "udp", "tcp", "arp", "eapol", "ospf", "ndp", "ethernet", "time", "dns", "dhcp"]
    if localDomain % 13 = 0 then .management component
    else .control component (protocols[localDomain % 13 - 1]?.getD "icmp")


def SourceFlow.request (flow : SourceFlow) : PacketSource.Request :=
  let payload : List UInt8 := [71, 69, 84, 32, 47, 32, 72, 84, 84, 80]
  { iface := flow.iface, originDomain := flow.domain,
    body := .datagram {
      source := flow.source, destination := flow.destination,
      protocol := "tcp", ingress := "", egress := "", sourcePort := 53000, destinationPort := 8080,
      ipv4HeaderWords := 5, matchedInboundPolicyIds := [], matchedOutboundPolicyIds := [], connectionState := "new",
      payloadBytes := some payload, hopLimit := 64 },
    application := payload, networkHeaderBytes := 20, transportHeaderBytes := 20,
    mode := .stream, requestId := 133 }


def ipsecTunnel (records : Records) (wireSeal : DataPlaneForwarding.TunnelSAStamp) : String :=
  let sender := (records.interfaces.find? (fun interface => interface.address == some wireSeal.sender)).map Interface.device
  let receiver := (records.interfaces.find? (fun interface => interface.address == some wireSeal.receiver)).map Interface.device
  ((records.tunnels.find? (fun tunnel => sender == some tunnel.sender && receiver == some tunnel.receiver)).map Tunnel.id).getD
    "unlisted-IPsec-tunnel"


def prototype {Key : Type} (records : Records) (installations : List PublicSARecord)
    (entries : List SourceEntry) (roles : List SizingRole) (policies : List (Nat × LinkAdmission.IfacePolicy))
    (epoch : String) (codec : IPsecFrameEncoding.Codec Key) (material : String → IPsecKeyMaterial) :
    DeviceExecutionBinding Unit Unit :=
  { configuration := completeConfiguration records installations policies codec
    state := fun _ => {
      iface := 0, datapathStage := .dropped, frame := {
        payload := 0, originDomain := 0,
        body := .ethernet ⟨0, 0, 0, []⟩ }, enteredIface := 0, authenticated := [], tracking := "" }
    action := fun _ => none
    ifaceName := records.ifaceName, componentName := records.componentName
    ipsecTunnel := ipsecTunnel records
    ipsecEpoch := some epoch, ipsecInstallations := installations.map PublicSARecord.installation
    ipsecKeyMaterial := publicKeyMaterial installations material
    macsecTunnel := fun _ => "unlisted-MACsec-tunnel", macsecKeyMaterial := fun _ => none
    sourceEntry := sourceEntry entries, sourceProcessing := PacketSource.sourceProcessing (sourceMtu roles)
    keyName := Nat.repr, domainName := fun domain =>
      match sourceOrigin entries records.componentName domain with
      | .red network => network
      | .control component _ | .management component => component
    origin := sourceOrigin entries records.componentName }

end TDN.Deployments.MtuSizing_Records
