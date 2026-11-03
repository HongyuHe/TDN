import TDN.Targets.ComplianceModel
import TDN.Targets.LayeredRequirements
import TDN.Targets.AuthenticationIsolation
import TDN.Targets.Topology
import TDN.Targets.Addressing
import TDN.Targets.Administration
import TDN.Targets.PacketSizing
import TDN.Targets.Transec

namespace TDN.Targets.Complete
open Compliance

structure Flow where
  sourceNetwork : String
  destinationNetwork : String
  innerTunnel : String
  outerTunnel : String

def Flow.Valid (d : Deployment) (flow : Flow) (independentKeys : String → String → Prop) : Prop :=
  ∃ inner ∈ d.tunnels, ∃ outer ∈ d.tunnels,
    inner.id = flow.innerTunnel ∧ outer.id = flow.outerTunnel ∧
    inner.layer = .inner ∧ outer.layer = .outer ∧
    independentKeys inner.keyContext outer.keyContext ∧
    (∀ tunnel ∈ [inner, outer], ∃ sender ∈ d.devices, ∃ receiver ∈ d.devices,
      sender.id = tunnel.sender ∧ receiver.id = tunnel.receiver ∧
      sender.infrastructure = true ∧ receiver.infrastructure = true ∧
      sender.layer = some tunnel.layer ∧ receiver.layer = some tunnel.layer ∧
      sender.site ≠ receiver.site ∧
      (tunnel.mechanism = .ipsec → sender.kind = .vpn ∧ receiver.kind = .vpn) ∧
      (tunnel.mechanism = .macsec → sender.kind = .macsec ∧ receiver.kind = .macsec)) ∧
    (∃ source ∈ d.networks, ∃ destination ∈ d.networks,
      source.id = flow.sourceNetwork ∧ destination.id = flow.destinationNetwork ∧
      inner.sender ∈ source.innerComponents ∧ inner.receiver ∈ destination.innerComponents ∧
      (∃ sender ∈ d.devices, sender.id = outer.sender ∧ sender.site = source.site) ∧
      ∃ receiver ∈ d.devices, receiver.id = outer.receiver ∧ receiver.site = destination.site) ∧
    (outer.mechanism = .macsec → ∃ first second,
      first ≠ second ∧ ∀ device ∈ d.devices, d.Relevant device.id →
        device.layer = some .outer → device.site = first ∨ device.site = second)

def ManagementDeployed (d : Deployment) : Prop :=
  ∃ workstation ∈ d.devices, workstation.kind = .workstation

def AuthenticationServices (d : Deployment) : Prop :=
  (∀ component ∈ d.devices, d.Relevant component.id →
    d.certificateAuthenticated component.id = true →
    ∃ authority ∈ d.devices, authority.kind = .certificationAuthority ∧
      d.keyManagementCA component.id authority.id) ∧
  (∀ component ∈ d.devices, d.Relevant component.id →
    d.preSharedCAKAuthenticated component.id = true →
    ∃ generator ∈ d.devices, generator.kind = .keyGenerationSolution ∧
      d.keyManagementGenerator component.id generator.id)

def ArchitectureServices (d : Deployment) : Prop :=
  AuthenticationServices d ∧
  ∀ a ∈ d.devices, ∀ b ∈ d.devices, a.layer = some .inner → b.layer = some .inner →
    a.level ≠ b.level → (∃ outer, d.innerUsesOuter a.id outer ∧ d.innerUsesOuter b.id outer) →
      ∃ firewall ∈ d.devices, firewall.kind = .grayFirewall

def CrossedBlack (d : Deployment) (events : List ProcessingEvent) (payload : PayloadId) : Prop :=
  ∃ interface ∈ d.interfaces, interface.zone = .black ∧ ∃ layers,
    ∃ trafficClass, .transmit payload interface.id layers trafficClass ∈ events ∨
      .receive payload interface.id layers trafficClass ∈ events

def Primitive_msc_nested_layer_protection {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (flows : List Flow) (flowOf : S → List A → S → PayloadId → Flow) (independentKeys : String → String → Prop) : Prop :=
  model.CoversDeployment d ∧ ArchitectureServices d ∧
  (∀ flow ∈ flows, flow.Valid d independentKeys) ∧
  (∀ start actions finish, model.initial start → model.system.MTr start actions finish →
    let events := model.TraceEvents actions
    let selectedFlow := flowOf start actions finish
    (∀ payload network, .inject payload network ∈ events →
      selectedFlow payload ∈ flows ∧ (selectedFlow payload).sourceNetwork = network) ∧
    (∀ earlier later payload port layers trafficClass,
      events = earlier ++ [.transmit payload port layers trafficClass] ++ later →
      model.ProtectedPayload d payload →
      ∀ interface ∈ d.interfaces, d.Relevant interface.device → interface.id = port →
      (interface.zone = .gray → selectedFlow payload ∈ flows ∧ layers = [(selectedFlow payload).innerTunnel] ∧
        .encrypt payload (selectedFlow payload).innerTunnel ∈ earlier) ∧
      (interface.zone = .black → selectedFlow payload ∈ flows ∧
        layers = [(selectedFlow payload).outerTunnel, (selectedFlow payload).innerTunnel] ∧
        Before earlier (.encrypt payload (selectedFlow payload).innerTunnel)
          (.encrypt payload (selectedFlow payload).outerTunnel))) ∧
    (∀ payload port layers trafficClass, .receive payload port layers trafficClass ∈ events →
      model.ProtectedPayload d payload →
      ∀ interface ∈ d.interfaces, d.Relevant interface.device → interface.id = port → interface.zone = .black →
      selectedFlow payload ∈ flows ∧
      layers = [(selectedFlow payload).outerTunnel, (selectedFlow payload).innerTunnel]) ∧
    ∀ earlier later payload network layers,
      events = earlier ++ [.deliver payload network layers] ++ later →
      .inject payload (selectedFlow payload).sourceNetwork ∈ earlier → CrossedBlack d earlier payload →
      selectedFlow payload ∈ flows ∧ network = (selectedFlow payload).destinationNetwork ∧ layers = [] ∧
      Before earlier (.decrypt payload (selectedFlow payload).outerTunnel)
        (.decrypt payload (selectedFlow payload).innerTunnel))

def SecurityLevelConnectivityCore {S A : Type} (d : Deployment)
    (model : ExecutionModel S A) (authenticatedInnerPairs establishedInnerTunnels : List (String × String))
    (requiredConnectivity : List (String × String)) (includedUnclassified : List String) : Prop :=
  model.CoversDeployment d ∧
  DedicatedInnerAssignments d.networks ∧
  (∀ network ∈ d.networks, ∀ inner ∈ network.innerComponents,
    ∃ device ∈ d.devices, device.id = inner ∧ device.layer = some .inner ∧
      device.level = network.level) ∧
  (∀ pair ∈ authenticatedInnerPairs ++ establishedInnerTunnels,
    ∃ first ∈ d.devices, ∃ second ∈ d.devices,
      first.id = pair.1 ∧ second.id = pair.2 ∧ first.layer = some .inner ∧
      second.layer = some .inner ∧ first.level = second.level) ∧
  (model.AllTraces (fun events => ∀ payload source destination layers,
    Before events (.inject payload source) (.deliver payload destination layers) →
    ∃ first ∈ d.networks, ∃ second ∈ d.networks,
      first.id = source ∧ second.id = destination ∧ first.level = second.level)) ∧
  (∀ pair ∈ requiredConnectivity, ∃ start actions finish payload,
    model.initial start ∧ model.system.MTr start actions finish ∧
    Before (model.TraceEvents actions) (.inject payload pair.1) (.deliver payload pair.2 [])) ∧
  ∀ network ∈ includedUnclassified,
    (∃ red ∈ d.networks, red.id = network ∧ red.level.classification = "unclassified")

def Primitive_msc_security_level_key_and_management_separation (managementDeployed : Bool)
    (peers : List InnerAuthentication) (establishedTunnel : String → String → Prop) : Prop :=
  TDN.Targets.msc_security_level_key_and_management_separation managementDeployed peers ∧
  ∀ a ∈ peers, ∀ b ∈ peers, a.level ≠ b.level → ¬ establishedTunnel a.component b.component

structure GrayTopology where
  edge : String → String → Prop
  inner : String → Prop
  grayFirewall : String → Prop
  outer : String → Prop
  workstation : String → Prop
  localCA : String → Prop
  certificationAuthority : String → Prop
  revocationService : String → Prop
  level : String → SecurityLevel
  highest : SecurityLevel
  dominates : SecurityLevel → SecurityLevel → Prop

def GrayManagement (topology : GrayTopology) (node : String) : Prop :=
  topology.workstation node ∨ topology.localCA node

def InnerEndpoints (d : Deployment) (traffic : Traffic) : Prop :=
  ∃ source destination, traffic.sourceDevice = some source ∧
    traffic.destinationDevice = some destination ∧
    d.IsLayer source .inner ∧ d.IsLayer destination .inner

def FiltersIntendedPeers (d : Deployment) (device : String) : Prop :=
  ∀ interface ∈ d.interfaces, d.Relevant interface.device → interface.device = device → interface.zone = .gray →
    d.PolicyCoverage interface ∧ ∀ direction traffic,
      d.Accepts interface.id direction traffic → InnerEndpoints d traffic →
      d.SameLevelInner traffic

def Primitive_msc_gray_firewall_path_coverage (d : Deployment) (topology : GrayTopology) : Prop :=
  d.AddressInventoryCoherent ∧
  (∀ node, topology.inner node ↔ d.IsLayer node .inner) ∧
  (∀ node, topology.grayFirewall node ↔ d.IsDevice node .grayFirewall) ∧
  (∀ node, topology.outer node ↔ d.IsLayer node .outer) ∧
  (∀ node, topology.workstation node ↔ d.grayWorkstation node) ∧
  (∀ node, topology.localCA node → topology.certificationAuthority node) ∧
  (∀ node, topology.certificationAuthority node ↔
    d.IsDevice node .certificationAuthority ∧
      ∃ interface ∈ d.interfaces, interface.device = node ∧ interface.zone = .gray) ∧
  (∀ node, topology.revocationService node ↔
    d.IsDevice node .revocationService ∧
      ∃ interface ∈ d.interfaces, interface.device = node ∧ interface.zone = .gray) ∧
  (∀ device ∈ d.devices, d.Relevant device.id → topology.level device.id = device.level) ∧
  TDN.Targets.msc_gray_firewall_path_coverage topology.edge topology.grayFirewall topology.inner
    (GrayManagement topology) topology.level topology.highest topology.dominates
    (FiltersIntendedPeers d) d.authority.protectsAsClassified ∧
  (∀ service component,
    (topology.workstation service ∨ topology.certificationAuthority service ∨
      topology.revocationService service) → topology.inner component →
    topology.level service ≠ topology.level component →
    ¬ Relation.ReflTransGen (Paths.Avoiding topology.edge topology.grayFirewall) service component) ∧
  (∀ outer, topology.outer outer → FiltersIntendedPeers d outer) ∧
  (∀ firewall, topology.grayFirewall firewall → ∀ interface ∈ d.interfaces, d.Relevant interface.device →
    interface.device = firewall → ∀ direction traffic,
      d.Accepts interface.id direction traffic →
      ∀ manager component, GrayManagement topology manager → topology.inner component →
        topology.level component ≠ topology.highest →
        ¬ ((traffic.sourceDevice = some manager ∧ traffic.destinationDevice = some component) ∨
          (traffic.sourceDevice = some component ∧ traffic.destinationDevice = some manager))) ∧
  ∀ firewall, topology.grayFirewall firewall → ∃ outer inner,
    topology.outer outer ∧ topology.inner inner ∧
    Relation.ReflTransGen topology.edge inner firewall ∧
    Relation.ReflTransGen topology.edge firewall outer

def Primitive_msc_gray_addressing_for_level_filtering (d : Deployment)
    (ranges : List (Addressing.Range SecurityLevel)) (pairs : List IntendedAddressPair) : Prop :=
  d.AddressInventoryCoherent ∧
  (∀ range ∈ ranges, range.low ≤ range.high) ∧
  (∀ address a b, Addressing.Owns ranges address a → Addressing.Owns ranges address b → a = b) ∧
  (∀ pair ∈ pairs, Addressing.Owns ranges pair.source pair.level ∧
    Addressing.Owns ranges pair.destination pair.level) ∧
  (∀ interface ∈ d.interfaces, d.Relevant interface.device → interface.zone = .gray → d.IsLayer interface.device .inner →
    ∃ device ∈ d.devices, device.id = interface.device ∧
      ∃ address, interface.address = some address ∧ Addressing.Owns ranges address device.level) ∧
  ∀ device ∈ d.devices, d.Relevant device.id → device.layer = some .outer ∨ device.kind = .grayFirewall →
    FiltersIntendedPeers d device.id ∧
    ∀ interface ∈ d.interfaces, d.Relevant interface.device → interface.device = device.id → interface.zone = .gray →
      ∀ direction traffic, d.Accepts interface.id direction traffic → InnerEndpoints d traffic →
        IntendedPair pairs traffic.packet

structure EncapsulationUse where
  protectedTunnel : String
  inner : String
  outer : Option String
  protocol : String
  builtInSupported : Bool
  encapsulator : String
  remoteEncapsulator : String
  inputInterface : String
  outputInterface : String
  traversesIP : Bool

def MACsecEncapsulationCore {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (uses : List EncapsulationUse) (crossesIP : String → Bool) : Prop :=
  model.CoversDeployment d ∧
  (∀ tunnel ∈ d.tunnels, (d.Relevant tunnel.sender ∨ d.Relevant tunnel.receiver) → tunnel.mechanism = .macsec →
    tunnel.layer = .inner ∨ crossesIP tunnel.id = true →
      ∃ use ∈ uses, use.protectedTunnel = tunnel.id ∧ use.inner = tunnel.sender ∧
        (tunnel.layer = .inner → use.outer.isSome = true) ∧
        (crossesIP tunnel.id = true → use.traversesIP = true)) ∧
  (∀ use ∈ uses, (d.Relevant use.inner ∨ d.Relevant use.encapsulator ∨
      d.Relevant use.remoteEncapsulator) →
    d.authority.aoApprovedEncapsulation use.protocol ∧
    (use.builtInSupported = false → d.standaloneEncapsulator use.encapsulator ∧
      d.OwnedGrayAttachment use.inner use.encapsulator use.inputInterface ∧
      (∀ outer, use.outer = some outer →
        d.OwnedGrayExit use.encapsulator use.outputInterface outer))) ∧
  model.AllTraces (fun events => ∀ use ∈ uses, (d.Relevant use.inner ∨ d.Relevant use.encapsulator ∨
      d.Relevant use.remoteEncapsulator) → ∀ payload,
    .encrypt payload use.protectedTunnel ∈ events →
      (∀ outer tunnel, use.outer = some outer →
        (∃ t ∈ d.tunnels, t.id = tunnel ∧ t.sender = outer) →
        BeforeEvery events (.encapsulate payload use.encapsulator use.protocol)
          (.encrypt payload tunnel)) ∧
      (use.traversesIP = true → ∀ earlier later layers trafficClass,
        events = earlier ++ [.transmit payload use.outputInterface layers trafficClass] ++ later →
        .encapsulate payload use.encapsulator use.protocol ∈ earlier) ∧
      (∀ first middle last,
        events = first ++ [.encapsulate payload use.encapsulator use.protocol] ++ middle ++
          [.decapsulate payload use.remoteEncapsulator use.protocol] ++ last →
        .decrypt payload use.protectedTunnel ∉ middle))

structure PrivateKey where
  id : String
  gateway : String

structure MandatoryKeyPolicy where
  gateway : String
  enforced : Bool
  permits : String → String → Prop

def StoredVPNKeyInventory (d : Deployment) (keys : List PrivateKey) : Prop :=
  ∀ gateway key, d.Relevant gateway →
    (d.storedVPNKey gateway key ↔ ∃ entry ∈ keys, entry.gateway = gateway ∧ entry.id = key)

def Primitive_msc_vpn_private_key_confinement {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (keys : List PrivateKey) (objectiveSelected : String → Bool)
    (policies : List MandatoryKeyPolicy) : Prop :=
  StoredVPNKeyInventory d keys ∧
  (model.AllTraces (fun events => ∀ key ∈ keys, d.Relevant key.gateway → ∀ interface,
    .privateKeyExport key.gateway key.id interface ∉ events)) ∧
  (∀ key ∈ keys, d.Relevant key.gateway → objectiveSelected key.gateway = true → ∃ policy ∈ policies,
    policy.gateway = key.gateway ∧ policy.enforced = true ∧
    ∀ principal, policy.permits principal key.id → principal = key.gateway) ∧
  model.AllTraces (fun events => ∀ key ∈ keys, d.Relevant key.gateway → objectiveSelected key.gateway = true →
    ∀ principal, .privateKeyRead key.gateway key.id principal ∈ events → principal = key.gateway)

inductive MACsecAuthenticationMethod where
  | preSharedCAK | eapTLS
  deriving DecidableEq

inductive EAPRole where
  | supplicant | authenticator
  deriving DecidableEq

structure TLSHandshakeInput where
  session : String
  device : String
  server : String
  deviceCertificate : String
  serverCertificate : String
  deviceIdentity : Trust.Identity SecurityLevel String
  serverIdentity : Trust.Identity SecurityLevel String
  transcript : List UInt8
  deviceNonce : List UInt8
  serverNonce : List UInt8
  role : EAPRole

structure TLSVerifiedSession where
  session : String
  device : String
  server : String
  deviceCertificate : String
  serverCertificate : String
  deviceIdentity : Trust.Identity SecurityLevel String
  serverIdentity : Trust.Identity SecurityLevel String
  transcript : List UInt8
  masterSessionKey : String

structure EAPBackendInput where
  session : String
  server : String
  authenticator : String
  supplicant : String
  masterSessionKey : String
  channelBinding : List UInt8
  protectedRecord : List UInt8
  nonce : List UInt8

structure EAPBackendVerified where
  session : String
  server : String
  authenticator : String
  supplicant : String
  masterSessionKey : String

structure EAPBackendDelivery where
  input : EAPBackendInput
  verified : EAPBackendVerified

structure TLSPrimitive where
  mutuallyAuthenticate : TLSHandshakeInput → Option TLSVerifiedSession
  authenticateBackendDelivery : EAPBackendInput → Option EAPBackendVerified
  supportsRole : String → EAPRole → Bool
  deriveCAK : String → String

def EAPBackendDelivery.Successful (primitive : TLSPrimitive)
    (delivery : EAPBackendDelivery) : Prop :=
  delivery.input.channelBinding ≠ [] ∧ delivery.input.protectedRecord ≠ [] ∧
  delivery.input.nonce ≠ [] ∧
  primitive.authenticateBackendDelivery delivery.input = some delivery.verified ∧
  delivery.verified.session = delivery.input.session ∧
  delivery.verified.server = delivery.input.server ∧
  delivery.verified.authenticator = delivery.input.authenticator ∧
  delivery.verified.supplicant = delivery.input.supplicant ∧
  delivery.verified.masterSessionKey = delivery.input.masterSessionKey

structure EAPExchange where
  input : TLSHandshakeInput
  verified : TLSVerifiedSession

def EAPExchange.Successful (primitive : TLSPrimitive) (exchange : EAPExchange) : Prop :=
  exchange.input.session ≠ "" ∧ exchange.input.transcript ≠ [] ∧
  exchange.input.deviceNonce ≠ [] ∧ exchange.input.serverNonce ≠ [] ∧
  primitive.mutuallyAuthenticate exchange.input = some exchange.verified ∧
  exchange.verified.session = exchange.input.session ∧
  exchange.verified.device = exchange.input.device ∧
  exchange.verified.server = exchange.input.server ∧
  exchange.verified.deviceCertificate = exchange.input.deviceCertificate ∧
  exchange.verified.serverCertificate = exchange.input.serverCertificate ∧
  exchange.verified.deviceIdentity = exchange.input.deviceIdentity ∧
  exchange.verified.serverIdentity = exchange.input.serverIdentity ∧
  exchange.verified.transcript = exchange.input.transcript ∧
  exchange.verified.masterSessionKey ≠ "" ∧
  Trust.MutuallyAdmits exchange.input.deviceIdentity exchange.input.serverIdentity

structure MACsecAuthentication where
  device : String
  peer : String
  method : MACsecAuthenticationMethod
  cak : String
  peerCAK : String
  server : String
  deviceCertificate : String
  peerCertificate : String
  serverCertificate : String
  masterSessionKey : String
  peerMasterSessionKey : String
  deviceIdentity : Trust.Identity SecurityLevel String
  peerIdentity : Trust.Identity SecurityLevel String
  serverIdentity : Trust.Identity SecurityLevel String
  eapSupplicant : String
  eapAuthenticator : String
  backendDelivery : EAPBackendDelivery
  exchanges : List EAPExchange
  supportedRoles : List EAPRole
  keyServer : String
  secureAssociationKey : String
  serverAttachments : List (String × Zone)

def EAPDeviceExchange (primitive : TLSPrimitive) (selected : MACsecAuthentication)
    (exchange : EAPExchange) : Prop :=
  exchange.Successful primitive ∧ exchange.input.device = selected.device ∧
  exchange.input.server = selected.server ∧
  exchange.input.deviceCertificate = selected.deviceCertificate ∧
  exchange.input.serverCertificate = selected.serverCertificate ∧
  exchange.input.deviceIdentity = selected.deviceIdentity ∧
  exchange.input.serverIdentity = selected.serverIdentity ∧
  exchange.verified.masterSessionKey = selected.masterSessionKey

def EAPPeerExchange (primitive : TLSPrimitive) (selected : MACsecAuthentication)
    (exchange : EAPExchange) : Prop :=
  exchange.Successful primitive ∧ exchange.input.device = selected.peer ∧
  exchange.input.server = selected.server ∧
  exchange.input.deviceCertificate = selected.peerCertificate ∧
  exchange.input.serverCertificate = selected.serverCertificate ∧
  exchange.input.deviceIdentity = selected.peerIdentity ∧
  exchange.input.serverIdentity = selected.serverIdentity ∧
  exchange.verified.masterSessionKey = selected.peerMasterSessionKey

def EAPSelectedExchange (primitive : TLSPrimitive) (selected : MACsecAuthentication)
    (exchange : EAPExchange) : Prop :=
  exchange.input.role = .supplicant ∧
  ((selected.eapSupplicant = selected.device ∧ selected.eapAuthenticator = selected.peer ∧
      EAPDeviceExchange primitive selected exchange) ∨
    (selected.eapSupplicant = selected.peer ∧ selected.eapAuthenticator = selected.device ∧
      EAPPeerExchange primitive selected exchange))

def EAPSessionBinding (primitive : TLSPrimitive) (selected : MACsecAuthentication)
    (exchange : EAPExchange) : Prop :=
  EAPSelectedExchange primitive selected exchange ∧
  selected.backendDelivery.Successful primitive ∧
  selected.backendDelivery.input.session = exchange.input.session ∧
  selected.backendDelivery.input.server = selected.server ∧
  selected.backendDelivery.input.authenticator = selected.eapAuthenticator ∧
  selected.backendDelivery.input.supplicant = selected.eapSupplicant ∧
  selected.backendDelivery.input.masterSessionKey = exchange.verified.masterSessionKey ∧
  selected.masterSessionKey = exchange.verified.masterSessionKey ∧
  selected.peerMasterSessionKey = exchange.verified.masterSessionKey ∧
  selected.cak = primitive.deriveCAK selected.masterSessionKey ∧
  selected.peerCAK = primitive.deriveCAK selected.peerMasterSessionKey ∧
  selected.cak = selected.peerCAK

def EAPEndpointRoleEvidence (primitive : TLSPrimitive) (selected : MACsecAuthentication) : Prop :=
  ∀ endpoint ∈ [selected.device, selected.peer],
    (∀ role ∈ selected.supportedRoles, primitive.supportsRole endpoint role = true) ∧
    ∃ exchange ∈ selected.exchanges, exchange.input.device = endpoint ∧
      exchange.input.server = selected.server ∧ exchange.input.role = .supplicant ∧
      exchange.input.serverCertificate = selected.serverCertificate ∧
      exchange.input.serverIdentity = selected.serverIdentity ∧
      (endpoint = selected.device →
        exchange.input.deviceCertificate = selected.deviceCertificate ∧
        exchange.input.deviceIdentity = selected.deviceIdentity) ∧
      (endpoint = selected.peer →
        exchange.input.deviceCertificate = selected.peerCertificate ∧
        exchange.input.deviceIdentity = selected.peerIdentity) ∧
      exchange.Successful primitive


def SAKKeyUseAt (selected : MACsecAuthentication) (payload : PayloadId) (tunnel : String)
    (events : List ProcessingEvent) (authenticated issued used : Nat) : Prop :=
  events[authenticated]? = some (.authenticate selected.keyServer
    (if selected.keyServer = selected.device then selected.peer else selected.device) selected.cak) ∧
  events[issued]? = some (.issueSAK selected.keyServer
    (if selected.keyServer = selected.device then selected.peer else selected.device)
      selected.secureAssociationKey) ∧
  events[used]? = some (.useSAK payload tunnel selected.secureAssociationKey) ∧
  authenticated < issued ∧ issued < used

def PreSharedKeyUsePrefix (selected : MACsecAuthentication) (payload : PayloadId)
    (tunnel : String) (events : List ProcessingEvent) : Prop :=
  ∃ authenticated issued used, SAKKeyUseAt selected payload tunnel events authenticated issued used

def EAPKeyUsePrefix (primitive : TLSPrimitive) (selected : MACsecAuthentication)
    (payload : PayloadId) (tunnel : String) (events : List ProcessingEvent) : Prop :=
  ∃ exchange ∈ selected.exchanges, EAPSessionBinding primitive selected exchange ∧
    ∃ verified delivered supplicantDerived authenticatorDerived authenticated issued used : Nat,
      events[verified]? = some (.eapTLSVerified exchange.input.session
        selected.eapSupplicant selected.server exchange.input.deviceCertificate
          selected.serverCertificate exchange.verified.masterSessionKey) ∧
      events[delivered]? = some (.eapKeyDelivered exchange.input.session selected.server
        selected.eapAuthenticator selected.eapSupplicant exchange.verified.masterSessionKey) ∧
      events[supplicantDerived]? = some (.deriveCAK exchange.input.session
        selected.eapSupplicant exchange.verified.masterSessionKey selected.cak) ∧
      events[authenticatorDerived]? = some (.deriveCAK exchange.input.session
        selected.eapAuthenticator exchange.verified.masterSessionKey selected.cak) ∧
      SAKKeyUseAt selected payload tunnel events authenticated issued used ∧
      verified < delivered ∧ verified < supplicantDerived ∧
      delivered < authenticatorDerived ∧ supplicantDerived < authenticated ∧
      authenticatorDerived < authenticated

def MACsecKeyUsePrefix (primitive : TLSPrimitive) (selected : MACsecAuthentication)
    (payload : PayloadId) (tunnel : String) (events : List ProcessingEvent) : Prop :=
  match selected.method with
  | .preSharedCAK => PreSharedKeyUsePrefix selected payload tunnel events
  | .eapTLS => EAPKeyUsePrefix primitive selected payload tunnel events

def HistoricalSetup (history : ObservedHistory) (session : Option String)
    (event : ProcessingEvent) (position : Nat) : Prop :=
  ∃ record ∈ history.entries, record.position = position ∧
    record.session = session ∧ record.event = event

def HistoricalSAKSetup (history : ObservedHistory) (selected : MACsecAuthentication)
    (installation : MACsecHistoryInstallation) : Prop :=
  installation.issuer = selected.keyServer ∧
  installation.peer = (if selected.keyServer = selected.device then selected.peer else selected.device) ∧
  installation.keyReference = selected.secureAssociationKey ∧
  ∃ authenticated,
    HistoricalSetup history installation.session (.authenticate installation.issuer
      installation.peer selected.cak) authenticated ∧ history.CausallyBefore authenticated installation.issuedAt

def HistoricalEAPSetup (history : ObservedHistory) (primitive : TLSPrimitive)
    (selected : MACsecAuthentication) (installation : MACsecHistoryInstallation) : Prop :=
  ∃ exchange ∈ selected.exchanges, EAPSessionBinding primitive selected exchange ∧
    installation.session = some exchange.input.session ∧
    ∃ verified delivered supplicantDerived authenticatorDerived authenticated : Nat,
      HistoricalSetup history installation.session (.eapTLSVerified exchange.input.session
        selected.eapSupplicant selected.server exchange.input.deviceCertificate
        selected.serverCertificate exchange.verified.masterSessionKey) verified ∧
      HistoricalSetup history installation.session (.eapKeyDelivered exchange.input.session
        selected.server selected.eapAuthenticator selected.eapSupplicant
        exchange.verified.masterSessionKey) delivered ∧
      HistoricalSetup history installation.session (.deriveCAK exchange.input.session
        selected.eapSupplicant exchange.verified.masterSessionKey selected.cak) supplicantDerived ∧
      HistoricalSetup history installation.session (.deriveCAK exchange.input.session
        selected.eapAuthenticator exchange.verified.masterSessionKey selected.peerCAK) authenticatorDerived ∧
      HistoricalSetup history installation.session (.authenticate installation.issuer
        installation.peer selected.cak) authenticated ∧
      history.CausallyBefore verified delivered ∧
      history.CausallyBefore verified supplicantDerived ∧
      history.CausallyBefore delivered authenticatorDerived ∧
      history.CausallyBefore supplicantDerived authenticated ∧
      history.CausallyBefore authenticatorDerived authenticated ∧
      history.CausallyBefore authenticated installation.issuedAt

def MACsecInstalledHistory {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (primitive : TLSPrimitive) (authentication : List MACsecAuthentication) : Prop :=
  model.history.Valid ∧
  ∀ port ∈ model.native.configuration.macPorts, ∀ association,
    port.transmitAssociation = some association →
    let owner := model.native.componentName
      (model.native.configuration.ip.owner port.physicalPort)
    d.Relevant owner →
    ∃ installation ∈ model.macsecInstallationHistory,
      installation.Bound model ∧
      installation.device = model.native.configuration.ip.owner port.physicalPort ∧
      installation.association = association ∧
      ∃ tunnel ∈ d.tunnels, tunnel.id = model.native.macsecTunnel association ∧
        tunnel.sender = owner ∧ tunnel.mechanism = .macsec ∧
        ∃ selected ∈ authentication, selected.device = owner ∧ selected.peer = tunnel.receiver ∧
          HistoricalSAKSetup model.history selected installation ∧
          match selected.method with
          | .preSharedCAK => installation.session = none
          | .eapTLS => HistoricalEAPSetup model.history primitive selected installation

def Primitive_msc_macsec_authentication_choice_and_as {S A : Type} (d : Deployment)
    (model : ExecutionModel S A) (primitive : TLSPrimitive)
    (authentication : List MACsecAuthentication) : Prop :=
  MACsecInstalledHistory d model primitive authentication ∧
  (∀ device ∈ d.devices, d.Relevant device.id → device.kind = .macsec →
    ∃ selected ∈ authentication, selected.device = device.id) ∧
  (∀ selected ∈ authentication, (d.Relevant selected.device ∨ d.Relevant selected.server) →
    d.IsDevice selected.device .macsec ∧ d.IsDevice selected.peer .macsec ∧
    (selected.method = .preSharedCAK ↔ d.preSharedCAKAuthenticated selected.device = true) ∧
    (selected.method = .eapTLS ↔ d.certificateAuthenticated selected.device = true) ∧
    (selected.keyServer = selected.device ∨ selected.keyServer = selected.peer) ∧
    selected.secureAssociationKey ≠ "" ∧
    match selected.method with
    | .preSharedCAK => selected.cak ≠ "" ∧ selected.cak = selected.peerCAK
    | .eapTLS => d.IsDevice selected.server .authenticationServer ∧
        selected.supportedRoles = [.supplicant, .authenticator] ∧
        selected.deviceCertificate ≠ "" ∧ selected.peerCertificate ≠ "" ∧
        selected.serverCertificate ≠ "" ∧
        EAPEndpointRoleEvidence primitive selected ∧
        (∃ exchange ∈ selected.exchanges, EAPSessionBinding primitive selected exchange) ∧
        (∀ site zone, (site, zone) ∈ selected.serverAttachments ↔
          d.networkAttachment selected.server site zone) ∧
        (∃ site zone, selected.serverAttachments ≠ [] ∧
          ∀ attachment ∈ selected.serverAttachments, attachment = (site, zone)) ∧
        ∀ attachment ∈ selected.serverAttachments, attachment.2 = .red ∨ attachment.2 = .gray) ∧
  model.AllTraces (fun events => ∀ earlier later payload tunnel,
    events = earlier ++ [.encrypt payload tunnel] ++ later →
    ∀ configured ∈ d.tunnels, configured.id = tunnel → configured.mechanism = .macsec →
    ∃ selected ∈ authentication, selected.device = configured.sender ∧
      selected.peer = configured.receiver ∧
      MACsecKeyUsePrefix primitive selected payload tunnel earlier)

inductive KeyOrigin where
  | generated (generator : String)
  | eapDerived (masterSessionKey : String)
  deriving DecidableEq

structure MACsecKey where
  cak : String
  cakOrigin : KeyOrigin
  ckn : List UInt8
  cknGenerator : String
  fallbackEnabled : Bool

structure KeyProvisioning where
  administrator : String
  key : String
  generator : String
  obtainedOrder : Nat
  applications : List (String × Nat)


structure MACsecServerPair where
  first : String
  second : String
  firstValue : Nat
  secondValue : Nat
  centralSite : Option String

def Primitive_msc_macsec_key_generation_and_server (d : Deployment) (keys : List MACsecKey)
    (pairs : List MACsecServerPair) (provisioning : List KeyProvisioning)
    (eapCAKGeneratedByApprovedKGS : String → String → Prop) : Prop :=
  (∀ key ∈ keys, d.RelevantKey key.cak → 16 ≤ key.ckn.length ∧ d.authority.nsaApprovedGenerator key.cknGenerator ∧
    (match key.cakOrigin with
      | .generated generator => d.authority.nsaApprovedGenerator generator ∧
          ∃ provision ∈ provisioning, provision.key = key.cak ∧ provision.generator = generator ∧
            d.authority.securityAdministrator provision.administrator ∧
            ∀ tunnel ∈ d.tunnels, (d.Relevant tunnel.sender ∨ d.Relevant tunnel.receiver) → tunnel.mechanism = .macsec → tunnel.keyContext = key.cak →
              (∃ applied ∈ provision.applications, applied.1 = tunnel.sender ∧
                provision.obtainedOrder < applied.2) ∧
              ∃ applied ∈ provision.applications, applied.1 = tunnel.receiver ∧
                provision.obtainedOrder < applied.2
      | .eapDerived msk => msk ≠ "" ∧ ∃ generator, d.authority.nsaApprovedGenerator generator ∧
          eapCAKGeneratedByApprovedKGS key.cak generator) ∧ key.fallbackEnabled = false) ∧
  (∀ tunnel ∈ d.tunnels, (d.Relevant tunnel.sender ∨ d.Relevant tunnel.receiver) → tunnel.mechanism = .macsec →
    (∃ key ∈ keys, key.cak = tunnel.keyContext) ∧
    ∃ pair ∈ pairs, pair.first = tunnel.sender ∧ pair.second = tunnel.receiver) ∧
  ∀ pair ∈ pairs, (d.Relevant pair.first ∨ d.Relevant pair.second) → pair.centralSite = d.centralManagementSite ∧ pair.first ≠ pair.second ∧
    ((pair.firstValue = 0 ∧ pair.secondValue = 1) ∨
      (pair.firstValue = 1 ∧ pair.secondValue = 0)) ∧
    ∀ site, pair.centralSite = some site →
      (∃ first ∈ d.devices, first.id = pair.first ∧ first.site = site ∧ pair.firstValue = 0) ∨
      (∃ second ∈ d.devices, second.id = pair.second ∧ second.site = site ∧ pair.secondValue = 0)

structure MACsecParameters where
  device : String
  dataDelayProtection : Bool
  lifetimeMilliseconds : Nat
  normalHelloMilliseconds : Nat
  activeHelloMilliseconds : Nat
  replayWindow : Nat
  feasibleReplayWindow : Nat → Prop
  confidentialityOffset : Nat
  mustSecure : Bool

def Primitive_msc_macsec_protection_parameters {S A : Type} (d : Deployment)
    (model : ExecutionModel S A) (parameters : List MACsecParameters) : Prop :=
  model.CoversDeployment d ∧
  (∀ device ∈ d.devices, d.Relevant device.id → device.kind = .macsec →
    ∃ parameter ∈ parameters, parameter.device = device.id) ∧
  (∀ parameter ∈ parameters, d.Relevant parameter.device → parameter.dataDelayProtection = true ∧
    parameter.lifetimeMilliseconds = 6000 ∧ parameter.normalHelloMilliseconds = 2000 ∧
    0 < parameter.activeHelloMilliseconds ∧ parameter.activeHelloMilliseconds ≤ 2000 ∧
    (parameter.replayWindow = 2 ∨ (parameter.feasibleReplayWindow parameter.replayWindow ∧
      ∀ feasible, parameter.feasibleReplayWindow feasible → parameter.replayWindow ≤ feasible)) ∧
    parameter.confidentialityOffset = 0 ∧ parameter.mustSecure = true) ∧
  model.AllTraces (fun events => ∀ payload port layers trafficClass,
    .transmit payload port layers trafficClass ∈ events → ¬ model.GenuineControl payload →
    ∀ interface ∈ d.interfaces, d.Relevant interface.device → interface.id = port →
    ∀ device ∈ d.devices, d.Relevant device.id → device.id = interface.device → device.kind = .macsec →
    device.layer = some .inner ∧ interface.zone = .gray ∨
      device.layer = some .outer ∧ interface.zone = .black →
    ∃ tunnel ∈ d.tunnels, tunnel.mechanism = .macsec ∧ tunnel.sender = device.id ∧ tunnel.id ∈ layers)

def InternalZone : Layer → Zone
  | .inner => .red
  | .outer => .gray

def ExternalZone : Layer → Zone
  | .inner => .gray
  | .outer => .black

def TraceNoBypass (d : Deployment) (genuineControl : PayloadId → Prop)
    (layer : Layer) (events : List ProcessingEvent) : Prop :=
  (∀ earlier middle later payload ingress receivedLayers receiveClass egress sentLayers sendClass,
    events = earlier ++ [.receive payload ingress receivedLayers receiveClass] ++ middle ++
      [.transmit payload egress sentLayers sendClass] ++ later →
    ¬ genuineControl payload →
    ∀ input ∈ d.interfaces, ∀ output ∈ d.interfaces,
      input.id = ingress → output.id = egress → input.device = output.device →
      d.IsLayer input.device layer →
      (input.zone = InternalZone layer → output.zone ≠ InternalZone layer →
        ∃ tunnel ∈ d.tunnels, tunnel.layer = layer ∧ tunnel.sender = input.device ∧
          tunnel.id ∈ sentLayers ∧ .encrypt payload tunnel.id ∈ middle) ∧
      (input.zone = ExternalZone layer → output.zone = InternalZone layer →
        ∃ tunnel ∈ d.tunnels, tunnel.layer = layer ∧ tunnel.receiver = input.device ∧
          tunnel.id ∈ receivedLayers ∧ .decrypt payload tunnel.id ∈ middle)) ∧
  ∀ earlier later payload port layers trafficClass,
    events = earlier ++ [.transmit payload port layers trafficClass] ++ later →
    ¬ genuineControl payload →
    ∀ interface ∈ d.interfaces, interface.id = port →
      d.IsLayer interface.device layer → interface.zone = ExternalZone layer →
      ∃ tunnel ∈ d.tunnels, tunnel.layer = layer ∧ tunnel.sender = interface.device ∧
        tunnel.id ∈ layers ∧ .encrypt payload tunnel.id ∈ earlier

def LayerNoBypass {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (layer : Layer) : Prop :=
  model.CoversDeployment d ∧ model.AllTraces (TraceNoBypass d model.GenuineControl layer)

def ComponentConfigurationCoverage (d : Deployment) (layer : Layer)
    (components : List EncryptionComponentConfiguration) : Prop :=
  ∀ device ∈ d.devices, d.Relevant device.id → device.layer = some layer →
    ∃ component ∈ components, component.id = device.id ∧
      ((device.kind = .vpn ∧ component.mechanism = .ipsec) ∨
        (device.kind = .macsec ∧ component.mechanism = .macsec))

def Primitive_msc_inner_tunnel_no_bypass {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool) : Prop :=
  ComponentConfigurationCoverage d .inner components ∧ LayerNoBypass d model .inner ∧
  ∀ component ∈ components, d.Relevant component.id →
    (component.mechanism = .ipsec → component.espTunnelMode = true ∧ component.associatedIPTunnel = true) ∧
    (outboundMACObjective = true → component.outboundMACPolicy = true) ∧
    (inboundMACObjective = true → component.inboundMACPolicy = true)

def Primitive_msc_outer_tunnel_no_bypass {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (components : List EncryptionComponentConfiguration)
    (outboundMACObjective inboundMACObjective : Bool) : Prop :=
  ComponentConfigurationCoverage d .outer components ∧ LayerNoBypass d model .outer ∧
  (∀ component ∈ components, d.Relevant component.id →
    (component.mechanism = .ipsec → component.espTunnelMode = true) ∧
    (outboundMACObjective = true → component.outboundMACPolicy = true) ∧
    (inboundMACObjective = true → component.inboundMACPolicy = true)) ∧
  model.AllTraces (fun events => ∀ payload ingress layers trafficClass,
    .receive payload ingress layers trafficClass ∈ events → ¬ model.GenuineControl payload →
    ∀ interface ∈ d.interfaces, d.Relevant interface.device → interface.id = ingress → interface.zone = .gray →
      d.IsLayer interface.device .outer →
      ∃ tunnel ∈ d.tunnels, tunnel.layer = .inner ∧ layers = [tunnel.id])

def Primitive_msc_transec_conditions (installations : List CoverInstallation) : Prop :=
  TDN.Targets.msc_transec_conditions (installations.map CoverInstallation.use) ∧
  (∀ installation ∈ installations, installation.use.enabled = installation.active) ∧
  ∀ installation ∈ installations,
    installation.use.publicInternet = true ∨
      (installation.use.objectiveSelected = true ∧ installation.use.externalMACsec = true ∧
        installation.use.outerFirewallAttached = true) →
    installation.active = true ∧ ScheduledCoverGuarantee installation.sender

structure FragmentationProfile where
  interface : Nat
  supportedPayloadSizes : List Nat
  workload : List Nat
  beforeMtu : Nat
  afterMtu : Nat
  beforeOverhead : Nat
  afterOverhead : Nat
  packetizeBefore : List UInt8 → List (List UInt8)
  packetizeAfter : List UInt8 → List (List UInt8)

def FragmentationProfile.CountBefore (profile : FragmentationProfile) (bytes : Nat) : Nat :=
  (bytes + (profile.beforeMtu - profile.beforeOverhead) - 1) /
    (profile.beforeMtu - profile.beforeOverhead)

def FragmentationProfile.CountAfter (profile : FragmentationProfile) (bytes : Nat) : Nat :=
  (bytes + (profile.afterMtu - profile.afterOverhead) - 1) /
    (profile.afterMtu - profile.afterOverhead)

def FragmentationProfile.Preserves (profile : FragmentationProfile)
    (packetize : List UInt8 → List (List UInt8)) (mtu overhead : Nat)
    (count : Nat → Nat) : Prop :=
  overhead < mtu ∧
  ∀ payload : List UInt8, payload.length ∈ profile.supportedPayloadSizes →
    (packetize payload).flatten = payload ∧
    (packetize payload).length = count payload.length ∧
    ∀ fragment ∈ packetize payload, fragment ≠ [] ∧ fragment.length + overhead ≤ mtu

def FragmentationProfile.Reduces (profile : FragmentationProfile) : Prop :=
  profile.workload ≠ [] ∧ profile.supportedPayloadSizes ≠ [] ∧
  profile.Preserves profile.packetizeBefore profile.beforeMtu profile.beforeOverhead
    profile.CountBefore ∧
  profile.Preserves profile.packetizeAfter profile.afterMtu profile.afterOverhead
    profile.CountAfter ∧
  (∀ bytes ∈ profile.workload, bytes ∈ profile.supportedPayloadSizes) ∧
  (∀ bytes ∈ profile.supportedPayloadSizes, 0 < bytes ∧
    profile.CountAfter bytes ≤ profile.CountBefore bytes) ∧
  ((profile.workload.map profile.CountAfter).sum < (profile.workload.map profile.CountBefore).sum ∨
    ∀ bytes ∈ profile.supportedPayloadSizes, profile.CountAfter bytes ≤ 1)

def Primitive_msc_packet_size_configuration (interfaces : List PacketSizing)
    (profiles : List FragmentationProfile) : Prop :=
  ∀ sizing ∈ interfaces,
    (sizing.role = .grayFirewallOrEncryptionExternal →
      0 < sizing.externalMtu ∧ 0 < sizing.payloadLimit ∧
      (sizing.family = .ipv6 → sizing.ipv6PmtuConfigured = true) ∧
      ∀ bytes, bytes ≤ sizing.payloadLimit → sizing.encodedSize bytes ≤ sizing.externalMtu) ∧
    (sizing.role = .innerExternal → sizing.innerObjectiveSelected = true →
      0 < sizing.externalMtu ∧
      (sizing.family = .ipv6 → sizing.ipv6PmtuConfigured = true) ∧
      ∃ profile ∈ profiles, profile.interface = sizing.interface ∧
        profile.afterMtu = sizing.externalMtu ∧
        (∀ bytes, 0 < bytes → bytes ≤ sizing.payloadLimit →
          bytes ∈ profile.supportedPayloadSizes ∧
          sizing.encodedSize bytes = bytes + profile.afterOverhead) ∧
        profile.Reduces)

structure WireSizeModel (State : Type) where
  payload : State → List UInt8
  serialize : State → LayeredFrame.Body → List UInt8 → List UInt8
  parse : State → List UInt8 → Option (LayeredFrame.Body × List UInt8)
  emission : State → PacketSource.Datagram
  configuredMtu : Nat → Nat
  configuredPayloadLimit : Nat → Nat

def WireSizeModel.StateEncoding {S A : Type} (sizes : WireSizeModel S)
    (model : ExecutionModel S A) (state : S) : Prop :=
  let native := model.native.state state
  native.frame.payload = PayloadCode (sizes.payload state) ∧
  sizes.parse state (sizes.serialize state native.frame.body (sizes.payload state)) =
    some (native.frame.body, sizes.payload state) ∧
  (sizes.payload state).length ≤
    (sizes.serialize state native.frame.body (sizes.payload state)).length ∧
  (match native.frame.visibleHeader with
   | some _ => model.native.configuration.networkBytes native.frame.body native.frame.payload =
       some (sizes.serialize state native.frame.body (sizes.payload state)).length
   | none => model.native.configuration.networkBytes native.frame.body native.frame.payload = none) ∧
  (∀ header, native.frame.body = .datagram header →
    header.payloadBytes = some (sizes.payload state) ∧
    header.networkBytes = some (sizes.serialize state native.frame.body (sizes.payload state)).length)

def WireSizeModel.WireEncoding {S A : Type} (sizes : WireSizeModel S)
    (model : ExecutionModel S A) (state : S) : Prop :=
  let native := model.native.state state
  let emission := sizes.emission state
  emission.Raw = sizes.serialize state native.frame.body (sizes.payload state) ∧
  emission.Reassembles (sizes.configuredMtu native.port) ∧
  match native.frame.visibleHeader with
  | some header =>
      emission.body = .datagram { header with networkBytes := some emission.Raw.length } ∧
      PacketSource.NetworkHeaderMatches header emission.networkHeader emission.Data.length
  | none =>
      ∃ header, emission.body = .ethernet header ∧
        PacketSource.EthernetHeaderMatches header emission.networkHeader ∧
        (∀ original, native.frame.body = .ethernet original → header = original) ∧
        (native.frame.body.isEthernetCiphertext = true → header.etherType = 35045)

def WireSizeModel.SourceEncoding {S A : Type} (sizes : WireSizeModel S)
    (model : ExecutionModel S A) : Prop :=
  ∀ start request datagram, model.initial start →
    model.sourceRecord start = some (request, datagram) →
    sizes.serialize start datagram.body datagram.application = datagram.Raw

def WireSizeModel.Correspondence {S A : Type} (sizes : WireSizeModel S)
    (model : ExecutionModel S A) (settings : List PacketSizing) : Prop :=
  sizes.SourceEncoding model ∧
  (∀ setting ∈ settings,
    setting.externalMtu = sizes.configuredMtu setting.interface ∧
    setting.payloadLimit = sizes.configuredPayloadLimit setting.interface) ∧
  (∀ start actions state, model.initial start → model.system.MTr start actions state →
    sizes.StateEncoding model state) ∧
  ∀ start actions before action after,
    model.initial start → model.system.MTr start actions before →
    model.system.Tr before action after → model.native.action action = some .wire →
    sizes.WireEncoding model before ∧
    ∀ setting ∈ settings, setting.interface = (model.native.state before).port →
      (sizes.payload before).length ≤ setting.payloadLimit ∧
      (sizes.emission before).MtuBytes ≤
        setting.encodedSize (sizes.payload before).length

def WireSizeModel.NoFurtherFragmentation {S A : Type} (sizes : WireSizeModel S)
    (model : ExecutionModel S A) (settings : List PacketSizing) : Prop :=
  ∀ start actions before action after setting,
    model.initial start → model.system.MTr start actions before →
    model.system.Tr before action after → model.native.action action = some .wire →
    setting ∈ settings → setting.interface = (model.native.state before).port →
    setting.role = .grayFirewallOrEncryptionExternal →
      (sizes.emission before).fragments.length = 1

def WireSizeModel.FragmentPayload {S A : Type} (sizes : WireSizeModel S)
    (model : ExecutionModel S A) (state : S) (fragment : PacketSource.Fragment)
    (payload : PayloadId) (sessions : List ProtectionSession) : Prop :=
  fragment ∈ (sizes.emission state).fragments ∧
  payload = ⟨(model.native.state state).frame.originDomain, (model.native.state state).frame.payload⟩ ∧
  sessions = BodySessions (model.native.state state).frame.body

def PacketSizingInventory {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (sizing : List PacketSizing) : Prop :=
  (∀ device ∈ d.devices, d.Relevant device.id → device.kind = .grayFirewall →
    ∃ interface ∈ d.interfaces, interface.device = device.id ∧ interface.externalData = true) ∧
  ∀ interface ∈ d.interfaces, ∀ device ∈ d.devices,
    interface.device = device.id → d.Relevant device.id →
    ((device.layer = some .inner ∧ interface.zone = .gray) ∨
      (device.layer = some .outer ∧ interface.zone = .black) ∨
      (device.kind = .grayFirewall ∧ interface.externalData = true)) →
    ∃ configuration ∈ sizing,
      model.native.portName configuration.interface = interface.id ∧
      configuration.role = (if device.layer = some .inner then
        .innerExternal else .grayFirewallOrEncryptionExternal) ∧
      (∀ address, interface.address = some address →
        (address < 2^32 → configuration.family = .ipv4) ∧
        (2^128 ≤ address → configuration.family = .ipv6))

def Primitive_msc_outer_firewall_placement {Node : Type}
    (untrustedBlack publicInternet grayFirewallRequired : Bool)
    (edge grayConnection : Node → Node → Prop)
    (outer firewall black grayFirewall inner : Node → Prop)
    (insideAttachment outsideAttachment externalBlackConnection : Node → Node → Prop) : Prop :=
  TDN.Targets.msc_outer_firewall_placement untrustedBlack publicInternet grayFirewallRequired
    edge grayConnection outer firewall black grayFirewall inner
    insideAttachment outsideAttachment externalBlackConnection

def ApprovedControl (d : Deployment) (device : String) (traffic : Traffic) : Prop :=
  traffic.trafficClass = .control ∧ d.policyApproved device traffic

def AOApprovedControl (d : Deployment) (device : String) (traffic : Traffic) : Prop :=
  ApprovedControl d device traffic ∧ d.aoApproved device traffic

def LocalOuterAddress (d : Deployment) (firewall outer : String) (address : Nat) : Prop :=
  d.IsDevice firewall .outerFirewall ∧ d.IsLayer outer .outer ∧
  ∃ interface ∈ d.interfaces, interface.device = outer ∧ interface.zone = .black ∧
    interface.address = some address

def Primitive_msc_boundary_interface_filtering (d : Deployment) (outerFirewallRequired : Bool)
    (firewallInternal : String → Bool) (localOuter : String → String) : Prop :=
  d.AddressInventoryCoherent ∧ d.ProcessingCoherent ∧ d.UDPBindingsCoherent ∧
  ∀ interface ∈ d.interfaces, d.Relevant interface.device → ∀ device ∈ d.devices, d.Relevant device.id → interface.device = device.id →
    ((device.layer = some .outer ∧ interface.zone = .black) ∨
      (device.layer = some .inner ∧ interface.zone = .gray) ∨
      (device.layer = some .inner ∧ interface.zone = .red) ∨
      (device.kind = .outerFirewall ∧ outerFirewallRequired = true)) →
    d.PolicyCoverage interface ∧ ∀ direction traffic, d.Accepts interface.id direction traffic →
      (device.layer = some .outer → interface.zone = .black →
        ((device.kind = .vpn → d.IPsecTraffic traffic ∨
          ApprovedControl d device.id traffic) ∧
        (device.kind = .macsec → PacketMACsec traffic.packet ∨
          ApprovedControl d device.id traffic) ∧
        (direction = .outbound → d.IntendedPacketPeerAt interface.id device.id traffic))) ∧
      (device.layer = some .inner → interface.zone = .gray →
        d.PermittedTunnelTraffic traffic ∨ AOApprovedControl d device.id traffic) ∧
      (device.layer = some .inner → interface.zone = .red →
        d.redService device.id traffic.packet.source traffic.packet.sourcePort ∨
        d.redService device.id traffic.packet.destination traffic.packet.destinationPort) ∧
      (device.kind = .outerFirewall → outerFirewallRequired = true →
        (d.PermittedTunnelTraffic traffic ∨ ApprovedControl d device.id traffic) ∧
        (direction = .inbound → ¬ ApprovedControl d device.id traffic →
          if firewallInternal interface.id then
            LocalOuterAddress d device.id (localOuter device.id) traffic.packet.source
          else LocalOuterAddress d device.id (localOuter device.id) traffic.packet.destination))

structure ThirdPartyFeature where
  device : String
  id : String
  canContactThirdParty : Bool
  enabled : Bool
  emittedTraffic : Traffic → Prop

def Primitive_msc_outer_third_party_services (d : Deployment) (objectiveSelected : String → Bool)
    (features : List ThirdPartyFeature) : Prop :=
  ∀ feature ∈ features, d.Relevant feature.device → d.IsLayer feature.device .outer → feature.canContactThirdParty = true →
    if objectiveSelected feature.device then feature.enabled = false else
      ∀ interface ∈ d.interfaces, d.Relevant interface.device → interface.device = feature.device →
        ∀ traffic, feature.emittedTraffic traffic →
          ¬ d.Accepts interface.id .outbound traffic

def HeaderFilterApplies (device : Device) (interface : Interface) : Prop :=
  (device.layer = some .outer ∧ interface.zone = .black) ∨ device.kind = .vpn

def NecessaryApprovedL2Control (d : Deployment) (interface : Interface) (traffic : Traffic) : Prop :=
  traffic.trafficClass = .control ∧ d.policyApproved interface.device traffic ∧
  traffic.packet.destination = 1652522221571 ∧
  ∃ inventory, d.processing = some inventory ∧
    ∃ endpoint ∈ inventory.mkaPeers,
      inventory.portName endpoint.destinationPort = interface.id ∧
      PacketPolicy.Packet.MKAFraming traffic.packet endpoint.actorSCI ∧
      (traffic.packet.payloadBytes.bind (fun bytes => bytes[0]?)) = some 3 ∧
      ∃ tunnel ∈ d.tunnels, tunnel.id = endpoint.tunnel ∧ tunnel.layer = .outer ∧
        tunnel.mechanism = .macsec ∧
        inventory.componentName (inventory.configuration.ip.owner endpoint.sourcePort) = tunnel.sender ∧
        inventory.componentName (inventory.configuration.ip.owner endpoint.destinationPort) = tunnel.receiver ∧
        tunnel.receiver = interface.device ∧ d.intendedPeer tunnel.sender tunnel.receiver

def Primitive_msc_ip_header_and_multicast_filtering (d : Deployment)
    (dropIPv4OptionsObjective : String → Bool) : Prop :=
  (∀ device, dropIPv4OptionsObjective device = d.dropIPv4Options device) ∧
  d.AddressInventoryCoherent ∧ d.ProcessingCoherent ∧ d.LinkPoliciesComplete ∧
  ∀ interface ∈ d.interfaces, d.Relevant interface.device → ∀ device ∈ d.devices, d.Relevant device.id → interface.device = device.id →
    HeaderFilterApplies device interface →
    d.PolicyCoverage interface ∧
    ∀ traffic, d.Accepts interface.id .inbound traffic →
      (device.layer = some .outer → interface.zone = .black →
        traffic.multicast = false ∨ NecessaryApprovedL2Control d interface traffic) ∧
      (device.kind = .vpn → traffic.ipVersion = some 4 → traffic.ipProtocol ∈ [6, 17, 50, 1]) ∧
      (device.kind = .vpn → traffic.ipVersion = some 6 →
        traffic.packet.ipv6NextHeader ∈ [50, 6, 17, 58]) ∧
      (device.kind = .vpn → device.layer = some .outer → traffic.ipVersion = some 4 →
        dropIPv4OptionsObjective device.id = true → traffic.packet.ipv4HeaderWords = 5)

def OuterManagementInitiation (d : Deployment) (traffic : Traffic) : Prop :=
  traffic.trafficClass = .management ∧
    (d.grayWorkstation traffic.originator ∨
      (d.IsLayer traffic.originator .outer ∧ traffic.service ∈ ["logging", "authentication"]))

def OuterTunnelAllowance (d : Deployment) (device : String) (traffic : Traffic) : Prop :=
  (d.TunnelTraffic traffic ∨ (∃ source destination, d.CarrierInnerPair traffic source destination)) ∧
    ((d.SameLevelInner traffic ∧ d.AppropriateInnerTunnel traffic) ∨
      (d.grayManagementService device traffic ∧ d.GrayManagementTunnel traffic))

def RevocationHTTP (traffic : Traffic) : Prop :=
  traffic.service = "http" ∧ traffic.innerRevocation = true

def OuterPolicyAllowance (d : Deployment) (device : String) (cdpOnGray : Bool)
    (traffic : Traffic) : Prop :=
  OuterTunnelAllowance d device traffic ∨
    (cdpOnGray = true ∧ d.IsDevice device .vpn ∧ RevocationHTTP traffic) ∨
    ((traffic.trafficClass = .management ∨ traffic.trafficClass = .control) ∧
      d.policyApproved device traffic)

def OuterGrayRestrictions (d : Deployment) (interface : Interface) (direction : Direction)
    (cdpOnGray : Bool) (traffic : Traffic) : Prop :=
  d.HeaderEligible interface traffic ∧
  (traffic.trafficClass = .management → OuterManagementInitiation d traffic) ∧
  (direction = .inbound → d.reachableSource interface.id traffic.packet.source) ∧
  (traffic.trafficClass = .protectedData → ¬ RevocationHTTP traffic →
    d.SameLevelInner traffic ∨
      (d.grayManagementService interface.device traffic ∧ d.GrayManagementTunnel traffic)) ∧
  (traffic.service = "http" → cdpOnGray = true → d.IsDevice interface.device .vpn →
    traffic.innerRevocation = true)

def Primitive_msc_outer_gray_interface_policy (d : Deployment) (cdpOnGray : Bool) : Prop :=
  d.AddressInventoryCoherent ∧ d.ProcessingCoherent ∧ d.UDPBindingsCoherent ∧
  ∀ interface ∈ d.interfaces, d.Relevant interface.device → d.IsLayer interface.device .outer → interface.zone = .gray →
    d.PolicyCoverage interface ∧
    (∀ direction traffic, d.Accepts interface.id direction traffic →
      OuterGrayRestrictions d interface direction cdpOnGray traffic ∧
      OuterPolicyAllowance d interface.device cdpOnGray traffic) ∧
    ∀ direction hook traffic, d.PacketEligibleAt interface direction hook traffic →
      OuterGrayRestrictions d interface direction cdpOnGray traffic →
      OuterPolicyAllowance d interface.device cdpOnGray traffic →
      d.AcceptsAt interface.id direction hook traffic

def GrayManagementAllowance (d : Deployment) (interface : Interface) (traffic : Traffic) : Prop :=
  interface.physical = true ∧ interface.managementNetwork = true ∧
    traffic.trafficClass = .management ∧ d.grayManagementService interface.device traffic ∧
    d.policyApproved interface.device traffic

def GrayPolicyAllowance (d : Deployment) (interface : Interface) (traffic : Traffic) : Prop :=
  ((d.TunnelTraffic traffic ∨ (∃ source destination, d.CarrierInnerPair traffic source destination)) ∧
    d.SameLevelInner traffic ∧ d.AppropriateInnerTunnel traffic) ∨ RevocationHTTP traffic ∨
    GrayManagementAllowance d interface traffic ∨
    (traffic.trafficClass = .control ∧ d.policyApproved interface.device traffic)

def DifferentClassificationVPNs (d : Deployment) (traffic : Traffic) : Prop :=
  ∃ source ∈ d.devices, ∃ destination ∈ d.devices,
    source.kind = .vpn ∧ destination.kind = .vpn ∧
    source.layer = some .inner ∧ destination.layer = some .inner ∧
    source.level.classification ≠ destination.level.classification ∧
    d.InnerPair traffic source.id destination.id

def GrayFirewallRestrictions (d : Deployment) (interface : Interface) (direction : Direction)
    (traffic : Traffic) : Prop :=
  d.HeaderEligible interface traffic ∧
  (traffic.trafficClass = .management → GrayManagementAllowance d interface traffic) ∧
  (traffic.trafficClass = .protectedData → ¬ RevocationHTTP traffic → d.SameLevelInner traffic) ∧
  (direction = .inbound → d.reachableSource interface.id traffic.packet.source) ∧
  (traffic.service = "http" → traffic.innerRevocation = true) ∧
  ¬ DifferentClassificationVPNs d traffic

def Primitive_msc_gray_firewall_allowlist (d : Deployment) (grayFirewallRequired : Bool) : Prop :=
  d.AddressInventoryCoherent ∧
  (grayFirewallRequired = true → d.ProcessingCoherent ∧ d.UDPBindingsCoherent ∧
    ∀ interface ∈ d.interfaces, d.Relevant interface.device →
      d.IsDevice interface.device .grayFirewall → d.PolicyCoverage interface ∧
        (∀ direction traffic, d.Accepts interface.id direction traffic →
          GrayFirewallRestrictions d interface direction traffic ∧
          GrayPolicyAllowance d interface traffic) ∧
        ∀ direction hook traffic, d.PacketEligibleAt interface direction hook traffic →
          GrayFirewallRestrictions d interface direction traffic →
          GrayPolicyAllowance d interface traffic →
          d.AcceptsAt interface.id direction hook traffic) ∧
  ∀ interface ∈ d.interfaces, d.Relevant interface.device → d.IsDevice interface.device .grayFirewall →
    ∀ direction traffic, DifferentClassificationVPNs d traffic →
      ¬ d.Accepts interface.id direction traffic

def Primitive_msc_administrator_authentication (d : Deployment)
    (certificateObjective nistObjective : Bool) (events : List AdminEvent)
    (accounts : List AdministrativeAccount) (sessions : List AdministrativeSession)
    (awAdministrators : List Nat) : Prop :=
  TDN.Targets.msc_administrator_authentication certificateObjective nistObjective
    events accounts sessions awAdministrators ∧
  ∀ event ∈ events, event.kind = .authentication →
    (certificateObjective = true → d.authority.certificateCNSACompliant event.credential) ∧
    (nistObjective = true → d.authority.authenticationConformsToNIST80063 event.credential)

structure Interoperation where
  firstSite : String
  secondSite : String
  layer : Layer
  mechanism : Mechanism
  firstComponent : String
  secondComponent : String
  forwardTunnel : String
  reverseTunnel : String

structure PayloadDomain where
  protocols : List String
  maximumBytes : Nat

def PayloadDomain.Supports (domain : PayloadDomain) (protocol : String)
    (bytes : List UInt8) : Prop :=
  protocol ∈ domain.protocols ∧ bytes.length ≤ domain.maximumBytes

def TunnelTransfer {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (domain : PayloadDomain) (tunnel : Tunnel) : Prop :=
  domain.protocols ≠ [] ∧ 0 < domain.maximumBytes ∧
  ∀ protocol bytes, domain.Supports protocol bytes →
  ∃ start actions finish payload session sent received senderPort receiverPort earlier
      encryptToSend sendToReceive receiveToDecrypt later,
    model.initial start ∧ model.system.MTr start actions finish ∧
    payload.value = PayloadCode bytes ∧
    payload.originDomain = (model.native.state start).frame.originDomain ∧
    payload.value = (model.native.state start).frame.payload ∧
    ((∃ header, (model.native.state start).frame.body.originalHeader = some header ∧
      header.protocol = protocol) ∨ (protocol = "ethernet" ∧
      (model.native.state start).frame.body.originalEthernet.isSome = true)) ∧
    model.native.SessionTunnel session = tunnel.id ∧
    senderPort ∈ d.interfaces ∧ receiverPort ∈ d.interfaces ∧
    senderPort.device = tunnel.sender ∧ receiverPort.device = tunnel.receiver ∧
    session ∈ sent ∧ session ∈ received ∧ sent = received ∧
    model.TraceEvents actions =
      earlier ++ [.protect payload tunnel.id session] ++ encryptToSend ++
      [.sessionTransmit payload senderPort.id sent] ++ sendToReceive ++
      [.sessionReceive payload receiverPort.id received] ++ receiveToDecrypt ++
      [.unprotect payload tunnel.id session] ++ later

def RequiredSitePairsBound (d : Deployment) (pairs : List (String × String)) : Prop :=
  (∀ source ∈ d.devices, ∀ destination ∈ d.devices,
    d.intendedPeer source.id destination.id → source.site ≠ destination.site →
      (source.site, destination.site) ∈ pairs ∨ (destination.site, source.site) ∈ pairs) ∧
  ∀ pair ∈ pairs, pair.1 ≠ pair.2 ∧
    (∃ source ∈ d.devices, source.site = pair.1) ∧
    (∃ destination ∈ d.devices, destination.site = pair.2)

def Interoperation.Binds (choice : Interoperation) (d : Deployment)
    (forward reverse : Tunnel) : Prop :=
  forward.id = choice.forwardTunnel ∧ reverse.id = choice.reverseTunnel ∧
  forward.sender = choice.firstComponent ∧ forward.receiver = choice.secondComponent ∧
  reverse.sender = choice.secondComponent ∧ reverse.receiver = choice.firstComponent ∧
  forward.layer = choice.layer ∧ reverse.layer = choice.layer ∧
  forward.mechanism = choice.mechanism ∧ reverse.mechanism = choice.mechanism ∧
  choice.firstSite ≠ choice.secondSite ∧
  ∃ first ∈ d.devices, ∃ second ∈ d.devices,
    first.id = choice.firstComponent ∧ second.id = choice.secondComponent ∧
    first.site = choice.firstSite ∧ second.site = choice.secondSite ∧
    first.layer = some choice.layer ∧ second.layer = some choice.layer ∧
    (choice.mechanism = .ipsec → first.kind = .vpn ∧ second.kind = .vpn) ∧
    (choice.mechanism = .macsec → first.kind = .macsec ∧ second.kind = .macsec)

def Interoperation.Relevant (choice : Interoperation) (d : Deployment) : Prop :=
  d.Relevant choice.firstComponent ∨ d.Relevant choice.secondComponent

def InteroperationInventory (d : Deployment) (selected : List Interoperation) : Prop :=
  (∀ choice ∈ selected,
    ∃ forward ∈ d.tunnels, ∃ reverse ∈ d.tunnels, choice.Binds d forward reverse) ∧
  (∀ source ∈ d.devices, ∀ destination ∈ d.devices,
    d.intendedPeer source.id destination.id → source.site ≠ destination.site →
    (d.Relevant source.id ∨ d.Relevant destination.id) →
    ∃ choice ∈ selected,
      (choice.firstComponent = source.id ∧ choice.secondComponent = destination.id) ∨
      (choice.firstComponent = destination.id ∧ choice.secondComponent = source.id)) ∧
  ∀ tunnel ∈ d.tunnels, (d.Relevant tunnel.sender ∨ d.Relevant tunnel.receiver) →
    ∃ choice ∈ selected, choice.Relevant d ∧
      ∃ opposite ∈ d.tunnels, choice.Binds d tunnel opposite ∨ choice.Binds d opposite tunnel

def InteroperationTransfers {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (selected : List Interoperation) (domain : PayloadDomain) : Prop :=
  ∀ choice ∈ selected, choice.Relevant d →
    ∃ forward ∈ d.tunnels, ∃ reverse ∈ d.tunnels,
      choice.Binds d forward reverse ∧
      TunnelTransfer d model domain forward ∧ TunnelTransfer d model domain reverse

def SiteLayerInteroperationCoverage (pairs : List (String × String))
    (selected : List Interoperation) : Prop :=
  ∀ pair ∈ pairs, ∀ layer, ∃ choice ∈ selected,
    choice.firstSite = pair.1 ∧ choice.secondSite = pair.2 ∧ choice.layer = layer

def Primitive_msc_site_interoperability {S A : Type} (d : Deployment) (model : ExecutionModel S A)
    (requiredSitePairs : List (String × String)) (selected : List Interoperation)
    (domain : PayloadDomain) : Prop :=
  model.CoversDeployment d ∧ RequiredSitePairsBound d requiredSitePairs ∧
  SiteLayerInteroperationCoverage requiredSitePairs selected ∧
  InteroperationInventory d selected ∧ InteroperationTransfers d model selected domain

def RedEgressCore (d : Deployment)
    (red outside : String → Prop) (conformingMSC aoApprovedProtection : String → Prop) : Prop :=
  (∀ solution, aoApprovedProtection solution → d.authority.aoApprovedTransitSolution solution) ∧
  ∀ source destination, red source → outside destination →
    ¬ Relation.ReflTransGen (Paths.Avoiding d.DeviceAdjacent
      (fun node => conformingMSC node ∨ aoApprovedProtection node)) source destination

end TDN.Targets.Complete
