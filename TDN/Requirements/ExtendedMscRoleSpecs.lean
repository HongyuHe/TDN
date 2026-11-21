import TDN.Requirements.ScopedMscRequirements
import TDN.Requirements.CrossEnclavePkiIsolationSpec
import TDN.Requirements.MscAddressingRequirements
import TDN.Requirements.ManagementPlaneRequirements
import TDN.Requirements.TunnelMtuAndFragmentationSpec
import TDN.Requirements.TrafficFlowConfidentialitySpec

namespace TDN.Requirements.Msc
open Compliance

def ManagementDeployed (d : Deployment) : Prop :=
  ∃ workstation ∈ d.devices, workstation.kind = .workstation

def RoleCatalog.security_level_key_and_management_separation (managementDeployed : Bool)
    (peers : List InnerAuthentication) (establishedTunnel : String → String → Prop) : Prop :=
  TDN.Requirements.msc_security_level_key_and_management_separation managementDeployed peers ∧
  ∀ a ∈ peers, ∀ b ∈ peers, a.level ≠ b.level → ¬ establishedTunnel a.component b.component

def RoleCatalog.gray_addressing_for_level_filtering (d : Deployment)
    (ranges : List (Addressing.Range SecurityLevel)) (pairs : List IntendedAddressPair) : Prop :=
  d.AddressInventoryCoherent ∧
  ValidGrayAddressPlan ranges pairs ∧
  (∀ interface ∈ d.interfaces, d.InScope interface.device → interface.zone = .gray → d.IsLayer interface.device .inner →
    ∃ device ∈ d.devices, device.id = interface.device ∧
      ∃ address, interface.address = some address ∧ Addressing.Owns ranges address device.level) ∧
  ∀ device ∈ d.devices, d.InScope device.id → device.layer = some .outer ∨ device.kind = .grayFirewall →
    FiltersIntendedPeers d device.id ∧
    ∀ interface ∈ d.interfaces, d.InScope interface.device → interface.device = device.id → interface.zone = .gray →
      ∀ direction traffic, d.PermitsOnInterface interface.id direction traffic → InnerEndpoints d traffic →
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

def macsec_encapsulation_over_ip {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (uses : List EncapsulationUse) (crossesIP : String → Bool) : Prop :=
  model.CoversDeployment d ∧
  (∀ tunnel ∈ d.tunnels, (d.InScope tunnel.sender ∨ d.InScope tunnel.receiver) → tunnel.protocol = .macsec →
    tunnel.layer = .inner ∨ crossesIP tunnel.id = true →
      ∃ use ∈ uses, use.protectedTunnel = tunnel.id ∧ use.inner = tunnel.sender ∧
        (tunnel.layer = .inner → use.outer.isSome = true) ∧
        (crossesIP tunnel.id = true → use.traversesIP = true)) ∧
  (∀ use ∈ uses, (d.InScope use.inner ∨ d.InScope use.encapsulator ∨
      d.InScope use.remoteEncapsulator) →
    d.authority.aoApprovedEncapsulation use.protocol ∧
    (use.builtInSupported = false → d.standaloneEncapsulator use.encapsulator ∧
      d.OwnedGrayAttachment use.inner use.encapsulator use.inputInterface ∧
      (∀ outer, use.outer = some outer →
        d.OwnedGrayExit use.encapsulator use.outputInterface outer))) ∧
  model.AllTraces (fun events => ∀ use ∈ uses, (d.InScope use.inner ∨ d.InScope use.encapsulator ∨
      d.InScope use.remoteEncapsulator) → ∀ payload,
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
  ∀ gateway key, d.InScope gateway →
    (d.storedVPNKey gateway key ↔ ∃ entry ∈ keys, entry.gateway = gateway ∧ entry.id = key)

def RoleCatalog.vpn_private_key_confinement {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (keys : List PrivateKey) (objectiveSelected : String → Bool)
    (policies : List MandatoryKeyPolicy) : Prop :=
  StoredVPNKeyInventory d keys ∧
  (model.AllTraces (fun events => ∀ key ∈ keys, d.InScope key.gateway → ∀ interface,
    .privateKeyExport key.gateway key.id interface ∉ events)) ∧
  (∀ key ∈ keys, d.InScope key.gateway → objectiveSelected key.gateway = true → ∃ policy ∈ policies,
    policy.gateway = key.gateway ∧ policy.enforced = true ∧
    ∀ principal, policy.permits principal key.id → principal = key.gateway) ∧
  model.AllTraces (fun events => ∀ key ∈ keys, d.InScope key.gateway → objectiveSelected key.gateway = true →
    ∀ principal, .privateKeyRead key.gateway key.id principal ∈ events → principal = key.gateway)

inductive MacsecAuthenticationMethod where
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

structure EapTlsAuthProvider where
  mutuallyAuthenticate : TLSHandshakeInput → Option TLSVerifiedSession
  authenticateBackendDelivery : EAPBackendInput → Option EAPBackendVerified
  supportsRole : String → EAPRole → Bool
  deriveCAK : String → String

def EAPBackendDelivery.Successful (tlsAuth : EapTlsAuthProvider)
    (delivery : EAPBackendDelivery) : Prop :=
  delivery.input.channelBinding ≠ [] ∧ delivery.input.protectedRecord ≠ [] ∧
  delivery.input.nonce ≠ [] ∧
  tlsAuth.authenticateBackendDelivery delivery.input = some delivery.verified ∧
  delivery.verified.session = delivery.input.session ∧
  delivery.verified.server = delivery.input.server ∧
  delivery.verified.authenticator = delivery.input.authenticator ∧
  delivery.verified.supplicant = delivery.input.supplicant ∧
  delivery.verified.masterSessionKey = delivery.input.masterSessionKey

structure EAPExchange where
  input : TLSHandshakeInput
  verified : TLSVerifiedSession

def EAPExchange.Successful (tlsAuth : EapTlsAuthProvider) (exchange : EAPExchange) : Prop :=
  exchange.input.session ≠ "" ∧ exchange.input.transcript ≠ [] ∧
  exchange.input.deviceNonce ≠ [] ∧ exchange.input.serverNonce ≠ [] ∧
  tlsAuth.mutuallyAuthenticate exchange.input = some exchange.verified ∧
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

structure MacsecAuthentication where
  device : String
  peer : String
  method : MacsecAuthenticationMethod
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

def EAPDeviceExchange (tlsAuth : EapTlsAuthProvider) (selected : MacsecAuthentication)
    (exchange : EAPExchange) : Prop :=
  exchange.Successful tlsAuth ∧ exchange.input.device = selected.device ∧
  exchange.input.server = selected.server ∧
  exchange.input.deviceCertificate = selected.deviceCertificate ∧
  exchange.input.serverCertificate = selected.serverCertificate ∧
  exchange.input.deviceIdentity = selected.deviceIdentity ∧
  exchange.input.serverIdentity = selected.serverIdentity ∧
  exchange.verified.masterSessionKey = selected.masterSessionKey

def EAPPeerExchange (tlsAuth : EapTlsAuthProvider) (selected : MacsecAuthentication)
    (exchange : EAPExchange) : Prop :=
  exchange.Successful tlsAuth ∧ exchange.input.device = selected.peer ∧
  exchange.input.server = selected.server ∧
  exchange.input.deviceCertificate = selected.peerCertificate ∧
  exchange.input.serverCertificate = selected.serverCertificate ∧
  exchange.input.deviceIdentity = selected.peerIdentity ∧
  exchange.input.serverIdentity = selected.serverIdentity ∧
  exchange.verified.masterSessionKey = selected.peerMasterSessionKey

def EAPSelectedExchange (tlsAuth : EapTlsAuthProvider) (selected : MacsecAuthentication)
    (exchange : EAPExchange) : Prop :=
  exchange.input.role = .supplicant ∧
  ((selected.eapSupplicant = selected.device ∧ selected.eapAuthenticator = selected.peer ∧
      EAPDeviceExchange tlsAuth selected exchange) ∨
    (selected.eapSupplicant = selected.peer ∧ selected.eapAuthenticator = selected.device ∧
      EAPPeerExchange tlsAuth selected exchange))

def EAPSessionBinding (tlsAuth : EapTlsAuthProvider) (selected : MacsecAuthentication)
    (exchange : EAPExchange) : Prop :=
  EAPSelectedExchange tlsAuth selected exchange ∧
  selected.backendDelivery.Successful tlsAuth ∧
  selected.backendDelivery.input.session = exchange.input.session ∧
  selected.backendDelivery.input.server = selected.server ∧
  selected.backendDelivery.input.authenticator = selected.eapAuthenticator ∧
  selected.backendDelivery.input.supplicant = selected.eapSupplicant ∧
  selected.backendDelivery.input.masterSessionKey = exchange.verified.masterSessionKey ∧
  selected.masterSessionKey = exchange.verified.masterSessionKey ∧
  selected.peerMasterSessionKey = exchange.verified.masterSessionKey ∧
  selected.cak = tlsAuth.deriveCAK selected.masterSessionKey ∧
  selected.peerCAK = tlsAuth.deriveCAK selected.peerMasterSessionKey ∧
  selected.cak = selected.peerCAK

def EAPEndpointRoleEvidence (tlsAuth : EapTlsAuthProvider) (selected : MacsecAuthentication) : Prop :=
  ∀ endpoint ∈ [selected.device, selected.peer],
    (∀ role ∈ selected.supportedRoles, tlsAuth.supportsRole endpoint role = true) ∧
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
      exchange.Successful tlsAuth


def SAKKeyUseAt (selected : MacsecAuthentication) (payload : PayloadId) (tunnel : String)
    (events : List NetworkEvent) (authenticated issued used : Nat) : Prop :=
  events[authenticated]? = some (.authenticate selected.keyServer
    (if selected.keyServer = selected.device then selected.peer else selected.device) selected.cak) ∧
  events[issued]? = some (.issueSAK selected.keyServer
    (if selected.keyServer = selected.device then selected.peer else selected.device)
      selected.secureAssociationKey) ∧
  events[used]? = some (.useSAK payload tunnel selected.secureAssociationKey) ∧
  authenticated < issued ∧ issued < used

def PreSharedKeyUsePrefix (selected : MacsecAuthentication) (payload : PayloadId)
    (tunnel : String) (events : List NetworkEvent) : Prop :=
  ∃ authenticated issued used, SAKKeyUseAt selected payload tunnel events authenticated issued used

def EAPKeyUsePrefix (tlsAuth : EapTlsAuthProvider) (selected : MacsecAuthentication)
    (payload : PayloadId) (tunnel : String) (events : List NetworkEvent) : Prop :=
  ∃ exchange ∈ selected.exchanges, EAPSessionBinding tlsAuth selected exchange ∧
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

def MACsecKeyUsePrefix (tlsAuth : EapTlsAuthProvider) (selected : MacsecAuthentication)
    (payload : PayloadId) (tunnel : String) (events : List NetworkEvent) : Prop :=
  match selected.method with
  | .preSharedCAK => PreSharedKeyUsePrefix selected payload tunnel events
  | .eapTLS => EAPKeyUsePrefix tlsAuth selected payload tunnel events

def HistoricalSetup (history : ObservedHistory) (session : Option String)
    (event : NetworkEvent) (position : Nat) : Prop :=
  ∃ record ∈ history.entries, record.position = position ∧
    record.session = session ∧ record.event = event

def HistoricalSAKSetup (history : ObservedHistory) (selected : MacsecAuthentication)
    (installation : MacsecHistoryInstallation) : Prop :=
  installation.issuer = selected.keyServer ∧
  installation.peer = (if selected.keyServer = selected.device then selected.peer else selected.device) ∧
  installation.keyReference = selected.secureAssociationKey ∧
  ∃ authenticated,
    HistoricalSetup history installation.session (.authenticate installation.issuer
      installation.peer selected.cak) authenticated ∧ history.CausallyBefore authenticated installation.issuedAt

def HistoricalEAPSetup (history : ObservedHistory) (tlsAuth : EapTlsAuthProvider)
    (selected : MacsecAuthentication) (installation : MacsecHistoryInstallation) : Prop :=
  ∃ exchange ∈ selected.exchanges, EAPSessionBinding tlsAuth selected exchange ∧
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

def MACsecInstalledHistory {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (tlsAuth : EapTlsAuthProvider) (authentication : List MacsecAuthentication) : Prop :=
  model.history.Valid ∧
  ∀ iface ∈ model.deviceDataPlane.configuration.macIfaces, ∀ association,
    iface.transmitAssociation = some association →
    let owner := model.deviceDataPlane.componentName
      (model.deviceDataPlane.configuration.ip.owner iface.physicalIface)
    d.InScope owner →
    ∃ installation ∈ model.macsecInstallationHistory,
      installation.Bound model ∧
      installation.device = model.deviceDataPlane.configuration.ip.owner iface.physicalIface ∧
      installation.association = association ∧
      ∃ tunnel ∈ d.tunnels, tunnel.id = model.deviceDataPlane.macsecTunnel association ∧
        tunnel.sender = owner ∧ tunnel.protocol = .macsec ∧
        ∃ selected ∈ authentication, selected.device = owner ∧ selected.peer = tunnel.receiver ∧
          HistoricalSAKSetup model.history selected installation ∧
          match selected.method with
          | .preSharedCAK => installation.session = none
          | .eapTLS => HistoricalEAPSetup model.history tlsAuth selected installation

def RoleCatalog.macsec_authentication_choice_and_as {S A : Type} (d : Deployment)
    (model : ForwardingModel S A) (tlsAuth : EapTlsAuthProvider)
    (authentication : List MacsecAuthentication) : Prop :=
  MACsecInstalledHistory d model tlsAuth authentication ∧
  (∀ device ∈ d.devices, d.InScope device.id → device.kind = .macsec →
    ∃ selected ∈ authentication, selected.device = device.id) ∧
  (∀ selected ∈ authentication, (d.InScope selected.device ∨ d.InScope selected.server) →
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
        EAPEndpointRoleEvidence tlsAuth selected ∧
        (∃ exchange ∈ selected.exchanges, EAPSessionBinding tlsAuth selected exchange) ∧
        (∀ site zone, (site, zone) ∈ selected.serverAttachments ↔
          d.networkAttachment selected.server site zone) ∧
        (∃ site zone, selected.serverAttachments ≠ [] ∧
          ∀ attachment ∈ selected.serverAttachments, attachment = (site, zone)) ∧
        ∀ attachment ∈ selected.serverAttachments, attachment.2 = .red ∨ attachment.2 = .gray) ∧
  model.AllTraces (fun events => ∀ earlier later payload tunnel,
    events = earlier ++ [.encrypt payload tunnel] ++ later →
    ∀ configured ∈ d.tunnels, configured.id = tunnel → configured.protocol = .macsec →
    ∃ selected ∈ authentication, selected.device = configured.sender ∧
      selected.peer = configured.receiver ∧
      MACsecKeyUsePrefix tlsAuth selected payload tunnel earlier)

inductive KeyOrigin where
  | generated (generator : String)
  | eapDerived (masterSessionKey : String)
  deriving DecidableEq

structure MacsecKey where
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


structure MacsecServerPair where
  first : String
  second : String
  firstValue : Nat
  secondValue : Nat
  centralSite : Option String

def RoleCatalog.macsec_key_generation_and_server (d : Deployment) (keys : List MacsecKey)
    (pairs : List MacsecServerPair) (provisioning : List KeyProvisioning)
    (eapCAKGeneratedByApprovedKGS : String → String → Prop) : Prop :=
  (∀ key ∈ keys, d.KeyInScope key.cak → 16 ≤ key.ckn.length ∧ d.authority.nsaApprovedGenerator key.cknGenerator ∧
    (match key.cakOrigin with
      | .generated generator => d.authority.nsaApprovedGenerator generator ∧
          ∃ provision ∈ provisioning, provision.key = key.cak ∧ provision.generator = generator ∧
            d.authority.securityAdministrator provision.administrator ∧
            ∀ tunnel ∈ d.tunnels, (d.InScope tunnel.sender ∨ d.InScope tunnel.receiver) → tunnel.protocol = .macsec → tunnel.keyContext = key.cak →
              (∃ applied ∈ provision.applications, applied.1 = tunnel.sender ∧
                provision.obtainedOrder < applied.2) ∧
              ∃ applied ∈ provision.applications, applied.1 = tunnel.receiver ∧
                provision.obtainedOrder < applied.2
      | .eapDerived msk => msk ≠ "" ∧ ∃ generator, d.authority.nsaApprovedGenerator generator ∧
          eapCAKGeneratedByApprovedKGS key.cak generator) ∧ key.fallbackEnabled = false) ∧
  (∀ tunnel ∈ d.tunnels, (d.InScope tunnel.sender ∨ d.InScope tunnel.receiver) → tunnel.protocol = .macsec →
    (∃ key ∈ keys, key.cak = tunnel.keyContext) ∧
    ∃ pair ∈ pairs, pair.first = tunnel.sender ∧ pair.second = tunnel.receiver) ∧
  ∀ pair ∈ pairs, (d.InScope pair.first ∨ d.InScope pair.second) → pair.centralSite = d.centralManagementSite ∧ pair.first ≠ pair.second ∧
    ((pair.firstValue = 0 ∧ pair.secondValue = 1) ∨
      (pair.firstValue = 1 ∧ pair.secondValue = 0)) ∧
    ∀ site, pair.centralSite = some site →
      (∃ first ∈ d.devices, first.id = pair.first ∧ first.site = site ∧ pair.firstValue = 0) ∨
      (∃ second ∈ d.devices, second.id = pair.second ∧ second.site = site ∧ pair.secondValue = 0)

structure MacsecParameters where
  device : String
  dataDelayProtection : Bool
  lifetimeMilliseconds : Nat
  normalHelloMilliseconds : Nat
  activeHelloMilliseconds : Nat
  replayWindow : Nat
  feasibleReplayWindow : Nat → Prop
  confidentialityOffset : Nat
  mustSecure : Bool

def MACsecParametersBound {S A : Type} (d : Deployment)
    (model : ForwardingModel S A) (parameters : List MacsecParameters) : Prop :=
  ∀ parameter ∈ parameters, d.InScope parameter.device →
    ∀ iface ∈ model.deviceDataPlane.configuration.macIfaces,
      model.deviceDataPlane.componentName (model.deviceDataPlane.configuration.ip.owner iface.physicalIface) = parameter.device →
      parameter.mustSecure = (iface.settings.protectFrames && iface.settings.encryptFrames) ∧
        parameter.confidentialityOffset = iface.settings.confidentialityOffset

def RoleCatalog.macsec_protection_parameters {S A : Type} (d : Deployment)
    (model : ForwardingModel S A) (parameters : List MacsecParameters) : Prop :=
  model.CoversDeployment d ∧ MACsecParametersBound d model parameters ∧
  (∀ device ∈ d.devices, d.InScope device.id → device.kind = .macsec →
    ∃ parameter ∈ parameters, parameter.device = device.id) ∧
  (∀ parameter ∈ parameters, d.InScope parameter.device → parameter.dataDelayProtection = true ∧
    parameter.lifetimeMilliseconds = 6000 ∧ parameter.normalHelloMilliseconds = 2000 ∧
    0 < parameter.activeHelloMilliseconds ∧ parameter.activeHelloMilliseconds ≤ 2000 ∧
    (parameter.replayWindow = 2 ∨ (parameter.feasibleReplayWindow parameter.replayWindow ∧
      ∀ feasible, parameter.feasibleReplayWindow feasible → parameter.replayWindow ≤ feasible)) ∧
    parameter.confidentialityOffset = 0 ∧ parameter.mustSecure = true) ∧
  model.AllTraces (fun events => ∀ payload iface layers trafficClass,
    .transmit payload iface layers trafficClass ∈ events → ¬ model.GenuineControl payload →
    ∀ interface ∈ d.interfaces, d.InScope interface.device → interface.id = iface →
    ∀ device ∈ d.devices, d.InScope device.id → device.id = interface.device → device.kind = .macsec →
    device.layer = some .inner ∧ interface.zone = .gray ∨
      device.layer = some .outer ∧ interface.zone = .black →
    ∃ tunnel ∈ d.tunnels, tunnel.protocol = .macsec ∧ tunnel.sender = device.id ∧ tunnel.id ∈ layers)

def RoleCatalog.traffic_flow_confidentiality (installations : List CoverInstallation) : Prop :=
  TDN.Requirements.msc_traffic_flow_confidentiality (installations.map CoverInstallation.use) ∧
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

def RoleCatalog.packet_size_configuration (interfaces : List PacketSizing)
    (profiles : List FragmentationProfile) : Prop :=
  ∀ sizing ∈ interfaces,
    (sizing.role ≠ .other →
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
  emission : State → PacketSource.EncodedDatagram
  configuredMtu : Nat → Nat
  configuredPayloadLimit : Nat → Nat

def WireSizeModel.StateEncoding {S A : Type} (sizes : WireSizeModel S)
    (model : ForwardingModel S A) (state : S) : Prop :=
  let deviceState := model.deviceDataPlane.state state
  deviceState.frame.payload = PayloadCode (sizes.payload state) ∧
  sizes.parse state (sizes.serialize state deviceState.frame.body (sizes.payload state)) =
    some (deviceState.frame.body, sizes.payload state) ∧
  (sizes.payload state).length ≤
    (sizes.serialize state deviceState.frame.body (sizes.payload state)).length ∧
  (match deviceState.frame.visibleHeader with
   | some _ => model.deviceDataPlane.configuration.networkBytes deviceState.frame.body deviceState.frame.payload =
       some (sizes.serialize state deviceState.frame.body (sizes.payload state)).length
   | none => model.deviceDataPlane.configuration.networkBytes deviceState.frame.body deviceState.frame.payload = none) ∧
  (∀ header, deviceState.frame.body = .datagram header →
    header.payloadBytes = some (sizes.payload state) ∧
    header.networkBytes = some (sizes.serialize state deviceState.frame.body (sizes.payload state)).length)

def WireSizeModel.WireEncoding {S A : Type} (sizes : WireSizeModel S)
    (model : ForwardingModel S A) (state : S) : Prop :=
  let deviceState := model.deviceDataPlane.state state
  let emission := sizes.emission state
  emission.Raw = sizes.serialize state deviceState.frame.body (sizes.payload state) ∧
  emission.Reassembles (sizes.configuredMtu deviceState.iface) ∧
  match deviceState.frame.visibleHeader with
  | some header =>
      emission.body = .datagram { header with networkBytes := some emission.Raw.length } ∧
      PacketSource.NetworkHeaderMatches header emission.networkHeader emission.Data.length
  | none =>
      ∃ header, emission.body = .ethernet header ∧
        PacketSource.EthernetHeaderMatches header emission.networkHeader ∧
        (∀ original, deviceState.frame.body = .ethernet original → header = original) ∧
        (deviceState.frame.body.isMACsecPdu = true → header.etherType = 35045)

def WireSizeModel.SourceEncoding {S A : Type} (sizes : WireSizeModel S)
    (model : ForwardingModel S A) : Prop :=
  ∀ start request datagram, model.initial start →
    model.sourceRecord start = some (request, datagram) →
    sizes.serialize start datagram.body datagram.application = datagram.Raw

def WireSizeModel.Correspondence {S A : Type} (sizes : WireSizeModel S)
    (model : ForwardingModel S A) (settings : List PacketSizing) : Prop :=
  sizes.SourceEncoding model ∧
  (∀ setting ∈ settings,
    setting.externalMtu = sizes.configuredMtu setting.interface ∧
    setting.payloadLimit = sizes.configuredPayloadLimit setting.interface) ∧
  (∀ start actions state, model.initial start → model.ForwardsAlongTrace start actions state →
    sizes.StateEncoding model state) ∧
  ∀ start actions before action after,
    model.initial start → model.ForwardsAlongTrace start actions before →
    model.system.Tr before action after → model.deviceDataPlane.action action = some .linkTransmit →
    sizes.WireEncoding model before ∧
    ∀ setting ∈ settings, setting.interface = (model.deviceDataPlane.state before).iface →
      (sizes.payload before).length ≤ setting.payloadLimit ∧
      (sizes.emission before).MtuBytes ≤
        setting.encodedSize (sizes.payload before).length

def WireSizeModel.NoFurtherFragmentation {S A : Type} (sizes : WireSizeModel S)
    (model : ForwardingModel S A) (settings : List PacketSizing) : Prop :=
  ∀ start actions before action after setting,
    model.initial start → model.ForwardsAlongTrace start actions before →
    model.system.Tr before action after → model.deviceDataPlane.action action = some .linkTransmit →
    setting ∈ settings → setting.interface = (model.deviceDataPlane.state before).iface →
    setting.role ≠ .other →
      (sizes.emission before).fragments.length = 1

def WireSizeModel.FragmentPayload {S A : Type} (sizes : WireSizeModel S)
    (model : ForwardingModel S A) (state : S) (fragment : PacketSource.EncodedFragment)
    (payload : PayloadId) (sessions : List ProtectionSession) : Prop :=
  fragment ∈ (sizes.emission state).fragments ∧
  payload = ⟨(model.deviceDataPlane.state state).frame.originDomain, (model.deviceDataPlane.state state).frame.payload⟩ ∧
  sessions = BodySessions (model.deviceDataPlane.state state).frame.body

def PacketSizingInventory {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (sizing : List PacketSizing) : Prop :=
  (∀ device ∈ d.devices, d.InScope device.id → device.kind = .grayFirewall →
    ∃ interface ∈ d.interfaces, interface.device = device.id ∧ interface.externalData = true) ∧
  ∀ interface ∈ d.interfaces, ∀ device ∈ d.devices,
    interface.device = device.id → d.InScope device.id →
    ((device.layer = some .inner ∧ interface.zone = .gray) ∨
      (device.layer = some .outer ∧ interface.zone = .black) ∨
      (device.kind = .grayFirewall ∧ interface.externalData = true)) →
    ∃ configuration ∈ sizing,
      model.deviceDataPlane.ifaceName configuration.interface = interface.id ∧
      configuration.role = (if device.layer = some .inner then
        .innerExternal else .grayFirewallOrEncryptionExternal) ∧
      (∀ address, interface.address = some address →
        (address < 2^32 → configuration.family = .ipv4) ∧
        (2^128 ≤ address → configuration.family = .ipv6))

structure ThirdPartyFeature where
  device : String
  id : String
  canContactThirdParty : Bool
  enabled : Bool
  emittedTraffic : Traffic → Prop

def RoleCatalog.outer_third_party_services (d : Deployment) (objectiveSelected : String → Bool)
    (features : List ThirdPartyFeature) : Prop :=
  ∀ feature ∈ features, d.InScope feature.device → d.IsLayer feature.device .outer → feature.canContactThirdParty = true →
    if objectiveSelected feature.device then feature.enabled = false else
      ∀ interface ∈ d.interfaces, d.InScope interface.device → interface.device = feature.device →
        ∀ traffic, feature.emittedTraffic traffic →
          ¬ d.PermitsOnInterface interface.id .outbound traffic

def RoleCatalog.administrator_authentication (d : Deployment)
    (certificateObjective nistObjective : Bool) (events : List AdminEvent)
    (accounts : List AdministrativeAccount) (sessions : List AdministrativeSession)
    (awAdministrators : List Nat) : Prop :=
  TDN.Requirements.msc_administrator_authentication certificateObjective nistObjective
    events accounts sessions awAdministrators ∧
  ∀ event ∈ events, event.kind = .authentication →
    (certificateObjective = true → d.authority.certificateCNSACompliant event.credential) ∧
    (nistObjective = true → d.authority.authenticationConformsToNIST80063 event.credential)

structure Interoperation where
  firstSite : String
  secondSite : String
  layer : EncryptionLayer
  protocol : EncryptionProtocol
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

def TunnelTransfer {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (domain : PayloadDomain) (tunnel : Tunnel) : Prop :=
  domain.protocols ≠ [] ∧ 0 < domain.maximumBytes ∧
  ∀ protocol bytes, domain.Supports protocol bytes →
  ∃ start actions finish payload session sent received senderIface receiverIface earlier
      encryptToSend sendToReceive receiveToDecrypt later,
    model.initial start ∧ model.ForwardsAlongTrace start actions finish ∧
    payload.value = PayloadCode bytes ∧
    payload.originDomain = (model.deviceDataPlane.state start).frame.originDomain ∧
    payload.value = (model.deviceDataPlane.state start).frame.payload ∧
    ((∃ header, (model.deviceDataPlane.state start).frame.body.originalHeader = some header ∧
      header.protocol = protocol) ∨ (protocol = "ethernet" ∧
      (model.deviceDataPlane.state start).frame.body.originalEthernet.isSome = true)) ∧
    model.deviceDataPlane.SessionTunnel session = tunnel.id ∧
    senderIface ∈ d.interfaces ∧ receiverIface ∈ d.interfaces ∧
    senderIface.device = tunnel.sender ∧ receiverIface.device = tunnel.receiver ∧
    session ∈ sent ∧ session ∈ received ∧ sent = received ∧
    model.TraceEvents actions =
      earlier ++ [.protect payload tunnel.id session] ++ encryptToSend ++
      [.sessionTransmit payload senderIface.id sent] ++ sendToReceive ++
      [.sessionReceive payload receiverIface.id received] ++ receiveToDecrypt ++
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
  forward.protocol = choice.protocol ∧ reverse.protocol = choice.protocol ∧
  choice.firstSite ≠ choice.secondSite ∧
  ∃ first ∈ d.devices, ∃ second ∈ d.devices,
    first.id = choice.firstComponent ∧ second.id = choice.secondComponent ∧
    first.site = choice.firstSite ∧ second.site = choice.secondSite ∧
    first.layer = some choice.layer ∧ second.layer = some choice.layer ∧
    (choice.protocol = .ipsec → first.kind = .vpn ∧ second.kind = .vpn) ∧
    (choice.protocol = .macsec → first.kind = .macsec ∧ second.kind = .macsec)

def Interoperation.InScope (choice : Interoperation) (d : Deployment) : Prop :=
  d.InScope choice.firstComponent ∨ d.InScope choice.secondComponent

def InteroperationInventory (d : Deployment) (selected : List Interoperation) : Prop :=
  (∀ choice ∈ selected,
    ∃ forward ∈ d.tunnels, ∃ reverse ∈ d.tunnels, choice.Binds d forward reverse) ∧
  (∀ source ∈ d.devices, ∀ destination ∈ d.devices,
    d.intendedPeer source.id destination.id → source.site ≠ destination.site →
    (d.InScope source.id ∨ d.InScope destination.id) →
    ∃ choice ∈ selected,
      (choice.firstComponent = source.id ∧ choice.secondComponent = destination.id) ∨
      (choice.firstComponent = destination.id ∧ choice.secondComponent = source.id)) ∧
  ∀ tunnel ∈ d.tunnels, (d.InScope tunnel.sender ∨ d.InScope tunnel.receiver) →
    ∃ choice ∈ selected, choice.InScope d ∧
      ∃ opposite ∈ d.tunnels, choice.Binds d tunnel opposite ∨ choice.Binds d opposite tunnel

def InteroperationTransfers {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (selected : List Interoperation) (domain : PayloadDomain) : Prop :=
  ∀ choice ∈ selected, choice.InScope d →
    ∃ forward ∈ d.tunnels, ∃ reverse ∈ d.tunnels,
      choice.Binds d forward reverse ∧
      TunnelTransfer d model domain forward ∧ TunnelTransfer d model domain reverse

def SiteLayerInteroperationCoverage (pairs : List (String × String))
    (selected : List Interoperation) : Prop :=
  ∀ pair ∈ pairs, ∀ layer, ∃ choice ∈ selected,
    choice.firstSite = pair.1 ∧ choice.secondSite = pair.2 ∧ choice.layer = layer

def RoleCatalog.site_interoperability {S A : Type} (d : Deployment) (model : ForwardingModel S A)
    (requiredSitePairs : List (String × String)) (selected : List Interoperation)
    (domain : PayloadDomain) : Prop :=
  model.CoversDeployment d ∧ RequiredSitePairsBound d requiredSitePairs ∧
  SiteLayerInteroperationCoverage requiredSitePairs selected ∧
  InteroperationInventory d selected ∧ InteroperationTransfers d model selected domain

def red_egress_waypointing (d : Deployment)
    (red outside : String → Prop) (conformingMSC aoApprovedProtection : String → Prop) : Prop :=
  (∀ solution, aoApprovedProtection solution → d.authority.aoApprovedTransitSolution solution) ∧
  ∀ source destination, red source → outside destination →
    ¬ Waypointing.ReachableWithoutWaypoint d.DeviceAdjacent
      (fun node => conformingMSC node ∨ aoApprovedProtection node) source destination

end TDN.Requirements.Msc
