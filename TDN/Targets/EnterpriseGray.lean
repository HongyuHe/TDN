import TDN.Targets.ManagementProtocols

namespace TDN.Targets.Complete
open Compliance

inductive EGNetworkRole where
  | management | data | outside
  deriving DecidableEq

structure EGNetwork where
  id : String
  role : EGNetworkRole
  site : String
  components : List String
  interfaces : List String
  addresses : List (Nat × Nat)

structure EGEncryptionComponent where
  component : String
  site : String
  firewall : String
  outer : String
  separateEncryptorSelected : Bool
  mechanism : Mechanism
  internalInterfaces : List String
  externalInterfaces : List String
  managementTunnels : List String
  dataTunnels : List String
  associatedIPTunnel : Bool
  ipsecTunnelMode : Bool

structure EGRemoteAdministration where
  component : String
  workstation : String
  site : String
  protocol : String
  sshVersion : Nat
  algorithmSuite : AlgorithmSuite
  protectionAtApplication : Bool

structure EGRoutePrefix where
  low : Nat
  high : Nat
  deriving DecidableEq

def EGRoutePrefix.Contains (routePrefix : EGRoutePrefix) (address : Nat) : Prop :=
  routePrefix.low ≤ address ∧ address ≤ routePrefix.high

structure EGRouteAdvertisement where
  component : String
  peer : String
  interface : String
  sourceRole : EGNetworkRole
  targetRole : EGNetworkRole
  routePrefix : EGRoutePrefix
  inbound : Bool

structure EGRouteRule where
  low : Nat
  high : Nat
  peer : Option String
  verdict : Filter.Verdict

def EGRouteRule.toFilter (rule : EGRouteRule) : Filter.Rule EGRouteAdvertisement :=
  ⟨fun advertisement => decide (rule.low ≤ advertisement.routePrefix.low ∧
    advertisement.routePrefix.high ≤ rule.high ∧
    (rule.peer = none ∨ rule.peer = some advertisement.peer)), rule.verdict⟩

structure EGRoutePolicy where
  component : String
  interface : String
  inbound : Bool
  rules : List EGRouteRule
  defaultVerdict : Filter.Verdict

structure EGRoutingPeer where
  component : String
  peer : String
  interface : String
  tunnel : String
  protocol : String
  key : String
  entropyBits : Nat
  hash : String
  hashBits : Nat
  authentication : AuthenticationObservation

structure EGRoutingInstance where
  component : String
  id : String
  role : EGNetworkRole
  routes : List EGRoutePrefix

structure EGRouteTransfer where
  component : String
  sourceInstance : String
  targetInstance : String
  routePrefix : EGRoutePrefix

structure EGSurvivabilitySite where
  site : String
  connectionLost : Bool
  localAuthenticationServer : String
  authenticatedComponents : List String
  localDNSRecords : List (String × Nat)
  mainDNSRecords : List (String × Nat)

structure EGConfiguration where
  networks : List EGNetwork
  encryptors : List EGEncryptionComponent
  grayFirewalls : List String
  administration : List EGRemoteAdministration
  routingPeers : List EGRoutingPeer
  advertisements : List EGRouteAdvertisement
  routingPolicies : List EGRoutePolicy
  routingInstances : List EGRoutingInstance
  routeTransfers : List EGRouteTransfer
  necessaryPrefixes : List EGRoutePrefix
  feasiblePrefixes : List EGRoutePrefix
  dynamicRouting : Bool
  sha256RoutingObjective : Bool
  pointToPointKeysObjective : Bool
  vrfsSelected : Bool
  trustedTimeObjective : Bool
  dnssecObjective : Bool
  siteSurvivabilityRequired : Bool
  survivability : List EGSurvivabilitySite
  additionalCapabilityPackages : List String
  httpResponseValidationObjective : Bool
  authorizedTLSSelected : Bool
  protocolPrimitive : MessageAuthenticationPrimitive
  authenticatedTime : List AuthenticatedTimeConfiguration
  dnssec : List DNSSECConfiguration

def EGConfiguration.SupportedMSCArchitecture (configuration : EGConfiguration) : Prop :=
  configuration.additionalCapabilityPackages = [] ∧ configuration.authorizedTLSSelected = false ∧ configuration.httpResponseValidationObjective = false

def EGConfiguration.Managed (configuration : EGConfiguration) (component : String) : Prop :=
  ∃ network ∈ configuration.networks, network.role = .management ∧
    component ∈ network.components

def EGConfiguration.GrayEncryption (configuration : EGConfiguration) (component : String) : Prop :=
  ∃ encryptor ∈ configuration.encryptors, encryptor.component = component

def EGConfiguration.ManagedTarget (configuration : EGConfiguration) (d : Deployment)
    (component : String) : Prop :=
  d.IsLayer component .outer ∨ component ∈ configuration.grayFirewalls ∨
    configuration.GrayEncryption component ∨
    (∃ interface ∈ d.interfaces, interface.device = component ∧ interface.zone = .gray ∧
      interface.managementNetwork = true)

def EGConfiguration.InventoryBound (configuration : EGConfiguration) (d : Deployment) : Prop :=
  configuration.networks ≠ [] ∧ configuration.encryptors ≠ [] ∧
  (∀ network ∈ configuration.networks, network.role = .management →
    network.components ≠ [] ∧ network.interfaces ≠ [] ∧ network.addresses ≠ []) ∧
  (∀ network ∈ configuration.networks, ∀ id ∈ network.interfaces,
    ∃ interface ∈ d.interfaces, interface.id = id ∧
      interface.device ∈ network.components ∧ interface.zone = .gray) ∧
  (∀ interface ∈ d.interfaces, interface.zone = .gray →
    (interface.managementNetwork = true ↔
      ∃ network ∈ configuration.networks, network.role = .management ∧
        interface.id ∈ network.interfaces)) ∧
  (∀ component, component ∈ configuration.grayFirewalls ↔ d.IsDevice component .grayFirewall) ∧
  (∀ encryptor ∈ configuration.encryptors,
    (∃ device ∈ d.devices, device.id = encryptor.component ∧ device.site = encryptor.site) ∧
    encryptor.firewall ∈ configuration.grayFirewalls ∧
    d.IsLayer encryptor.outer .outer ∧
    encryptor.internalInterfaces ≠ [] ∧ encryptor.externalInterfaces ≠ [] ∧
    (∀ interface ∈ d.interfaces, interface.device = encryptor.component →
      interface.id ∈ encryptor.internalInterfaces ++ encryptor.externalInterfaces) ∧
    (∀ id ∈ encryptor.internalInterfaces, ∃ interface ∈ d.interfaces,
      interface.id = id ∧ interface.device = encryptor.component ∧
        interface.zone = .gray ∧ interface.managementNetwork = true) ∧
    (∀ id ∈ encryptor.externalInterfaces, ∃ interface ∈ d.interfaces,
      interface.id = id ∧ interface.device = encryptor.component ∧
        interface.zone = .gray ∧ interface.managementNetwork = false) ∧
    (∀ id ∈ encryptor.internalInterfaces, id ∉ encryptor.externalInterfaces)) ∧
  (∀ site, (∃ device ∈ d.devices, device.site = site ∧
    configuration.ManagedTarget d device.id) →
    ∃ encryptor ∈ configuration.encryptors, encryptor.site = site)

def EGEndpointData (configuration : EGConfiguration) (d : Deployment) (traffic : Traffic) : Prop :=
  ∃ source ∈ d.devices, ∃ destination ∈ d.devices,
    source.level.classification = destination.level.classification ∧
    traffic.sourceDevice = some source.id ∧ traffic.destinationDevice = some destination.id ∧
    (source.layer.isSome = true ∨ source.kind = .grayFirewall ∨ configuration.GrayEncryption source.id) ∧
    (destination.layer.isSome = true ∨ destination.kind = .grayFirewall ∨ configuration.GrayEncryption destination.id)

def EGAuthenticationRevocationHTTP (d : Deployment) (traffic : Traffic) : Prop :=
  traffic.service = "http" ∧
  ∃ server ∈ d.devices, ∃ responder ∈ d.devices,
    server.kind = .authenticationServer ∧ responder.kind = .revocationService ∧
    (∃ interface ∈ d.interfaces, interface.device = responder.id ∧ interface.zone = .gray) ∧
    ((traffic.sourceDevice = some server.id ∧ traffic.destinationDevice = some responder.id) ∨
      (traffic.sourceDevice = some responder.id ∧ traffic.destinationDevice = some server.id))

def EGControlPeers (configuration : EGConfiguration) (d : Deployment) (traffic : Traffic) : Prop :=
  traffic.trafficClass = .control ∧
  ∃ source destination, traffic.sourceDevice = some source ∧
    traffic.destinationDevice = some destination ∧
    (configuration.ManagedTarget d source ∨ configuration.Managed source) ∧
    (configuration.ManagedTarget d destination ∨ configuration.Managed destination)

def EGFirewallRestrictions (configuration : EGConfiguration) (d : Deployment)
    (interface : Interface) (direction : Direction) (traffic : Traffic) : Prop :=
  d.HeaderEligible interface traffic ∧
  (traffic.trafficClass = .management →
    interface.physical = true ∧ interface.managementNetwork = true) ∧
  (traffic.trafficClass = .protectedData → ¬ EGAuthenticationRevocationHTTP d traffic →
    EGEndpointData configuration d traffic) ∧
  (direction = .inbound → d.reachableSource interface.id traffic.packet.source) ∧
  (traffic.service = "http" → EGAuthenticationRevocationHTTP d traffic) ∧
  ¬ DifferentClassificationVPNs d traffic

def EGConfiguration.FirewallPolicies (configuration : EGConfiguration) (d : Deployment) : Prop :=
  d.AddressInventoryCoherent ∧ d.ProcessingCoherent ∧ d.UDPBindingsCoherent ∧
  ∀ interface ∈ d.interfaces, d.Relevant interface.device →
    interface.device ∈ configuration.grayFirewalls →
    d.PolicyCoverage interface ∧
    (∀ policy ∈ d.policies, policy.interface = interface.id → policy.defaultVerdict = .deny) ∧
    (∀ direction traffic, d.Accepts interface.id direction traffic →
      EGFirewallRestrictions configuration d interface direction traffic) ∧
    ∀ direction hook traffic, d.PacketEligibleAt interface direction hook traffic →
      EGFirewallRestrictions configuration d interface direction traffic →
      (EGAuthenticationRevocationHTTP d traffic ∨ EGControlPeers configuration d traffic) →
      d.AcceptsAt interface.id direction hook traffic

def EGConfiguration.ManagementTopology (configuration : EGConfiguration)
    (d : Deployment) : Prop :=
  ∀ source target, configuration.Managed source → configuration.ManagedTarget d target →
    source ≠ target →
    Relation.ReflTransGen d.DeviceAdjacent source target ∧
    ¬ Relation.ReflTransGen (Paths.Avoiding d.DeviceAdjacent
      (fun component => component ∈ configuration.grayFirewalls)) source target

def EGConfiguration.ManagementPaths (configuration : EGConfiguration) (d : Deployment)
    (records : TechnicalDutyRecords) : Prop :=
  configuration.ManagementTopology d ∧
  (∀ component ∈ d.devices, configuration.ManagedTarget d component.id →
    ∃ administration ∈ configuration.administration, administration.component = component.id) ∧
  (∀ administration ∈ configuration.administration,
    (∃ target ∈ d.devices, target.id = administration.component ∧
      target.site = administration.site) ∧
    (∃ workstation ∈ d.devices, workstation.id = administration.workstation ∧
      workstation.kind = .workstation ∧ workstation.site = administration.site ∧
      configuration.Managed workstation.id) ∧
    administration.protectionAtApplication = true ∧
    ((administration.protocol = "ssh" ∧ administration.sshVersion = 2) ∨
      administration.protocol ∈ ["ipsec", "tls"]) ∧
    (CNSA1IPsec administration.algorithmSuite ∨ CNSA2IPsec administration.algorithmSuite)) ∧
  (∀ component ∈ d.devices, component.kind = .authenticationServer →
    ∀ auth ∈ records.components, auth.component = component.id →
      ∀ other ∈ records.components, other.component ≠ component.id →
      (d.IsLayer other.component .inner ∨ d.IsLayer other.component .outer) →
      auth.physicalDevice ≠ other.physicalDevice) ∧
  (∀ component ∈ d.devices, configuration.Managed component.id →
    ∀ service ∈ d.services, service.device = component.id →
      service.kind = .application → False) ∧
  (configuration.trustedTimeObjective = true →
    (∀ service ∈ d.services, service.kind = .time →
      ∃ time ∈ configuration.authenticatedTime, time.server = service.device ∧
        time.Secure configuration.protocolPrimitive)) ∧
  (configuration.dnssecObjective = true →
    (∀ service ∈ d.services, service.port = 53 →
      ∃ dns ∈ configuration.dnssec, dns.server = service.device ∧
        dns.Secure configuration.protocolPrimitive))

def EGConfiguration.EncryptorArchitecture (configuration : EGConfiguration) (d : Deployment)
    (records : TechnicalDutyRecords) : Prop :=
  (∀ firewall ∈ configuration.grayFirewalls,
    records.external.Confirms .egTrafficFirewallEligibility (.component firewall)) ∧
  ∀ encryptor ∈ configuration.encryptors, d.Relevant encryptor.component →
    (if encryptor.separateEncryptorSelected then
      encryptor.component ≠ encryptor.firewall ∧
        records.external.Confirms .egSeparateEncryptorNecessary (.component encryptor.component)
    else encryptor.component = encryptor.firewall) ∧
    (∀ inner ∈ records.components, ∀ outer ∈ records.components,
      inner.component = encryptor.component → outer.component = encryptor.outer →
      inner.physicalDevice ≠ outer.physicalDevice ∧
      inner.operatingSystemFamily ≠ outer.operatingSystemFamily ∧
      IndependentCryptographicLibraries records inner outer ∧
      (IndependentManufacturers inner outer ∨
        (inner.product ≠ outer.product ∧ records.external.Confirms
          .egEncryptionIndependenceApproval (.componentPair inner.component outer.component)))) ∧
    (encryptor.mechanism = .ipsec →
      (encryptor.ipsecTunnelMode = true ∨ encryptor.associatedIPTunnel = true) ∧
      records.external.Confirms .egIPsecEligibility (.component encryptor.component) ∧
      ∀ record ∈ records.components, record.component = encryptor.component →
        IPsecAlgorithmConfiguration record) ∧
    (encryptor.mechanism = .macsec →
      records.external.Confirms .egMACsecEligibility (.component encryptor.component) ∧
      ∀ record ∈ records.components, record.component = encryptor.component →
        record.macsecBits = 256 ∧ record.macsecAlgorithm ∈ ["GCM-AES-256", "GCM-AES-XPN-256"] ∧
        record.keyWrapAlgorithm = "AES-Key-Wrap" ∧ record.keyWrapBits = 256)

def EGConfiguration.NoSplitTunneling {S A : Type} (configuration : EGConfiguration)
    (d : Deployment) (model : ExecutionModel S A) : Prop :=
  model.CoversDeployment d ∧
  model.AllTraces (fun events =>
    (∀ encryptor ∈ configuration.encryptors, d.Relevant encryptor.component →
      ∀ earlier middle later payload ingress received receiveClass egress sent sendClass,
      events = earlier ++ [.receive payload ingress received receiveClass] ++ middle ++
        [.transmit payload egress sent sendClass] ++ later →
      ¬ model.GenuineControl payload →
      (ingress ∈ encryptor.internalInterfaces → egress ∈ encryptor.externalInterfaces →
        ∃ tunnel ∈ d.tunnels, tunnel.sender = encryptor.component ∧
          tunnel.layer = .inner ∧ tunnel.mechanism = encryptor.mechanism ∧
          tunnel.id ∈ sent ∧ .encrypt payload tunnel.id ∈ middle) ∧
      (ingress ∈ encryptor.externalInterfaces → egress ∈ encryptor.internalInterfaces →
        ∃ tunnel ∈ d.tunnels, tunnel.receiver = encryptor.component ∧
          tunnel.layer = .inner ∧ tunnel.mechanism = encryptor.mechanism ∧
          tunnel.id ∈ received ∧ .decrypt payload tunnel.id ∈ middle)) ∧
    (∀ encryptor ∈ configuration.encryptors, d.Relevant encryptor.component →
      ∀ earlier later payload egress sent trafficClass,
        events = earlier ++ [.transmit payload egress sent trafficClass] ++ later →
        egress ∈ encryptor.externalInterfaces → ¬ model.GenuineControl payload →
        ∃ tunnel ∈ d.tunnels, tunnel.sender = encryptor.component ∧
          tunnel.layer = .inner ∧ tunnel.mechanism = encryptor.mechanism ∧
          tunnel.id ∈ sent ∧ .encrypt payload tunnel.id ∈ earlier) ∧
    ∀ earlier middle later payload ingress received receiveClass egress sent sendClass,
      events = earlier ++ [.receive payload ingress received receiveClass] ++ middle ++
        [.transmit payload egress sent sendClass] ++ later →
      ∀ input ∈ d.interfaces, ∀ output ∈ d.interfaces,
        input.id = ingress → output.id = egress → input.device = output.device →
        d.IsLayer input.device .outer → d.Relevant input.device →
        input.zone = .gray → output.zone = .gray → ingress = egress)

def EGConfiguration.IntersiteProtection {S A : Type} (configuration : EGConfiguration)
    (d : Deployment) (model : ExecutionModel S A) (domain : PayloadDomain) (records : TechnicalDutyRecords) : Prop :=
  (∀ first ∈ configuration.encryptors, ∀ second ∈ configuration.encryptors,
    first.site ≠ second.site →
    ∃ tunnel ∈ d.tunnels, tunnel.id ∈ first.managementTunnels ∧
      tunnel.layer = .inner ∧ tunnel.sender = first.component ∧
      tunnel.receiver = second.component ∧ tunnel.mechanism = first.mechanism ∧
      TunnelTransfer d model domain tunnel) ∧
  (∀ encryptor ∈ configuration.encryptors, ∀ id ∈ encryptor.dataTunnels,
    (∃ tunnel ∈ d.tunnels, tunnel.id = id ∧ tunnel.sender = encryptor.component) ∧
    records.external.Confirms .egNecessaryGrayDataTunnel (.component id)) ∧
  model.AllTraces (fun events => ∀ payload port layers,
    .transmit payload port layers .management ∈ events →
    ∀ interface ∈ d.interfaces, interface.id = port → interface.zone = .black →
      ∃ gray ∈ d.tunnels, ∃ outer ∈ d.tunnels,
        gray.layer = .inner ∧ outer.layer = .outer ∧ layers = [outer.id, gray.id] ∧
        configuration.GrayEncryption gray.sender ∧ d.IsLayer outer.sender .outer ∧
        Before events (.encrypt payload gray.id) (.encrypt payload outer.id))

def EGRoutePolicy.Accepts (policy : EGRoutePolicy) (advertisement : EGRouteAdvertisement) : Prop :=
  Filter.evaluate (policy.rules.map EGRouteRule.toFilter) policy.defaultVerdict advertisement = .allow

def EGConfiguration.SpecificRoute (configuration : EGConfiguration)
    (routePrefix : EGRoutePrefix) : Prop :=
  routePrefix ∈ configuration.feasiblePrefixes ∧
  (∃ necessary ∈ configuration.necessaryPrefixes,
    routePrefix.low ≤ necessary.low ∧ necessary.high ≤ routePrefix.high) ∧
  ∀ candidate ∈ configuration.feasiblePrefixes,
    routePrefix.low ≤ candidate.low → candidate.high ≤ routePrefix.high →
    (∀ necessary ∈ configuration.necessaryPrefixes,
      routePrefix.low ≤ necessary.low → necessary.high ≤ routePrefix.high →
      candidate.low ≤ necessary.low ∧ necessary.high ≤ candidate.high) →
    candidate = routePrefix

def EGConfiguration.Routing (configuration : EGConfiguration) (d : Deployment)
    (records : TechnicalDutyRecords) : Prop :=
  (configuration.dynamicRouting = true →
    configuration.vrfsSelected = true ∧
    (∀ use ∈ records.routing, use.dynamicProtocol = true →
      (configuration.GrayEncryption use.component ∨ use.component ∈ configuration.grayFirewalls) ∧
      ∃ peer ∈ configuration.routingPeers, peer.component = use.component) ∧
    (∀ peer ∈ configuration.routingPeers,
      peer.protocol ∈ ["RIPv2", "OSPF", "EIGRP", "BGP", "IS-IS"] ∧
      (configuration.GrayEncryption peer.component ∨ peer.component ∈ configuration.grayFirewalls) ∧
      (configuration.GrayEncryption peer.peer ∨ peer.peer ∈ configuration.grayFirewalls) ∧
      256 ≤ peer.entropyBits ∧
      (if configuration.sha256RoutingObjective then
        peer.hash ∈ ["SHA256", "SHA384", "SHA512"] ∧ 256 ≤ peer.hashBits
      else peer.hash = "MD5") ∧
      peer.authentication.input.verifier = peer.component ∧
      peer.authentication.input.claimant = peer.peer ∧
      AuthenticatedSharedKey records peer.authentication peer.key ∧
      (∃ interface ∈ d.interfaces, interface.id = peer.interface ∧ interface.device = peer.component) ∧
      (∃ tunnel ∈ d.tunnels, tunnel.id = peer.tunnel ∧
        ((tunnel.sender = peer.component ∧ tunnel.receiver = peer.peer) ∨
          (tunnel.receiver = peer.component ∧ tunnel.sender = peer.peer))) ∧
      (∀ direction : Bool, ∃ policy ∈ configuration.routingPolicies,
        policy.component = peer.component ∧ policy.interface = peer.interface ∧
        policy.inbound = direction ∧ policy.defaultVerdict = .deny) ∧
      ∃ encryptor ∈ configuration.encryptors,
        (encryptor.component = peer.component ∨ encryptor.firewall = peer.component) ∧
        peer.tunnel ∈ encryptor.managementTunnels ++ encryptor.dataTunnels) ∧
    (∀ policy ∈ configuration.routingPolicies,
      ∃ peer ∈ configuration.routingPeers,
        peer.component = policy.component ∧ peer.interface = policy.interface) ∧
    (∀ first ∈ configuration.routingPeers, ∀ second ∈ configuration.routingPeers,
      if configuration.pointToPointKeysObjective then
        ({first.component, first.peer} : Finset String) ≠ {second.component, second.peer} →
          first.key ≠ second.key
      else first.key = second.key) ∧
    (∀ advertisement ∈ configuration.advertisements,
      (∃ peer ∈ configuration.routingPeers,
        peer.component = advertisement.component ∧ peer.peer = advertisement.peer ∧
        peer.interface = advertisement.interface) ∧
      advertisement.sourceRole = advertisement.targetRole ∧
      configuration.SpecificRoute advertisement.routePrefix ∧
      ∃ policy ∈ configuration.routingPolicies,
        policy.component = advertisement.component ∧
        policy.interface = advertisement.interface ∧ policy.inbound = advertisement.inbound ∧
        policy.defaultVerdict = .deny ∧ policy.Accepts advertisement)) ∧
  (configuration.vrfsSelected = true →
    (∀ encryptor ∈ configuration.encryptors,
      (∃ management ∈ configuration.routingInstances,
        management.component = encryptor.component ∧ management.role = .management) ∧
      (∃ data ∈ configuration.routingInstances,
        data.component = encryptor.component ∧ data.role = .data)) ∧
    (∀ routingInstance ∈ configuration.routingInstances, ∀ routePrefix ∈ routingInstance.routes,
      ∃ network ∈ configuration.networks, routingInstance.role = network.role ∧
        (routePrefix.low, routePrefix.high) ∈ network.addresses) ∧
    (∀ transfer ∈ configuration.routeTransfers,
      ∀ source ∈ configuration.routingInstances, ∀ target ∈ configuration.routingInstances,
        source.id = transfer.sourceInstance → target.id = transfer.targetInstance →
        source.role = .outside ∨ source.role = target.role) ∧
    ∀ transfer ∈ configuration.routeTransfers,
      ∀ target ∈ configuration.routingInstances, target.id = transfer.targetInstance →
        transfer.routePrefix ∈ target.routes)

def EGConfiguration.Survivability (configuration : EGConfiguration) (d : Deployment)
    (records : TechnicalDutyRecords) : Prop :=
  (configuration.siteSurvivabilityRequired = true →
    ∀ encryptor ∈ configuration.encryptors, ∃ site ∈ configuration.survivability,
      site.site = encryptor.site ∧ site.localDNSRecords = site.mainDNSRecords) ∧
  (∀ encryptor ∈ configuration.encryptors, ∃ site ∈ configuration.survivability,
    site.site = encryptor.site ∧
      (site.connectionLost = true → encryptor.component ∈ site.authenticatedComponents)) ∧
  ∀ site ∈ configuration.survivability, site.connectionLost = true →
    (∃ server ∈ d.devices, server.id = site.localAuthenticationServer ∧
      server.kind = .authenticationServer ∧ server.site = site.site) ∧
    ∀ component ∈ site.authenticatedComponents,
      ∃ observation ∈ records.authentications,
        observation.input.verifier = site.localAuthenticationServer ∧
        observation.input.claimant = component ∧ AuthenticatedCertificate records observation

def EGConfiguration.ExternalSizing {S A : Type} (configuration : EGConfiguration)
    (d : Deployment) (model : ExecutionModel S A) (sizing : List PacketSizing) : Prop :=
  ∀ encryptor ∈ configuration.encryptors, d.Relevant encryptor.component →
    ∀ id ∈ encryptor.externalInterfaces,
      ∃ setting ∈ sizing, model.native.portName setting.interface = id ∧
        setting.role = .grayFirewallOrEncryptionExternal ∧
        0 < setting.externalMtu ∧ 0 < setting.payloadLimit ∧
        (setting.family = .ipv6 → setting.ipv6PmtuConfigured = true) ∧
        (∀ interface ∈ d.interfaces, interface.id = id →
          ∀ address, interface.address = some address →
            (address < 2^32 → setting.family = .ipv4) ∧
            (2^128 ≤ address → setting.family = .ipv6)) ∧
        ∀ bytes, bytes ≤ setting.payloadLimit → setting.encodedSize bytes ≤ setting.externalMtu

def EGConfiguration.Core {S A : Type} (configuration : EGConfiguration)
    (d : Deployment) (records : TechnicalDutyRecords) (model : ExecutionModel S A)
    (domain : PayloadDomain) (sizing : List PacketSizing) : Prop :=
  configuration.SupportedMSCArchitecture ∧ configuration.InventoryBound d ∧
  configuration.FirewallPolicies d ∧ configuration.ManagementPaths d records ∧
  configuration.EncryptorArchitecture d records ∧ configuration.NoSplitTunneling d model ∧
  configuration.IntersiteProtection d model domain records ∧ configuration.Routing d records ∧
  configuration.Survivability d records ∧ configuration.ExternalSizing d model sizing ∧
  records.external.Confirms .egTestingAnnex (.solution "central-Gray-management")

end TDN.Targets.Complete
