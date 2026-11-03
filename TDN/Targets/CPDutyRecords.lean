import TDN.Targets.DirectSpecifications
import TDN.Targets.TimeSynchronization

namespace TDN.Targets.Complete
open Compliance

inductive ExternalDuty where
  | niapModificationDoesNotAlterCertification
  | evaluatedProductConfiguration | componentsListEligibility | nsaIndependenceApproval
  | supplyChainThreatAssessment | supplyChainMitigation | trustedRedGrayControl
  | grayUnclassifiedDetermination | localPolicyAndUSGovernmentGuidance | cnssPolicy
  | policyConflictsReported
  | authorizedAdministratorClearance | outerAdministratorClearance
  | protectedFacility | grayPhysicalProtection | authorizedPhysicalAccess | macsecConfigurationProtection
  | classifiedDisposalOrAODeclassification | aoVirusUpdatePolicy | criticalPatchTesting
  | localPatchingPolicy | tempest | authorizedHardwareInventory | baselineAvailableToAuditor
  | procurementPurposeExclusion | nsaAuditPermission | nsaAuditCooperation
  | annualAOAudit | annualAuditResultsReview | nsaRegistrationApproval
  | aoRegistrationPackage | annualRenewal | registrationChanges | versionMigrationDeadline
  | frequentAuditOffload | incidentResponseGuidance | auditLowSpacePlan | auditOffloadPlan | auditOverflowPlan | auditPowerPlan
  | incidentDeadlineAndChannel | incidentRequiredFields
  | reportSecurityFailure | reportClassifiedCompromise | reportMaliciousGrayTraffic
  | reportUnauthorizedClassifiedAccess | reportUnauthorizedDestination
  | reportMaliciousConfigurationChange | reportUnauthorizedPrivilegeEscalation
  | reportConcurrentCertificateReuse | reportMaliciousPhysicalTampering
  | reportProtectionLayerFailure | reportSignificantServiceDegradation
  | reportOuterConnectionDiscrepancy | reportInnerConnectionDiscrepancy
  | differentAdministratorAndAuditor | differentRedAndGrayAdministrators | optionalRoleMAC
  | securityTraining | tamperInspection
  | administratorMaintainsMonitorsControls | administratorLatestCriticalUpdates
  | administratorIncidentDocumentationReporting | administratorLogisticSupport
  | administratorAuxiliaryDeviceDefenses | administratorVersionCompliance
  | auditorReviewsActionsAndEvents | auditorOnlyAdministrationAccess
  | auditorManagesLogs | auditorIncidentDocumentationReporting | auditorCapabilitySurvey
  | assessmentAuthorization | assessmentResultsToAO | aoImplementationVerification
  | lifecycleAOConfigurationControl | lifecycleAORequiredUpdates
  | externalEngagementVariants | compromiseRevocation | nsaRiskAssessmentToAO
  | testingAnnex | capabilityTestCoverage | blackGrayBoxTests | testDiscrepancyDocumentation
  | testBaselineDocumentation | testPlanAOAdditionalRequirements | testArtifactsAndAOReport
  | crossDomainDoDI | crossDomainConnectionGuide | crossDomainOfficialBaseline
  | vendorAndLocalHardening | legalUndertaking
  | egSeparateEncryptorNecessary | egEncryptionIndependenceApproval
  | egTrafficFirewallEligibility | egIPsecEligibility | egMACsecEligibility
  | egTestingAnnex | egNecessaryGrayDataTunnel
  | companionMAFirewallEligibility | companionWLANFirewallEligibility | companionFirewallPhysicalSeparation
  deriving DecidableEq, Repr

inductive ExternalSubject where
  | solution (id : String)
  | network (id : String)
  | component (id : String)
  | product (component product version : String) (role : DeviceKind)
  | componentPair (first second : String)
  | libraryPair (first second : String)
  deriving DecidableEq

structure ExternalFacts where
  established : ExternalDuty → ExternalSubject → Prop

def ExternalFacts.Confirms (facts : ExternalFacts) (duty : ExternalDuty)
    (subject : ExternalSubject) : Prop :=
  facts.established duty subject

structure CryptographicLibraryRecord where
  id : String
  product : String
  version : String
  manufacturer : String
  manufacturerGroup : String

structure AlgorithmSuite where
  confidentiality : String
  confidentialityBits : Nat
  signature : String
  signatureBits : Nat
  signatureHash : String
  keyEstablishment : String
  hash : String
  mode : String

def CNSA1IPsec (suite : AlgorithmSuite) : Prop :=
  suite.confidentiality = "AES" ∧ suite.confidentialityBits = 256 ∧
  ((suite.signature = "RSA" ∧ suite.signatureBits = 3072) ∨
    (suite.signature = "ECDSA-P384" ∧ suite.signatureHash = "SHA384")) ∧
  suite.keyEstablishment ∈ ["ECDH-P384", "DH3072", "DH4096"] ∧
  suite.hash ∈ ["SHA384", "SHA512"]

def CNSA2IPsec (suite : AlgorithmSuite) : Prop :=
  suite.confidentiality = "AES" ∧ suite.confidentialityBits = 256 ∧ suite.mode = "GCM" ∧
  suite.signature = "ML-DSA-87" ∧ suite.keyEstablishment = "ML-KEM-1024" ∧
  suite.hash ∈ ["SHA384", "SHA512"]

def CNSA1EAP (suite : AlgorithmSuite) : Prop :=
  suite.confidentiality = "AES" ∧ suite.confidentialityBits = 256 ∧ suite.mode = "GCM" ∧
  ((suite.signature = "RSA" ∧ suite.signatureBits = 3072) ∨ (suite.signature = "ECDSA-P384" ∧ suite.signatureHash = "SHA384")) ∧
  suite.keyEstablishment ∈ ["ECDH-P384", "DH3072", "DH4096"] ∧
  suite.hash ∈ ["SHA384", "SHA512"]

def CNSA2EAP (suite : AlgorithmSuite) : Prop :=
  suite.confidentiality = "AES" ∧ suite.confidentialityBits = 256 ∧ suite.mode = "GCM" ∧
  suite.signature = "ML-DSA-87" ∧ suite.keyEstablishment = "ML-KEM-1024" ∧
  suite.hash ∈ ["SHA384", "SHA512"]

structure CertificateRecord where
  id : String
  subject : String
  issuer : String
  trustAnchor : String
  chain : List String
  validFrom : Nat
  validUntil : Nat
  revokedAt : Option Nat
  nonPersonEntity : Bool
  vendorDefault : Bool
  selfSigned : Bool
  proprietary : Bool

structure AuthenticationInput where
  session : String
  verifier : String
  claimant : String
  credential : String
  nonce : List UInt8
  transcript : List UInt8
  time : Nat

structure AuthenticationPrimitive where
  verifyCertificatePossession : AuthenticationInput → Bool
  verifySharedKeyPossession : AuthenticationInput → Bool

structure AuthenticationObservation where
  input : AuthenticationInput
  association : String

structure RekeyObservation where
  device : String
  peer : String
  association : String
  authenticatedAt : Nat
  rekeyedAt : Nat

structure KeyExchangeRecord where
  connection : String
  initial : AlgorithmSuite
  intermediate : AlgorithmSuite
  initialMessageBytes : Nat
  initialMessageLimit : Nat
  intermediateEncrypted : Bool
  multipleKeyExchanges : Bool
  intermediateExchangeSupported : Bool
  ikeFragmentationSupported : Bool

structure DefaultAccessRecord where
  mechanism : String
  vendorValue : String
  currentValue : String
  removed : Bool

structure ControlServiceRecord where
  name : String
  network : Zone
  layer : Nat
  enabled : Bool
  neededForOperation : Bool
  aoApproved : Bool

structure ManagementConnection where
  administrator : String
  component : String
  interface : String
  initiatedFromAW : String
  directPhysical : Bool
  protocol : String
  tlsMajor : Nat
  tlsMinor : Nat
  approvedEncryptionLayers : Nat
  crossesBlack : Bool
  localDedicatedLAN : Bool
  sameVLAN : Bool

structure HostService where
  host : String
  virtualMachine : Option String
  service : String
  component : String

structure AuditRecord where
  component : String
  event : String
  time : Nat
  retainedUntil : Nat
  backedUpAt : List Nat

structure AuditStorage where
  component : String
  capacityCheckedAt : List Nat
  operatingFrom : Nat
  operatingUntil : Nat
  warningOnLowSpace : Bool
  offloadEnabled : Bool
  overflowHandling : String
  powerLossHandling : String

structure ProvisioningObservation where
  component : String
  administrator : String
  csr : String
  keyGeneratedOnComponent : Bool
  securePhysicalArea : Bool
  outOfBand : Bool
  ca : String
  certificate : String
  provisionedAt : Nat
  firstUsedAt : Nat

structure RoutingUse where
  component : String
  sourceComponent : String
  destinationComponent : String
  ownTunnelLookup : Bool
  dynamicProtocol : Bool

inductive SoftwareSignatureFamily where
  | lms | hss | xmss | xmssMT | mlDSA
  deriving DecidableEq

structure SoftwareSignatureParameters where
  family : SoftwareSignatureFamily
  hash : String
  digestBits : Nat
  treeHeight : Nat
  winternitz : Nat
  layers : Nat
  hssTrees : List (Nat × Nat)
  mlDSAParameter : Nat

def SoftwareSignatureParameters.Approved (parameters : SoftwareSignatureParameters) : Prop :=
  match parameters.family with
  | .mlDSA => parameters.mlDSAParameter = 87
  | .lms | .hss =>
    parameters.hash ∈ ["SHA256", "SHAKE256"] ∧ parameters.digestBits ∈ [192, 256] ∧
    (if parameters.family = .lms then
      parameters.treeHeight ∈ [5, 10, 15, 20, 25] ∧ parameters.winternitz ∈ [1, 2, 4, 8]
    else parameters.hssTrees ≠ [] ∧ parameters.hssTrees.length ≤ 8 ∧
      ∀ tree ∈ parameters.hssTrees, tree.1 ∈ [5, 10, 15, 20, 25] ∧ tree.2 ∈ [1, 2, 4, 8])
  | .xmss | .xmssMT =>
    parameters.hash ∈ ["SHA256", "SHAKE256"] ∧ parameters.digestBits ∈ [192, 256] ∧
    parameters.winternitz = 16 ∧
    (if parameters.family = .xmss then parameters.treeHeight ∈ [10, 16, 20]
    else (parameters.treeHeight, parameters.layers) ∈
      [(20, 2), (20, 4), (40, 2), (40, 4), (40, 8), (60, 3), (60, 6), (60, 12)])


structure ComponentDutyRecord where
  component : String
  product : String
  version : String
  modified : Bool
  manufacturer : String
  manufacturerGroup : String
  operatingSystemFamily : String
  cryptographicLibraries : List String
  physicalDevice : String
  optionalClearVLAN : Bool
  optionalXPN : Bool
  supportedFeatures : List String
  ikeVersion : Nat
  ikeMode : String
  espMode : String
  espHMAC : Bool
  ikeLifetimeSeconds : Nat
  espLifetimeSeconds : Nat
  cnsa2Selected : Bool
  ikeGCMSelected : Bool
  espGCMSelected : Bool
  removeDefaultCertificatesSelected : Bool
  offeredIPsecSuites : List AlgorithmSuite
  ipsecConnections : List KeyExchangeRecord
  keyWrapAlgorithm : String
  keyWrapBits : Nat
  macsecAlgorithm : String
  macsecBits : Nat
  eapCNSA2Selected : Bool
  eapTLSVersionMajor : Nat
  eapTLSVersionMinor : Nat
  offeredEAPSuites : List AlgorithmSuite
  defaults : List DefaultAccessRecord
  dnsEnabled : Bool
  dnsServers : List Nat
  dnsLookupDisableSelected : Bool
  dnsLookupEnabled : Bool
  automaticRemoteBoot : Bool
  services : List ControlServiceRecord
  unusedInterfaces : List String
  enabledInterfaces : List String
  minimumFeasibleExposure : List String
  managementInterfaces : List String
  dataInterfaces : List String
  managementConnections : List ManagementConnection
  managementPhysicalSeparated : Bool
  managementCryptographicSeparated : Bool
  managementACLSeparated : Bool
  directNIPRConnection : Bool
  awPoweredOnWhenUnused : Bool
  awCurrentlyUsed : Bool
  awHost : String
  administratorAddresses : List Nat
  minimumAdministratorAddresses : List Nat
  loggingEnabled : Bool
  flowLoggingEnabled : Bool
  alerts : List String
  collectedLogSources : List String
  analyzedLogSources : List String
  collectedFlowSources : List String
  analyzedFlowSources : List String
  siem : Option String
  siemZone : Option Zone
  approvedCrossDomainPath : Bool
  infrastructureSecretEntropyBits : Nat
  domainAuthenticationService : Option String
  passwordAlternativeSelected : Bool
  signatureObjectiveSelected : Bool
  softwareSigningAlgorithms : List SoftwareSignatureParameters
  credentialRevocationInitiatedAt : Option Nat
  cakDestructionInitiatedAt : Option Nat
  disposedAt : Option Nat

structure ParallelAttachment where
  inner : String
  outer : String
  redNetwork : String
  outerPhysicalInterface : String
  vlanTrunk : Bool
  serialPredecessor : Option String

structure TechnicalDutyRecords where
  libraries : List CryptographicLibraryRecord
  components : List ComponentDutyRecord
  time : TimeObservationInventory
  certificates : List CertificateRecord
  authentications : List AuthenticationObservation
  authenticationPrimitive : AuthenticationPrimitive
  rekeys : List RekeyObservation
  provisioning : List ProvisioningObservation
  routing : List RoutingUse
  hostServices : List HostService
  audits : List AuditRecord
  storage : List AuditStorage
  attachments : List ParallelAttachment
  managementDeployed : Bool
  independentlyManaged : Bool
  optionalRoleMACSelected : Bool := false
  certificateObjectiveSelected : Bool
  integrityProtectionSelected : Bool
  combinedSolutionRequiresGrayFirewall : Bool
  combinedEndUserSolution : Bool
  crossDomainSolutions : List String
  selectedIntegrator : Option String
  selectedScreeningRouters : List String
  external : ExternalFacts

def TechnicalDutyRecords.InventoryComplete (records : TechnicalDutyRecords) (d : Deployment) : Prop :=
  (∀ device ∈ d.devices, ∃ record ∈ records.components, record.component = device.id) ∧
  (∀ record ∈ records.components, ∃ device ∈ d.devices, device.id = record.component) ∧
  (∀ first ∈ records.components, ∀ second ∈ records.components,
    first.component = second.component → first = second) ∧
  (records.managementDeployed = true ↔ ManagementDeployed d) ∧
  records.time.InventoryBound d

def AuthenticatedCertificate (records : TechnicalDutyRecords)
    (observation : AuthenticationObservation) : Prop :=
  observation.input.session ≠ "" ∧ observation.input.nonce ≠ [] ∧
  observation.input.transcript ≠ [] ∧
  records.authenticationPrimitive.verifyCertificatePossession observation.input = true ∧
  ∃ certificate ∈ records.certificates,
    certificate.id = observation.input.credential ∧
    certificate.subject = observation.input.claimant ∧ certificate.nonPersonEntity = true ∧
    certificate.validFrom ≤ observation.input.time ∧
    observation.input.time < certificate.validUntil ∧
    (certificate.revokedAt = none ∨
      ∃ revoked, certificate.revokedAt = some revoked ∧ observation.input.time < revoked) ∧
    certificate.vendorDefault = false ∧ certificate.selfSigned = false ∧
    certificate.proprietary = false

def IndependentManufacturers (first second : ComponentDutyRecord) : Prop :=
  first.manufacturer ≠ second.manufacturer ∧
    first.manufacturerGroup ≠ second.manufacturerGroup

def IndependentCryptographicLibraries (records : TechnicalDutyRecords)
    (first second : ComponentDutyRecord) : Prop :=
  first.cryptographicLibraries ≠ [] ∧ second.cryptographicLibraries ≠ [] ∧
  ∀ firstId ∈ first.cryptographicLibraries, ∀ secondId ∈ second.cryptographicLibraries,
    ∃ firstLibrary ∈ records.libraries, ∃ secondLibrary ∈ records.libraries,
      firstLibrary.id = firstId ∧ secondLibrary.id = secondId ∧
      ((firstLibrary.manufacturer ≠ secondLibrary.manufacturer ∧
        firstLibrary.manufacturerGroup ≠ secondLibrary.manufacturerGroup) ∨
      (firstLibrary.product ≠ secondLibrary.product ∧
        records.external.Confirms .nsaIndependenceApproval
          (.libraryPair firstId secondId)))

def IndependentComponents (records : TechnicalDutyRecords) (d : Deployment) : Prop :=
  ∀ inner ∈ d.devices, inner.layer = some .inner →
    ∀ other ∈ d.devices, (d.Relevant inner.id ∨ d.Relevant other.id) →
    other.layer = some .outer ∨ other.kind = .grayFirewall →
    ∀ first ∈ records.components, ∀ second ∈ records.components,
      first.component = inner.id → second.component = other.id →
      first.physicalDevice ≠ second.physicalDevice ∧
      (IndependentManufacturers first second ∨
        (first.product ≠ second.product ∧ records.external.Confirms
          .nsaIndependenceApproval (.componentPair inner.id other.id))) ∧
      (other.layer = some .outer →
        first.operatingSystemFamily ≠ second.operatingSystemFamily ∧
        IndependentCryptographicLibraries records first second)

def PhysicalRoleSeparation (records : TechnicalDutyRecords) (d : Deployment) : Prop :=
  ∀ first ∈ records.components, ∀ second ∈ records.components,
    first.component ≠ second.component → (d.Relevant first.component ∨ d.Relevant second.component) →
    (d.IsLayer first.component .inner ∧ d.IsLayer second.component .outer ∨
      d.IsDevice first.component .grayFirewall ∧
        (d.IsLayer second.component .inner ∨ d.IsLayer second.component .outer)) →
    first.physicalDevice ≠ second.physicalDevice

def CertificateIdentityConfiguration (records : TechnicalDutyRecords) (component : String)
    (removeDefaults : Bool) : Prop :=
  (∃ certificate ∈ records.certificates,
    certificate.subject = component ∧ certificate.nonPersonEntity = true ∧
    certificate.id ≠ "" ∧ certificate.trustAnchor ∈ certificate.chain ∧
    certificate.issuer ∈ certificate.chain) ∧
  (∀ first ∈ records.certificates, ∀ second ∈ records.certificates,
    first.subject = component → first.id = second.id → second.subject = component) ∧
  (∀ observation ∈ records.authentications, (observation.input.verifier = component ∨ observation.input.claimant = component) →
    AuthenticatedCertificate records observation) ∧
  (removeDefaults = true → ∀ certificate ∈ records.certificates,
    certificate.subject = component →
    certificate.vendorDefault = false ∧ certificate.selfSigned = false ∧
      certificate.proprietary = false)

def AuthenticatedSharedKey (records : TechnicalDutyRecords)
    (observation : AuthenticationObservation) (key : String) : Prop :=
  observation.input.session ≠ "" ∧ observation.input.nonce ≠ [] ∧
  observation.input.transcript ≠ [] ∧ observation.input.credential = key ∧
  records.authenticationPrimitive.verifySharedKeyPossession observation.input = true

def MutuallyAuthenticatedTunnels (records : TechnicalDutyRecords) (d : Deployment) : Prop :=
  ∀ tunnel ∈ d.tunnels, (d.Relevant tunnel.sender ∨ d.Relevant tunnel.receiver) →
    ∃ first ∈ records.authentications, ∃ second ∈ records.authentications,
      first.input.verifier = tunnel.sender ∧ first.input.claimant = tunnel.receiver ∧
      second.input.verifier = tunnel.receiver ∧ second.input.claimant = tunnel.sender ∧
      first.association = tunnel.id ∧ second.association = tunnel.id ∧
      match tunnel.mechanism with
      | .ipsec => AuthenticatedCertificate records first ∧ AuthenticatedCertificate records second
      | .macsec => AuthenticatedSharedKey records first tunnel.keyContext ∧
          AuthenticatedSharedKey records second tunnel.keyContext

def CentralManagementConfiguration (records : TechnicalDutyRecords) (d : Deployment) : Prop :=
  ∀ site, d.centralManagementSite = some site →
    (∀ component ∈ d.devices, d.certificateAuthenticated component.id = true →
      ∃ authority ∈ d.devices, authority.kind = .certificationAuthority ∧
        authority.site = site ∧ d.keyManagementCA component.id authority.id) ∧
    (∀ first ∈ d.devices, ∀ second ∈ d.devices,
      first.layer = some .inner → second.layer = some .outer →
      d.certificateAuthenticated first.id = true → d.certificateAuthenticated second.id = true →
      ∀ firstCA secondCA, d.keyManagementCA first.id firstCA →
        d.keyManagementCA second.id secondCA → firstCA ≠ secondCA) ∧
    (∀ component ∈ d.devices, component.kind = .macsec →
      d.certificateAuthenticated component.id = true →
      ∃ server ∈ d.devices, server.kind = .authenticationServer ∧ server.site = site) ∧
    (∀ record ∈ records.components, ∀ connection ∈ record.managementConnections,
      connection.crossesBlack = true → 2 ≤ connection.approvedEncryptionLayers) ∧
    (∀ record ∈ records.components, record.managementConnections ≠ [] →
      record.managementCryptographicSeparated = true)

def IPsecAlgorithmConfiguration (record : ComponentDutyRecord) : Prop :=
  record.offeredIPsecSuites ≠ [] ∧
  if record.cnsa2Selected then
    (∀ suite ∈ record.offeredIPsecSuites, CNSA2IPsec suite) ∧
    (∀ connection ∈ record.ipsecConnections,
      connection.initial.keyEstablishment ∈ ["ECDH-P384", "DH3072", "DH4096"] ∧
      connection.intermediate.keyEstablishment = "ML-KEM-1024" ∧
      connection.intermediateEncrypted = true ∧ connection.multipleKeyExchanges = true ∧
      connection.intermediateExchangeSupported = true ∧ connection.ikeFragmentationSupported = true)
  else ∀ suite ∈ record.offeredIPsecSuites, CNSA1IPsec suite

def IPsecModesAndLifetimes (record : ComponentDutyRecord) : Prop :=
  record.ikeVersion = 2 ∧
  record.ikeMode = (if record.ikeGCMSelected then "GCM" else "CBC") ∧
  record.espMode = (if record.espGCMSelected then "GCM" else "CBC") ∧
  (record.espMode = "CBC" → record.espHMAC = true) ∧
  0 < record.ikeLifetimeSeconds ∧ record.ikeLifetimeSeconds ≤ 86400 ∧
  0 < record.espLifetimeSeconds ∧ record.espLifetimeSeconds ≤ 28800

def EAPAlgorithmConfiguration (record : ComponentDutyRecord) : Prop :=
  record.offeredEAPSuites ≠ [] ∧
  if record.eapCNSA2Selected then record.eapTLSVersionMajor = 1 ∧
    record.eapTLSVersionMinor = 3 ∧
    ∀ suite ∈ record.offeredEAPSuites, CNSA2EAP suite
  else ∀ suite ∈ record.offeredEAPSuites, CNSA1EAP suite

def DefaultAndDNSConfiguration (record : ComponentDutyRecord) : Prop :=
  (∀ mechanism ∈ record.defaults,
    mechanism.removed = true ∨ mechanism.currentValue ≠ mechanism.vendorValue) ∧
  (record.dnsEnabled = true → record.dnsServers ≠ []) ∧ record.automaticRemoteBoot = false ∧
  (record.dnsLookupDisableSelected = true → record.dnsLookupEnabled = false)

def ControlServiceConfiguration (record : ComponentDutyRecord) (device : Device) : Prop :=
  ∀ service ∈ record.services, service.enabled = true →
    (device.layer = some .inner → service.network = .red) ∧
    (device.layer = some .outer → service.network = .gray) ∧
    ((service.layer = 2 ∧ service.neededForOperation = true) ∨ service.aoApproved = true)

def ManagementTransportConfiguration (record : ComponentDutyRecord) : Prop :=
  record.administratorAddresses = record.minimumAdministratorAddresses ∧
  ∀ connection ∈ record.managementConnections,
    connection.interface ∈ record.managementInterfaces ∧
    (connection.directPhysical = true ∨
      connection.protocol ∈ ["ssh", "ipsec", "macsec"] ∨
      (connection.protocol = "tls" ∧ connection.tlsMajor = 1 ∧ 2 ≤ connection.tlsMinor)) ∧
    (connection.crossesBlack = true →
      2 ≤ connection.approvedEncryptionLayers ∧
      (connection.localDedicatedLAN = true → connection.sameVLAN = true))

def ManagementSeparation (record : ComponentDutyRecord) : Prop :=
  (∀ port ∈ record.managementInterfaces, port ∉ record.dataInterfaces) ∧
  record.managementPhysicalSeparated = true ∧ record.managementCryptographicSeparated = true ∧
  record.managementACLSeparated = true ∧ record.directNIPRConnection = false

def ManagementAttachmentConfiguration (records : TechnicalDutyRecords) (d : Deployment) : Prop :=
  records.managementDeployed = true →
  (∃ red ∈ d.devices, red.kind = .workstation ∧
    ∃ interface ∈ d.interfaces, interface.device = red.id ∧ interface.zone = .red ∧
      interface.managementNetwork = true) ∧
  (∃ gray ∈ d.devices, gray.kind = .workstation ∧
    ∃ interface ∈ d.interfaces, interface.device = gray.id ∧ interface.zone = .gray ∧
      interface.managementNetwork = true) ∧
  ∀ device ∈ d.devices, d.Relevant device.id →
    ∀ record ∈ records.components, record.component = device.id →
      ManagementSeparation record ∧
      (∀ port ∈ record.managementInterfaces, ∃ interface ∈ d.interfaces,
        interface.id = port ∧ interface.device = device.id ∧ interface.managementNetwork = true) ∧
      record.managementConnections ≠ [] ∧
      ∀ connection ∈ record.managementConnections,
        connection.component = device.id ∧
        (∃ workstation ∈ d.devices, workstation.id = connection.initiatedFromAW ∧
          workstation.kind = .workstation ∧
          ∃ source ∈ d.interfaces, source.device = workstation.id ∧
            source.managementNetwork = true ∧
            ∃ target ∈ d.interfaces, target.id = connection.interface ∧
              target.device = device.id ∧ target.managementNetwork = true ∧
              source.zone = target.zone ∧
              (device.layer = some .inner ∨ device.kind = .innerFirewall →
                target.zone = .red) ∧
              (device.layer = some .outer ∨ device.kind = .grayFirewall →
                target.zone = .gray))

def WorkstationHostConfiguration (records : TechnicalDutyRecords)
    (record : ComponentDutyRecord) : Prop :=
  (record.awCurrentlyUsed = false → record.awPoweredOnWhenUnused = false) ∧
  ∀ service ∈ records.hostServices, service.host = record.awHost →
    service.service = "administrative-workstation"


def ProvisioningConfiguration (records : TechnicalDutyRecords) (d : Deployment)
    (component : String) : Prop :=
  (∀ certificate ∈ records.certificates, certificate.subject = component →
    certificate.vendorDefault = false → certificate.selfSigned = false →
    certificate.proprietary = false →
    ∃ provision ∈ records.provisioning, provision.component = component ∧
      provision.certificate = certificate.id) ∧
  ∀ provision ∈ records.provisioning, provision.component = component →
    d.authority.securityAdministrator provision.administrator ∧
    provision.keyGeneratedOnComponent = true ∧ provision.csr ≠ "" ∧
    provision.securePhysicalArea = true ∧ provision.outOfBand = true ∧
    provision.provisionedAt < provision.firstUsedAt ∧
    (∀ authentication ∈ records.authentications,
      authentication.input.credential = provision.certificate →
      provision.provisionedAt < authentication.input.time) ∧
    (∃ certificate ∈ records.certificates, certificate.id = provision.certificate ∧
      certificate.subject = component ∧ certificate.issuer = provision.ca) ∧
    (∃ authority ∈ d.devices, authority.id = provision.ca ∧
      authority.kind = .certificationAuthority ∧ d.keyManagementCA component authority.id)

def ComponentMonitoringZone (d : Deployment) (device : Device) (zone : Zone) : Prop :=
  (zone = .red ∧ (device.layer = some .inner ∨ device.kind = .innerFirewall)) ∨
  (zone = .gray ∧ (device.layer = some .outer ∨ device.kind = .grayFirewall)) ∨
  ∃ interface ∈ d.interfaces, interface.device = device.id ∧
    interface.managementNetwork = true ∧ interface.zone = zone

def SIEMConfiguration (records : TechnicalDutyRecords) (d : Deployment) : Prop :=
  ∀ device ∈ d.devices, d.Relevant device.id → ∀ zone,
    ComponentMonitoringZone d device zone →
    (∃ siem ∈ d.devices, siem.kind = .siem ∧
      ∃ interface ∈ d.interfaces, interface.device = siem.id ∧
        (interface.zone = zone ∨ (zone = .gray ∧ interface.zone = .red))) →
    ∀ source ∈ records.components, source.component = device.id →
    ∃ receiver ∈ d.devices, receiver.kind = .siem ∧ source.siem = some receiver.id ∧
      ∃ interface ∈ d.interfaces, interface.device = receiver.id ∧
        source.siemZone = some interface.zone ∧
        (interface.zone = zone ∨
          (zone = .gray ∧ interface.zone = .red ∧ source.approvedCrossDomainPath = true)) ∧
        source.loggingEnabled = true ∧
        ∃ target ∈ records.components, target.component = receiver.id ∧
          device.id ∈ target.collectedLogSources ∧ device.id ∈ target.analyzedLogSources ∧
          target.alerts ≠ [] ∧
          (zone = .red → source.flowLoggingEnabled = true ∧
            device.id ∈ target.collectedFlowSources ∧ device.id ∈ target.analyzedFlowSources) ∧
          (device.layer = some .outer ∨ device.kind = .grayFirewall →
            "unexpected-boundary-traffic-drop" ∈ target.alerts)

def GregorianDaysBeforeYear (year : Nat) : Nat :=
  365 * year + (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400

def GregorianLeapYear (year : Nat) : Bool :=
  year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)

def CalendarQuarterStart (year : Nat) (quarter : Fin 4) : Nat :=
  let leap := if GregorianLeapYear year then 1 else 0
  let days := match quarter.val with
    | 0 => 0
    | 1 => 90 + leap
    | 2 => 181 + leap
    | _ => 273 + leap
  (GregorianDaysBeforeYear year + days) * 86400

def CalendarQuarterEnd (year : Nat) (quarter : Fin 4) : Nat :=
  if h : quarter.val < 3 then CalendarQuarterStart year ⟨quarter.val + 1, by omega⟩
  else CalendarQuarterStart (year + 1) 0

def AuditRetentionConfiguration (records : TechnicalDutyRecords) (component : String) : Prop :=
  (∀ event ∈ records.audits, event.component = component →
    event.time + 365 * 86400 ≤ event.retainedUntil ∧
    ∃ backup ∈ event.backedUpAt, event.time ≤ backup) ∧
  (∃ storage ∈ records.storage, storage.component = component ∧
    (∀ year quarter,
      CalendarQuarterStart year quarter < storage.operatingUntil →
      storage.operatingFrom < CalendarQuarterEnd year quarter →
      ∃ checked ∈ storage.capacityCheckedAt,
        CalendarQuarterStart year quarter ≤ checked ∧
        checked < CalendarQuarterEnd year quarter ∧
        storage.operatingFrom ≤ checked ∧ checked ≤ storage.operatingUntil) ∧
    storage.warningOnLowSpace = true ∧ storage.offloadEnabled = true ∧
    storage.overflowHandling ≠ "" ∧ storage.powerLossHandling ≠ "") ∧
  records.external.Confirms .frequentAuditOffload (.component component)

def RevocationBeforeDisposal (record : ComponentDutyRecord)
    (usesCertificate usesCAK : Bool) : Prop :=
  ∀ disposed, record.disposedAt = some disposed →
    (usesCertificate = true →
      ∃ initiated, record.credentialRevocationInitiatedAt = some initiated ∧ initiated < disposed) ∧
    (usesCAK = true →
      ∃ initiated, record.cakDestructionInitiatedAt = some initiated ∧ initiated < disposed)

def SigningConfiguration (record : ComponentDutyRecord) : Prop :=
  record.signatureObjectiveSelected = true →
    record.softwareSigningAlgorithms ≠ [] ∧
    ∀ algorithm ∈ record.softwareSigningAlgorithms, algorithm.Approved

end TDN.Targets.Complete
