import TDN.Targets.CompanionFirewalls

namespace TDN.Targets.Complete
open Compliance

structure CPContext (State Action : Type) where
  solution : String
  deployment : Deployment
  model : ExecutionModel State Action
  records : TechnicalDutyRecords
  enterpriseGray : Option EGConfiguration
  companionFirewalls : List CompanionFirewall
  flows : List Flow
  flowOf : State → List Action → State → PayloadId → Flow
  independentKeys : String → String → Prop
  authenticatedInnerPairs : List (String × String)
  establishedInnerTunnels : List (String × String)
  requiredConnectivity : List (String × String)
  includedUnclassified : List String
  peers : List InnerAuthentication
  establishedTunnel : String → String → Prop
  grayTopology : GrayTopology
  addressRanges : List (Addressing.Range SecurityLevel)
  intendedAddressPairs : List IntendedAddressPair
  encapsulations : List EncapsulationUse
  crossesIP : String → Bool
  privateKeys : List PrivateKey
  privateKeyObjective : String → Bool
  privateKeyPolicies : List MandatoryKeyPolicy
  tls : TLSPrimitive
  macsecAuthentication : List MACsecAuthentication
  macsecKeys : List MACsecKey
  macsecServers : List MACsecServerPair
  provisioning : List KeyProvisioning
  eapCAKGeneratedByApprovedKGS : String → String → Prop
  macsecParameters : List MACsecParameters
  innerConfigurations : List EncryptionComponentConfiguration
  outerConfigurations : List EncryptionComponentConfiguration
  innerOutboundMACObjective : Bool
  innerInboundMACObjective : Bool
  outerOutboundMACObjective : Bool
  outerInboundMACObjective : Bool
  coverInstallations : List CoverInstallation
  wireSizes : WireSizeModel State
  sizing : List PacketSizing
  fragmentation : List FragmentationProfile
  untrustedBlack : Bool
  publicInternet : Bool
  grayFirewallRequired : Bool
  edge : String → String → Prop
  grayConnection : String → String → Prop
  outer : String → Prop
  outerFirewall : String → Prop
  black : String → Prop
  grayFirewall : String → Prop
  inner : String → Prop
  insideAttachment : String → String → Prop
  outsideAttachment : String → String → Prop
  externalBlackConnection : String → String → Prop
  firewallInternal : String → Bool
  localOuter : String → String
  thirdPartyDisableObjective : String → Bool
  thirdPartyFeatures : List ThirdPartyFeature
  dropIPv4OptionsObjective : String → Bool
  cdpOnGray : Bool
  certificateAdminObjective : Bool
  nistAdminObjective : Bool
  administrativeEvents : List AdminEvent
  accounts : List AdministrativeAccount
  sessions : List AdministrativeSession
  awAdministrators : List Nat
  requiredSitePairs : List (String × String)
  interoperation : List Interoperation
  payloadDomain : PayloadDomain
  red : String → Prop
  outside : String → Prop
  conformingMSC : String → Prop
  aoApprovedProtection : String → Prop

inductive DutySubject where
  | solution (id : String)
  | network (id : String)
  | component (id : String)
  deriving DecidableEq

def DutySubject.id : DutySubject → String
  | .solution id | .network id | .component id => id

def DutySubject.Contains (subject : DutySubject) (component : String) : Prop :=
  match subject with
  | .component id => component = id
  | _ => True

def DutySubject.external : DutySubject → ExternalSubject
  | .solution id => .solution id
  | .network id => .network id
  | .component id => .component id

def CPContext.KnownSubject {S A : Type} (context : CPContext S A)
    (subject : DutySubject) : Prop :=
  match subject with
  | .solution id => id = context.solution
  | .network id => ∃ network ∈ context.deployment.networks, network.id = id
  | .component id => ∃ device ∈ context.deployment.devices, device.id = id

def CPContext.EachComponent {S A : Type} (context : CPContext S A) (subject : DutySubject)
    (condition : Device → ComponentDutyRecord → Prop) : Prop :=
  ∀ device ∈ context.deployment.devices, subject.Contains device.id →
    (¬ context.deployment.OrdinaryGray device.id ∨ context.deployment.standaloneEncapsulator device.id) →
    ∀ record ∈ context.records.components, record.component = device.id → condition device record

def CPContext.External {S A : Type} (context : CPContext S A) (subject : DutySubject)
    (duties : List ExternalDuty) : Prop :=
  ∀ duty ∈ duties, context.records.external.Confirms duty subject.external

def CPContext.ConfigurationDefaults {S A : Type} (context : CPContext S A)
    (subject : DutySubject) : Prop :=
  context.EachComponent subject (fun _ record => DefaultAndDNSConfiguration record)

def CPContext.ScopedDeployment {S A : Type} (context : CPContext S A)
    (subject : DutySubject) : Deployment :=
  { context.deployment with focus := match subject with
      | .component component => some component
      | _ => none }

def CPContext.ComponentConnectivity {S A : Type} (context : CPContext S A)
    (component : String) : Prop :=
  (∀ network ∈ context.deployment.networks, component ∈ network.innerComponents →
    ∃ device ∈ context.deployment.devices, device.id = component ∧ device.level = network.level) ∧
  (∀ first ∈ context.deployment.networks, ∀ second ∈ context.deployment.networks,
    component ∈ first.innerComponents → component ∈ second.innerComponents →
      first.id = second.id ∧ first.level = second.level) ∧
  ∀ pair ∈ context.authenticatedInnerPairs ++ context.establishedInnerTunnels,
    pair.1 = component ∨ pair.2 = component →
      ∃ first ∈ context.deployment.devices, ∃ second ∈ context.deployment.devices,
        first.id = pair.1 ∧ second.id = pair.2 ∧ first.level = second.level

def CPContext.ComponentSeparation {S A : Type} (context : CPContext S A)
    (component : String) : Prop :=
  (context.records.managementDeployed = true → ∀ peer ∈ context.peers,
    peer.component = component → peer.managementDevices.Nonempty) ∧
  ∀ first ∈ context.peers, ∀ second ∈ context.peers,
    first.component = component ∨ second.component = component →
    first.level ≠ second.level →
      MaterialsSeparated first second ∧ ¬ InnerCanAuthenticate first second ∧
      ¬ context.establishedTunnel first.component second.component ∧
      (context.records.managementDeployed = true →
        Disjoint first.managementDevices second.managementDevices)

def CPContext.ComponentInterop {S A : Type} (context : CPContext S A)
    (component : String) : Prop :=
  let d := { context.deployment with focus := some component }
  context.model.CoversDeployment d ∧ InteroperationInventory d context.interoperation ∧
    InteroperationTransfers d context.model context.interoperation context.payloadDomain

def CPContext.DirectMeaning {S A : Type} (context : CPContext S A) (subject : DutySubject) (group : Fin 76) : Prop :=
  let d := context.ScopedDeployment subject
  let model := context.model
  match group.val + 1 with
  | 7 => Primitive_msc_nested_layer_protection d model context.flows context.flowOf context.independentKeys
  | 8 => match subject with
    | .component component => context.ComponentConnectivity component
    | _ => SecurityLevelConnectivityCore d model context.authenticatedInnerPairs
      context.establishedInnerTunnels context.requiredConnectivity context.includedUnclassified
  | 12 => match subject with
    | .component component => context.ComponentSeparation component
    | _ => Primitive_msc_security_level_key_and_management_separation context.records.managementDeployed
      context.peers context.establishedTunnel
  | 13 => Primitive_msc_gray_firewall_path_coverage d context.grayTopology
  | 14 => Primitive_msc_gray_addressing_for_level_filtering d context.addressRanges context.intendedAddressPairs
  | 15 => MACsecEncapsulationCore d model context.encapsulations context.crossesIP
  | 21 => Primitive_msc_vpn_private_key_confinement d model context.privateKeys
      context.privateKeyObjective context.privateKeyPolicies
  | 24 => Primitive_msc_macsec_authentication_choice_and_as d model context.tls context.macsecAuthentication
  | 27 => Primitive_msc_macsec_key_generation_and_server d context.macsecKeys context.macsecServers
      context.provisioning context.eapCAKGeneratedByApprovedKGS
  | 28 => Primitive_msc_macsec_protection_parameters d model context.macsecParameters
  | 29 => Primitive_msc_inner_tunnel_no_bypass d model context.innerConfigurations
      context.innerOutboundMACObjective context.innerInboundMACObjective
  | 30 => Primitive_msc_outer_tunnel_no_bypass d model context.outerConfigurations
      context.outerOutboundMACObjective context.outerInboundMACObjective
  | 32 => Primitive_msc_transec_conditions (context.coverInstallations.filter
      (fun installation => d.focus.isNone || d.focus == some installation.device))
  | 33 => context.model.CoversDeployment d ∧
      context.wireSizes.Correspondence context.model context.sizing ∧
      context.wireSizes.NoFurtherFragmentation context.model context.sizing ∧ PacketSizingInventory d model context.sizing ∧
      Primitive_msc_packet_size_configuration (context.sizing.filter
      (fun sizing => d.interfaces.any (fun interface =>
        interface.id == model.native.ifaceName sizing.interface &&
          (d.focus.isNone || d.focus == some interface.device)))) context.fragmentation
  | 34 => Primitive_msc_outer_firewall_placement context.untrustedBlack context.publicInternet
      context.grayFirewallRequired context.edge context.grayConnection context.outer
      context.outerFirewall context.black context.grayFirewall context.inner
      context.insideAttachment context.outsideAttachment context.externalBlackConnection
  | 35 => Primitive_msc_boundary_interface_filtering d context.untrustedBlack
      context.firewallInternal context.localOuter
  | 37 => Primitive_msc_outer_third_party_services d context.thirdPartyDisableObjective context.thirdPartyFeatures
  | 38 => Primitive_msc_ip_header_and_multicast_filtering d context.dropIPv4OptionsObjective
  | 39 => Primitive_msc_outer_gray_interface_policy d context.cdpOnGray
  | 40 => Primitive_msc_gray_firewall_allowlist d context.grayFirewallRequired
  | 47 => Primitive_msc_administrator_authentication d context.certificateAdminObjective context.nistAdminObjective
      context.administrativeEvents context.accounts context.sessions context.awAdministrators
  | 54 => match subject with
    | .component component => context.ComponentInterop component
    | _ => Primitive_msc_site_interoperability d model context.requiredSitePairs context.interoperation context.payloadDomain
  | 56 => RedEgressCore d context.red context.outside context.conformingMSC context.aoApprovedProtection
  | _ => True

def CPContext.BaseSourceMeaning {S A : Type} (context : CPContext S A)
    (subject : DutySubject) (group : Fin 76) : Prop :=
  let d := context.ScopedDeployment subject
  let records := context.records
  let each := context.EachComponent subject
  let external := context.External subject
  match group.val + 1 with
  | 1 => external [.localPolicyAndUSGovernmentGuidance, .cnssPolicy, .policyConflictsReported]
  | 2 => each (fun device record =>
      records.external.Confirms .evaluatedProductConfiguration
        (.product device.id record.product record.version device.kind) ∧
      (record.modified = true → records.external.Confirms
        .niapModificationDoesNotAlterCertification (.component device.id)))
  | 3 => each (fun device record => device.kind ∈
      [.vpn, .macsec, .grayFirewall, .outerFirewall, .innerFirewall, .authenticationServer, .intrusionPrevention] →
      records.external.Confirms .componentsListEligibility
        (.product device.id record.product record.version device.kind))
  | 4 => IndependentComponents records d
  | 5 => PhysicalRoleSeparation records d
  | 6 => each (fun device record =>
      records.external.Confirms .supplyChainThreatAssessment
        (.product device.id record.product record.version device.kind) ∧
      records.external.Confirms .supplyChainMitigation
        (.product device.id record.product record.version device.kind))
  | 9 => external [.trustedRedGrayControl, .grayUnclassifiedDetermination]
  | 10 => (records.independentlyManaged = true →
      (∀ record ∈ records.components, ∀ connection ∈ record.managementConnections,
        connection.crossesBlack = false) ∧
      (∀ tunnel ∈ d.tunnels, tunnel.mechanism = .ipsec →
        ∃ first ∈ records.certificates, ∃ second ∈ records.certificates,
          first.subject = tunnel.sender ∧ second.subject = tunnel.receiver ∧
          first.issuer ∈ second.chain ∧ second.issuer ∈ first.chain))
  | 11 => CentralManagementConfiguration records d
  | 16 => each (fun device record => device.kind = .macsec →
      (record.optionalClearVLAN = true → "clear-vlan" ∈ record.supportedFeatures) ∧
      (record.optionalXPN = true → "xpn" ∈ record.supportedFeatures))
  | 17 => MutuallyAuthenticatedTunnels records d
  | 18 => each (fun device record =>
      (device.kind = .vpn → IPsecAlgorithmConfiguration record) ∧
      (device.kind = .macsec → record.macsecBits = 256 ∧
        record.macsecAlgorithm ∈ ["GCM-AES-256", "GCM-AES-XPN-256"]))
  | 19 => each (fun device record => device.kind = .vpn → IPsecAlgorithmConfiguration record)
  | 20 => each (fun device record => device.kind = .vpn →
      CertificateIdentityConfiguration records device.id record.removeDefaultCertificatesSelected)
  | 22 => each (fun device record => device.kind = .vpn → IPsecModesAndLifetimes record)
  | 23 => each (fun device record => device.kind = .vpn →
      IPsecModesAndLifetimes record ∧
      ∀ rekey ∈ records.rekeys, rekey.device = device.id →
        rekey.authenticatedAt < rekey.rekeyedAt ∧
        ∃ observation ∈ records.authentications,
          observation.input.verifier = device.id ∧ observation.input.claimant = rekey.peer ∧
          observation.association = rekey.association ∧
          observation.input.time = rekey.authenticatedAt ∧ AuthenticatedCertificate records observation)
  | 25 => each (fun device record => device.kind = .macsec →
      record.keyWrapAlgorithm = "AES-Key-Wrap" ∧ record.keyWrapBits = 256 ∧
      record.macsecBits = 256 ∧ record.macsecAlgorithm ∈ ["GCM-AES-256", "GCM-AES-XPN-256"])
  | 26 => each (fun device record =>
      (device.kind = .macsec ∧ d.certificateAuthenticated device.id = true ∨
        device.kind = .authenticationServer) → EAPAlgorithmConfiguration record)
  | 31 => ∀ use ∈ records.routing, subject.Contains use.component →
      (d.IsLayer use.component .outer → use.dynamicProtocol = false) ∧
      (d.IsLayer use.component .inner → use.ownTunnelLookup = true ∨
        (use.sourceComponent = use.component ∧ use.destinationComponent = use.component))
  | 36 => each (fun _ record => record.enabledInterfaces = record.minimumFeasibleExposure ∧
      ∀ interface ∈ record.unusedInterfaces, interface ∉ record.enabledInterfaces)
  | 41 => each (fun device record => ControlServiceConfiguration record device)
  | 42 => each (fun device _ => TrustedTimeConfiguration records.time device d)
  | 43 => context.ConfigurationDefaults subject
  | 44 => ManagementAttachmentConfiguration records d
  | 45 => each (fun device record => device.kind = .workstation →
      WorkstationHostConfiguration records record ∧
      records.external.Confirms .vendorAndLocalHardening (.component device.id) ∧
      records.external.Confirms .protectedFacility (.component device.id))
  | 46 => each (fun _ record => ManagementTransportConfiguration record)
  | 48 => each (fun device _ => ProvisioningConfiguration records d device.id)
  | 49 => external [.authorizedAdministratorClearance, .outerAdministratorClearance]
  | 50 => SIEMConfiguration records d
  | 51 => ∀ solution ∈ records.crossDomainSolutions,
      records.external.Confirms .crossDomainDoDI (.component solution) ∧
      records.external.Confirms .crossDomainConnectionGuide (.component solution) ∧
      records.external.Confirms .crossDomainOfficialBaseline (.component solution)
  | 52 => each (fun device _ =>
      (device.kind ≠ .outerFirewall →
        records.external.Confirms .grayPhysicalProtection (.component device.id)) ∧
      records.external.Confirms .authorizedPhysicalAccess (.component device.id) ∧
      records.external.Confirms .classifiedDisposalOrAODeclassification (.component device.id) ∧
      (device.kind = .macsec →
        records.external.Confirms .macsecConfigurationProtection (.component device.id)))
  | 53 => (∀ first ∈ records.attachments, ∀ second ∈ records.attachments,
      first.outer = second.outer → first.inner ≠ second.inner →
      first.serialPredecessor = none ∧ second.serialPredecessor = none ∧
      first.vlanTrunk = false ∧ second.vlanTrunk = false ∧
      (first.redNetwork ≠ second.redNetwork →
        first.outerPhysicalInterface ≠ second.outerPhysicalInterface))
  | 55 => (records.combinedSolutionRequiresGrayFirewall = true →
      ∃ firewall ∈ d.devices, firewall.kind = .grayFirewall) ∧
      (records.combinedEndUserSolution = true ↔ context.companionFirewalls ≠ []) ∧
      ∀ companion ∈ context.companionFirewalls, companion.Requirements d records
  | 57 => each (fun device _ =>
      ∀ duty ∈ [.aoVirusUpdatePolicy, .criticalPatchTesting, .localPatchingPolicy, .tempest],
        records.external.Confirms duty (.component device.id))
  | 58 => each (fun device _ =>
      records.external.Confirms .authorizedHardwareInventory (.component device.id) ∧
      records.external.Confirms .baselineAvailableToAuditor (.component device.id))
  | 59 => external [.procurementPurposeExclusion]
  | 60 => external [.nsaAuditPermission, .nsaAuditCooperation, .annualAOAudit, .annualAuditResultsReview]
  | 61 => external [.nsaRegistrationApproval, .aoRegistrationPackage, .annualRenewal,
      .registrationChanges, .versionMigrationDeadline]
  | 62 => each (fun device _ => AuditRetentionConfiguration records device.id) ∧
      external [.incidentResponseGuidance, .auditLowSpacePlan, .auditOffloadPlan,
        .auditOverflowPlan, .auditPowerPlan]
  | 63 => each (fun _ record => if record.passwordAlternativeSelected then
      record.domainAuthenticationService.isSome = true else 112 ≤ record.infrastructureSecretEntropyBits)
  | 64 => external [.incidentDeadlineAndChannel, .incidentRequiredFields,
      .reportSecurityFailure, .reportClassifiedCompromise, .reportMaliciousGrayTraffic,
      .reportUnauthorizedClassifiedAccess, .reportUnauthorizedDestination,
      .reportMaliciousConfigurationChange, .reportUnauthorizedPrivilegeEscalation,
      .reportConcurrentCertificateReuse, .reportMaliciousPhysicalTampering,
      .reportProtectionLayerFailure, .reportSignificantServiceDegradation,
      .reportOuterConnectionDiscrepancy, .reportInnerConnectionDiscrepancy]
  | 65 => external [.differentAdministratorAndAuditor, .differentRedAndGrayAdministrators] ∧
      (records.optionalRoleMACSelected = true → external [.optionalRoleMAC])
  | 66 => external [.securityTraining, .tamperInspection]
  | 67 => each (fun device record => RevocationBeforeDisposal record
      (records.certificates.any (fun certificate => certificate.subject == device.id))
      (d.preSharedCAKAuthenticated device.id))
  | 68 => external [.administratorMaintainsMonitorsControls, .administratorLatestCriticalUpdates,
      .administratorIncidentDocumentationReporting, .administratorLogisticSupport,
      .administratorAuxiliaryDeviceDefenses, .administratorVersionCompliance]
  | 69 => external [.auditorReviewsActionsAndEvents, .auditorOnlyAdministrationAccess,
      .auditorManagesLogs, .auditorIncidentDocumentationReporting, .auditorCapabilitySurvey]
  | 70 => True
  | 71 => external [.assessmentAuthorization, .assessmentResultsToAO, .aoImplementationVerification,
      .lifecycleAOConfigurationControl, .lifecycleAORequiredUpdates,
      .externalEngagementVariants, .compromiseRevocation, .nsaRiskAssessmentToAO]
  | 72 => external [.testingAnnex, .capabilityTestCoverage, .blackGrayBoxTests,
      .testDiscrepancyDocumentation, .testBaselineDocumentation,
      .testPlanAOAdditionalRequirements, .testArtifactsAndAOReport]
  | 73 => each (fun _ record => SigningConfiguration record)
  | 74 => True
  | 75 => (∀ router ∈ records.selectedScreeningRouters,
      ∃ device ∈ d.devices, device.id = router ∧ device.layer = none)
  | 76 => external [.legalUndertaking]
  | _ => context.DirectMeaning subject group

def CPContext.ComponentApplies {S A : Type} (context : CPContext S A)
    (device : Device) (group : Fin 76) : Prop :=
  let encryption := device.layer = some .inner ∨ device.layer = some .outer
  let infrastructure := device.kind ∈ [.workstation, .certificationAuthority,
    .revocationService, .authenticationServer, .keyGenerationSolution]
  let standalone := context.deployment.standaloneEncapsulator device.id
  match group.val + 1 with
  | 7 | 9 | 10 | 11 | 13 | 34 | 53 | 55 | 56 | 59 | 60 | 61 | 64 |
      65 | 66 | 68 | 69 | 70 | 71 | 72 | 74 | 75 | 76 => False
  | 3 => device.kind ∈ [.vpn, .macsec, .grayFirewall, .outerFirewall, .innerFirewall, .authenticationServer, .intrusionPrevention]
  | 4 | 5 => encryption ∨ device.kind = .grayFirewall
  | 14 => encryption ∨ device.kind = .grayFirewall
  | 32 | 54 => encryption
  | 8 | 12 | 29 => device.layer = some .inner
  | 15 => device.kind = .macsec ∨ standalone
  | 16 | 25 | 27 | 28 => device.kind = .macsec
  | 17 | 18 | 35 => encryption ∨ device.kind = .outerFirewall
  | 19 | 20 | 21 | 22 | 23 => device.kind = .vpn
  | 24 => device.kind = .macsec ∨ device.kind = .authenticationServer
  | 26 => (device.kind = .macsec ∧ context.deployment.certificateAuthenticated device.id = true) ∨
      device.kind = .authenticationServer
  | 30 | 37 | 39 => device.layer = some .outer
  | 31 => encryption
  | 33 => encryption ∨ device.kind = .grayFirewall
  | 38 => device.kind = .vpn ∨ device.layer = some .outer
  | 40 => device.kind = .grayFirewall
  | 42 => RequiresTrustedTime context.deployment device.id
  | 45 => device.kind = .workstation
  | 48 => encryption ∧ context.deployment.certificateAuthenticated device.id = true
  | 44 | 46 => infrastructure ∨ standalone ∨ encryption ∨ device.kind = .grayFirewall ∨
      device.kind = .outerFirewall
  | 51 => device.id ∈ context.records.crossDomainSolutions
  | _ => True

def CPContext.Applicable {S A : Type} (context : CPContext S A)
    (subject : DutySubject) (group : Fin 76) : Prop :=
  match subject with
  | .solution _ | .network _ => True
  | .component component =>
      ∃ device ∈ context.deployment.devices, device.id = component ∧
        (¬ context.deployment.OrdinaryGray component ∨
          context.deployment.standaloneEncapsulator component) ∧
        context.ComponentApplies device group

def CPContext.EncryptionView {S A : Type} (context : CPContext S A)
    (encryptor : EGEncryptionComponent) : CPContext S A :=
  { context with deployment := { context.deployment with
      devices := context.deployment.devices.map (fun device =>
        if device.id = encryptor.component then
          { device with kind := match encryptor.mechanism with
            | .ipsec => .vpn
            | .macsec => .macsec }
        else device) } }

def CPContext.EnterpriseGrayMeaning {S A : Type} (context : CPContext S A)
    (subject : DutySubject) : Prop :=
  context.deployment.centralManagementSite.isSome = true →
  ∃ configuration, context.enterpriseGray = some configuration ∧
    configuration.Core (context.ScopedDeployment subject) context.records
      context.model context.payloadDomain context.sizing ∧
    ∀ encryptor ∈ configuration.encryptors, subject.Contains encryptor.component →
      let view := context.EncryptionView encryptor
      ∀ device ∈ view.deployment.devices, device.id = encryptor.component →
      ∀ group : Fin 76,
        group.val + 1 ∈ [1, 2, 3, 6, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
          26, 27, 28, 31, 32, 33, 36, 38, 41, 42, 43, 44, 46, 47, 48, 49,
          50, 52, 57, 58, 62, 63, 66, 67, 73] →
        context.ComponentApplies { device with layer := some .inner } group →
        view.BaseSourceMeaning (.component encryptor.component) group

def CPContext.AllApplicableDuties {S A : Type} (context : CPContext S A)
    (subject : DutySubject) : Prop :=
  context.KnownSubject subject ∧ context.records.InventoryComplete context.deployment ∧
  context.EnterpriseGrayMeaning subject ∧
  ∀ group : Fin 76, context.Applicable subject group → context.BaseSourceMeaning subject group

def MSCReferencesClosed {S A : Type} (contexts : List (CPContext S A)) : Prop :=
  ∀ context ∈ contexts, ∀ solution, context.conformingMSC solution →
    ∃ referenced ∈ contexts, referenced.solution = solution ∧
      referenced.AllApplicableDuties (.solution solution)

end TDN.Targets.Complete
