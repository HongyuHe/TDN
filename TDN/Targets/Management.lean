import TDN.Targets.Architecture
import TDN.Semantics.Admission
import TDN.Semantics.RecordCoverage

namespace TDN.Targets

inductive ManagementZone where
  | red | gray | black
  deriving DecidableEq, Repr

inductive ManagedRole where
  | inner | outer | innerFirewall | grayFirewall | outerFirewall | redService | grayService
  deriving DecidableEq, Repr

structure ManagementComponent where
  id : Nat
  site : Nat
  role : ManagedRole
  securityFunctions : List Nat
  certificateAuthentication : Bool
  authority : String
  deriving DecidableEq, Repr

structure AdministrativeWorkstation where
  id : Nat
  site : Nat
  zone : ManagementZone
  physicalHost : String
  virtualMachine : Bool
  inUse : Bool
  poweredOn : Bool
  deriving DecidableEq, Repr

structure AdministrationAccess where
  workstation : Nat
  component : Nat
  function : Nat
  internalPort : Bool
  dedicatedInterface : Bool
  deriving DecidableEq, Repr

def ExpectedManagementZone : ManagedRole → ManagementZone
  | .inner | .innerFirewall | .redService => .red
  | .outer | .grayFirewall | .grayService => .gray
  | .outerFirewall => .black

structure ManagementSeparation where
  dataInterface : Nat
  managementInterface : Nat
  physicalPathSeparated : Bool
  cryptographicContextsDisjoint : Bool
  grayDataManagementACLSeparated : Bool
  deriving DecidableEq, Repr

/-- Management is explicitly selected in this target. The management-free data-path scope
does not discharge the full-document requirements for Red and Gray AWs. -/
def msc_layered_administrative_separation (managementSelected : Bool)
    (components : List ManagementComponent) (workstations : List AdministrativeWorkstation)
    (accesses : List AdministrationAccess) (separation : List ManagementSeparation)
    (grayServices : List Nat) (attachedToGrayFirewallOrOuter : Nat → Prop)
    (grayManagementDirectlyConnectedToUnrelatedUnclassified : Bool) : Prop :=
  managementSelected = true →
  (∃ aw ∈ workstations, aw.zone = .red) ∧
  (∃ aw ∈ workstations, aw.zone = .gray) ∧
  (∀ component ∈ components, ∀ function ∈ component.securityFunctions,
    ∃ access ∈ accesses, access.component = component.id ∧ access.function = function) ∧
  (∀ access ∈ accesses, access.internalPort = true ∧ access.dedicatedInterface = true ∧
    ∃ aw ∈ workstations, ∃ component ∈ components,
      aw.id = access.workstation ∧ component.id = access.component ∧
      aw.zone = ExpectedManagementZone component.role) ∧
  (∀ item ∈ separation, item.dataInterface ≠ item.managementInterface ∧
    item.physicalPathSeparated = true ∧ item.cryptographicContextsDisjoint = true ∧
    item.grayDataManagementACLSeparated = true) ∧
  (∀ service ∈ grayServices, attachedToGrayFirewallOrOuter service) ∧
  grayManagementDirectlyConnectedToUnrelatedUnclassified = false

/-- A workstation with one fixed zone cannot manage both Inner and Outer components.
The premise is the local authorization check for each access, not global separation. -/
theorem workstation_zone_check_excludes_cross_layer
    (aw : AdministrativeWorkstation) (inner outer : ManagementComponent)
    (innerRole : inner.role = .inner) (outerRole : outer.role = .outer)
    (innerAuthorized : aw.zone = ExpectedManagementZone inner.role)
    (outerAuthorized : aw.zone = ExpectedManagementZone outer.role) : False := by
  simp only [innerRole, ExpectedManagementZone] at innerAuthorized
  simp only [outerRole, ExpectedManagementZone] at outerAuthorized
  rw [innerAuthorized] at outerAuthorized
  cases outerAuthorized

inductive WorkloadFunction where
  | administrativeWorkstation | provisioning | enrollment | certificateRegistration
  | siem | otherManagement | nonCSfC | dataPlane
  deriving DecidableEq, Repr

structure HostedWorkload where
  id : Nat
  physicalHost : String
  functions : List WorkloadFunction
  deriving DecidableEq, Repr

def msc_dedicated_and_hardened_aws (workstations : List AdministrativeWorkstation)
    (workloads : List HostedWorkload) (protectedFacility : String → Prop)
    (vendorHardening localConfiguration localPatching localOperation : Nat → Prop)
    (nonCSfCWorkstationHosts : List String) : Prop :=
  (∀ aw ∈ workstations,
    protectedFacility aw.physicalHost ∧ aw.physicalHost ∉ nonCSfCWorkstationHosts ∧
    vendorHardening aw.id ∧ localConfiguration aw.id ∧ localPatching aw.id ∧ localOperation aw.id ∧
    (aw.inUse = false → aw.poweredOn = false) ∧
    ∀ workload ∈ workloads, workload.physicalHost = aw.physicalHost →
      workload.functions = [.administrativeWorkstation]) ∧
  ∀ workload ∈ workloads, .otherManagement ∈ workload.functions →
    ∀ function ∈ workload.functions, function = .otherManagement

theorem non_aw_workload_refutes_host_dedication
    (workstations : List AdministrativeWorkstation) (workloads : List HostedWorkload)
    (protectedFacility : String → Prop) (hardening configuration patching operation : Nat → Prop)
    (otherHosts : List String) (aw : AdministrativeWorkstation) (workload : HostedWorkload)
    (awPresent : aw ∈ workstations) (workloadPresent : workload ∈ workloads)
    (sameHost : workload.physicalHost = aw.physicalHost)
    (differentFunction : workload.functions ≠ [.administrativeWorkstation]) :
    ¬ msc_dedicated_and_hardened_aws workstations workloads protectedFacility
      hardening configuration patching operation otherHosts := by
  intro compliant
  exact differentFunction ((compliant.1 aw awPresent).2.2.2.2.2.2.2 workload workloadPresent sameHost)

inductive ManagementProtection where
  | ssh2 | tls12 | tls13 | ipsec | macsec | other
  deriving DecidableEq, Repr

def ApprovedManagementProtocol (protocol : ManagementProtection) : Prop :=
  protocol ∈ [.ssh2, .tls12, .tls13, .ipsec, .macsec]

structure ManagementTransmission where
  id : Nat
  originZone : ManagementZone
  fromAW : Bool
  localDirectPhysical : Bool
  sameLANOrVLAN : Bool
  crossesBlack : Bool
  protection : List ManagementProtection
  remoteNSAApprovedSolution : Bool
  localAdministration : Bool
  deriving DecidableEq, Repr

structure AdministrationAddressRange where
  component : Nat
  low : Nat
  high : Nat
  deriving DecidableEq, Repr

def RangeCovers (range : AdministrationAddressRange) (addresses : List Nat) : Prop :=
  ∀ address ∈ addresses, range.low ≤ address ∧ address ≤ range.high

/-- The feasible address ranges encode actual implementation choices that cover the
necessary AW addresses. Minimality is checked against that inventory, not merely asserted. -/
def msc_secure_management_transport (traffic : List ManagementTransmission)
    (ranges feasibleRanges : List AdministrationAddressRange) (requiredAddresses : Nat → List Nat) : Prop :=
  (∀ transmission ∈ traffic,
    (transmission.localDirectPhysical = false →
      transmission.protection ≠ [] ∧ ∀ p ∈ transmission.protection, ApprovedManagementProtocol p) ∧
    (transmission.originZone = .gray → transmission.fromAW = true →
      transmission.localDirectPhysical = false → transmission.sameLANOrVLAN = false →
        2 ≤ transmission.protection.length) ∧
    (transmission.crossesBlack = true →
      2 ≤ transmission.protection.length ∧ transmission.remoteNSAApprovedSolution = true) ∧
    (transmission.localAdministration = true ∨ transmission.remoteNSAApprovedSolution = true)) ∧
  ∀ range ∈ ranges, RangeCovers range (requiredAddresses range.component) ∧
    range ∈ feasibleRanges ∧ ∀ candidate ∈ feasibleRanges,
      candidate.component = range.component → RangeCovers candidate (requiredAddresses range.component) →
        range.high - range.low ≤ candidate.high - candidate.low

lemma endpoint_range_is_minimal (range candidate : AdministrationAddressRange)
    (ordered : range.low ≤ range.high)
    (lowCovered : candidate.low ≤ range.low)
    (highCovered : range.high ≤ candidate.high) :
    range.high - range.low ≤ candidate.high - candidate.low := by omega

structure SiteAuthority where
  site : Nat
  identity : String
  locallyManaged : Bool
  enterprise : Bool
  deriving DecidableEq, Repr

structure PeerAuthenticationMaterial where
  source : Nat
  peer : Nat
  certificateAuthentication : Bool
  signingCertificatesLoaded : Bool
  revocationInformationLoaded : Bool
  authorityTrusted : Bool
  cak : Option String
  peerCAK : Option String
  deriving DecidableEq, Repr

/-- Site count is unrestricted. The partner inventory is limited to intended authenticated
peers, so cross-level trust is never introduced by the phrase all other sites. -/
def msc_independently_managed_sites (selected : Bool) (sites : List Nat)
    (components : List ManagementComponent) (administratorSite : Nat → Nat)
    (authorities : List SiteAuthority) (peers : List PeerAuthenticationMaterial)
    (interoperates : Nat → Nat → Prop) (managementTraffic : List ManagementTransmission)
    (authenticationServers : List Nat) (connectedRed connectedGray : Nat → Prop) : Prop :=
  selected = true →
  (∀ component ∈ components, component.site ∈ sites ∧ administratorSite component.id = component.site) ∧
  (∀ authority ∈ authorities, authority.locallyManaged = true ∨ authority.enterprise = true) ∧
  (∀ peer ∈ peers, interoperates peer.source peer.peer ∧
    (peer.certificateAuthentication = true → peer.signingCertificatesLoaded = true ∧
      peer.revocationInformationLoaded = true ∧ peer.authorityTrusted = true) ∧
    (peer.cak ≠ none → peer.cak = peer.peerCAK)) ∧
  (∀ transmission ∈ managementTraffic, transmission.crossesBlack = false) ∧
  ∀ server ∈ authenticationServers, ¬ (connectedRed server ∧ connectedGray server)

structure CentralManagementAssignment where
  component : Nat
  administratorSite : Nat
  keyingSite : Nat
  deviceManagementSite : Nat
  deriving DecidableEq, Repr

/-- Each certificate-authenticated layer requires its own central CA. A selected PSK layer
does not acquire an invented CA obligation; cross-layer authority separation remains explicit. -/
def msc_centrally_managed_sites (selected : Bool) (centralSite : Nat)
    (components : List ManagementComponent) (assignments : List CentralManagementAssignment)
    (authorityAt : String → Nat → Prop) (eapComponents : List Nat)
    (centralAuthenticationServer : Nat → Prop) (interoperates : Nat → Nat → Prop)
    (requiredPeerPairs : List (Nat × Nat)) (traffic : List ManagementTransmission)
    (managementEncryptionBeforeInnerOuter : Nat → Prop)
    (enterpriseGrayAnnexSatisfied : Prop) : Prop :=
  selected = true →
  (∀ component ∈ components, ∃ assignment ∈ assignments,
    assignment.component = component.id ∧ assignment.administratorSite = centralSite ∧
    assignment.keyingSite = centralSite ∧ assignment.deviceManagementSite = centralSite) ∧
  (∀ component ∈ components, component.certificateAuthentication = true →
    authorityAt component.authority centralSite) ∧
  (∀ inner ∈ components, ∀ outer ∈ components,
    inner.role = .inner → outer.role = .outer →
    inner.certificateAuthentication = true → outer.certificateAuthentication = true →
      inner.authority ≠ outer.authority) ∧
  (∀ component ∈ eapComponents, centralAuthenticationServer component) ∧
  (∀ pair ∈ requiredPeerPairs, interoperates pair.1 pair.2) ∧
  enterpriseGrayAnnexSatisfied ∧
  ∀ transmission ∈ traffic, transmission.crossesBlack = true →
    2 ≤ transmission.protection.length ∧
    (transmission.originZone = .red → managementEncryptionBeforeInnerOuter transmission.id)

end TDN.Targets
