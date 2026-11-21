import TDN.Deployments.SecurityLevelConnectivity_Records

namespace TDN.Deployments.SecurityLevelConnectivity
open Requirements Requirements.Msc Compliance MtuSizing_Records NestedProtection

structure SolutionRoster where
  profile : String
  solution : String
  profileSha256 : String
  snapshotSha256 : String
  transportDevices : List String
  devices : List String
  referencedConformingSolutions : List String

structure ConfiguredInnerPeer where
  sourceInner : String
  peerInner : String
  sourceNetwork : String
  peerNetwork : String

structure HostPlacement where
  device : String
  role : String
  host : String
  virtualization : String
  image : String
  observations : List String

structure RedProbe where
  source : String
  destination : String
  expected : String
  observed : String
  id : String
  observations : List String

structure RedEndpoint where
  network : String
  host : String
  site : String
  link : String
  declaredInner : String
  observedInner : String
  profileLevel : String
  assignedLevel : SecurityLevel

structure ConnectivityCapture where
  roster : SolutionRoster
  peers : List ConfiguredInnerPeer
  placements : List HostPlacement
  probes : List RedProbe
  endpoints : List RedEndpoint
  epoch : String

def RecordsMatchPhysicalHosts (records : TechnicalDutyRecords) (placements : List HostPlacement) : Prop :=
  ∀ placement ∈ placements, ∀ record ∈ records.components, placement.device = record.component →
    placement.host = record.physicalDevice

def recordsWithObservedPlacement (placements : List HostPlacement)
    (records : TechnicalDutyRecords) (fields : String → ComponentDutyRecord) : TechnicalDutyRecords :=
  { records with components := placements.map fun (row : HostPlacement) =>
      { fields row.device with component := row.device, physicalDevice := row.host } }

def CompleteHostPlacements (devices : List Device) (placements : List HostPlacement) : Prop :=
  (∀ first ∈ placements, ∀ last ∈ placements, first.device = last.device → first.host = last.host) ∧
  (∀ device ∈ devices, ∃ row ∈ placements, row.device = device.id) ∧
  ∀ row ∈ placements, row.observations ≠ [] ∧ row.host ≠ "" ∧ ∃ device ∈ devices, device.id = row.device

lemma observed_placement_records_match (devices : List Device) (placements : List HostPlacement)
    (complete : CompleteHostPlacements devices placements)
    (base : TechnicalDutyRecords) (fields : String → ComponentDutyRecord) :
    RecordsMatchPhysicalHosts (recordsWithObservedPlacement placements base fields) placements ∧
    ∀ device ∈ devices, ∃ record ∈ (recordsWithObservedPlacement placements base fields).components,
      record.component = device.id := by
  constructor
  · intro row listed record stored name
    obtain ⟨actual, actualRow, rfl⟩ := List.mem_map.mp stored
    exact complete.1 row listed actual actualRow name
  · intro device member
    obtain ⟨row, listed, name⟩ := complete.2.1 device member
    exact ⟨_, List.mem_map.mpr ⟨row, listed, rfl⟩, name⟩

def ConnectivityCapture.ProbeResultsAgree (capture : ConnectivityCapture)
    (networks : List RedNetworkIdentity) (demands : List (String × String)) : Prop :=
  (capture.probes.map (fun probe => (probe.source, probe.destination))).Nodup ∧
  (∀ a ∈ networks, ∀ b ∈ networks, a.id ≠ b.id → ∃ probe ∈ capture.probes,
    probe.source = a.id ∧ probe.destination = b.id) ∧
  ∀ probe ∈ capture.probes, probe.source ≠ probe.destination ∧ probe.observations ≠ [] ∧
    (∃ a ∈ networks, ∃ b ∈ networks, a.id = probe.source ∧ b.id = probe.destination ∧
      probe.expected = (if a.level = b.level then "delivered" else "no_reply")) ∧
    (probe.expected = "delivered" ↔ (probe.source, probe.destination) ∈ demands) ∧
    probe.observed = probe.expected

def ConnectivityCapture.MatchesEndpoints (capture : ConnectivityCapture) (devices : List Device)
    (networks : List RedNetworkIdentity) (entries : List SourceEntry) : Prop :=
  capture.roster.devices.toFinset = (devices.map Device.id).toFinset ∧
  (∀ n ∈ networks, ∃ e ∈ capture.endpoints,
    e.network = n.id ∧ e.site = n.site ∧ e.assignedLevel = n.level ∧
    e.observedInner = e.declaredInner ∧ n.innerComponents = {e.observedInner} ∧ e.link ≠ "" ∧
    ∃ row ∈ entries, row.network = n.id ∧ row.sourceHost = e.host) ∧
  (∀ e ∈ capture.endpoints, ∃ n ∈ networks, e.network = n.id) ∧
  ∀ p ∈ capture.peers, ∃ a ∈ capture.endpoints, ∃ b ∈ capture.endpoints,
    a.network = p.sourceNetwork ∧ a.observedInner = p.sourceInner ∧
    b.network = p.peerNetwork ∧ b.observedInner = p.peerInner

def ConnectivityCapture.MatchesPeerSessions (capture : ConnectivityCapture)
    (authentication : List PublicAuthenticationBinding) (children : List InstalledChild)
    (authenticated installed : List (String × String)) (tunnels : List Tunnel) : Prop :=
  (∀ row ∈ authentication, row.Check capture.epoch) ∧
  (∀ child ∈ children, ∃ row ∈ authentication, row.device = child.device ∧ row.peerDevice = child.peer ∧
    row.ikeUniqueId = child.ike ∧ row.childUniqueId = child.child) ∧
  authenticated.toFinset = (capture.peers.map (fun p => (p.sourceInner, p.peerInner))).toFinset ∧
  installed.toFinset = authenticated.toFinset ∧
  installed.toFinset = ((tunnels.filter (fun t => t.layer == .inner)).map (fun t => (t.sender, t.receiver))).toFinset

structure ConnectivityCapture.MatchesContext {S A : Type} (capture : ConnectivityCapture)
    (context : ComplianceContext S A) (entries : List SourceEntry)
    (authentication : List PublicAuthenticationBinding) (children : List InstalledChild) : Prop where
  solution : context.solution = capture.roster.solution
  references : ∀ name, context.conformingMSC name ↔ name ∈ capture.roster.referencedConformingSolutions
  endpoints : capture.MatchesEndpoints context.deployment.devices context.deployment.networks entries
  sessions : capture.MatchesPeerSessions authentication children context.authenticatedInnerPairs
    context.establishedInnerTunnels context.deployment.tunnels
  authenticationRows : context.authenticatedInnerPairs =
    observedInnerPairs context.deployment.devices (authentication.map fun row => (row.device, row.peerDevice))
  installedRows : context.establishedInnerTunnels =
    observedInnerPairs context.deployment.devices (children.map fun row => (row.device, row.peer))
  demands : context.requiredConnectivity = capture.peers.map (fun row => (row.sourceNetwork, row.peerNetwork))
  unclassified : context.includedUnclassified = unclassifiedNetworkIds context.deployment.networks
  placement : RecordsMatchPhysicalHosts context.records capture.placements
  technicalRecords : ∀ device ∈ context.deployment.devices, ∃ record ∈ context.records.components, record.component = device.id

end TDN.Deployments.SecurityLevelConnectivity
