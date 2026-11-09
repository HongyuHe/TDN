import TDN.Import.SnapshotLoader
import TDN.Deployments.ProfileShared_DataPlane
import TDN.Requirements.PacketEnclaveIsolation
import TDN.Requirements.TwoLayerOverlayArchitecture

namespace TDN.Deployments.ProfileShared_EnclaveIsolation
open DataPlaneForwarding

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option linter.unusedSimpArgs false

def ownerDomain : Nat → Option Nat
  | 12 => some 1
  | 13 => some 2
  | 14 => some 3
  | 15 => some 4
  | 16 => some 1
  | 17 => some 2
  | 18 => some 3
  | 19 => some 4
  | 24 => some 1
  | 25 => some 2
  | 26 => some 3
  | 27 => some 4
  | 28 => some 1
  | 29 => some 2
  | 30 => some 3
  | 31 => some 4
  | _ => none

def ownerTag : Nat → Nat
  | 12 => 11
  | 13 => 12
  | 14 => 13
  | 15 => 14
  | 16 => 11
  | 17 => 12
  | 18 => 13
  | 19 => 14
  | 22 => 2
  | 23 => 2
  | _ => 0

def fullLevel : Nat → SecurityLevel
  | 1 => ⟨"TOP_SECRET", {}, {}, {}⟩
  | 2 => ⟨"SECRET", {}, {"US_ONLY"}, {}⟩
  | 3 => ⟨"SECRET", {}, {"COALITION"}, {}⟩
  | 4 => ⟨"UNCLASSIFIED", {}, {}, {}⟩
  | _ => ⟨"", {}, {}, {}⟩

def taggedDevices : List DeviceData := TDN.Deployments.ProfileShared_DataPlane.devices.zipIdx.map fun pair =>
  { pair.1 with
    egressPolicies := pair.1.egressPolicies.map (fun a => { a with tag := ownerTag pair.2 })
    ingressPolicies := pair.1.ingressPolicies.map (fun a => { a with tag := ownerTag pair.2 })
    ifaceSecurityDomain := pair.1.ifaceSecurityDomain.bind (fun _ => ownerDomain pair.2) }

def stackFor (domain : Nat) (iface : IfaceData) : List Nat :=
  if iface.stack = [] then [] else if iface.stack = [1] then [domain + 10] else [2, domain + 10]
def allowedRecord (domain : Nat) (iface : IfaceData) : Bool :=
  !iface.stack.isEmpty || decide (ownerDomain iface.owner = some domain)

def config : DataPlaneForwarding.DataPlaneModel := dataPlaneModelFromRecords taggedDevices TDN.Deployments.ProfileShared_DataPlane.ifaces TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches
def redSources : List Nat := TDN.Deployments.ProfileShared_DataPlane.redSources
load_network_records domains : List Nat from "../../data/evidence/ProfileShared_EnclaveIsolation.json" ["TDN.Deployments.ProfileShared_EnclaveIsolation.domains"]

lemma peer_tag_checks : TableDrivenPeerTagAgreement taggedDevices := by
  (try simp only [TableDrivenPeerTagAgreement, taggedDevices, TDN.Deployments.ProfileShared_DataPlane.devices, ownerTag, ownerDomain, saMatchesPolicy, SameWireAssociation]); all_goals decide
lemma peer_tags_justified_by_wire_SAs : PeerTagAgreement config :=
  table_driven_peer_tag_agreement_sound taggedDevices TDN.Deployments.ProfileShared_DataPlane.ifaces TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches peer_tag_checks

def domainIfaces1 : List IfaceData := withEncapStackAnnotations TDN.Deployments.ProfileShared_DataPlane.ifaces (stackFor 1)
def domainLayout1 : Nat → List Nat := expectedEncapStackFromRecords domainIfaces1
def domainAllowed1 (p : Nat) : Prop := allowedRecord 1 (ifaceAt domainIfaces1 p) = true
lemma config_same1 : dataPlaneModelFromRecords taggedDevices domainIfaces1 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches = config :=
  data_plane_ignores_encap_stack_annotations taggedDevices TDN.Deployments.ProfileShared_DataPlane.ifaces (stackFor 1) TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches
lemma route_owner_checks1 : ∀ r ∈ TDN.Deployments.ProfileShared_DataPlane.routes, (ifaceAt domainIfaces1 r.egress).owner = (ifaceAt domainIfaces1 r.ingress).owner := by
  (try simp only [TDN.Deployments.ProfileShared_DataPlane.routes, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma link_checks1 : ∀ edge ∈ TDN.Deployments.ProfileShared_DataPlane.links, allowedRecord 1 (ifaceAt domainIfaces1 edge.1) = true → (ifaceAt domainIfaces1 edge.1).stack = (ifaceAt domainIfaces1 edge.2).stack ∧ allowedRecord 1 (ifaceAt domainIfaces1 edge.2) = true := by
  (try simp only [TDN.Deployments.ProfileShared_DataPlane.links, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma switch_checks1 : ∀ edge ∈ TDN.Deployments.ProfileShared_DataPlane.switches, allowedRecord 1 (ifaceAt domainIfaces1 edge.1) = true → ((ifaceAt domainIfaces1 edge.1).stack = (ifaceAt domainIfaces1 edge.2).stack ∧ (deviceAt taggedDevices (ifaceAt domainIfaces1 edge.1).owner).ingressPolicies = []) ∧ allowedRecord 1 (ifaceAt domainIfaces1 edge.2) = true := by
  (try simp only [TDN.Deployments.ProfileShared_DataPlane.switches, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma forward_default_checks1 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma forward_checks1 : TableDrivenDomainForwardChecks taggedDevices domainIfaces1 (allowedRecord 1) := by
  (try simp only [TableDrivenDomainForwardChecks, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma output_checks1 : TableDrivenDomainOutputChecks taggedDevices domainIfaces1 (allowedRecord 1) := by
  (try simp only [TableDrivenDomainOutputChecks, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma outer_route_checks1 : TableDrivenDomainOuterRoutes taggedDevices domainIfaces1 TDN.Deployments.ProfileShared_DataPlane.routes (allowedRecord 1) := by
  (try simp only [TableDrivenDomainOuterRoutes, TDN.Deployments.ProfileShared_DataPlane.routes, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma local_domain_conditions1 : LocalDomainConditions config domainLayout1 domainAllowed1 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainIfaces1 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches (allowedRecord 1)
    route_owner_checks1 link_checks1 switch_checks1 forward_default_checks1 forward_checks1 output_checks1 outer_route_checks1
  rw [config_same1] at checked
  exact checked
lemma source_checks1 : ∀ p ∈ redSources, config.ifaceSecurityDomain p = some 1 → domainLayout1 p = [] ∧ config.canOriginateTraffic p ∧ domainAllowed1 p := by
  (try simp only [redSources, TDN.Deployments.ProfileShared_DataPlane.redSources, config, dataPlaneModelFromRecords, domainLayout1, expectedEncapStackFromRecords, domainAllowed1, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma recipient_records1 : ∀ p ∈ ({} : IfaceData) :: domainIfaces1, allowedRecord 1 p = true → (deviceAt taggedDevices p.owner).ifaceSecurityDomain = none ∨ (deviceAt taggedDevices p.owner).ifaceSecurityDomain = some 1 := by
  (try simp only [domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma recipient_checks1 : ∀ p, domainAllowed1 p → config.ifaceSecurityDomain p = none ∨ config.ifaceSecurityDomain p = some 1 := by
  intro p permitted
  have checked := recipient_records1 (ifaceAt domainIfaces1 p) (iface_at_member_or_default domainIfaces1 p) permitted
  change (dataPlaneModelFromRecords taggedDevices domainIfaces1 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches).ifaceSecurityDomain p = none ∨ (dataPlaneModelFromRecords taggedDevices domainIfaces1 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches).ifaceSecurityDomain p = some 1 at checked
  rw [config_same1] at checked
  exact checked

def domainIfaces2 : List IfaceData := withEncapStackAnnotations TDN.Deployments.ProfileShared_DataPlane.ifaces (stackFor 2)
def domainLayout2 : Nat → List Nat := expectedEncapStackFromRecords domainIfaces2
def domainAllowed2 (p : Nat) : Prop := allowedRecord 2 (ifaceAt domainIfaces2 p) = true
lemma config_same2 : dataPlaneModelFromRecords taggedDevices domainIfaces2 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches = config :=
  data_plane_ignores_encap_stack_annotations taggedDevices TDN.Deployments.ProfileShared_DataPlane.ifaces (stackFor 2) TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches
lemma route_owner_checks2 : ∀ r ∈ TDN.Deployments.ProfileShared_DataPlane.routes, (ifaceAt domainIfaces2 r.egress).owner = (ifaceAt domainIfaces2 r.ingress).owner := by
  (try simp only [TDN.Deployments.ProfileShared_DataPlane.routes, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma link_checks2 : ∀ edge ∈ TDN.Deployments.ProfileShared_DataPlane.links, allowedRecord 2 (ifaceAt domainIfaces2 edge.1) = true → (ifaceAt domainIfaces2 edge.1).stack = (ifaceAt domainIfaces2 edge.2).stack ∧ allowedRecord 2 (ifaceAt domainIfaces2 edge.2) = true := by
  (try simp only [TDN.Deployments.ProfileShared_DataPlane.links, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma switch_checks2 : ∀ edge ∈ TDN.Deployments.ProfileShared_DataPlane.switches, allowedRecord 2 (ifaceAt domainIfaces2 edge.1) = true → ((ifaceAt domainIfaces2 edge.1).stack = (ifaceAt domainIfaces2 edge.2).stack ∧ (deviceAt taggedDevices (ifaceAt domainIfaces2 edge.1).owner).ingressPolicies = []) ∧ allowedRecord 2 (ifaceAt domainIfaces2 edge.2) = true := by
  (try simp only [TDN.Deployments.ProfileShared_DataPlane.switches, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma forward_default_checks2 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma forward_checks2 : TableDrivenDomainForwardChecks taggedDevices domainIfaces2 (allowedRecord 2) := by
  (try simp only [TableDrivenDomainForwardChecks, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma output_checks2 : TableDrivenDomainOutputChecks taggedDevices domainIfaces2 (allowedRecord 2) := by
  (try simp only [TableDrivenDomainOutputChecks, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma outer_route_checks2 : TableDrivenDomainOuterRoutes taggedDevices domainIfaces2 TDN.Deployments.ProfileShared_DataPlane.routes (allowedRecord 2) := by
  (try simp only [TableDrivenDomainOuterRoutes, TDN.Deployments.ProfileShared_DataPlane.routes, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma local_domain_conditions2 : LocalDomainConditions config domainLayout2 domainAllowed2 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainIfaces2 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches (allowedRecord 2)
    route_owner_checks2 link_checks2 switch_checks2 forward_default_checks2 forward_checks2 output_checks2 outer_route_checks2
  rw [config_same2] at checked
  exact checked
lemma source_checks2 : ∀ p ∈ redSources, config.ifaceSecurityDomain p = some 2 → domainLayout2 p = [] ∧ config.canOriginateTraffic p ∧ domainAllowed2 p := by
  (try simp only [redSources, TDN.Deployments.ProfileShared_DataPlane.redSources, config, dataPlaneModelFromRecords, domainLayout2, expectedEncapStackFromRecords, domainAllowed2, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma recipient_records2 : ∀ p ∈ ({} : IfaceData) :: domainIfaces2, allowedRecord 2 p = true → (deviceAt taggedDevices p.owner).ifaceSecurityDomain = none ∨ (deviceAt taggedDevices p.owner).ifaceSecurityDomain = some 2 := by
  (try simp only [domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma recipient_checks2 : ∀ p, domainAllowed2 p → config.ifaceSecurityDomain p = none ∨ config.ifaceSecurityDomain p = some 2 := by
  intro p permitted
  have checked := recipient_records2 (ifaceAt domainIfaces2 p) (iface_at_member_or_default domainIfaces2 p) permitted
  change (dataPlaneModelFromRecords taggedDevices domainIfaces2 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches).ifaceSecurityDomain p = none ∨ (dataPlaneModelFromRecords taggedDevices domainIfaces2 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches).ifaceSecurityDomain p = some 2 at checked
  rw [config_same2] at checked
  exact checked

def domainIfaces3 : List IfaceData := withEncapStackAnnotations TDN.Deployments.ProfileShared_DataPlane.ifaces (stackFor 3)
def domainLayout3 : Nat → List Nat := expectedEncapStackFromRecords domainIfaces3
def domainAllowed3 (p : Nat) : Prop := allowedRecord 3 (ifaceAt domainIfaces3 p) = true
lemma config_same3 : dataPlaneModelFromRecords taggedDevices domainIfaces3 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches = config :=
  data_plane_ignores_encap_stack_annotations taggedDevices TDN.Deployments.ProfileShared_DataPlane.ifaces (stackFor 3) TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches
lemma route_owner_checks3 : ∀ r ∈ TDN.Deployments.ProfileShared_DataPlane.routes, (ifaceAt domainIfaces3 r.egress).owner = (ifaceAt domainIfaces3 r.ingress).owner := by
  (try simp only [TDN.Deployments.ProfileShared_DataPlane.routes, domainIfaces3, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma link_checks3 : ∀ edge ∈ TDN.Deployments.ProfileShared_DataPlane.links, allowedRecord 3 (ifaceAt domainIfaces3 edge.1) = true → (ifaceAt domainIfaces3 edge.1).stack = (ifaceAt domainIfaces3 edge.2).stack ∧ allowedRecord 3 (ifaceAt domainIfaces3 edge.2) = true := by
  (try simp only [TDN.Deployments.ProfileShared_DataPlane.links, domainIfaces3, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma switch_checks3 : ∀ edge ∈ TDN.Deployments.ProfileShared_DataPlane.switches, allowedRecord 3 (ifaceAt domainIfaces3 edge.1) = true → ((ifaceAt domainIfaces3 edge.1).stack = (ifaceAt domainIfaces3 edge.2).stack ∧ (deviceAt taggedDevices (ifaceAt domainIfaces3 edge.1).owner).ingressPolicies = []) ∧ allowedRecord 3 (ifaceAt domainIfaces3 edge.2) = true := by
  (try simp only [TDN.Deployments.ProfileShared_DataPlane.switches, domainIfaces3, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma forward_default_checks3 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainIfaces3, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma forward_checks3 : TableDrivenDomainForwardChecks taggedDevices domainIfaces3 (allowedRecord 3) := by
  (try simp only [TableDrivenDomainForwardChecks, domainIfaces3, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma output_checks3 : TableDrivenDomainOutputChecks taggedDevices domainIfaces3 (allowedRecord 3) := by
  (try simp only [TableDrivenDomainOutputChecks, domainIfaces3, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma outer_route_checks3 : TableDrivenDomainOuterRoutes taggedDevices domainIfaces3 TDN.Deployments.ProfileShared_DataPlane.routes (allowedRecord 3) := by
  (try simp only [TableDrivenDomainOuterRoutes, TDN.Deployments.ProfileShared_DataPlane.routes, domainIfaces3, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma local_domain_conditions3 : LocalDomainConditions config domainLayout3 domainAllowed3 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainIfaces3 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches (allowedRecord 3)
    route_owner_checks3 link_checks3 switch_checks3 forward_default_checks3 forward_checks3 output_checks3 outer_route_checks3
  rw [config_same3] at checked
  exact checked
lemma source_checks3 : ∀ p ∈ redSources, config.ifaceSecurityDomain p = some 3 → domainLayout3 p = [] ∧ config.canOriginateTraffic p ∧ domainAllowed3 p := by
  (try simp only [redSources, TDN.Deployments.ProfileShared_DataPlane.redSources, config, dataPlaneModelFromRecords, domainLayout3, expectedEncapStackFromRecords, domainAllowed3, domainIfaces3, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma recipient_records3 : ∀ p ∈ ({} : IfaceData) :: domainIfaces3, allowedRecord 3 p = true → (deviceAt taggedDevices p.owner).ifaceSecurityDomain = none ∨ (deviceAt taggedDevices p.owner).ifaceSecurityDomain = some 3 := by
  (try simp only [domainIfaces3, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma recipient_checks3 : ∀ p, domainAllowed3 p → config.ifaceSecurityDomain p = none ∨ config.ifaceSecurityDomain p = some 3 := by
  intro p permitted
  have checked := recipient_records3 (ifaceAt domainIfaces3 p) (iface_at_member_or_default domainIfaces3 p) permitted
  change (dataPlaneModelFromRecords taggedDevices domainIfaces3 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches).ifaceSecurityDomain p = none ∨ (dataPlaneModelFromRecords taggedDevices domainIfaces3 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches).ifaceSecurityDomain p = some 3 at checked
  rw [config_same3] at checked
  exact checked

def domainIfaces4 : List IfaceData := withEncapStackAnnotations TDN.Deployments.ProfileShared_DataPlane.ifaces (stackFor 4)
def domainLayout4 : Nat → List Nat := expectedEncapStackFromRecords domainIfaces4
def domainAllowed4 (p : Nat) : Prop := allowedRecord 4 (ifaceAt domainIfaces4 p) = true
lemma config_same4 : dataPlaneModelFromRecords taggedDevices domainIfaces4 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches = config :=
  data_plane_ignores_encap_stack_annotations taggedDevices TDN.Deployments.ProfileShared_DataPlane.ifaces (stackFor 4) TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches
lemma route_owner_checks4 : ∀ r ∈ TDN.Deployments.ProfileShared_DataPlane.routes, (ifaceAt domainIfaces4 r.egress).owner = (ifaceAt domainIfaces4 r.ingress).owner := by
  (try simp only [TDN.Deployments.ProfileShared_DataPlane.routes, domainIfaces4, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma link_checks4 : ∀ edge ∈ TDN.Deployments.ProfileShared_DataPlane.links, allowedRecord 4 (ifaceAt domainIfaces4 edge.1) = true → (ifaceAt domainIfaces4 edge.1).stack = (ifaceAt domainIfaces4 edge.2).stack ∧ allowedRecord 4 (ifaceAt domainIfaces4 edge.2) = true := by
  (try simp only [TDN.Deployments.ProfileShared_DataPlane.links, domainIfaces4, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma switch_checks4 : ∀ edge ∈ TDN.Deployments.ProfileShared_DataPlane.switches, allowedRecord 4 (ifaceAt domainIfaces4 edge.1) = true → ((ifaceAt domainIfaces4 edge.1).stack = (ifaceAt domainIfaces4 edge.2).stack ∧ (deviceAt taggedDevices (ifaceAt domainIfaces4 edge.1).owner).ingressPolicies = []) ∧ allowedRecord 4 (ifaceAt domainIfaces4 edge.2) = true := by
  (try simp only [TDN.Deployments.ProfileShared_DataPlane.switches, domainIfaces4, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma forward_default_checks4 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainIfaces4, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma forward_checks4 : TableDrivenDomainForwardChecks taggedDevices domainIfaces4 (allowedRecord 4) := by
  (try simp only [TableDrivenDomainForwardChecks, domainIfaces4, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma output_checks4 : TableDrivenDomainOutputChecks taggedDevices domainIfaces4 (allowedRecord 4) := by
  (try simp only [TableDrivenDomainOutputChecks, domainIfaces4, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma outer_route_checks4 : TableDrivenDomainOuterRoutes taggedDevices domainIfaces4 TDN.Deployments.ProfileShared_DataPlane.routes (allowedRecord 4) := by
  (try simp only [TableDrivenDomainOuterRoutes, TDN.Deployments.ProfileShared_DataPlane.routes, domainIfaces4, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma local_domain_conditions4 : LocalDomainConditions config domainLayout4 domainAllowed4 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainIfaces4 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches (allowedRecord 4)
    route_owner_checks4 link_checks4 switch_checks4 forward_default_checks4 forward_checks4 output_checks4 outer_route_checks4
  rw [config_same4] at checked
  exact checked
lemma source_checks4 : ∀ p ∈ redSources, config.ifaceSecurityDomain p = some 4 → domainLayout4 p = [] ∧ config.canOriginateTraffic p ∧ domainAllowed4 p := by
  (try simp only [redSources, TDN.Deployments.ProfileShared_DataPlane.redSources, config, dataPlaneModelFromRecords, domainLayout4, expectedEncapStackFromRecords, domainAllowed4, domainIfaces4, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma recipient_records4 : ∀ p ∈ ({} : IfaceData) :: domainIfaces4, allowedRecord 4 p = true → (deviceAt taggedDevices p.owner).ifaceSecurityDomain = none ∨ (deviceAt taggedDevices p.owner).ifaceSecurityDomain = some 4 := by
  (try simp only [domainIfaces4, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileShared_DataPlane.ifaces, TDN.Deployments.ProfileShared_DataPlane.devices]); all_goals decide
lemma recipient_checks4 : ∀ p, domainAllowed4 p → config.ifaceSecurityDomain p = none ∨ config.ifaceSecurityDomain p = some 4 := by
  intro p permitted
  have checked := recipient_records4 (ifaceAt domainIfaces4 p) (iface_at_member_or_default domainIfaces4 p) permitted
  change (dataPlaneModelFromRecords taggedDevices domainIfaces4 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches).ifaceSecurityDomain p = none ∨ (dataPlaneModelFromRecords taggedDevices domainIfaces4 TDN.Deployments.ProfileShared_DataPlane.routes TDN.Deployments.ProfileShared_DataPlane.links TDN.Deployments.ProfileShared_DataPlane.switches).ifaceSecurityDomain p = some 4 at checked
  rw [config_same4] at checked
  exact checked

lemma source_domains_checked : ∀ p ∈ redSources, config.ifaceSecurityDomain p ∈ domains.map some := by
  (try simp only [redSources, TDN.Deployments.ProfileShared_DataPlane.redSources, config, dataPlaneModelFromRecords, taggedDevices, ownerTag, ownerDomain, domains, TDN.Deployments.ProfileShared_DataPlane.devices, TDN.Deployments.ProfileShared_DataPlane.ifaces]); all_goals decide
theorem snapshot_RG008_IPv4_ESP_delivery : Requirements.plaintext_delivery_preserves_security_enclave config redSources := by
  intro start finish actions sourceDomain destinationDomain origin sourceLevel run delivered recipientLevel
  have member : some sourceDomain ∈ domains.map some := by
    rw [← sourceLevel]
    exact source_domains_checked start.iface origin.1
  have domainMember : sourceDomain ∈ domains := by simpa using member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at domainMember
  rcases domainMember with rfl | rfl | rfl | rfl
  · exact Requirements.delivered_domain_from_local_checks config domainLayout1 domainAllowed1 redSources 1
      local_domain_conditions1 source_checks1 recipient_checks1 origin sourceLevel run delivered recipientLevel
  · exact Requirements.delivered_domain_from_local_checks config domainLayout2 domainAllowed2 redSources 2
      local_domain_conditions2 source_checks2 recipient_checks2 origin sourceLevel run delivered recipientLevel
  · exact Requirements.delivered_domain_from_local_checks config domainLayout3 domainAllowed3 redSources 3
      local_domain_conditions3 source_checks3 recipient_checks3 origin sourceLevel run delivered recipientLevel
  · exact Requirements.delivered_domain_from_local_checks config domainLayout4 domainAllowed4 redSources 4
      local_domain_conditions4 source_checks4 recipient_checks4 origin sourceLevel run delivered recipientLevel

theorem snapshot_RG008_full_label_delivery {start finish : DataPlaneForwarding.State} {actions : List DataPlaneForwarding.Action} {source recipient : Nat}
    (origin : Requirements.RedPayloadOrigin config redSources start) (sourceLevel : config.ifaceSecurityDomain start.iface = some source)
    (run : (lts config).MTr start actions finish) (delivered : finish.datapathStage = .delivered)
    (recipientLevel : config.ifaceSecurityDomain finish.iface = some recipient) : fullLevel source = fullLevel recipient :=
  congrArg fullLevel (snapshot_RG008_IPv4_ESP_delivery start finish actions source recipient origin sourceLevel run delivered recipientLevel)

def expectedEncapStack : Nat → List Nat := domainLayout1

end TDN.Deployments.ProfileShared_EnclaveIsolation
