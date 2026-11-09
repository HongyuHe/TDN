import TDN.Import.SnapshotLoader
import TDN.Deployments.ProfileBaseline_DataPlane
import TDN.Requirements.PacketEnclaveIsolation
import TDN.Requirements.TwoLayerOverlayArchitecture

namespace TDN.Deployments.ProfileBaseline_EnclaveIsolation
open DataPlaneForwarding

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
set_option linter.unusedSimpArgs false

def ownerDomain : Nat → Option Nat
  | 8 => some 1
  | 9 => some 2
  | 10 => some 1
  | 11 => some 2
  | 20 => some 1
  | 21 => some 2
  | 22 => some 1
  | 23 => some 2
  | _ => none

def ownerTag : Nat → Nat
  | 8 => 11
  | 9 => 12
  | 10 => 11
  | 11 => 12
  | 16 => 2
  | 17 => 2
  | 18 => 2
  | 19 => 2
  | _ => 0

def fullLevel : Nat → SecurityLevel
  | 1 => ⟨"SECRET", {}, {}, {}⟩
  | 2 => ⟨"TOP_SECRET", {}, {}, {}⟩
  | _ => ⟨"", {}, {}, {}⟩

def taggedDevices : List DeviceData := TDN.Deployments.ProfileBaseline_DataPlane.devices.zipIdx.map fun pair =>
  { pair.1 with
    egressPolicies := pair.1.egressPolicies.map (fun a => { a with tag := ownerTag pair.2 })
    ingressPolicies := pair.1.ingressPolicies.map (fun a => { a with tag := ownerTag pair.2 })
    ifaceSecurityDomain := pair.1.ifaceSecurityDomain.bind (fun _ => ownerDomain pair.2) }

def stackFor (domain : Nat) (iface : IfaceData) : List Nat :=
  if iface.stack = [] then [] else if iface.stack = [1] then [domain + 10] else [2, domain + 10]
def allowedRecord (domain : Nat) (iface : IfaceData) : Bool :=
  !iface.stack.isEmpty || decide (ownerDomain iface.owner = some domain)

def config : DataPlaneForwarding.DataPlaneModel := dataPlaneModelFromRecords taggedDevices TDN.Deployments.ProfileBaseline_DataPlane.ifaces TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches
def redSources : List Nat := TDN.Deployments.ProfileBaseline_DataPlane.redSources
load_network_records domains : List Nat from "../../data/evidence/ProfileBaseline_EnclaveIsolation.json" ["TDN.Deployments.ProfileBaseline_EnclaveIsolation.domains"]

lemma peer_tag_checks : TableDrivenPeerTagAgreement taggedDevices := by
  (try simp only [TableDrivenPeerTagAgreement, taggedDevices, TDN.Deployments.ProfileBaseline_DataPlane.devices, ownerTag, ownerDomain, saMatchesPolicy, SameWireAssociation]); all_goals decide
lemma peer_tags_justified_by_wire_SAs : PeerTagAgreement config :=
  table_driven_peer_tag_agreement_sound taggedDevices TDN.Deployments.ProfileBaseline_DataPlane.ifaces TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches peer_tag_checks

def domainIfaces1 : List IfaceData := withEncapStackAnnotations TDN.Deployments.ProfileBaseline_DataPlane.ifaces (stackFor 1)
def domainLayout1 : Nat → List Nat := expectedEncapStackFromRecords domainIfaces1
def domainAllowed1 (p : Nat) : Prop := allowedRecord 1 (ifaceAt domainIfaces1 p) = true
lemma config_same1 : dataPlaneModelFromRecords taggedDevices domainIfaces1 TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches = config :=
  data_plane_ignores_encap_stack_annotations taggedDevices TDN.Deployments.ProfileBaseline_DataPlane.ifaces (stackFor 1) TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches
lemma route_owner_checks1 : ∀ r ∈ TDN.Deployments.ProfileBaseline_DataPlane.routes, (ifaceAt domainIfaces1 r.egress).owner = (ifaceAt domainIfaces1 r.ingress).owner := by
  (try simp only [TDN.Deployments.ProfileBaseline_DataPlane.routes, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma link_checks1 : ∀ edge ∈ TDN.Deployments.ProfileBaseline_DataPlane.links, allowedRecord 1 (ifaceAt domainIfaces1 edge.1) = true → (ifaceAt domainIfaces1 edge.1).stack = (ifaceAt domainIfaces1 edge.2).stack ∧ allowedRecord 1 (ifaceAt domainIfaces1 edge.2) = true := by
  (try simp only [TDN.Deployments.ProfileBaseline_DataPlane.links, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma switch_checks1 : ∀ edge ∈ TDN.Deployments.ProfileBaseline_DataPlane.switches, allowedRecord 1 (ifaceAt domainIfaces1 edge.1) = true → ((ifaceAt domainIfaces1 edge.1).stack = (ifaceAt domainIfaces1 edge.2).stack ∧ (deviceAt taggedDevices (ifaceAt domainIfaces1 edge.1).owner).ingressPolicies = []) ∧ allowedRecord 1 (ifaceAt domainIfaces1 edge.2) = true := by
  (try simp only [TDN.Deployments.ProfileBaseline_DataPlane.switches, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma forward_default_checks1 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma forward_checks1 : TableDrivenDomainForwardChecks taggedDevices domainIfaces1 (allowedRecord 1) := by
  (try simp only [TableDrivenDomainForwardChecks, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma output_checks1 : TableDrivenDomainOutputChecks taggedDevices domainIfaces1 (allowedRecord 1) := by
  (try simp only [TableDrivenDomainOutputChecks, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma outer_route_checks1 : TableDrivenDomainOuterRoutes taggedDevices domainIfaces1 TDN.Deployments.ProfileBaseline_DataPlane.routes (allowedRecord 1) := by
  (try simp only [TableDrivenDomainOuterRoutes, TDN.Deployments.ProfileBaseline_DataPlane.routes, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma local_domain_conditions1 : LocalDomainConditions config domainLayout1 domainAllowed1 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainIfaces1 TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches (allowedRecord 1)
    route_owner_checks1 link_checks1 switch_checks1 forward_default_checks1 forward_checks1 output_checks1 outer_route_checks1
  rw [config_same1] at checked
  exact checked
lemma source_checks1 : ∀ p ∈ redSources, config.ifaceSecurityDomain p = some 1 → domainLayout1 p = [] ∧ config.canOriginateTraffic p ∧ domainAllowed1 p := by
  (try simp only [redSources, TDN.Deployments.ProfileBaseline_DataPlane.redSources, config, dataPlaneModelFromRecords, domainLayout1, expectedEncapStackFromRecords, domainAllowed1, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma recipient_records1 : ∀ p ∈ ({} : IfaceData) :: domainIfaces1, allowedRecord 1 p = true → (deviceAt taggedDevices p.owner).ifaceSecurityDomain = none ∨ (deviceAt taggedDevices p.owner).ifaceSecurityDomain = some 1 := by
  (try simp only [domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma recipient_checks1 : ∀ p, domainAllowed1 p → config.ifaceSecurityDomain p = none ∨ config.ifaceSecurityDomain p = some 1 := by
  intro p permitted
  have checked := recipient_records1 (ifaceAt domainIfaces1 p) (iface_at_member_or_default domainIfaces1 p) permitted
  change (dataPlaneModelFromRecords taggedDevices domainIfaces1 TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches).ifaceSecurityDomain p = none ∨ (dataPlaneModelFromRecords taggedDevices domainIfaces1 TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches).ifaceSecurityDomain p = some 1 at checked
  rw [config_same1] at checked
  exact checked

def domainIfaces2 : List IfaceData := withEncapStackAnnotations TDN.Deployments.ProfileBaseline_DataPlane.ifaces (stackFor 2)
def domainLayout2 : Nat → List Nat := expectedEncapStackFromRecords domainIfaces2
def domainAllowed2 (p : Nat) : Prop := allowedRecord 2 (ifaceAt domainIfaces2 p) = true
lemma config_same2 : dataPlaneModelFromRecords taggedDevices domainIfaces2 TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches = config :=
  data_plane_ignores_encap_stack_annotations taggedDevices TDN.Deployments.ProfileBaseline_DataPlane.ifaces (stackFor 2) TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches
lemma route_owner_checks2 : ∀ r ∈ TDN.Deployments.ProfileBaseline_DataPlane.routes, (ifaceAt domainIfaces2 r.egress).owner = (ifaceAt domainIfaces2 r.ingress).owner := by
  (try simp only [TDN.Deployments.ProfileBaseline_DataPlane.routes, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma link_checks2 : ∀ edge ∈ TDN.Deployments.ProfileBaseline_DataPlane.links, allowedRecord 2 (ifaceAt domainIfaces2 edge.1) = true → (ifaceAt domainIfaces2 edge.1).stack = (ifaceAt domainIfaces2 edge.2).stack ∧ allowedRecord 2 (ifaceAt domainIfaces2 edge.2) = true := by
  (try simp only [TDN.Deployments.ProfileBaseline_DataPlane.links, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma switch_checks2 : ∀ edge ∈ TDN.Deployments.ProfileBaseline_DataPlane.switches, allowedRecord 2 (ifaceAt domainIfaces2 edge.1) = true → ((ifaceAt domainIfaces2 edge.1).stack = (ifaceAt domainIfaces2 edge.2).stack ∧ (deviceAt taggedDevices (ifaceAt domainIfaces2 edge.1).owner).ingressPolicies = []) ∧ allowedRecord 2 (ifaceAt domainIfaces2 edge.2) = true := by
  (try simp only [TDN.Deployments.ProfileBaseline_DataPlane.switches, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma forward_default_checks2 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma forward_checks2 : TableDrivenDomainForwardChecks taggedDevices domainIfaces2 (allowedRecord 2) := by
  (try simp only [TableDrivenDomainForwardChecks, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma output_checks2 : TableDrivenDomainOutputChecks taggedDevices domainIfaces2 (allowedRecord 2) := by
  (try simp only [TableDrivenDomainOutputChecks, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma outer_route_checks2 : TableDrivenDomainOuterRoutes taggedDevices domainIfaces2 TDN.Deployments.ProfileBaseline_DataPlane.routes (allowedRecord 2) := by
  (try simp only [TableDrivenDomainOuterRoutes, TDN.Deployments.ProfileBaseline_DataPlane.routes, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma local_domain_conditions2 : LocalDomainConditions config domainLayout2 domainAllowed2 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainIfaces2 TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches (allowedRecord 2)
    route_owner_checks2 link_checks2 switch_checks2 forward_default_checks2 forward_checks2 output_checks2 outer_route_checks2
  rw [config_same2] at checked
  exact checked
lemma source_checks2 : ∀ p ∈ redSources, config.ifaceSecurityDomain p = some 2 → domainLayout2 p = [] ∧ config.canOriginateTraffic p ∧ domainAllowed2 p := by
  (try simp only [redSources, TDN.Deployments.ProfileBaseline_DataPlane.redSources, config, dataPlaneModelFromRecords, domainLayout2, expectedEncapStackFromRecords, domainAllowed2, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma recipient_records2 : ∀ p ∈ ({} : IfaceData) :: domainIfaces2, allowedRecord 2 p = true → (deviceAt taggedDevices p.owner).ifaceSecurityDomain = none ∨ (deviceAt taggedDevices p.owner).ifaceSecurityDomain = some 2 := by
  (try simp only [domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Deployments.ProfileBaseline_DataPlane.ifaces, TDN.Deployments.ProfileBaseline_DataPlane.devices]); all_goals decide
lemma recipient_checks2 : ∀ p, domainAllowed2 p → config.ifaceSecurityDomain p = none ∨ config.ifaceSecurityDomain p = some 2 := by
  intro p permitted
  have checked := recipient_records2 (ifaceAt domainIfaces2 p) (iface_at_member_or_default domainIfaces2 p) permitted
  change (dataPlaneModelFromRecords taggedDevices domainIfaces2 TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches).ifaceSecurityDomain p = none ∨ (dataPlaneModelFromRecords taggedDevices domainIfaces2 TDN.Deployments.ProfileBaseline_DataPlane.routes TDN.Deployments.ProfileBaseline_DataPlane.links TDN.Deployments.ProfileBaseline_DataPlane.switches).ifaceSecurityDomain p = some 2 at checked
  rw [config_same2] at checked
  exact checked

lemma source_domains_checked : ∀ p ∈ redSources, config.ifaceSecurityDomain p ∈ domains.map some := by
  (try simp only [redSources, TDN.Deployments.ProfileBaseline_DataPlane.redSources, config, dataPlaneModelFromRecords, taggedDevices, ownerTag, ownerDomain, domains, TDN.Deployments.ProfileBaseline_DataPlane.devices, TDN.Deployments.ProfileBaseline_DataPlane.ifaces]); all_goals decide
theorem snapshot_RG008_IPv4_ESP_delivery : Requirements.plaintext_delivery_preserves_security_enclave config redSources := by
  intro start finish actions sourceDomain destinationDomain origin sourceLevel run delivered recipientLevel
  have member : some sourceDomain ∈ domains.map some := by
    rw [← sourceLevel]
    exact source_domains_checked start.iface origin.1
  have domainMember : sourceDomain ∈ domains := by simpa using member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at domainMember
  rcases domainMember with rfl | rfl
  · exact Requirements.delivered_domain_from_local_checks config domainLayout1 domainAllowed1 redSources 1
      local_domain_conditions1 source_checks1 recipient_checks1 origin sourceLevel run delivered recipientLevel
  · exact Requirements.delivered_domain_from_local_checks config domainLayout2 domainAllowed2 redSources 2
      local_domain_conditions2 source_checks2 recipient_checks2 origin sourceLevel run delivered recipientLevel

theorem snapshot_RG008_full_label_delivery {start finish : DataPlaneForwarding.State} {actions : List DataPlaneForwarding.Action} {source recipient : Nat}
    (origin : Requirements.RedPayloadOrigin config redSources start) (sourceLevel : config.ifaceSecurityDomain start.iface = some source)
    (run : (lts config).MTr start actions finish) (delivered : finish.datapathStage = .delivered)
    (recipientLevel : config.ifaceSecurityDomain finish.iface = some recipient) : fullLevel source = fullLevel recipient :=
  congrArg fullLevel (snapshot_RG008_IPv4_ESP_delivery start finish actions source recipient origin sourceLevel run delivered recipientLevel)

def expectedEncapStack : Nat → List Nat := domainLayout1

end TDN.Deployments.ProfileBaseline_EnclaveIsolation
