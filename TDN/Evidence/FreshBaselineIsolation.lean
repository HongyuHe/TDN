import TDN.Import.Command
import TDN.Evidence.FreshBaselineExecution
import TDN.Targets.DeliveryIsolation
import TDN.Targets.Architecture

namespace TDN.Imported.FreshBaselineIsolation
open Execution

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

def taggedDevices : List DeviceData := TDN.Imported.FreshBaselineExecution.devices.zipIdx.map fun pair =>
  { pair.1 with
    outbound := pair.1.outbound.map (fun a => { a with tag := ownerTag pair.2 })
    inbound := pair.1.inbound.map (fun a => { a with tag := ownerTag pair.2 })
    recipientDomain := pair.1.recipientDomain.bind (fun _ => ownerDomain pair.2) }

def stackFor (domain : Nat) (iface : IfaceData) : List Nat :=
  if iface.stack = [] then [] else if iface.stack = [1] then [domain + 10] else [2, domain + 10]
def allowedRecord (domain : Nat) (iface : IfaceData) : Bool :=
  !iface.stack.isEmpty || decide (ownerDomain iface.owner = some domain)

def config : Execution.Environment := dataPlaneConfigFromRecords taggedDevices TDN.Imported.FreshBaselineExecution.ifaces TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches
def redSources : List Nat := TDN.Imported.FreshBaselineExecution.redSources
tdn_data domains : List Nat from "../../data/evidence/FreshBaselineIsolation.json" ["TDN.Imported.FreshBaselineIsolation.domains"]

lemma peer_tag_checks : FinitePeerTagAgreement taggedDevices := by
  (try simp only [FinitePeerTagAgreement, taggedDevices, TDN.Imported.FreshBaselineExecution.devices, ownerTag, ownerDomain, StateBindsPolicy, SameWireAssociation]); all_goals decide
lemma peer_tags_justified_by_wire_SAs : PeerTagAgreement config :=
  finite_peer_tag_agreement_sound taggedDevices TDN.Imported.FreshBaselineExecution.ifaces TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches peer_tag_checks

def domainIfaces1 : List IfaceData := withEncapStackAnnotations TDN.Imported.FreshBaselineExecution.ifaces (stackFor 1)
def domainLayout1 : Nat → List Nat := expectedEncapStackFromRecords domainIfaces1
def domainAllowed1 (p : Nat) : Prop := allowedRecord 1 (ifaceAt domainIfaces1 p) = true
lemma config_same1 : dataPlaneConfigFromRecords taggedDevices domainIfaces1 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches = config :=
  data_plane_ignores_encap_stack_annotations taggedDevices TDN.Imported.FreshBaselineExecution.ifaces (stackFor 1) TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches
lemma route_owner_checks1 : ∀ r ∈ TDN.Imported.FreshBaselineExecution.routes, (ifaceAt domainIfaces1 r.egress).owner = (ifaceAt domainIfaces1 r.ingress).owner := by
  (try simp only [TDN.Imported.FreshBaselineExecution.routes, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma link_checks1 : ∀ edge ∈ TDN.Imported.FreshBaselineExecution.links, allowedRecord 1 (ifaceAt domainIfaces1 edge.1) = true → (ifaceAt domainIfaces1 edge.1).stack = (ifaceAt domainIfaces1 edge.2).stack ∧ allowedRecord 1 (ifaceAt domainIfaces1 edge.2) = true := by
  (try simp only [TDN.Imported.FreshBaselineExecution.links, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma switch_checks1 : ∀ edge ∈ TDN.Imported.FreshBaselineExecution.switches, allowedRecord 1 (ifaceAt domainIfaces1 edge.1) = true → ((ifaceAt domainIfaces1 edge.1).stack = (ifaceAt domainIfaces1 edge.2).stack ∧ (deviceAt taggedDevices (ifaceAt domainIfaces1 edge.1).owner).inbound = []) ∧ allowedRecord 1 (ifaceAt domainIfaces1 edge.2) = true := by
  (try simp only [TDN.Imported.FreshBaselineExecution.switches, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma forward_default_checks1 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma forward_checks1 : FiniteDomainForwardChecks taggedDevices domainIfaces1 (allowedRecord 1) := by
  (try simp only [FiniteDomainForwardChecks, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma output_checks1 : FiniteDomainOutputChecks taggedDevices domainIfaces1 (allowedRecord 1) := by
  (try simp only [FiniteDomainOutputChecks, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma outer_route_checks1 : FiniteDomainOuterRoutes taggedDevices domainIfaces1 TDN.Imported.FreshBaselineExecution.routes (allowedRecord 1) := by
  (try simp only [FiniteDomainOuterRoutes, TDN.Imported.FreshBaselineExecution.routes, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma local_domain_conditions1 : LocalDomainConditions config domainLayout1 domainAllowed1 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainIfaces1 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches (allowedRecord 1)
    route_owner_checks1 link_checks1 switch_checks1 forward_default_checks1 forward_checks1 output_checks1 outer_route_checks1
  rw [config_same1] at checked
  exact checked
lemma source_checks1 : ∀ p ∈ redSources, config.recipientDomain p = some 1 → domainLayout1 p = [] ∧ config.payloadOrigin p ∧ domainAllowed1 p := by
  (try simp only [redSources, TDN.Imported.FreshBaselineExecution.redSources, config, dataPlaneConfigFromRecords, domainLayout1, expectedEncapStackFromRecords, domainAllowed1, domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma recipient_records1 : ∀ p ∈ ({} : IfaceData) :: domainIfaces1, allowedRecord 1 p = true → (deviceAt taggedDevices p.owner).recipientDomain = none ∨ (deviceAt taggedDevices p.owner).recipientDomain = some 1 := by
  (try simp only [domainIfaces1, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma recipient_checks1 : ∀ p, domainAllowed1 p → config.recipientDomain p = none ∨ config.recipientDomain p = some 1 := by
  intro p permitted
  have checked := recipient_records1 (ifaceAt domainIfaces1 p) (iface_at_member_or_default domainIfaces1 p) permitted
  change (dataPlaneConfigFromRecords taggedDevices domainIfaces1 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches).recipientDomain p = none ∨ (dataPlaneConfigFromRecords taggedDevices domainIfaces1 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches).recipientDomain p = some 1 at checked
  rw [config_same1] at checked
  exact checked

def domainIfaces2 : List IfaceData := withEncapStackAnnotations TDN.Imported.FreshBaselineExecution.ifaces (stackFor 2)
def domainLayout2 : Nat → List Nat := expectedEncapStackFromRecords domainIfaces2
def domainAllowed2 (p : Nat) : Prop := allowedRecord 2 (ifaceAt domainIfaces2 p) = true
lemma config_same2 : dataPlaneConfigFromRecords taggedDevices domainIfaces2 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches = config :=
  data_plane_ignores_encap_stack_annotations taggedDevices TDN.Imported.FreshBaselineExecution.ifaces (stackFor 2) TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches
lemma route_owner_checks2 : ∀ r ∈ TDN.Imported.FreshBaselineExecution.routes, (ifaceAt domainIfaces2 r.egress).owner = (ifaceAt domainIfaces2 r.ingress).owner := by
  (try simp only [TDN.Imported.FreshBaselineExecution.routes, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma link_checks2 : ∀ edge ∈ TDN.Imported.FreshBaselineExecution.links, allowedRecord 2 (ifaceAt domainIfaces2 edge.1) = true → (ifaceAt domainIfaces2 edge.1).stack = (ifaceAt domainIfaces2 edge.2).stack ∧ allowedRecord 2 (ifaceAt domainIfaces2 edge.2) = true := by
  (try simp only [TDN.Imported.FreshBaselineExecution.links, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma switch_checks2 : ∀ edge ∈ TDN.Imported.FreshBaselineExecution.switches, allowedRecord 2 (ifaceAt domainIfaces2 edge.1) = true → ((ifaceAt domainIfaces2 edge.1).stack = (ifaceAt domainIfaces2 edge.2).stack ∧ (deviceAt taggedDevices (ifaceAt domainIfaces2 edge.1).owner).inbound = []) ∧ allowedRecord 2 (ifaceAt domainIfaces2 edge.2) = true := by
  (try simp only [TDN.Imported.FreshBaselineExecution.switches, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma forward_default_checks2 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma forward_checks2 : FiniteDomainForwardChecks taggedDevices domainIfaces2 (allowedRecord 2) := by
  (try simp only [FiniteDomainForwardChecks, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma output_checks2 : FiniteDomainOutputChecks taggedDevices domainIfaces2 (allowedRecord 2) := by
  (try simp only [FiniteDomainOutputChecks, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma outer_route_checks2 : FiniteDomainOuterRoutes taggedDevices domainIfaces2 TDN.Imported.FreshBaselineExecution.routes (allowedRecord 2) := by
  (try simp only [FiniteDomainOuterRoutes, TDN.Imported.FreshBaselineExecution.routes, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma local_domain_conditions2 : LocalDomainConditions config domainLayout2 domainAllowed2 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainIfaces2 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches (allowedRecord 2)
    route_owner_checks2 link_checks2 switch_checks2 forward_default_checks2 forward_checks2 output_checks2 outer_route_checks2
  rw [config_same2] at checked
  exact checked
lemma source_checks2 : ∀ p ∈ redSources, config.recipientDomain p = some 2 → domainLayout2 p = [] ∧ config.payloadOrigin p ∧ domainAllowed2 p := by
  (try simp only [redSources, TDN.Imported.FreshBaselineExecution.redSources, config, dataPlaneConfigFromRecords, domainLayout2, expectedEncapStackFromRecords, domainAllowed2, domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma recipient_records2 : ∀ p ∈ ({} : IfaceData) :: domainIfaces2, allowedRecord 2 p = true → (deviceAt taggedDevices p.owner).recipientDomain = none ∨ (deviceAt taggedDevices p.owner).recipientDomain = some 2 := by
  (try simp only [domainIfaces2, withEncapStackAnnotations, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ifaces, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma recipient_checks2 : ∀ p, domainAllowed2 p → config.recipientDomain p = none ∨ config.recipientDomain p = some 2 := by
  intro p permitted
  have checked := recipient_records2 (ifaceAt domainIfaces2 p) (iface_at_member_or_default domainIfaces2 p) permitted
  change (dataPlaneConfigFromRecords taggedDevices domainIfaces2 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches).recipientDomain p = none ∨ (dataPlaneConfigFromRecords taggedDevices domainIfaces2 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches).recipientDomain p = some 2 at checked
  rw [config_same2] at checked
  exact checked

lemma source_domains_checked : ∀ p ∈ redSources, config.recipientDomain p ∈ domains.map some := by
  (try simp only [redSources, TDN.Imported.FreshBaselineExecution.redSources, config, dataPlaneConfigFromRecords, taggedDevices, ownerTag, ownerDomain, domains, TDN.Imported.FreshBaselineExecution.devices, TDN.Imported.FreshBaselineExecution.ifaces]); all_goals decide
theorem snapshot_RG008_IPv4_ESP_delivery : Targets.msc_same_domain_plaintext_delivery config redSources := by
  intro start finish actions sourceDomain recipientDomain origin sourceLevel run delivered recipientLevel
  have member : some sourceDomain ∈ domains.map some := by
    rw [← sourceLevel]
    exact source_domains_checked start.iface origin.1
  have domainMember : sourceDomain ∈ domains := by simpa using member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at domainMember
  rcases domainMember with rfl | rfl
  · exact Targets.delivered_domain_from_local_checks config domainLayout1 domainAllowed1 redSources 1
      local_domain_conditions1 source_checks1 recipient_checks1 origin sourceLevel run delivered recipientLevel
  · exact Targets.delivered_domain_from_local_checks config domainLayout2 domainAllowed2 redSources 2
      local_domain_conditions2 source_checks2 recipient_checks2 origin sourceLevel run delivered recipientLevel

theorem snapshot_RG008_full_label_delivery {start finish : Execution.State} {actions : List Execution.Action} {source recipient : Nat}
    (origin : Targets.RedPayloadOrigin config redSources start) (sourceLevel : config.recipientDomain start.iface = some source)
    (run : (lts config).MTr start actions finish) (delivered : finish.datapathStage = .delivered)
    (recipientLevel : config.recipientDomain finish.iface = some recipient) : fullLevel source = fullLevel recipient :=
  congrArg fullLevel (snapshot_RG008_IPv4_ESP_delivery start finish actions source recipient origin sourceLevel run delivered recipientLevel)

def expectedEncapStack : Nat → List Nat := domainLayout1

end TDN.Imported.FreshBaselineIsolation
