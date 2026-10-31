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

def stackFor (domain : Nat) (port : PortData) : List Nat :=
  if port.stack = [] then [] else if port.stack = [1] then [domain + 10] else [2, domain + 10]
def allowedRecord (domain : Nat) (port : PortData) : Bool :=
  !port.stack.isEmpty || decide (ownerDomain port.owner = some domain)

def config : Execution.Config := finiteConfig taggedDevices TDN.Imported.FreshBaselineExecution.ports TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches
def redSources : List Nat := TDN.Imported.FreshBaselineExecution.redSources
tdn_data domains : List Nat from "../../evidence/lean/FreshBaselineIsolation.json" ["TDN.Imported.FreshBaselineIsolation.domains"]

lemma peer_tag_checks : FinitePeerTagAgreement taggedDevices := by
  (try simp only [FinitePeerTagAgreement, taggedDevices, TDN.Imported.FreshBaselineExecution.devices, ownerTag, ownerDomain, StateBindsPolicy, SameWireAssociation]); all_goals decide
lemma peer_tags_justified_by_wire_SAs : PeerTagAgreement config :=
  finite_peer_tag_agreement_sound taggedDevices TDN.Imported.FreshBaselineExecution.ports TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches peer_tag_checks

def domainPorts1 : List PortData := withPortStacks TDN.Imported.FreshBaselineExecution.ports (stackFor 1)
def domainLayout1 : Nat → List Nat := finiteLayout domainPorts1
def domainAllowed1 (p : Nat) : Prop := allowedRecord 1 (portAt domainPorts1 p) = true
lemma config_same1 : finiteConfig taggedDevices domainPorts1 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches = config :=
  finite_config_ignores_port_stack_annotations taggedDevices TDN.Imported.FreshBaselineExecution.ports (stackFor 1) TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches
lemma route_owner_checks1 : ∀ r ∈ TDN.Imported.FreshBaselineExecution.routes, (portAt domainPorts1 r.egress).owner = (portAt domainPorts1 r.ingress).owner := by
  (try simp only [TDN.Imported.FreshBaselineExecution.routes, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma link_checks1 : ∀ edge ∈ TDN.Imported.FreshBaselineExecution.links, allowedRecord 1 (portAt domainPorts1 edge.1) = true → (portAt domainPorts1 edge.1).stack = (portAt domainPorts1 edge.2).stack ∧ allowedRecord 1 (portAt domainPorts1 edge.2) = true := by
  (try simp only [TDN.Imported.FreshBaselineExecution.links, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma switch_checks1 : ∀ edge ∈ TDN.Imported.FreshBaselineExecution.switches, allowedRecord 1 (portAt domainPorts1 edge.1) = true → ((portAt domainPorts1 edge.1).stack = (portAt domainPorts1 edge.2).stack ∧ (deviceAt taggedDevices (portAt domainPorts1 edge.1).owner).inbound = []) ∧ allowedRecord 1 (portAt domainPorts1 edge.2) = true := by
  (try simp only [TDN.Imported.FreshBaselineExecution.switches, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma forward_default_checks1 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma forward_checks1 : FiniteDomainForwardChecks taggedDevices domainPorts1 (allowedRecord 1) := by
  (try simp only [FiniteDomainForwardChecks, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma output_checks1 : FiniteDomainOutputChecks taggedDevices domainPorts1 (allowedRecord 1) := by
  (try simp only [FiniteDomainOutputChecks, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma outer_route_checks1 : FiniteDomainOuterRoutes taggedDevices domainPorts1 TDN.Imported.FreshBaselineExecution.routes (allowedRecord 1) := by
  (try simp only [FiniteDomainOuterRoutes, TDN.Imported.FreshBaselineExecution.routes, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma local_domain_conditions1 : LocalDomainConditions config domainLayout1 domainAllowed1 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainPorts1 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches (allowedRecord 1)
    route_owner_checks1 link_checks1 switch_checks1 forward_default_checks1 forward_checks1 output_checks1 outer_route_checks1
  rw [config_same1] at checked
  exact checked
lemma source_checks1 : ∀ p ∈ redSources, config.recipientDomain p = some 1 → domainLayout1 p = [] ∧ config.payloadOrigin p ∧ domainAllowed1 p := by
  (try simp only [redSources, TDN.Imported.FreshBaselineExecution.redSources, config, finiteConfig, domainLayout1, finiteLayout, domainAllowed1, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma recipient_records1 : ∀ p ∈ ({} : PortData) :: domainPorts1, allowedRecord 1 p = true → (deviceAt taggedDevices p.owner).recipientDomain = none ∨ (deviceAt taggedDevices p.owner).recipientDomain = some 1 := by
  (try simp only [domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma recipient_checks1 : ∀ p, domainAllowed1 p → config.recipientDomain p = none ∨ config.recipientDomain p = some 1 := by
  intro p permitted
  have checked := recipient_records1 (portAt domainPorts1 p) (port_at_member_or_default domainPorts1 p) permitted
  change (finiteConfig taggedDevices domainPorts1 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches).recipientDomain p = none ∨ (finiteConfig taggedDevices domainPorts1 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches).recipientDomain p = some 1 at checked
  rw [config_same1] at checked
  exact checked

def domainPorts2 : List PortData := withPortStacks TDN.Imported.FreshBaselineExecution.ports (stackFor 2)
def domainLayout2 : Nat → List Nat := finiteLayout domainPorts2
def domainAllowed2 (p : Nat) : Prop := allowedRecord 2 (portAt domainPorts2 p) = true
lemma config_same2 : finiteConfig taggedDevices domainPorts2 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches = config :=
  finite_config_ignores_port_stack_annotations taggedDevices TDN.Imported.FreshBaselineExecution.ports (stackFor 2) TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches
lemma route_owner_checks2 : ∀ r ∈ TDN.Imported.FreshBaselineExecution.routes, (portAt domainPorts2 r.egress).owner = (portAt domainPorts2 r.ingress).owner := by
  (try simp only [TDN.Imported.FreshBaselineExecution.routes, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma link_checks2 : ∀ edge ∈ TDN.Imported.FreshBaselineExecution.links, allowedRecord 2 (portAt domainPorts2 edge.1) = true → (portAt domainPorts2 edge.1).stack = (portAt domainPorts2 edge.2).stack ∧ allowedRecord 2 (portAt domainPorts2 edge.2) = true := by
  (try simp only [TDN.Imported.FreshBaselineExecution.links, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma switch_checks2 : ∀ edge ∈ TDN.Imported.FreshBaselineExecution.switches, allowedRecord 2 (portAt domainPorts2 edge.1) = true → ((portAt domainPorts2 edge.1).stack = (portAt domainPorts2 edge.2).stack ∧ (deviceAt taggedDevices (portAt domainPorts2 edge.1).owner).inbound = []) ∧ allowedRecord 2 (portAt domainPorts2 edge.2) = true := by
  (try simp only [TDN.Imported.FreshBaselineExecution.switches, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma forward_default_checks2 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma forward_checks2 : FiniteDomainForwardChecks taggedDevices domainPorts2 (allowedRecord 2) := by
  (try simp only [FiniteDomainForwardChecks, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma output_checks2 : FiniteDomainOutputChecks taggedDevices domainPorts2 (allowedRecord 2) := by
  (try simp only [FiniteDomainOutputChecks, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma outer_route_checks2 : FiniteDomainOuterRoutes taggedDevices domainPorts2 TDN.Imported.FreshBaselineExecution.routes (allowedRecord 2) := by
  (try simp only [FiniteDomainOuterRoutes, TDN.Imported.FreshBaselineExecution.routes, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma local_domain_conditions2 : LocalDomainConditions config domainLayout2 domainAllowed2 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainPorts2 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches (allowedRecord 2)
    route_owner_checks2 link_checks2 switch_checks2 forward_default_checks2 forward_checks2 output_checks2 outer_route_checks2
  rw [config_same2] at checked
  exact checked
lemma source_checks2 : ∀ p ∈ redSources, config.recipientDomain p = some 2 → domainLayout2 p = [] ∧ config.payloadOrigin p ∧ domainAllowed2 p := by
  (try simp only [redSources, TDN.Imported.FreshBaselineExecution.redSources, config, finiteConfig, domainLayout2, finiteLayout, domainAllowed2, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma recipient_records2 : ∀ p ∈ ({} : PortData) :: domainPorts2, allowedRecord 2 p = true → (deviceAt taggedDevices p.owner).recipientDomain = none ∨ (deviceAt taggedDevices p.owner).recipientDomain = some 2 := by
  (try simp only [domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshBaselineExecution.ports, TDN.Imported.FreshBaselineExecution.devices]); all_goals decide
lemma recipient_checks2 : ∀ p, domainAllowed2 p → config.recipientDomain p = none ∨ config.recipientDomain p = some 2 := by
  intro p permitted
  have checked := recipient_records2 (portAt domainPorts2 p) (port_at_member_or_default domainPorts2 p) permitted
  change (finiteConfig taggedDevices domainPorts2 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches).recipientDomain p = none ∨ (finiteConfig taggedDevices domainPorts2 TDN.Imported.FreshBaselineExecution.routes TDN.Imported.FreshBaselineExecution.links TDN.Imported.FreshBaselineExecution.switches).recipientDomain p = some 2 at checked
  rw [config_same2] at checked
  exact checked

lemma source_domains_checked : ∀ p ∈ redSources, config.recipientDomain p ∈ domains.map some := by
  (try simp only [redSources, TDN.Imported.FreshBaselineExecution.redSources, config, finiteConfig, taggedDevices, ownerTag, ownerDomain, domains, TDN.Imported.FreshBaselineExecution.devices, TDN.Imported.FreshBaselineExecution.ports]); all_goals decide
theorem snapshot_RG008_IPv4_ESP_delivery : Targets.msc_same_domain_plaintext_delivery config redSources := by
  intro start finish actions sourceDomain recipientDomain origin sourceLevel run delivered recipientLevel
  have member : some sourceDomain ∈ domains.map some := by
    rw [← sourceLevel]
    exact source_domains_checked start.port origin.1
  have domainMember : sourceDomain ∈ domains := by simpa using member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at domainMember
  rcases domainMember with rfl | rfl
  · exact Targets.delivered_domain_from_local_checks config domainLayout1 domainAllowed1 redSources 1
      local_domain_conditions1 source_checks1 recipient_checks1 origin sourceLevel run delivered recipientLevel
  · exact Targets.delivered_domain_from_local_checks config domainLayout2 domainAllowed2 redSources 2
      local_domain_conditions2 source_checks2 recipient_checks2 origin sourceLevel run delivered recipientLevel

theorem snapshot_RG008_full_label_delivery {start finish : Execution.State} {actions : List Execution.Action} {source recipient : Nat}
    (origin : Targets.RedPayloadOrigin config redSources start) (sourceLevel : config.recipientDomain start.port = some source)
    (run : (lts config).MTr start actions finish) (delivered : finish.phase = .delivered)
    (recipientLevel : config.recipientDomain finish.port = some recipient) : fullLevel source = fullLevel recipient :=
  congrArg fullLevel (snapshot_RG008_IPv4_ESP_delivery start finish actions source recipient origin sourceLevel run delivered recipientLevel)

def layout : Nat → List Nat := domainLayout1

end TDN.Imported.FreshBaselineIsolation
