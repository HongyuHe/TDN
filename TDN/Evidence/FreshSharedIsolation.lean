import TDN.Import.Command
import TDN.Evidence.FreshSharedExecution
import TDN.Targets.DeliveryIsolation
import TDN.Targets.Architecture

namespace TDN.Imported.FreshSharedIsolation
open Execution

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

def taggedDevices : List DeviceData := TDN.Imported.FreshSharedExecution.devices.zipIdx.map fun pair =>
  { pair.1 with
    outbound := pair.1.outbound.map (fun a => { a with tag := ownerTag pair.2 })
    inbound := pair.1.inbound.map (fun a => { a with tag := ownerTag pair.2 })
    recipientDomain := pair.1.recipientDomain.bind (fun _ => ownerDomain pair.2) }

def stackFor (domain : Nat) (port : PortData) : List Nat :=
  if port.stack = [] then [] else if port.stack = [1] then [domain + 10] else [2, domain + 10]
def allowedRecord (domain : Nat) (port : PortData) : Bool :=
  !port.stack.isEmpty || decide (ownerDomain port.owner = some domain)

def config : Execution.Config := finiteConfig taggedDevices TDN.Imported.FreshSharedExecution.ports TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches
def redSources : List Nat := TDN.Imported.FreshSharedExecution.redSources
tdn_data domains : List Nat from "../../evidence/lean/FreshSharedIsolation.json" ["TDN.Imported.FreshSharedIsolation.domains"]

lemma peer_tag_checks : FinitePeerTagAgreement taggedDevices := by
  (try simp only [FinitePeerTagAgreement, taggedDevices, TDN.Imported.FreshSharedExecution.devices, ownerTag, ownerDomain, StateBindsPolicy, SameWireAssociation]); all_goals decide
lemma peer_tags_justified_by_wire_SAs : PeerTagAgreement config :=
  finite_peer_tag_agreement_sound taggedDevices TDN.Imported.FreshSharedExecution.ports TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches peer_tag_checks

def domainPorts1 : List PortData := withPortStacks TDN.Imported.FreshSharedExecution.ports (stackFor 1)
def domainLayout1 : Nat → List Nat := finiteLayout domainPorts1
def domainAllowed1 (p : Nat) : Prop := allowedRecord 1 (portAt domainPorts1 p) = true
lemma config_same1 : finiteConfig taggedDevices domainPorts1 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches = config :=
  finite_config_ignores_port_stack_annotations taggedDevices TDN.Imported.FreshSharedExecution.ports (stackFor 1) TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches
lemma route_owner_checks1 : ∀ r ∈ TDN.Imported.FreshSharedExecution.routes, (portAt domainPorts1 r.egress).owner = (portAt domainPorts1 r.ingress).owner := by
  (try simp only [TDN.Imported.FreshSharedExecution.routes, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma link_checks1 : ∀ edge ∈ TDN.Imported.FreshSharedExecution.links, allowedRecord 1 (portAt domainPorts1 edge.1) = true → (portAt domainPorts1 edge.1).stack = (portAt domainPorts1 edge.2).stack ∧ allowedRecord 1 (portAt domainPorts1 edge.2) = true := by
  (try simp only [TDN.Imported.FreshSharedExecution.links, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma switch_checks1 : ∀ edge ∈ TDN.Imported.FreshSharedExecution.switches, allowedRecord 1 (portAt domainPorts1 edge.1) = true → ((portAt domainPorts1 edge.1).stack = (portAt domainPorts1 edge.2).stack ∧ (deviceAt taggedDevices (portAt domainPorts1 edge.1).owner).inbound = []) ∧ allowedRecord 1 (portAt domainPorts1 edge.2) = true := by
  (try simp only [TDN.Imported.FreshSharedExecution.switches, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma forward_default_checks1 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma forward_checks1 : FiniteDomainForwardChecks taggedDevices domainPorts1 (allowedRecord 1) := by
  (try simp only [FiniteDomainForwardChecks, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma output_checks1 : FiniteDomainOutputChecks taggedDevices domainPorts1 (allowedRecord 1) := by
  (try simp only [FiniteDomainOutputChecks, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma outer_route_checks1 : FiniteDomainOuterRoutes taggedDevices domainPorts1 TDN.Imported.FreshSharedExecution.routes (allowedRecord 1) := by
  (try simp only [FiniteDomainOuterRoutes, TDN.Imported.FreshSharedExecution.routes, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma local_domain_conditions1 : LocalDomainConditions config domainLayout1 domainAllowed1 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainPorts1 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches (allowedRecord 1)
    route_owner_checks1 link_checks1 switch_checks1 forward_default_checks1 forward_checks1 output_checks1 outer_route_checks1
  rw [config_same1] at checked
  exact checked
lemma source_checks1 : ∀ p ∈ redSources, config.recipientDomain p = some 1 → domainLayout1 p = [] ∧ config.payloadOrigin p ∧ domainAllowed1 p := by
  (try simp only [redSources, TDN.Imported.FreshSharedExecution.redSources, config, finiteConfig, domainLayout1, finiteLayout, domainAllowed1, domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma recipient_records1 : ∀ p ∈ ({} : PortData) :: domainPorts1, allowedRecord 1 p = true → (deviceAt taggedDevices p.owner).recipientDomain = none ∨ (deviceAt taggedDevices p.owner).recipientDomain = some 1 := by
  (try simp only [domainPorts1, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma recipient_checks1 : ∀ p, domainAllowed1 p → config.recipientDomain p = none ∨ config.recipientDomain p = some 1 := by
  intro p permitted
  have checked := recipient_records1 (portAt domainPorts1 p) (port_at_member_or_default domainPorts1 p) permitted
  change (finiteConfig taggedDevices domainPorts1 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches).recipientDomain p = none ∨ (finiteConfig taggedDevices domainPorts1 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches).recipientDomain p = some 1 at checked
  rw [config_same1] at checked
  exact checked

def domainPorts2 : List PortData := withPortStacks TDN.Imported.FreshSharedExecution.ports (stackFor 2)
def domainLayout2 : Nat → List Nat := finiteLayout domainPorts2
def domainAllowed2 (p : Nat) : Prop := allowedRecord 2 (portAt domainPorts2 p) = true
lemma config_same2 : finiteConfig taggedDevices domainPorts2 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches = config :=
  finite_config_ignores_port_stack_annotations taggedDevices TDN.Imported.FreshSharedExecution.ports (stackFor 2) TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches
lemma route_owner_checks2 : ∀ r ∈ TDN.Imported.FreshSharedExecution.routes, (portAt domainPorts2 r.egress).owner = (portAt domainPorts2 r.ingress).owner := by
  (try simp only [TDN.Imported.FreshSharedExecution.routes, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma link_checks2 : ∀ edge ∈ TDN.Imported.FreshSharedExecution.links, allowedRecord 2 (portAt domainPorts2 edge.1) = true → (portAt domainPorts2 edge.1).stack = (portAt domainPorts2 edge.2).stack ∧ allowedRecord 2 (portAt domainPorts2 edge.2) = true := by
  (try simp only [TDN.Imported.FreshSharedExecution.links, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma switch_checks2 : ∀ edge ∈ TDN.Imported.FreshSharedExecution.switches, allowedRecord 2 (portAt domainPorts2 edge.1) = true → ((portAt domainPorts2 edge.1).stack = (portAt domainPorts2 edge.2).stack ∧ (deviceAt taggedDevices (portAt domainPorts2 edge.1).owner).inbound = []) ∧ allowedRecord 2 (portAt domainPorts2 edge.2) = true := by
  (try simp only [TDN.Imported.FreshSharedExecution.switches, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma forward_default_checks2 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma forward_checks2 : FiniteDomainForwardChecks taggedDevices domainPorts2 (allowedRecord 2) := by
  (try simp only [FiniteDomainForwardChecks, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma output_checks2 : FiniteDomainOutputChecks taggedDevices domainPorts2 (allowedRecord 2) := by
  (try simp only [FiniteDomainOutputChecks, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma outer_route_checks2 : FiniteDomainOuterRoutes taggedDevices domainPorts2 TDN.Imported.FreshSharedExecution.routes (allowedRecord 2) := by
  (try simp only [FiniteDomainOuterRoutes, TDN.Imported.FreshSharedExecution.routes, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma local_domain_conditions2 : LocalDomainConditions config domainLayout2 domainAllowed2 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainPorts2 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches (allowedRecord 2)
    route_owner_checks2 link_checks2 switch_checks2 forward_default_checks2 forward_checks2 output_checks2 outer_route_checks2
  rw [config_same2] at checked
  exact checked
lemma source_checks2 : ∀ p ∈ redSources, config.recipientDomain p = some 2 → domainLayout2 p = [] ∧ config.payloadOrigin p ∧ domainAllowed2 p := by
  (try simp only [redSources, TDN.Imported.FreshSharedExecution.redSources, config, finiteConfig, domainLayout2, finiteLayout, domainAllowed2, domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma recipient_records2 : ∀ p ∈ ({} : PortData) :: domainPorts2, allowedRecord 2 p = true → (deviceAt taggedDevices p.owner).recipientDomain = none ∨ (deviceAt taggedDevices p.owner).recipientDomain = some 2 := by
  (try simp only [domainPorts2, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma recipient_checks2 : ∀ p, domainAllowed2 p → config.recipientDomain p = none ∨ config.recipientDomain p = some 2 := by
  intro p permitted
  have checked := recipient_records2 (portAt domainPorts2 p) (port_at_member_or_default domainPorts2 p) permitted
  change (finiteConfig taggedDevices domainPorts2 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches).recipientDomain p = none ∨ (finiteConfig taggedDevices domainPorts2 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches).recipientDomain p = some 2 at checked
  rw [config_same2] at checked
  exact checked

def domainPorts3 : List PortData := withPortStacks TDN.Imported.FreshSharedExecution.ports (stackFor 3)
def domainLayout3 : Nat → List Nat := finiteLayout domainPorts3
def domainAllowed3 (p : Nat) : Prop := allowedRecord 3 (portAt domainPorts3 p) = true
lemma config_same3 : finiteConfig taggedDevices domainPorts3 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches = config :=
  finite_config_ignores_port_stack_annotations taggedDevices TDN.Imported.FreshSharedExecution.ports (stackFor 3) TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches
lemma route_owner_checks3 : ∀ r ∈ TDN.Imported.FreshSharedExecution.routes, (portAt domainPorts3 r.egress).owner = (portAt domainPorts3 r.ingress).owner := by
  (try simp only [TDN.Imported.FreshSharedExecution.routes, domainPorts3, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma link_checks3 : ∀ edge ∈ TDN.Imported.FreshSharedExecution.links, allowedRecord 3 (portAt domainPorts3 edge.1) = true → (portAt domainPorts3 edge.1).stack = (portAt domainPorts3 edge.2).stack ∧ allowedRecord 3 (portAt domainPorts3 edge.2) = true := by
  (try simp only [TDN.Imported.FreshSharedExecution.links, domainPorts3, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma switch_checks3 : ∀ edge ∈ TDN.Imported.FreshSharedExecution.switches, allowedRecord 3 (portAt domainPorts3 edge.1) = true → ((portAt domainPorts3 edge.1).stack = (portAt domainPorts3 edge.2).stack ∧ (deviceAt taggedDevices (portAt domainPorts3 edge.1).owner).inbound = []) ∧ allowedRecord 3 (portAt domainPorts3 edge.2) = true := by
  (try simp only [TDN.Imported.FreshSharedExecution.switches, domainPorts3, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma forward_default_checks3 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainPorts3, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma forward_checks3 : FiniteDomainForwardChecks taggedDevices domainPorts3 (allowedRecord 3) := by
  (try simp only [FiniteDomainForwardChecks, domainPorts3, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma output_checks3 : FiniteDomainOutputChecks taggedDevices domainPorts3 (allowedRecord 3) := by
  (try simp only [FiniteDomainOutputChecks, domainPorts3, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma outer_route_checks3 : FiniteDomainOuterRoutes taggedDevices domainPorts3 TDN.Imported.FreshSharedExecution.routes (allowedRecord 3) := by
  (try simp only [FiniteDomainOuterRoutes, TDN.Imported.FreshSharedExecution.routes, domainPorts3, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma local_domain_conditions3 : LocalDomainConditions config domainLayout3 domainAllowed3 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainPorts3 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches (allowedRecord 3)
    route_owner_checks3 link_checks3 switch_checks3 forward_default_checks3 forward_checks3 output_checks3 outer_route_checks3
  rw [config_same3] at checked
  exact checked
lemma source_checks3 : ∀ p ∈ redSources, config.recipientDomain p = some 3 → domainLayout3 p = [] ∧ config.payloadOrigin p ∧ domainAllowed3 p := by
  (try simp only [redSources, TDN.Imported.FreshSharedExecution.redSources, config, finiteConfig, domainLayout3, finiteLayout, domainAllowed3, domainPorts3, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma recipient_records3 : ∀ p ∈ ({} : PortData) :: domainPorts3, allowedRecord 3 p = true → (deviceAt taggedDevices p.owner).recipientDomain = none ∨ (deviceAt taggedDevices p.owner).recipientDomain = some 3 := by
  (try simp only [domainPorts3, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma recipient_checks3 : ∀ p, domainAllowed3 p → config.recipientDomain p = none ∨ config.recipientDomain p = some 3 := by
  intro p permitted
  have checked := recipient_records3 (portAt domainPorts3 p) (port_at_member_or_default domainPorts3 p) permitted
  change (finiteConfig taggedDevices domainPorts3 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches).recipientDomain p = none ∨ (finiteConfig taggedDevices domainPorts3 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches).recipientDomain p = some 3 at checked
  rw [config_same3] at checked
  exact checked

def domainPorts4 : List PortData := withPortStacks TDN.Imported.FreshSharedExecution.ports (stackFor 4)
def domainLayout4 : Nat → List Nat := finiteLayout domainPorts4
def domainAllowed4 (p : Nat) : Prop := allowedRecord 4 (portAt domainPorts4 p) = true
lemma config_same4 : finiteConfig taggedDevices domainPorts4 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches = config :=
  finite_config_ignores_port_stack_annotations taggedDevices TDN.Imported.FreshSharedExecution.ports (stackFor 4) TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches
lemma route_owner_checks4 : ∀ r ∈ TDN.Imported.FreshSharedExecution.routes, (portAt domainPorts4 r.egress).owner = (portAt domainPorts4 r.ingress).owner := by
  (try simp only [TDN.Imported.FreshSharedExecution.routes, domainPorts4, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma link_checks4 : ∀ edge ∈ TDN.Imported.FreshSharedExecution.links, allowedRecord 4 (portAt domainPorts4 edge.1) = true → (portAt domainPorts4 edge.1).stack = (portAt domainPorts4 edge.2).stack ∧ allowedRecord 4 (portAt domainPorts4 edge.2) = true := by
  (try simp only [TDN.Imported.FreshSharedExecution.links, domainPorts4, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma switch_checks4 : ∀ edge ∈ TDN.Imported.FreshSharedExecution.switches, allowedRecord 4 (portAt domainPorts4 edge.1) = true → ((portAt domainPorts4 edge.1).stack = (portAt domainPorts4 edge.2).stack ∧ (deviceAt taggedDevices (portAt domainPorts4 edge.1).owner).inbound = []) ∧ allowedRecord 4 (portAt domainPorts4 edge.2) = true := by
  (try simp only [TDN.Imported.FreshSharedExecution.switches, domainPorts4, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma forward_default_checks4 : ∀ d ∈ ({} : DeviceData) :: taggedDevices, d.forwardFallback = .deny := by
  (try simp only [domainPorts4, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma forward_checks4 : FiniteDomainForwardChecks taggedDevices domainPorts4 (allowedRecord 4) := by
  (try simp only [FiniteDomainForwardChecks, domainPorts4, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma output_checks4 : FiniteDomainOutputChecks taggedDevices domainPorts4 (allowedRecord 4) := by
  (try simp only [FiniteDomainOutputChecks, domainPorts4, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma outer_route_checks4 : FiniteDomainOuterRoutes taggedDevices domainPorts4 TDN.Imported.FreshSharedExecution.routes (allowedRecord 4) := by
  (try simp only [FiniteDomainOuterRoutes, TDN.Imported.FreshSharedExecution.routes, domainPorts4, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma local_domain_conditions4 : LocalDomainConditions config domainLayout4 domainAllowed4 := by
  have checked := local_domain_conditions_of_finite_checks taggedDevices domainPorts4 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches (allowedRecord 4)
    route_owner_checks4 link_checks4 switch_checks4 forward_default_checks4 forward_checks4 output_checks4 outer_route_checks4
  rw [config_same4] at checked
  exact checked
lemma source_checks4 : ∀ p ∈ redSources, config.recipientDomain p = some 4 → domainLayout4 p = [] ∧ config.payloadOrigin p ∧ domainAllowed4 p := by
  (try simp only [redSources, TDN.Imported.FreshSharedExecution.redSources, config, finiteConfig, domainLayout4, finiteLayout, domainAllowed4, domainPorts4, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma recipient_records4 : ∀ p ∈ ({} : PortData) :: domainPorts4, allowedRecord 4 p = true → (deviceAt taggedDevices p.owner).recipientDomain = none ∨ (deviceAt taggedDevices p.owner).recipientDomain = some 4 := by
  (try simp only [domainPorts4, withPortStacks, stackFor, allowedRecord, taggedDevices, ownerTag, ownerDomain, TDN.Imported.FreshSharedExecution.ports, TDN.Imported.FreshSharedExecution.devices]); all_goals decide
lemma recipient_checks4 : ∀ p, domainAllowed4 p → config.recipientDomain p = none ∨ config.recipientDomain p = some 4 := by
  intro p permitted
  have checked := recipient_records4 (portAt domainPorts4 p) (port_at_member_or_default domainPorts4 p) permitted
  change (finiteConfig taggedDevices domainPorts4 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches).recipientDomain p = none ∨ (finiteConfig taggedDevices domainPorts4 TDN.Imported.FreshSharedExecution.routes TDN.Imported.FreshSharedExecution.links TDN.Imported.FreshSharedExecution.switches).recipientDomain p = some 4 at checked
  rw [config_same4] at checked
  exact checked

lemma source_domains_checked : ∀ p ∈ redSources, config.recipientDomain p ∈ domains.map some := by
  (try simp only [redSources, TDN.Imported.FreshSharedExecution.redSources, config, finiteConfig, taggedDevices, ownerTag, ownerDomain, domains, TDN.Imported.FreshSharedExecution.devices, TDN.Imported.FreshSharedExecution.ports]); all_goals decide
theorem snapshot_RG008_IPv4_ESP_delivery : Targets.msc_same_domain_plaintext_delivery config redSources := by
  intro start finish actions sourceDomain recipientDomain origin sourceLevel run delivered recipientLevel
  have member : some sourceDomain ∈ domains.map some := by
    rw [← sourceLevel]
    exact source_domains_checked start.port origin.1
  have domainMember : sourceDomain ∈ domains := by simpa using member
  simp only [domains, List.mem_cons, List.not_mem_nil, or_false] at domainMember
  rcases domainMember with rfl | rfl | rfl | rfl
  · exact Targets.delivered_domain_from_local_checks config domainLayout1 domainAllowed1 redSources 1
      local_domain_conditions1 source_checks1 recipient_checks1 origin sourceLevel run delivered recipientLevel
  · exact Targets.delivered_domain_from_local_checks config domainLayout2 domainAllowed2 redSources 2
      local_domain_conditions2 source_checks2 recipient_checks2 origin sourceLevel run delivered recipientLevel
  · exact Targets.delivered_domain_from_local_checks config domainLayout3 domainAllowed3 redSources 3
      local_domain_conditions3 source_checks3 recipient_checks3 origin sourceLevel run delivered recipientLevel
  · exact Targets.delivered_domain_from_local_checks config domainLayout4 domainAllowed4 redSources 4
      local_domain_conditions4 source_checks4 recipient_checks4 origin sourceLevel run delivered recipientLevel

theorem snapshot_RG008_full_label_delivery {start finish : Execution.State} {actions : List Execution.Action} {source recipient : Nat}
    (origin : Targets.RedPayloadOrigin config redSources start) (sourceLevel : config.recipientDomain start.port = some source)
    (run : (lts config).MTr start actions finish) (delivered : finish.phase = .delivered)
    (recipientLevel : config.recipientDomain finish.port = some recipient) : fullLevel source = fullLevel recipient :=
  congrArg fullLevel (snapshot_RG008_IPv4_ESP_delivery start finish actions source recipient origin sourceLevel run delivered recipientLevel)

def layout : Nat → List Nat := domainLayout1

end TDN.Imported.FreshSharedIsolation
