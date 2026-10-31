import TDN.Semantics.Network

namespace TDN.Targets

inductive TimeNetwork where
  | red
  | grayManagement
  deriving DecidableEq

/-- Role membership and actual synchronization are separate from receipt of an NTP reply. -/
structure TimeSynchronizationModel (Component Source : Type) where
  components : Finset Component
  inner : Component → Prop
  outer : Component → Prop
  redManagementService : Component → Prop
  grayManagementService : Component → Prop
  grayFirewall : Component → Prop
  locatedIn : Source → TimeNetwork → Prop
  trusted : Source → Prop
  synchronizedTo : Component → Source → Prop

/-- RG-042, both threshold clauses. Trust and synchronization require evidence beyond probes. -/
def msc_trusted_time_synchronization {C S : Type} (m : TimeSynchronizationModel C S) : Prop :=
  (∀ c ∈ m.components, m.inner c ∨ m.redManagementService c →
    ∃ s, m.locatedIn s .red ∧ m.trusted s ∧ m.synchronizedTo c s) ∧
  (∀ c ∈ m.components, m.outer c ∨ m.grayManagementService c ∨ m.grayFirewall c →
    ∃ s, m.locatedIn s .grayManagement ∧ m.trusted s ∧ m.synchronizedTo c s)

inductive DefaultAccessKind where
  | account
  | password
  | communityString
  | other
  deriving DecidableEq

structure DefaultAccessMechanism where
  identity : String
  kind : DefaultAccessKind
  deriving DecidableEq

abbrev DNSAddress := Sum (Fin (2^32)) (Fin (2^128))

/-- The default-mechanism inventory must be complete for a concrete instance. -/
structure DefaultsModel (Component : Type) where
  components : Finset Component
  networkDevice : Component → Prop
  originalDefaults : Component → Finset DefaultAccessMechanism
  changed : Component → DefaultAccessMechanism → Prop
  removed : Component → DefaultAccessMechanism → Prop
  dnsServers : Component → List DNSAddress
  dnsServicesDisabled : Component → Prop
  dnsLookupDisabled : Component → Prop
  automaticRemoteBootDisabled : Component → Prop
  dnsLookupObjectiveSelected : Bool

/-- RG-043 preserves all default kinds, DNS alternatives, and the optional lookup objective. -/
def msc_defaults_dns_and_boot_configuration {C : Type} (m : DefaultsModel C) : Prop :=
  (∀ c ∈ m.components, ∀ d ∈ m.originalDefaults c, m.changed c d ∨ m.removed c d) ∧
  (∀ c ∈ m.components, m.dnsServers c ≠ [] ∨ m.dnsServicesDisabled c) ∧
  (∀ c ∈ m.components, m.automaticRemoteBootDisabled c) ∧
  (m.dnsLookupObjectiveSelected = true →
    ∀ c ∈ m.components, m.networkDevice c → m.dnsLookupDisabled c)

/-- Routing activity has an explicit implementation interpretation. A route-table entry alone
is neither an active routing protocol nor a proof of the broader source phrase. -/
structure RoutingDutyModel (Component Interface : Type) where
  components : Finset Component
  inner : Component → Prop
  outer : Component → Prop
  encryptionComponent : Component → Prop
  outerFirewall : Component → Prop
  grayFirewall : Component → Prop
  interfaces : Component → Finset Interface
  runsRoutingProtocol : Component → Interface → Prop
  performsRoutingFunction : Component → Prop
  switchesOrRoutesFor : Component → Component → Prop
  dynamicRoutingRequired : Component → Prop
  suppliesDynamicRoutingTo : Component → Component → Prop

/-- RG-031 includes the broader routing-function prohibition without resolving it by fiat.
Concrete proofs must justify that phrase's mapping to implementation behavior. -/
def msc_encryption_component_routing_limits {C I : Type} (m : RoutingDutyModel C I) : Prop :=
  (∀ c ∈ m.components, m.outer c →
    (∀ i ∈ m.interfaces c, ¬ m.runsRoutingProtocol c i) ∧
    ¬ m.performsRoutingFunction c ∧
    (m.dynamicRoutingRequired c → ∃ f ∈ m.components,
      (m.outerFirewall f ∨ m.grayFirewall f) ∧ m.suppliesDynamicRoutingTo f c)) ∧
  (∀ c ∈ m.components, m.inner c → ∀ other ∈ m.components,
    other ≠ c → m.encryptionComponent other → ¬ m.switchesOrRoutesFor c other)

end TDN.Targets
