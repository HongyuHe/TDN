import TDN.Semantics.ExecutionDomains

namespace TDN.Execution

def RecordDomainCheck (allowed : PortData → Bool) (entry output : PortData)
    (device : DeviceData) (authenticated : List Nat) (rule : PacketPolicy.Rule) : Prop :=
  ¬ PortCompatible rule entry.name output.name ∨
  ImpossibleAuthentication rule authenticated ∨
  (allowed output = true ∧
    (HasOutboundGuard rule ∨
      (if authenticated = [] then entry.stack else entry.stack.tail) = output.stack) ∧
    ∀ association ∈ device.outbound, ExcludesSelector rule association ∨
      association.tag :: (if authenticated = [] then entry.stack else entry.stack.tail) = output.stack)

instance (allowed : PortData → Bool) (i o : PortData) (d : DeviceData)
    (a : List Nat) (r : PacketPolicy.Rule) :
    Decidable (RecordDomainCheck allowed i o d a r) := by unfold RecordDomainCheck; infer_instance

lemma domain_check_implies_stack_check {allowed : PortData → Bool} {i o : PortData}
    {d : DeviceData} {auth : List Nat} {r : PacketPolicy.Rule}
    (checked : RecordDomainCheck allowed i o d auth r) :
    RecordRuleCheck i o d auth r := by
  rcases checked with incompatible | impossible | ⟨_, stack⟩
  · exact Or.inl incompatible
  · exact Or.inr (Or.inl impossible)
  · exact Or.inr (Or.inr stack)

lemma matched_domain_check_allows_output {allowed : PortData → Bool} {i o : PortData}
    {d : DeviceData} {auth : List Nat} {r : PacketPolicy.Rule} {p : PacketPolicy.Packet}
    (checked : RecordDomainCheck allowed i o d auth r)
    (matched : r.toFilter.accepts p = true)
    (ingress : p.ingress = i.name) (egress : p.egress = o.name)
    (authentication : p.inboundPolicies = auth) : allowed o = true := by
  rcases checked with incompatible | impossible | ⟨permitted, _⟩
  · exact False.elim (incompatible (by simpa [ingress, egress] using matched_ports_compatible matched))
  · exact False.elim ((matching_authentication_possible matched)
      (by simpa [authentication] using impossible))
  · exact permitted

def FiniteDomainForwardChecks (devices : List DeviceData) (ports : List PortData)
    (allowed : PortData → Bool) : Prop :=
  ∀ entry ∈ ({} : PortData) :: ports, ∀ output ∈ ({} : PortData) :: ports,
    output.owner = entry.owner → allowed entry = true →
    ∀ auth ∈ possibleAuthentications (deviceAt devices entry.owner) entry,
    ∀ rule ∈ (deviceAt devices output.owner).forwardRules, rule.verdict = .allow →
      RecordDomainCheck allowed entry output (deviceAt devices output.owner) auth rule

instance (devices : List DeviceData) (ports : List PortData) (allowed : PortData → Bool) :
    Decidable (FiniteDomainForwardChecks devices ports allowed) := by
  unfold FiniteDomainForwardChecks
  infer_instance

theorem finite_domain_forward_checks_sound (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (links switches : List (Nat × Nat)) (allowed : PortData → Bool)
    (checked : FiniteDomainForwardChecks devices ports allowed)
    (denying : ∀ p, (finiteConfig devices ports routes links switches).forwardFallback p = .deny)
    (port : Nat) (frame : Frame) (authenticated : List Nat)
    (ingress : frame.packet.ingress =
      (finiteConfig devices ports routes links switches).interfaceName frame.enteredPort)
    (valid : LocalAuthentication (finiteConfig devices ports routes links switches)
      (finiteLayout ports) frame.enteredPort authenticated)
    (owner : (finiteConfig devices ports routes links switches).owner port =
      (finiteConfig devices ports routes links switches).owner frame.enteredPort)
    (permitted : allowed (portAt ports frame.enteredPort) = true)
    (accepted : accepts ((finiteConfig devices ports routes links switches).forwardRules port)
      ((finiteConfig devices ports routes links switches).forwardFallback port)
      (policyPacket (finiteConfig devices ports routes links switches) port frame authenticated)) :
    ((selectedAssociations ((finiteConfig devices ports routes links switches).outbound port)
      frame.packet = [] →
      processingStack (finiteLayout ports) frame.enteredPort authenticated = finiteLayout ports port) ∧
    (∀ association ∈ selectedAssociations
      ((finiteConfig devices ports routes links switches).outbound port) frame.packet,
      association.tag :: processingStack (finiteLayout ports) frame.enteredPort authenticated =
        finiteLayout ports port)) ∧ allowed (portAt ports port) = true := by
  rw [denying] at accepted
  obtain ⟨filtered, member, matched, allow⟩ := Filter.allowed_has_matching_allow _ _ accepted
  obtain ⟨rule, inRules, rfl⟩ := List.mem_map.mp member
  have check := checked (portAt ports frame.enteredPort)
    (port_at_member_or_default ports frame.enteredPort) (portAt ports port)
    (port_at_member_or_default ports port) owner permitted authenticated
    (valid_authentication_in_finite_list devices ports routes links switches
      frame.enteredPort authenticated valid) rule inRules allow
  exact ⟨checked_rule_stack_effect ingress (domain_check_implies_stack_check check) matched,
    matched_domain_check_allows_output check matched ingress rfl rfl⟩

def FiniteDomainOutputChecks (devices : List DeviceData) (ports : List PortData)
    (allowed : PortData → Bool) : Prop :=
  ∀ entry ∈ ({} : PortData) :: ports, ∀ output ∈ ({} : PortData) :: ports,
    entry.payloadOrigin = true → output.owner = entry.owner → allowed entry = true →
    entry.stack = output.stack ∧ (deviceAt devices output.owner).outbound = [] ∧
      allowed output = true

instance (devices : List DeviceData) (ports : List PortData) (allowed : PortData → Bool) :
    Decidable (FiniteDomainOutputChecks devices ports allowed) := by
  unfold FiniteDomainOutputChecks
  infer_instance

def FiniteDomainOuterRoutes (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (allowed : PortData → Bool) : Prop :=
  ∀ route ∈ routes, ∀ association ∈ (deviceAt devices (portAt ports route.ingress).owner).outbound,
    (portAt ports route.ingress).stack.head? = some association.tag →
    allowed (portAt ports route.ingress) = true →
    route.low ≤ association.receiver → association.receiver ≤ route.high →
      (portAt ports route.ingress).stack = (portAt ports route.egress).stack ∧
      allowed (portAt ports route.egress) = true

instance (devices : List DeviceData) (ports : List PortData) (routes : List Route)
    (allowed : PortData → Bool) : Decidable (FiniteDomainOuterRoutes devices ports routes allowed) := by
  unfold FiniteDomainOuterRoutes
  infer_instance

theorem local_domain_conditions_of_finite_checks
    (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (links switches : List (Nat × Nat)) (allowed : PortData → Bool)
    (routeOwner : ∀ r ∈ routes, (portAt ports r.egress).owner = (portAt ports r.ingress).owner)
    (linkStack : ∀ edge ∈ links, allowed (portAt ports edge.1) = true →
      (portAt ports edge.1).stack = (portAt ports edge.2).stack ∧ allowed (portAt ports edge.2) = true)
    (switchStack : ∀ edge ∈ switches, allowed (portAt ports edge.1) = true →
      ((portAt ports edge.1).stack = (portAt ports edge.2).stack ∧
      (deviceAt devices (portAt ports edge.1).owner).inbound = []) ∧
      allowed (portAt ports edge.2) = true)
    (forwardDefaults : ∀ device ∈ ({} : DeviceData) :: devices, device.forwardFallback = .deny)
    (forward : FiniteDomainForwardChecks devices ports allowed)
    (output : FiniteDomainOutputChecks devices ports allowed)
    (outerRoutes : FiniteDomainOuterRoutes devices ports routes allowed) :
    LocalDomainConditions (finiteConfig devices ports routes links switches) (finiteLayout ports)
      (fun p => allowed (portAt ports p) = true) := by
  have defaults : ∀ p,
      (finiteConfig devices ports routes links switches).forwardFallback p = .deny :=
    fun p => forwardDefaults _ (device_at_member_or_default devices (portAt ports p).owner)
  constructor
  · exact routeOwner
  · intro a b linked permitted
    exact linkStack (a, b) linked permitted
  · intro a b packet authenticated switched valid permitted
    obtain ⟨⟨same, empty⟩, allowedOutput⟩ := switchStack (a, b) switched permitted
    have noAuth : authenticated = [] := by
      rcases valid with none | ⟨association, member, _, _⟩
      · exact none
      · change association ∈ (deviceAt devices (portAt ports a).owner).inbound at member
        simp [empty] at member
    exact ⟨by simpa [processingStack, noAuth, finiteLayout] using same, allowedOutput⟩
  · exact finite_domain_forward_checks_sound devices ports routes links switches allowed forward defaults
  · intro port frame origin ingress owner permitted accepted
    obtain ⟨same, empty, allowedOutput⟩ := output (portAt ports frame.enteredPort)
      (port_at_member_or_default ports frame.enteredPort) (portAt ports port)
      (port_at_member_or_default ports port) origin owner permitted
    refine ⟨⟨fun _ => same, ?_⟩, allowedOutput⟩
    intro association selected
    have configured := (matched_policy_is_configured selected).1
    change association ∈ (deviceAt devices (portAt ports port).owner).outbound at configured
    simp [empty] at configured
  · intro port association member head permitted sa frame route chosen atPort
    have matching : route.low ≤ association.receiver ∧ association.receiver ≤ route.high := chosen.2.1
    have localCheck := outerRoutes route chosen.1
    rw [atPort] at localCheck
    exact localCheck association member head permitted matching.1 matching.2


/-- Stack labels guide proofs and never affect the operational configuration. -/
def withPortStacks (ports : List PortData) (stackMap : PortData → List Nat) : List PortData :=
  ports.map (fun port => { port with stack := stackMap port })

lemma port_stack_update_keeps_operational_fields (ports : List PortData)
    (stackMap : PortData → List Nat) (n : Nat) :
    (portAt (withPortStacks ports stackMap) n).owner = (portAt ports n).owner ∧
    (portAt (withPortStacks ports stackMap) n).name = (portAt ports n).name ∧
    (portAt (withPortStacks ports stackMap) n).payloadOrigin = (portAt ports n).payloadOrigin := by
  simp only [portAt, withPortStacks, List.getElem?_map]
  cases ports[n]? <;> exact ⟨rfl, rfl, rfl⟩

theorem finite_config_ignores_port_stack_annotations (devices : List DeviceData)
    (ports : List PortData) (stackMap : PortData → List Nat)
    (routes : List Route) (links switches : List (Nat × Nat)) :
    finiteConfig devices (withPortStacks ports stackMap) routes links switches =
      finiteConfig devices ports routes links switches := by
  have owner := fun p => (port_stack_update_keeps_operational_fields ports stackMap p).1
  have name := fun p => (port_stack_update_keeps_operational_fields ports stackMap p).2.1
  have origin := fun p => (port_stack_update_keeps_operational_fields ports stackMap p).2.2
  unfold finiteConfig
  congr 1 <;> funext p <;> simp only [owner, name, origin]

end TDN.Execution
