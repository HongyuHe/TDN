import TDN.Semantics.FiniteExecution

namespace TDN.Execution

/-- A disjoint destination interval makes a rule impossible on a selected route. -/
def ExcludesRoute (rule : PacketPolicy.Rule) (route : Route) : Prop :=
  ∃ atom ∈ rule.atoms, match atom with
    | .destinationRange low high => high < route.low ∨ route.high < low
    | _ => False

instance (rule : PacketPolicy.Rule) (route : Route) : Decidable (ExcludesRoute rule route) := by
  unfold ExcludesRoute
  letI (a : PacketPolicy.Atom) : Decidable (match a with
    | .destinationRange low high => high < route.low ∨ route.high < low
    | _ => False) := by cases a <;> infer_instance
  infer_instance

lemma matching_route_not_excluded {rule : PacketPolicy.Rule} {route : Route}
    {packet : PacketPolicy.Packet} (matched : rule.toFilter.accepts packet = true)
    (routed : route.matches packet) : ¬ ExcludesRoute rule route := by
  rintro ⟨atom, member, conflict⟩
  have holds := PacketPolicy.matching_atom matched member
  cases atom <;> simp only at conflict <;> try contradiction
  simp only [PacketPolicy.Atom.holds] at holds
  unfold Route.matches at routed
  omega

/-- The route destination interval is a checked fact at the following hook. -/
def withRoute (rule : PacketPolicy.Rule) (route : Route) : PacketPolicy.Rule :=
  { rule with atoms := .destinationRange route.low route.high :: rule.atoms }

lemma matches_with_route {rule : PacketPolicy.Rule} {route : Route}
    {packet : PacketPolicy.Packet} (matched : rule.toFilter.accepts packet = true)
    (routed : route.matches packet) :
    (withRoute rule route).toFilter.accepts packet = true := by
  simp only [withRoute, PacketPolicy.Rule.toFilter, List.all_cons, Bool.and_eq_true,
    PacketPolicy.Atom.holds]
  exact ⟨decide_eq_true routed, matched⟩

/-- Every route alternative is checked. A rule is skipped only when its destination
interval cannot match that route. No captured rule or default action is removed. -/
def FiniteRoutedForwardChecks (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) : Prop :=
  ∀ route ∈ routes,
    ∀ auth ∈ possibleAuthentications
      (deviceAt devices (portAt ports route.ingress).owner) (portAt ports route.ingress),
    ∀ rule ∈ (deviceAt devices (portAt ports route.egress).owner).forwardRules,
      rule.verdict = .allow →
      ExcludesRoute rule route ∨ RecordRuleCheck (portAt ports route.ingress)
        (portAt ports route.egress) (deviceAt devices (portAt ports route.egress).owner) auth (withRoute rule route)

instance (devices : List DeviceData) (ports : List PortData) (routes : List Route) :
    Decidable (FiniteRoutedForwardChecks devices ports routes) := by
  unfold FiniteRoutedForwardChecks
  infer_instance

theorem finite_routed_forward_checks_sound (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (links switches : List (Nat × Nat))
    (checked : FiniteRoutedForwardChecks devices ports routes)
    (denying : ∀ p, (finiteConfig devices ports routes links switches).forwardFallback p = .deny)
    (port : Nat) (frame : Frame) (authenticated : List Nat)
    (routed : RoutedFrame (finiteConfig devices ports routes links switches) port frame)
    (ingress : frame.packet.ingress =
      (finiteConfig devices ports routes links switches).interfaceName frame.enteredPort)
    (valid : LocalAuthentication (finiteConfig devices ports routes links switches)
      (finiteLayout ports) frame.enteredPort authenticated)
    (accepted : accepts
      ((finiteConfig devices ports routes links switches).forwardRules port)
      ((finiteConfig devices ports routes links switches).forwardFallback port)
      (policyPacket (finiteConfig devices ports routes links switches) port frame authenticated)) :
    (selectedAssociations ((finiteConfig devices ports routes links switches).outbound port)
      frame.packet = [] →
      processingStack (finiteLayout ports) frame.enteredPort authenticated = finiteLayout ports port) ∧
    (∀ association ∈ selectedAssociations
      ((finiteConfig devices ports routes links switches).outbound port) frame.packet,
      association.tag :: processingStack (finiteLayout ports) frame.enteredPort authenticated =
        finiteLayout ports port) := by
  obtain ⟨route, selected, atEntry, atPort⟩ := routed
  rw [denying] at accepted
  obtain ⟨filtered, member, matched, allow⟩ := Filter.allowed_has_matching_allow _ _ accepted
  obtain ⟨rule, inRules, rfl⟩ := List.mem_map.mp member
  have authMember := valid_authentication_in_finite_list devices ports routes links switches
    frame.enteredPort authenticated valid
  have check := checked route selected.1
  rw [atEntry, atPort] at check
  rcases check authenticated authMember rule inRules allow with excluded | stack
  · exact False.elim (matching_route_not_excluded matched selected.2.1 excluded)
  · exact checked_rule_stack_effect ingress stack (matches_with_route matched selected.2.1)

/-- Route-aware literal checks establish the same local conditions and global theorem
used by the native IPv4 cases. The output check remains a stronger sufficient condition. -/
theorem local_stack_conditions_of_routed_finite_checks
    (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (links switches : List (Nat × Nat))
    (routeOwner : ∀ r ∈ routes, (portAt ports r.egress).owner = (portAt ports r.ingress).owner)
    (linkStack : ∀ edge ∈ links, (portAt ports edge.1).stack = (portAt ports edge.2).stack)
    (switchStack : ∀ edge ∈ switches,
      (portAt ports edge.1).stack = (portAt ports edge.2).stack ∧
      (deviceAt devices (portAt ports edge.1).owner).inbound = [])
    (forwardDefaults : ∀ device ∈ ({} : DeviceData) :: devices, device.forwardFallback = .deny)
    (forward : FiniteRoutedForwardChecks devices ports routes)
    (output : FiniteOutputChecks devices ports)
    (outerRoutes : FiniteOuterRoutes devices ports routes) :
    LocalStackConditions (finiteConfig devices ports routes links switches) (finiteLayout ports) := by
  have defaults : ∀ p,
      (finiteConfig devices ports routes links switches).forwardFallback p = .deny :=
    fun p => forwardDefaults _ (device_at_member_or_default devices (portAt ports p).owner)
  constructor
  · exact routeOwner
  · intro a b linked
    exact linkStack (a, b) linked
  · intro a b packet authenticated switched valid
    obtain ⟨same, empty⟩ := switchStack (a, b) switched
    have noAuth : authenticated = [] := by
      rcases valid with none | ⟨association, member, _, _⟩
      · exact none
      · change association ∈ (deviceAt devices (portAt ports a).owner).inbound at member
        simp [empty] at member
    simpa [processingStack, noAuth, finiteLayout] using same
  · intro port frame authenticated routed ingress valid owner accepted
    exact finite_routed_forward_checks_sound devices ports routes links switches
      forward defaults port frame authenticated routed ingress valid accepted
  · intro port frame routed origin ingress owner accepted
    exact finite_output_checks_sound devices ports routes links switches output port frame origin owner
  · exact finite_outer_routes_sound devices ports routes links switches outerRoutes

end TDN.Execution
