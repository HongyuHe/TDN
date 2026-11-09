import TDN.Models.TableDrivenDataPlane

namespace TDN.DataPlaneForwarding

def ExcludesRoute (rule : PacketPolicy.Rule) (route : FibRoute) : Prop :=
  ∃ atom ∈ rule.atoms, match atom with
    | .destinationRange low high => high < route.destPrefixLow ∨ route.destPrefixHigh < low
    | _ => False

instance (rule : PacketPolicy.Rule) (route : FibRoute) : Decidable (ExcludesRoute rule route) := by
  unfold ExcludesRoute
  letI (a : PacketPolicy.MatchCondition) : Decidable (match a with
    | .destinationRange low high => high < route.destPrefixLow ∨ route.destPrefixHigh < low
    | _ => False) := by cases a <;> infer_instance
  infer_instance

lemma matching_route_not_excluded {rule : PacketPolicy.Rule} {route : FibRoute}
    {packet : PacketPolicy.Packet} (matched : rule.toFilter.accepts packet = true)
    (routed : route.matches packet) : ¬ ExcludesRoute rule route := by
  rintro ⟨atom, member, conflict⟩
  have holds := PacketPolicy.matching_atom matched member
  cases atom <;> simp only at conflict <;> try contradiction
  simp only [PacketPolicy.MatchCondition.matchesPacket] at holds
  unfold FibRoute.matches at routed
  omega

def withRoute (rule : PacketPolicy.Rule) (route : FibRoute) : PacketPolicy.Rule :=
  { rule with atoms := .destinationRange route.destPrefixLow route.destPrefixHigh :: rule.atoms }

lemma matches_with_route {rule : PacketPolicy.Rule} {route : FibRoute}
    {packet : PacketPolicy.Packet} (matched : rule.toFilter.accepts packet = true)
    (routed : route.matches packet) :
    (withRoute rule route).toFilter.accepts packet = true := by
  simp only [withRoute, PacketPolicy.Rule.toFilter, List.all_cons, Bool.and_eq_true,
    PacketPolicy.MatchCondition.matchesPacket]
  exact ⟨decide_eq_true routed, matched⟩

def TableDrivenRoutedForwardChecks (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) : Prop :=
  ∀ route ∈ routes,
    ∀ auth ∈ possibleAuthentications
      (deviceAt devices (ifaceAt ifaces route.ingress).owner) (ifaceAt ifaces route.ingress),
    ∀ rule ∈ (deviceAt devices (ifaceAt ifaces route.egress).owner).forwardRules,
      rule.verdict = .allow →
      ExcludesRoute rule route ∨ RecordRuleCheck (ifaceAt ifaces route.ingress)
        (ifaceAt ifaces route.egress) (deviceAt devices (ifaceAt ifaces route.egress).owner) auth (withRoute rule route)

instance (devices : List DeviceData) (ifaces : List IfaceData) (routes : List FibRoute) :
    Decidable (TableDrivenRoutedForwardChecks devices ifaces routes) := by
  unfold TableDrivenRoutedForwardChecks
  infer_instance

theorem table_driven_routed_forward_checks_sound (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) (links switches : List (Nat × Nat))
    (checked : TableDrivenRoutedForwardChecks devices ifaces routes)
    (denying : ∀ p, (dataPlaneModelFromRecords devices ifaces routes links switches).forwardFallback p = .deny)
    (iface : Nat) (frame : Frame) (authenticated : List Nat)
    (routed : RoutedFrame (dataPlaneModelFromRecords devices ifaces routes links switches) iface frame)
    (ingress : frame.packet.ingress =
      (dataPlaneModelFromRecords devices ifaces routes links switches).interfaceName frame.enteredIface)
    (valid : LocalAuthentication (dataPlaneModelFromRecords devices ifaces routes links switches)
      (expectedEncapStackFromRecords ifaces) frame.enteredIface authenticated)
    (accepted : accepts
      ((dataPlaneModelFromRecords devices ifaces routes links switches).forwardRules iface)
      ((dataPlaneModelFromRecords devices ifaces routes links switches).forwardFallback iface)
      (policyPacket (dataPlaneModelFromRecords devices ifaces routes links switches) iface frame authenticated)) :
    (lookupSpdPolicies ((dataPlaneModelFromRecords devices ifaces routes links switches).egressPolicies iface)
      frame.packet = [] →
      encapStackAfterIngress (expectedEncapStackFromRecords ifaces) frame.enteredIface authenticated = expectedEncapStackFromRecords ifaces iface) ∧
    (∀ association ∈ lookupSpdPolicies
      ((dataPlaneModelFromRecords devices ifaces routes links switches).egressPolicies iface) frame.packet,
      association.tag :: encapStackAfterIngress (expectedEncapStackFromRecords ifaces) frame.enteredIface authenticated =
        expectedEncapStackFromRecords ifaces iface) := by
  obtain ⟨route, selected, atEntry, atIface⟩ := routed
  rw [denying] at accepted
  obtain ⟨filtered, member, matched, allow⟩ := Filter.allowed_has_matching_allow _ _ accepted
  obtain ⟨rule, inRules, rfl⟩ := List.mem_map.mp member
  have authMember := valid_authentication_in_finite_list devices ifaces routes links switches
    frame.enteredIface authenticated valid
  have check := checked route selected.1
  rw [atEntry, atIface] at check
  rcases check authenticated authMember rule inRules allow with excluded | stack
  · exact False.elim (matching_route_not_excluded matched selected.2.1 excluded)
  · exact checked_rule_stack_effect ingress stack (matches_with_route matched selected.2.1)

theorem local_stack_conditions_of_routed_finite_checks
    (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) (links switches : List (Nat × Nat))
    (routeOwner : ∀ r ∈ routes, (ifaceAt ifaces r.egress).owner = (ifaceAt ifaces r.ingress).owner)
    (linkStack : ∀ edge ∈ links, (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack)
    (switchStack : ∀ edge ∈ switches,
      (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack ∧
      (deviceAt devices (ifaceAt ifaces edge.1).owner).ingressPolicies = [])
    (forwardDefaults : ∀ device ∈ ({} : DeviceData) :: devices, device.forwardFallback = .deny)
    (forward : TableDrivenRoutedForwardChecks devices ifaces routes)
    (output : TableDrivenOutputChecks devices ifaces)
    (outerRoutes : TableDrivenOuterRoutes devices ifaces routes) :
    PerHopEncapConditions (dataPlaneModelFromRecords devices ifaces routes links switches) (expectedEncapStackFromRecords ifaces) := by
  have defaults : ∀ p,
      (dataPlaneModelFromRecords devices ifaces routes links switches).forwardFallback p = .deny :=
    fun p => forwardDefaults _ (device_at_member_or_default devices (ifaceAt ifaces p).owner)
  constructor
  · exact routeOwner
  · intro a b linked
    exact linkStack (a, b) linked
  · intro a b packet authenticated switched valid
    obtain ⟨same, empty⟩ := switchStack (a, b) switched
    have noAuth : authenticated = [] := by
      rcases valid with none | ⟨association, member, _, _⟩
      · exact none
      · change association ∈ (deviceAt devices (ifaceAt ifaces a).owner).ingressPolicies at member
        simp [empty] at member
    simpa [encapStackAfterIngress, noAuth, expectedEncapStackFromRecords] using same
  · intro iface frame authenticated routed ingress valid owner accepted
    exact table_driven_routed_forward_checks_sound devices ifaces routes links switches
      forward defaults iface frame authenticated routed ingress valid accepted
  · intro iface frame routed origin ingress owner accepted
    exact table_driven_output_checks_sound devices ifaces routes links switches output iface frame origin owner
  · exact table_driven_outer_routes_sound devices ifaces routes links switches outerRoutes

end TDN.DataPlaneForwarding
