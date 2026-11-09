import TDN.Models.EnclaveIsolationInvariants

namespace TDN.DataPlaneForwarding

def RecordDomainCheck (allowed : IfaceData → Bool) (entry output : IfaceData)
    (device : DeviceData) (authenticated : List Nat) (rule : PacketPolicy.Rule) : Prop :=
  ¬ IfaceCompatible rule entry.name output.name ∨
  ImpossibleAuthentication rule authenticated ∨
  (allowed output = true ∧
    (HasOutboundGuard rule ∨
      (if authenticated = [] then entry.stack else entry.stack.tail) = output.stack) ∧
    ∀ association ∈ device.egressPolicies, ExcludesSelector rule association ∨
      association.tag :: (if authenticated = [] then entry.stack else entry.stack.tail) = output.stack)

instance (allowed : IfaceData → Bool) (i o : IfaceData) (d : DeviceData)
    (a : List Nat) (r : PacketPolicy.Rule) :
    Decidable (RecordDomainCheck allowed i o d a r) := by unfold RecordDomainCheck; infer_instance

lemma domain_check_implies_stack_check {allowed : IfaceData → Bool} {i o : IfaceData}
    {d : DeviceData} {auth : List Nat} {r : PacketPolicy.Rule}
    (checked : RecordDomainCheck allowed i o d auth r) :
    RecordRuleCheck i o d auth r := by
  rcases checked with incompatible | impossible | ⟨_, stack⟩
  · exact Or.inl incompatible
  · exact Or.inr (Or.inl impossible)
  · exact Or.inr (Or.inr stack)

lemma matched_domain_check_allows_output {allowed : IfaceData → Bool} {i o : IfaceData}
    {d : DeviceData} {auth : List Nat} {r : PacketPolicy.Rule} {p : PacketPolicy.Packet}
    (checked : RecordDomainCheck allowed i o d auth r)
    (matched : r.toFilter.accepts p = true)
    (ingress : p.ingress = i.name) (egress : p.egress = o.name)
    (authentication : p.matchedInboundPolicyIds = auth) : allowed o = true := by
  rcases checked with incompatible | impossible | ⟨permitted, _⟩
  · exact False.elim (incompatible (by simpa [ingress, egress] using matched_ifaces_compatible matched))
  · exact False.elim ((matching_authentication_possible matched)
      (by simpa [authentication] using impossible))
  · exact permitted

def TableDrivenDomainForwardChecks (devices : List DeviceData) (ifaces : List IfaceData)
    (allowed : IfaceData → Bool) : Prop :=
  ∀ entry ∈ ({} : IfaceData) :: ifaces, ∀ output ∈ ({} : IfaceData) :: ifaces,
    output.owner = entry.owner → allowed entry = true →
    ∀ auth ∈ possibleAuthentications (deviceAt devices entry.owner) entry,
    ∀ rule ∈ (deviceAt devices output.owner).forwardRules, rule.verdict = .allow →
      RecordDomainCheck allowed entry output (deviceAt devices output.owner) auth rule

instance (devices : List DeviceData) (ifaces : List IfaceData) (allowed : IfaceData → Bool) :
    Decidable (TableDrivenDomainForwardChecks devices ifaces allowed) := by
  unfold TableDrivenDomainForwardChecks
  infer_instance

theorem table_driven_domain_forward_checks_sound (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) (links switches : List (Nat × Nat)) (allowed : IfaceData → Bool)
    (checked : TableDrivenDomainForwardChecks devices ifaces allowed)
    (denying : ∀ p, (dataPlaneModelFromRecords devices ifaces routes links switches).forwardFallback p = .deny)
    (iface : Nat) (frame : Frame) (authenticated : List Nat)
    (ingress : frame.packet.ingress =
      (dataPlaneModelFromRecords devices ifaces routes links switches).interfaceName frame.enteredIface)
    (valid : LocalAuthentication (dataPlaneModelFromRecords devices ifaces routes links switches)
      (expectedEncapStackFromRecords ifaces) frame.enteredIface authenticated)
    (owner : (dataPlaneModelFromRecords devices ifaces routes links switches).owner iface =
      (dataPlaneModelFromRecords devices ifaces routes links switches).owner frame.enteredIface)
    (permitted : allowed (ifaceAt ifaces frame.enteredIface) = true)
    (accepted : accepts ((dataPlaneModelFromRecords devices ifaces routes links switches).forwardRules iface)
      ((dataPlaneModelFromRecords devices ifaces routes links switches).forwardFallback iface)
      (policyPacket (dataPlaneModelFromRecords devices ifaces routes links switches) iface frame authenticated)) :
    ((lookupSpdPolicies ((dataPlaneModelFromRecords devices ifaces routes links switches).egressPolicies iface)
      frame.packet = [] →
      encapStackAfterIngress (expectedEncapStackFromRecords ifaces) frame.enteredIface authenticated = expectedEncapStackFromRecords ifaces iface) ∧
    (∀ association ∈ lookupSpdPolicies
      ((dataPlaneModelFromRecords devices ifaces routes links switches).egressPolicies iface) frame.packet,
      association.tag :: encapStackAfterIngress (expectedEncapStackFromRecords ifaces) frame.enteredIface authenticated =
        expectedEncapStackFromRecords ifaces iface)) ∧ allowed (ifaceAt ifaces iface) = true := by
  rw [denying] at accepted
  obtain ⟨filtered, member, matched, allow⟩ := Filter.allowed_has_matching_allow _ _ accepted
  obtain ⟨rule, inRules, rfl⟩ := List.mem_map.mp member
  have check := checked (ifaceAt ifaces frame.enteredIface)
    (iface_at_member_or_default ifaces frame.enteredIface) (ifaceAt ifaces iface)
    (iface_at_member_or_default ifaces iface) owner permitted authenticated
    (valid_authentication_in_finite_list devices ifaces routes links switches
      frame.enteredIface authenticated valid) rule inRules allow
  exact ⟨checked_rule_stack_effect ingress (domain_check_implies_stack_check check) matched,
    matched_domain_check_allows_output check matched ingress rfl rfl⟩

def TableDrivenDomainOutputChecks (devices : List DeviceData) (ifaces : List IfaceData)
    (allowed : IfaceData → Bool) : Prop :=
  ∀ entry ∈ ({} : IfaceData) :: ifaces, ∀ output ∈ ({} : IfaceData) :: ifaces,
    entry.canOriginateTraffic = true → output.owner = entry.owner → allowed entry = true →
    entry.stack = output.stack ∧ (deviceAt devices output.owner).egressPolicies = [] ∧
      allowed output = true

instance (devices : List DeviceData) (ifaces : List IfaceData) (allowed : IfaceData → Bool) :
    Decidable (TableDrivenDomainOutputChecks devices ifaces allowed) := by
  unfold TableDrivenDomainOutputChecks
  infer_instance

def TableDrivenDomainOuterRoutes (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) (allowed : IfaceData → Bool) : Prop :=
  ∀ route ∈ routes, ∀ association ∈ (deviceAt devices (ifaceAt ifaces route.ingress).owner).egressPolicies,
    (ifaceAt ifaces route.ingress).stack.head? = some association.tag →
    allowed (ifaceAt ifaces route.ingress) = true →
    route.destPrefixLow ≤ association.receiver → association.receiver ≤ route.destPrefixHigh →
      (ifaceAt ifaces route.ingress).stack = (ifaceAt ifaces route.egress).stack ∧
      allowed (ifaceAt ifaces route.egress) = true

instance (devices : List DeviceData) (ifaces : List IfaceData) (routes : List FibRoute)
    (allowed : IfaceData → Bool) : Decidable (TableDrivenDomainOuterRoutes devices ifaces routes allowed) := by
  unfold TableDrivenDomainOuterRoutes
  infer_instance

theorem local_domain_conditions_of_finite_checks
    (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) (links switches : List (Nat × Nat)) (allowed : IfaceData → Bool)
    (routeOwner : ∀ r ∈ routes, (ifaceAt ifaces r.egress).owner = (ifaceAt ifaces r.ingress).owner)
    (linkStack : ∀ edge ∈ links, allowed (ifaceAt ifaces edge.1) = true →
      (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack ∧ allowed (ifaceAt ifaces edge.2) = true)
    (switchStack : ∀ edge ∈ switches, allowed (ifaceAt ifaces edge.1) = true →
      ((ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack ∧
      (deviceAt devices (ifaceAt ifaces edge.1).owner).ingressPolicies = []) ∧
      allowed (ifaceAt ifaces edge.2) = true)
    (forwardDefaults : ∀ device ∈ ({} : DeviceData) :: devices, device.forwardFallback = .deny)
    (forward : TableDrivenDomainForwardChecks devices ifaces allowed)
    (output : TableDrivenDomainOutputChecks devices ifaces allowed)
    (outerRoutes : TableDrivenDomainOuterRoutes devices ifaces routes allowed) :
    LocalDomainConditions (dataPlaneModelFromRecords devices ifaces routes links switches) (expectedEncapStackFromRecords ifaces)
      (fun p => allowed (ifaceAt ifaces p) = true) := by
  have defaults : ∀ p,
      (dataPlaneModelFromRecords devices ifaces routes links switches).forwardFallback p = .deny :=
    fun p => forwardDefaults _ (device_at_member_or_default devices (ifaceAt ifaces p).owner)
  constructor
  · exact routeOwner
  · intro a b linked permitted
    exact linkStack (a, b) linked permitted
  · intro a b packet authenticated switched valid permitted
    obtain ⟨⟨same, empty⟩, allowedOutput⟩ := switchStack (a, b) switched permitted
    have noAuth : authenticated = [] := by
      rcases valid with none | ⟨association, member, _, _⟩
      · exact none
      · change association ∈ (deviceAt devices (ifaceAt ifaces a).owner).ingressPolicies at member
        simp [empty] at member
    exact ⟨by simpa [encapStackAfterIngress, noAuth, expectedEncapStackFromRecords] using same, allowedOutput⟩
  · exact table_driven_domain_forward_checks_sound devices ifaces routes links switches allowed forward defaults
  · intro iface frame origin ingress owner permitted accepted
    obtain ⟨same, empty, allowedOutput⟩ := output (ifaceAt ifaces frame.enteredIface)
      (iface_at_member_or_default ifaces frame.enteredIface) (ifaceAt ifaces iface)
      (iface_at_member_or_default ifaces iface) origin owner permitted
    refine ⟨⟨fun _ => same, ?_⟩, allowedOutput⟩
    intro association selected
    have configured := (matched_policy_is_configured selected).1
    change association ∈ (deviceAt devices (ifaceAt ifaces iface).owner).egressPolicies at configured
    simp [empty] at configured
  · intro iface association member head permitted sa frame route chosen atIface
    have matching : route.destPrefixLow ≤ association.receiver ∧ association.receiver ≤ route.destPrefixHigh := chosen.2.1
    have localCheck := outerRoutes route chosen.1
    rw [atIface] at localCheck
    exact localCheck association member head permitted matching.1 matching.2

def withEncapStackAnnotations (ifaces : List IfaceData) (annotateIfaceStack : IfaceData → List Nat) : List IfaceData :=
  ifaces.map (fun iface => { iface with stack := annotateIfaceStack iface })

lemma encap_stack_update_preserves_data_plane_fields (ifaces : List IfaceData)
    (annotateIfaceStack : IfaceData → List Nat) (n : Nat) :
    (ifaceAt (withEncapStackAnnotations ifaces annotateIfaceStack) n).owner = (ifaceAt ifaces n).owner ∧
    (ifaceAt (withEncapStackAnnotations ifaces annotateIfaceStack) n).name = (ifaceAt ifaces n).name ∧
    (ifaceAt (withEncapStackAnnotations ifaces annotateIfaceStack) n).canOriginateTraffic = (ifaceAt ifaces n).canOriginateTraffic := by
  simp only [ifaceAt, withEncapStackAnnotations, List.getElem?_map]
  cases ifaces[n]? <;> exact ⟨rfl, rfl, rfl⟩

theorem data_plane_ignores_encap_stack_annotations (devices : List DeviceData)
    (ifaces : List IfaceData) (annotateIfaceStack : IfaceData → List Nat)
    (routes : List FibRoute) (links switches : List (Nat × Nat)) :
    dataPlaneModelFromRecords devices (withEncapStackAnnotations ifaces annotateIfaceStack) routes links switches =
      dataPlaneModelFromRecords devices ifaces routes links switches := by
  have owner := fun p => (encap_stack_update_preserves_data_plane_fields ifaces annotateIfaceStack p).1
  have name := fun p => (encap_stack_update_preserves_data_plane_fields ifaces annotateIfaceStack p).2.1
  have origin := fun p => (encap_stack_update_preserves_data_plane_fields ifaces annotateIfaceStack p).2.2
  unfold dataPlaneModelFromRecords
  congr 1 <;> funext p <;> simp only [owner, name, origin]

end TDN.DataPlaneForwarding
