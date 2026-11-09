import TDN.Models.PerHopForwardingChecks

namespace TDN.DataPlaneForwarding

structure DeviceData where
  forwardRules : List PacketPolicy.Rule := []
  inputRules : List PacketPolicy.Rule := []
  outputRules : List PacketPolicy.Rule := []
  forwardFallback : Filter.Verdict := .deny
  inputFallback : Filter.Verdict := .deny
  outputFallback : Filter.Verdict := .deny
  egressPolicies : List IpsecPolicy := []
  ingressPolicies : List IpsecPolicy := []
  states : List InstalledSA := []
  localAddresses : List Nat := []
  ifaceSecurityDomain : Option Nat := none

structure IfaceData where
  owner : Nat := 0
  name : String := ""
  stack : List Nat := []
  canOriginateTraffic : Bool := false
  deriving DecidableEq, Repr

def deviceAt (devices : List DeviceData) (index : Nat) : DeviceData :=
  devices[index]?.getD {}

def ifaceAt (ifaces : List IfaceData) (index : Nat) : IfaceData :=
  ifaces[index]?.getD {}

def dataPlaneModelFromRecords (devices : List DeviceData) (ifaces : List IfaceData) (routes : List FibRoute)
    (links switches : List (Nat × Nat)) : DataPlaneModel where
  routes := routes
  forwardRules p := (deviceAt devices (ifaceAt ifaces p).owner).forwardRules
  inputRules p := (deviceAt devices (ifaceAt ifaces p).owner).inputRules
  outputRules p := (deviceAt devices (ifaceAt ifaces p).owner).outputRules
  forwardFallback p := (deviceAt devices (ifaceAt ifaces p).owner).forwardFallback
  inputFallback p := (deviceAt devices (ifaceAt ifaces p).owner).inputFallback
  outputFallback p := (deviceAt devices (ifaceAt ifaces p).owner).outputFallback
  egressPolicies p := (deviceAt devices (ifaceAt ifaces p).owner).egressPolicies
  ingressPolicies p := (deviceAt devices (ifaceAt ifaces p).owner).ingressPolicies
  egressSAs p := (deviceAt devices (ifaceAt ifaces p).owner).states
  ingressSAs p := (deviceAt devices (ifaceAt ifaces p).owner).states
  interfaceName p := (ifaceAt ifaces p).name
  owner p := (ifaceAt ifaces p).owner
  link a b := (a, b) ∈ links
  bridging a b _ := (a, b) ∈ switches
  localAddress p address := address ∈ (deviceAt devices (ifaceAt ifaces p).owner).localAddresses
  ifaceSecurityDomain p := (deviceAt devices (ifaceAt ifaces p).owner).ifaceSecurityDomain
  canOriginateTraffic p := (ifaceAt ifaces p).canOriginateTraffic = true

def expectedEncapStackFromRecords (ifaces : List IfaceData) (p : Nat) : List Nat :=
  (ifaceAt ifaces p).stack

lemma iface_at_member_or_default (ifaces : List IfaceData) (n : Nat) :
    ifaceAt ifaces n ∈ ({} : IfaceData) :: ifaces := by
  unfold ifaceAt
  cases h : ifaces[n]? with
  | none => simp
  | some p =>
    simp only [Option.getD_some, List.mem_cons]
    exact Or.inr (List.mem_of_getElem? h)

def possibleAuthentications (device : DeviceData) (iface : IfaceData) : List (List Nat) :=
  [] :: (device.ingressPolicies.filter fun a => iface.stack.head? == some a.tag).map (fun a => [a.id])

lemma valid_authentication_in_finite_list (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) (links switches : List (Nat × Nat)) (entry : Nat)
    (authenticated : List Nat)
    (valid : LocalAuthentication (dataPlaneModelFromRecords devices ifaces routes links switches)
      (expectedEncapStackFromRecords ifaces) entry authenticated) :
    authenticated ∈ possibleAuthentications (deviceAt devices (ifaceAt ifaces entry).owner)
      (ifaceAt ifaces entry) := by
  rcases valid with empty | ⟨association, member, same, rest, shape⟩
  · simp [possibleAuthentications, empty]
  · apply List.mem_cons_of_mem
    apply List.mem_map.mpr
    refine ⟨association, List.mem_filter.mpr ⟨member, ?_⟩, same.symm⟩
    change (ifaceAt ifaces entry).stack = association.tag :: rest at shape
    simp [shape]

def RecordRuleCheck (entry output : IfaceData) (device : DeviceData)
    (authenticated : List Nat) (rule : PacketPolicy.Rule) : Prop :=
  ¬ IfaceCompatible rule entry.name output.name ∨
  ImpossibleAuthentication rule authenticated ∨
  ((HasOutboundGuard rule ∨
      (if authenticated = [] then entry.stack else entry.stack.tail) = output.stack) ∧
    ∀ association ∈ device.egressPolicies, ExcludesSelector rule association ∨
      association.tag :: (if authenticated = [] then entry.stack else entry.stack.tail) = output.stack)

instance (i o : IfaceData) (d : DeviceData) (a : List Nat) (r : PacketPolicy.Rule) :
    Decidable (RecordRuleCheck i o d a r) := by unfold RecordRuleCheck; infer_instance

def TableDrivenForwardChecks (devices : List DeviceData) (ifaces : List IfaceData) : Prop :=
  ∀ entry ∈ ({} : IfaceData) :: ifaces, ∀ output ∈ ({} : IfaceData) :: ifaces,
    output.owner = entry.owner →
    ∀ auth ∈ possibleAuthentications (deviceAt devices entry.owner) entry,
    ∀ rule ∈ (deviceAt devices output.owner).forwardRules, rule.verdict = .allow →
      RecordRuleCheck entry output (deviceAt devices output.owner) auth rule

instance (devices : List DeviceData) (ifaces : List IfaceData) :
    Decidable (TableDrivenForwardChecks devices ifaces) := by unfold TableDrivenForwardChecks; infer_instance

theorem table_driven_forward_checks_sound (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) (links switches : List (Nat × Nat))
    (checked : TableDrivenForwardChecks devices ifaces)
    (denying : ∀ p, (dataPlaneModelFromRecords devices ifaces routes links switches).forwardFallback p = .deny)
    (iface : Nat) (frame : Frame) (authenticated : List Nat)
    (ingress : frame.packet.ingress =
      (dataPlaneModelFromRecords devices ifaces routes links switches).interfaceName frame.enteredIface)
    (valid : LocalAuthentication (dataPlaneModelFromRecords devices ifaces routes links switches)
      (expectedEncapStackFromRecords ifaces) frame.enteredIface authenticated)
    (owner : (dataPlaneModelFromRecords devices ifaces routes links switches).owner iface =
      (dataPlaneModelFromRecords devices ifaces routes links switches).owner frame.enteredIface)
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
  rw [denying] at accepted
  apply checked_hook_stack_effect _ _ _ _ _ _ ingress _ accepted
  intro rule member allow
  exact checked (ifaceAt ifaces frame.enteredIface)
    (iface_at_member_or_default ifaces frame.enteredIface) (ifaceAt ifaces iface)
    (iface_at_member_or_default ifaces iface) owner authenticated
    (valid_authentication_in_finite_list devices ifaces routes links switches
      frame.enteredIface authenticated valid) rule member allow

def TableDrivenOutputChecks (devices : List DeviceData) (ifaces : List IfaceData) : Prop :=
  ∀ entry ∈ ({} : IfaceData) :: ifaces, ∀ output ∈ ({} : IfaceData) :: ifaces,
    entry.canOriginateTraffic = true → output.owner = entry.owner →
    entry.stack = output.stack ∧ (deviceAt devices output.owner).egressPolicies = []

instance (devices : List DeviceData) (ifaces : List IfaceData) :
    Decidable (TableDrivenOutputChecks devices ifaces) := by unfold TableDrivenOutputChecks; infer_instance

theorem table_driven_output_checks_sound (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) (links switches : List (Nat × Nat))
    (checked : TableDrivenOutputChecks devices ifaces)
    (iface : Nat) (frame : Frame)
    (origin : (dataPlaneModelFromRecords devices ifaces routes links switches).canOriginateTraffic frame.enteredIface)
    (owner : (dataPlaneModelFromRecords devices ifaces routes links switches).owner iface =
      (dataPlaneModelFromRecords devices ifaces routes links switches).owner frame.enteredIface) :
    (lookupSpdPolicies ((dataPlaneModelFromRecords devices ifaces routes links switches).egressPolicies iface)
      frame.packet = [] →
      encapStackAfterIngress (expectedEncapStackFromRecords ifaces) frame.enteredIface [] = expectedEncapStackFromRecords ifaces iface) ∧
    (∀ association ∈ lookupSpdPolicies
      ((dataPlaneModelFromRecords devices ifaces routes links switches).egressPolicies iface) frame.packet,
      association.tag :: encapStackAfterIngress (expectedEncapStackFromRecords ifaces) frame.enteredIface [] =
        expectedEncapStackFromRecords ifaces iface) := by
  obtain ⟨same, empty⟩ := checked (ifaceAt ifaces frame.enteredIface)
    (iface_at_member_or_default ifaces frame.enteredIface) (ifaceAt ifaces iface)
    (iface_at_member_or_default ifaces iface) origin owner
  constructor
  · intro _
    exact same
  · intro association selected
    have configured := (matched_policy_is_configured selected).1
    change association ∈ (deviceAt devices (ifaceAt ifaces iface).owner).egressPolicies at configured
    simp [empty] at configured

def TableDrivenOuterRoutes (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) : Prop :=
  ∀ route ∈ routes, ∀ association ∈ (deviceAt devices (ifaceAt ifaces route.ingress).owner).egressPolicies,
    (ifaceAt ifaces route.ingress).stack.head? = some association.tag →
    route.destPrefixLow ≤ association.receiver → association.receiver ≤ route.destPrefixHigh →
      (ifaceAt ifaces route.ingress).stack = (ifaceAt ifaces route.egress).stack

instance (devices : List DeviceData) (ifaces : List IfaceData) (routes : List FibRoute) :
    Decidable (TableDrivenOuterRoutes devices ifaces routes) := by unfold TableDrivenOuterRoutes; infer_instance

theorem table_driven_outer_routes_sound (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) (links switches : List (Nat × Nat))
    (checked : TableDrivenOuterRoutes devices ifaces routes)
    (iface : Nat) (association : IpsecPolicy)
    (member : association ∈ (dataPlaneModelFromRecords devices ifaces routes links switches).egressPolicies iface)
    (head : (expectedEncapStackFromRecords ifaces iface).head? = some association.tag)
    (sa : InstalledSA) (frame : Frame) (route : FibRoute)
    (chosen : SelectedFibRoute routes route (encrypt association sa frame).packet)
    (atIface : route.ingress = iface) :
    expectedEncapStackFromRecords ifaces iface = expectedEncapStackFromRecords ifaces route.egress := by
  have matching : route.destPrefixLow ≤ association.receiver ∧ association.receiver ≤ route.destPrefixHigh := chosen.2.1
  have localCheck := checked route chosen.1
  rw [atIface] at localCheck
  exact localCheck association member head matching.1 matching.2

lemma device_at_member_or_default (devices : List DeviceData) (n : Nat) :
    deviceAt devices n ∈ ({} : DeviceData) :: devices := by
  unfold deviceAt
  cases h : devices[n]? with
  | none => simp
  | some d =>
    simp only [Option.getD_some, List.mem_cons]
    exact Or.inr (List.mem_of_getElem? h)

theorem local_stack_conditions_of_finite_checks
    (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List FibRoute) (links switches : List (Nat × Nat))
    (routeOwner : ∀ r ∈ routes, (ifaceAt ifaces r.egress).owner = (ifaceAt ifaces r.ingress).owner)
    (linkStack : ∀ edge ∈ links, (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack)
    (switchStack : ∀ edge ∈ switches,
      (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack ∧
      (deviceAt devices (ifaceAt ifaces edge.1).owner).ingressPolicies = [])
    (forwardDefaults : ∀ device ∈ ({} : DeviceData) :: devices, device.forwardFallback = .deny)
    (forward : TableDrivenForwardChecks devices ifaces)
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
  · intro iface frame authenticated routed
    exact table_driven_forward_checks_sound devices ifaces routes links switches forward defaults iface frame authenticated
  · intro iface frame routed origin ingress owner accepted
    exact table_driven_output_checks_sound devices ifaces routes links switches output iface frame origin owner
  · exact table_driven_outer_routes_sound devices ifaces routes links switches outerRoutes

end TDN.DataPlaneForwarding
