import TDN.Semantics.ExecutionChecks

namespace TDN.Execution

structure DeviceData where
  forwardRules : List PacketPolicy.Rule := []
  inputRules : List PacketPolicy.Rule := []
  outputRules : List PacketPolicy.Rule := []
  forwardFallback : Filter.Verdict := .deny
  inputFallback : Filter.Verdict := .deny
  outputFallback : Filter.Verdict := .deny
  outbound : List Association := []
  inbound : List Association := []
  states : List SecurityAssociation := []
  localAddresses : List Nat := []
  recipientDomain : Option Nat := none

structure IfaceData where
  owner : Nat := 0
  name : String := ""
  stack : List Nat := []
  payloadOrigin : Bool := false
  deriving DecidableEq, Repr

def deviceAt (devices : List DeviceData) (index : Nat) : DeviceData :=
  devices[index]?.getD {}

def ifaceAt (ifaces : List IfaceData) (index : Nat) : IfaceData :=
  ifaces[index]?.getD {}

def dataPlaneConfigFromRecords (devices : List DeviceData) (ifaces : List IfaceData) (routes : List Route)
    (links switches : List (Nat × Nat)) : Environment where
  routes := routes
  forwardRules p := (deviceAt devices (ifaceAt ifaces p).owner).forwardRules
  inputRules p := (deviceAt devices (ifaceAt ifaces p).owner).inputRules
  outputRules p := (deviceAt devices (ifaceAt ifaces p).owner).outputRules
  forwardFallback p := (deviceAt devices (ifaceAt ifaces p).owner).forwardFallback
  inputFallback p := (deviceAt devices (ifaceAt ifaces p).owner).inputFallback
  outputFallback p := (deviceAt devices (ifaceAt ifaces p).owner).outputFallback
  outbound p := (deviceAt devices (ifaceAt ifaces p).owner).outbound
  inbound p := (deviceAt devices (ifaceAt ifaces p).owner).inbound
  outboundStates p := (deviceAt devices (ifaceAt ifaces p).owner).states
  inboundStates p := (deviceAt devices (ifaceAt ifaces p).owner).states
  interfaceName p := (ifaceAt ifaces p).name
  owner p := (ifaceAt ifaces p).owner
  link a b := (a, b) ∈ links
  bridging a b _ := (a, b) ∈ switches
  localAddress p address := address ∈ (deviceAt devices (ifaceAt ifaces p).owner).localAddresses
  recipientDomain p := (deviceAt devices (ifaceAt ifaces p).owner).recipientDomain
  payloadOrigin p := (ifaceAt ifaces p).payloadOrigin = true

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
  [] :: (device.inbound.filter fun a => iface.stack.head? == some a.tag).map (fun a => [a.id])

lemma valid_authentication_in_finite_list (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List Route) (links switches : List (Nat × Nat)) (entry : Nat)
    (authenticated : List Nat)
    (valid : LocalAuthentication (dataPlaneConfigFromRecords devices ifaces routes links switches)
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
    ∀ association ∈ device.outbound, ExcludesSelector rule association ∨
      association.tag :: (if authenticated = [] then entry.stack else entry.stack.tail) = output.stack)

instance (i o : IfaceData) (d : DeviceData) (a : List Nat) (r : PacketPolicy.Rule) :
    Decidable (RecordRuleCheck i o d a r) := by unfold RecordRuleCheck; infer_instance

def FiniteForwardChecks (devices : List DeviceData) (ifaces : List IfaceData) : Prop :=
  ∀ entry ∈ ({} : IfaceData) :: ifaces, ∀ output ∈ ({} : IfaceData) :: ifaces,
    output.owner = entry.owner →
    ∀ auth ∈ possibleAuthentications (deviceAt devices entry.owner) entry,
    ∀ rule ∈ (deviceAt devices output.owner).forwardRules, rule.verdict = .allow →
      RecordRuleCheck entry output (deviceAt devices output.owner) auth rule

instance (devices : List DeviceData) (ifaces : List IfaceData) :
    Decidable (FiniteForwardChecks devices ifaces) := by unfold FiniteForwardChecks; infer_instance

theorem finite_forward_checks_sound (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List Route) (links switches : List (Nat × Nat))
    (checked : FiniteForwardChecks devices ifaces)
    (denying : ∀ p, (dataPlaneConfigFromRecords devices ifaces routes links switches).forwardFallback p = .deny)
    (iface : Nat) (frame : Frame) (authenticated : List Nat)
    (ingress : frame.packet.ingress =
      (dataPlaneConfigFromRecords devices ifaces routes links switches).interfaceName frame.enteredIface)
    (valid : LocalAuthentication (dataPlaneConfigFromRecords devices ifaces routes links switches)
      (expectedEncapStackFromRecords ifaces) frame.enteredIface authenticated)
    (owner : (dataPlaneConfigFromRecords devices ifaces routes links switches).owner iface =
      (dataPlaneConfigFromRecords devices ifaces routes links switches).owner frame.enteredIface)
    (accepted : accepts
      ((dataPlaneConfigFromRecords devices ifaces routes links switches).forwardRules iface)
      ((dataPlaneConfigFromRecords devices ifaces routes links switches).forwardFallback iface)
      (policyPacket (dataPlaneConfigFromRecords devices ifaces routes links switches) iface frame authenticated)) :
    (selectedAssociations ((dataPlaneConfigFromRecords devices ifaces routes links switches).outbound iface)
      frame.packet = [] →
      encapStackAfterIngress (expectedEncapStackFromRecords ifaces) frame.enteredIface authenticated = expectedEncapStackFromRecords ifaces iface) ∧
    (∀ association ∈ selectedAssociations
      ((dataPlaneConfigFromRecords devices ifaces routes links switches).outbound iface) frame.packet,
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

def FiniteOutputChecks (devices : List DeviceData) (ifaces : List IfaceData) : Prop :=
  ∀ entry ∈ ({} : IfaceData) :: ifaces, ∀ output ∈ ({} : IfaceData) :: ifaces,
    entry.payloadOrigin = true → output.owner = entry.owner →
    entry.stack = output.stack ∧ (deviceAt devices output.owner).outbound = []

instance (devices : List DeviceData) (ifaces : List IfaceData) :
    Decidable (FiniteOutputChecks devices ifaces) := by unfold FiniteOutputChecks; infer_instance

theorem finite_output_checks_sound (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List Route) (links switches : List (Nat × Nat))
    (checked : FiniteOutputChecks devices ifaces)
    (iface : Nat) (frame : Frame)
    (origin : (dataPlaneConfigFromRecords devices ifaces routes links switches).payloadOrigin frame.enteredIface)
    (owner : (dataPlaneConfigFromRecords devices ifaces routes links switches).owner iface =
      (dataPlaneConfigFromRecords devices ifaces routes links switches).owner frame.enteredIface) :
    (selectedAssociations ((dataPlaneConfigFromRecords devices ifaces routes links switches).outbound iface)
      frame.packet = [] →
      encapStackAfterIngress (expectedEncapStackFromRecords ifaces) frame.enteredIface [] = expectedEncapStackFromRecords ifaces iface) ∧
    (∀ association ∈ selectedAssociations
      ((dataPlaneConfigFromRecords devices ifaces routes links switches).outbound iface) frame.packet,
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
    change association ∈ (deviceAt devices (ifaceAt ifaces iface).owner).outbound at configured
    simp [empty] at configured

def FiniteOuterRoutes (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List Route) : Prop :=
  ∀ route ∈ routes, ∀ association ∈ (deviceAt devices (ifaceAt ifaces route.ingress).owner).outbound,
    (ifaceAt ifaces route.ingress).stack.head? = some association.tag →
    route.low ≤ association.receiver → association.receiver ≤ route.high →
      (ifaceAt ifaces route.ingress).stack = (ifaceAt ifaces route.egress).stack

instance (devices : List DeviceData) (ifaces : List IfaceData) (routes : List Route) :
    Decidable (FiniteOuterRoutes devices ifaces routes) := by unfold FiniteOuterRoutes; infer_instance

theorem finite_outer_routes_sound (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List Route) (links switches : List (Nat × Nat))
    (checked : FiniteOuterRoutes devices ifaces routes)
    (iface : Nat) (association : Association)
    (member : association ∈ (dataPlaneConfigFromRecords devices ifaces routes links switches).outbound iface)
    (head : (expectedEncapStackFromRecords ifaces iface).head? = some association.tag)
    (sa : SecurityAssociation) (frame : Frame) (route : Route)
    (chosen : SelectedRoute routes route (encrypt association sa frame).packet)
    (atIface : route.ingress = iface) :
    expectedEncapStackFromRecords ifaces iface = expectedEncapStackFromRecords ifaces route.egress := by
  have matching : route.low ≤ association.receiver ∧ association.receiver ≤ route.high := chosen.2.1
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
    (routes : List Route) (links switches : List (Nat × Nat))
    (routeOwner : ∀ r ∈ routes, (ifaceAt ifaces r.egress).owner = (ifaceAt ifaces r.ingress).owner)
    (linkStack : ∀ edge ∈ links, (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack)
    (switchStack : ∀ edge ∈ switches,
      (ifaceAt ifaces edge.1).stack = (ifaceAt ifaces edge.2).stack ∧
      (deviceAt devices (ifaceAt ifaces edge.1).owner).inbound = [])
    (forwardDefaults : ∀ device ∈ ({} : DeviceData) :: devices, device.forwardFallback = .deny)
    (forward : FiniteForwardChecks devices ifaces)
    (output : FiniteOutputChecks devices ifaces)
    (outerRoutes : FiniteOuterRoutes devices ifaces routes) :
    LocalStackConditions (dataPlaneConfigFromRecords devices ifaces routes links switches) (expectedEncapStackFromRecords ifaces) := by
  have defaults : ∀ p,
      (dataPlaneConfigFromRecords devices ifaces routes links switches).forwardFallback p = .deny :=
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
      · change association ∈ (deviceAt devices (ifaceAt ifaces a).owner).inbound at member
        simp [empty] at member
    simpa [encapStackAfterIngress, noAuth, expectedEncapStackFromRecords] using same
  · intro iface frame authenticated routed
    exact finite_forward_checks_sound devices ifaces routes links switches forward defaults iface frame authenticated
  · intro iface frame routed origin ingress owner accepted
    exact finite_output_checks_sound devices ifaces routes links switches output iface frame origin owner
  · exact finite_outer_routes_sound devices ifaces routes links switches outerRoutes

end TDN.Execution
