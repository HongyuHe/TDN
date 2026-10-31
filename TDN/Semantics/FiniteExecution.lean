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

structure PortData where
  owner : Nat := 0
  name : String := ""
  stack : List Nat := []
  payloadOrigin : Bool := false
  deriving DecidableEq, Repr

def deviceAt (devices : List DeviceData) (index : Nat) : DeviceData :=
  devices[index]?.getD {}

def portAt (ports : List PortData) (index : Nat) : PortData :=
  ports[index]?.getD {}

def finiteConfig (devices : List DeviceData) (ports : List PortData) (routes : List Route)
    (links switches : List (Nat × Nat)) : Config where
  routes := routes
  forwardRules p := (deviceAt devices (portAt ports p).owner).forwardRules
  inputRules p := (deviceAt devices (portAt ports p).owner).inputRules
  outputRules p := (deviceAt devices (portAt ports p).owner).outputRules
  forwardFallback p := (deviceAt devices (portAt ports p).owner).forwardFallback
  inputFallback p := (deviceAt devices (portAt ports p).owner).inputFallback
  outputFallback p := (deviceAt devices (portAt ports p).owner).outputFallback
  outbound p := (deviceAt devices (portAt ports p).owner).outbound
  inbound p := (deviceAt devices (portAt ports p).owner).inbound
  outboundStates p := (deviceAt devices (portAt ports p).owner).states
  inboundStates p := (deviceAt devices (portAt ports p).owner).states
  interfaceName p := (portAt ports p).name
  owner p := (portAt ports p).owner
  link a b := (a, b) ∈ links
  switching a b _ := (a, b) ∈ switches
  localAddress p address := address ∈ (deviceAt devices (portAt ports p).owner).localAddresses
  recipientDomain p := (deviceAt devices (portAt ports p).owner).recipientDomain
  payloadOrigin p := (portAt ports p).payloadOrigin = true

def finiteLayout (ports : List PortData) (p : Nat) : List Nat :=
  (portAt ports p).stack

lemma port_at_member_or_default (ports : List PortData) (n : Nat) :
    portAt ports n ∈ ({} : PortData) :: ports := by
  unfold portAt
  cases h : ports[n]? with
  | none => simp
  | some p =>
    simp only [Option.getD_some, List.mem_cons]
    exact Or.inr (List.mem_of_getElem? h)

def possibleAuthentications (device : DeviceData) (port : PortData) : List (List Nat) :=
  [] :: (device.inbound.filter fun a => port.stack.head? == some a.tag).map (fun a => [a.id])

lemma valid_authentication_in_finite_list (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (links switches : List (Nat × Nat)) (entry : Nat)
    (authenticated : List Nat)
    (valid : LocalAuthentication (finiteConfig devices ports routes links switches)
      (finiteLayout ports) entry authenticated) :
    authenticated ∈ possibleAuthentications (deviceAt devices (portAt ports entry).owner)
      (portAt ports entry) := by
  rcases valid with empty | ⟨association, member, same, rest, shape⟩
  · simp [possibleAuthentications, empty]
  · apply List.mem_cons_of_mem
    apply List.mem_map.mpr
    refine ⟨association, List.mem_filter.mpr ⟨member, ?_⟩, same.symm⟩
    change (portAt ports entry).stack = association.tag :: rest at shape
    simp [shape]

def RecordRuleCheck (entry output : PortData) (device : DeviceData)
    (authenticated : List Nat) (rule : PacketPolicy.Rule) : Prop :=
  ¬ PortCompatible rule entry.name output.name ∨
  ImpossibleAuthentication rule authenticated ∨
  ((HasOutboundGuard rule ∨
      (if authenticated = [] then entry.stack else entry.stack.tail) = output.stack) ∧
    ∀ association ∈ device.outbound, ExcludesSelector rule association ∨
      association.tag :: (if authenticated = [] then entry.stack else entry.stack.tail) = output.stack)

instance (i o : PortData) (d : DeviceData) (a : List Nat) (r : PacketPolicy.Rule) :
    Decidable (RecordRuleCheck i o d a r) := by unfold RecordRuleCheck; infer_instance

def FiniteForwardChecks (devices : List DeviceData) (ports : List PortData) : Prop :=
  ∀ entry ∈ ({} : PortData) :: ports, ∀ output ∈ ({} : PortData) :: ports,
    output.owner = entry.owner →
    ∀ auth ∈ possibleAuthentications (deviceAt devices entry.owner) entry,
    ∀ rule ∈ (deviceAt devices output.owner).forwardRules, rule.verdict = .allow →
      RecordRuleCheck entry output (deviceAt devices output.owner) auth rule

instance (devices : List DeviceData) (ports : List PortData) :
    Decidable (FiniteForwardChecks devices ports) := by unfold FiniteForwardChecks; infer_instance

theorem finite_forward_checks_sound (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (links switches : List (Nat × Nat))
    (checked : FiniteForwardChecks devices ports)
    (denying : ∀ p, (finiteConfig devices ports routes links switches).forwardFallback p = .deny)
    (port : Nat) (frame : Frame) (authenticated : List Nat)
    (ingress : frame.packet.ingress =
      (finiteConfig devices ports routes links switches).interfaceName frame.enteredPort)
    (valid : LocalAuthentication (finiteConfig devices ports routes links switches)
      (finiteLayout ports) frame.enteredPort authenticated)
    (owner : (finiteConfig devices ports routes links switches).owner port =
      (finiteConfig devices ports routes links switches).owner frame.enteredPort)
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
  rw [denying] at accepted
  apply checked_hook_stack_effect _ _ _ _ _ _ ingress _ accepted
  intro rule member allow
  exact checked (portAt ports frame.enteredPort)
    (port_at_member_or_default ports frame.enteredPort) (portAt ports port)
    (port_at_member_or_default ports port) owner authenticated
    (valid_authentication_in_finite_list devices ports routes links switches
      frame.enteredPort authenticated valid) rule member allow

def FiniteOutputChecks (devices : List DeviceData) (ports : List PortData) : Prop :=
  ∀ entry ∈ ({} : PortData) :: ports, ∀ output ∈ ({} : PortData) :: ports,
    entry.payloadOrigin = true → output.owner = entry.owner →
    entry.stack = output.stack ∧ (deviceAt devices output.owner).outbound = []

instance (devices : List DeviceData) (ports : List PortData) :
    Decidable (FiniteOutputChecks devices ports) := by unfold FiniteOutputChecks; infer_instance

theorem finite_output_checks_sound (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (links switches : List (Nat × Nat))
    (checked : FiniteOutputChecks devices ports)
    (port : Nat) (frame : Frame)
    (origin : (finiteConfig devices ports routes links switches).payloadOrigin frame.enteredPort)
    (owner : (finiteConfig devices ports routes links switches).owner port =
      (finiteConfig devices ports routes links switches).owner frame.enteredPort) :
    (selectedAssociations ((finiteConfig devices ports routes links switches).outbound port)
      frame.packet = [] →
      processingStack (finiteLayout ports) frame.enteredPort [] = finiteLayout ports port) ∧
    (∀ association ∈ selectedAssociations
      ((finiteConfig devices ports routes links switches).outbound port) frame.packet,
      association.tag :: processingStack (finiteLayout ports) frame.enteredPort [] =
        finiteLayout ports port) := by
  obtain ⟨same, empty⟩ := checked (portAt ports frame.enteredPort)
    (port_at_member_or_default ports frame.enteredPort) (portAt ports port)
    (port_at_member_or_default ports port) origin owner
  constructor
  · intro _
    exact same
  · intro association selected
    have configured := (matched_policy_is_configured selected).1
    change association ∈ (deviceAt devices (portAt ports port).owner).outbound at configured
    simp [empty] at configured

def FiniteOuterRoutes (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) : Prop :=
  ∀ route ∈ routes, ∀ association ∈ (deviceAt devices (portAt ports route.ingress).owner).outbound,
    (portAt ports route.ingress).stack.head? = some association.tag →
    route.low ≤ association.receiver → association.receiver ≤ route.high →
      (portAt ports route.ingress).stack = (portAt ports route.egress).stack

instance (devices : List DeviceData) (ports : List PortData) (routes : List Route) :
    Decidable (FiniteOuterRoutes devices ports routes) := by unfold FiniteOuterRoutes; infer_instance

theorem finite_outer_routes_sound (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (links switches : List (Nat × Nat))
    (checked : FiniteOuterRoutes devices ports routes)
    (port : Nat) (association : Association)
    (member : association ∈ (finiteConfig devices ports routes links switches).outbound port)
    (head : (finiteLayout ports port).head? = some association.tag)
    (sa : SecurityAssociation) (frame : Frame) (route : Route)
    (chosen : SelectedRoute routes route (encrypt association sa frame).packet)
    (atPort : route.ingress = port) :
    finiteLayout ports port = finiteLayout ports route.egress := by
  have matching : route.low ≤ association.receiver ∧ association.receiver ≤ route.high := chosen.2.1
  have localCheck := checked route chosen.1
  rw [atPort] at localCheck
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
    (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (links switches : List (Nat × Nat))
    (routeOwner : ∀ r ∈ routes, (portAt ports r.egress).owner = (portAt ports r.ingress).owner)
    (linkStack : ∀ edge ∈ links, (portAt ports edge.1).stack = (portAt ports edge.2).stack)
    (switchStack : ∀ edge ∈ switches,
      (portAt ports edge.1).stack = (portAt ports edge.2).stack ∧
      (deviceAt devices (portAt ports edge.1).owner).inbound = [])
    (forwardDefaults : ∀ device ∈ ({} : DeviceData) :: devices, device.forwardFallback = .deny)
    (forward : FiniteForwardChecks devices ports)
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
  · intro port frame authenticated routed
    exact finite_forward_checks_sound devices ports routes links switches forward defaults port frame authenticated
  · intro port frame routed origin ingress owner accepted
    exact finite_output_checks_sound devices ports routes links switches output port frame origin owner
  · exact finite_outer_routes_sound devices ports routes links switches outerRoutes

end TDN.Execution
