import TDN.MSC.FirewallControl
import TDN.MSC.Execution

/-!
PF-18 and PF-29 constrain sources on the receiving interface. The selected
source policy uses a reverse FIB lookup with the receiving interface's sampled
local address. A successful lookup must choose unicast delivery through that
same interface. The source policy is derived from routing evidence independently
of the packet filter. Exact source guards then connect accepted packets to it.

The proof covers retained Gray interfaces on Outer and Gray Firewalls, with
both local INPUT and routed FORWARD events. The addresses identify permitted
source locations; authenticating the physical sender remains a separate claim.
-/
namespace TDN.MSC.SourceReachability
set_option synthInstance.maxSize 512
open Deployment
open TDN.Network (FibRoute RoutingRule WirePacket)
open TDN.Network.Execution
open TDN.MSC.Execution

def localAddresses (owner port : String) : List UInt32 :=
  ((liveInterfaces owner).filter (fun interface => interface.name == port)).flatMap
    (fun interface => interface.addresses.map Prefix.address)

def routingRules (owner : String) : List RoutingRule :=
  ((operational? owner).bind TDN.Network.OperationalSnapshot.routingRules).getD []

def knownSource (owner port : String) (source : UInt32) : Bool :=
  (localAddresses owner port).any fun address =>
    TDN.Network.Routing.sourceReachableVia (liveRoutes owner) (routingRules owner) address source port

def coveredRole (device : Device) : Prop :=
  device.role = .outer ∨ device.role = .grayFirewall

instance (device : Device) : Decidable (coveredRole device) :=
  inferInstanceAs (Decidable (device.role = .outer ∨ device.role = .grayFirewall))

inductive IngressChain where
  | input | forward
  deriving DecidableEq, BEq, Repr

def table? (chain : IngressChain) (owner : String) : Option ForwardTable :=
  match chain with
  | .input => localTable? .input owner
  | .forward => forwardingTable? owner

def decision (chain : IngressChain) (owner : String) (packet : RoutedPacket) : Option Bool :=
  (table? chain owner).map (fun table => table.accepts packet)

/-- Every required Gray interface has a sampled address and a connected
unicast route for its subnet. The address comparison retains the prefix length
and compares network indices to allow interface addresses with host bits. -/
theorem gray_interfaces_have_return_routes : ∀ device ∈ devices, coveredRole device →
    ∀ port ∈ device.interfaces, port.zone = .gray →
      (localAddresses device.id port.name).isEmpty = false ∧
      ∃ route ∈ liveRoutes device.id, ∃ declared ∈ (Prefix.parse? port.address).toList,
        route.kind = "unicast" ∧ route.output = port.name ∧ route.gateway = none ∧
        route.destination.length = declared.length ∧
        route.destination.networkIndex = declared.networkIndex := by decide

/-- For each Gray arrival port, every potentially matching ACCEPT rule has
an exact source address whose reverse route uses that port. Empty Gray
Firewall allowance lists satisfy the negative restriction through denial.
Their positive service obligations are assessed separately. -/
theorem gray_ingress_source_certificate : ∀ device ∈ devices, coveredRole device →
    ∀ port ∈ device.interfaces, port.zone = .gray →
    ∀ chain ∈ [IngressChain.input, .forward],
      ∃ table ∈ (table? chain device.id).toList,
        table? chain device.id = some table ∧ table.defaultAccept = false ∧
        ∀ rule ∈ table.rules, optionalMatch rule.input port.name = true →
          ∃ source ∈ (rule.source.map Prefix.address).toList,
            rule.source = some ⟨source, 32⟩ ∧ knownSource device.id port.name source = true := by decide

/-- Local delivery on a Gray interface is denied in the selected profile.
The finite port-signature check supports a later receive-path argument: an
Outer Gateway cannot first strip a layer on Gray and hide the arrival source. -/
theorem gray_local_input_impossible : ∀ device ∈ devices, coveredRole device →
    ∀ port ∈ device.interfaces, port.zone = .gray → inputPossible device.id port.name = false := by decide

theorem known_source_has_reverse_route (owner port : String) (source : UInt32)
    (known : knownSource owner port source = true) :
    ∃ address ∈ localAddresses owner port, ∃ route ∈ liveRoutes owner,
      TDN.Network.Routing.lookup (liveRoutes owner) (routingRules owner) address source = some route ∧
      route.kind = "unicast" ∧ route.output = port ∧ route.destination.contains source = true := by
  obtain ⟨address, member, reachable⟩ := List.any_eq_true.mp known
  obtain ⟨route, routeMember, selected, kind, output, contains, _⟩ :=
    TDN.Network.Routing.source_reachability_has_route (liveRoutes owner) (routingRules owner)
      address source port reachable
  exact ⟨address, member, route, routeMember, selected, kind, output, contains⟩

/-- The finite rule certificate is lifted to arbitrary packet fields. A
matched /32 source guard fixes the actual packet source, so the independently
computed reverse route applies to every accepted packet. -/
theorem accepted_gray_ingress_has_reachable_source (device : Device) (member : device ∈ devices)
    (role : coveredRole device) (port : Interface) (portMember : port ∈ device.interfaces)
    (gray : port.zone = .gray) (chain : IngressChain) (packet : RoutedPacket)
    (arrival : packet.input = port.name) (accepted : decision chain device.id packet = some true) :
    knownSource device.id port.name packet.source = true := by
  have chainMember : chain ∈ [IngressChain.input, .forward] := by cases chain <;> simp
  obtain ⟨table, _, lookup, deny, guarded⟩ :=
    gray_ingress_source_certificate device member role port portMember gray chain chainMember
  simp only [decision, lookup, Option.map_some, Option.some.injEq,
    ForwardTable.accepts, deny, Bool.or_false, List.any_eq_true] at accepted
  obtain ⟨rule, ruleMember, matched⟩ := accepted
  have inputMatch : optionalMatch rule.input port.name = true := by
    simp_all [ForwardRule.matches]
  obtain ⟨source, _, guardedSource, reachable⟩ := guarded rule ruleMember inputMatch
  have equalSource : packet.source = source := by
    have sourceMatch : (TDN.Network.Prefix.mk source 32).contains packet.source = true := by
      simp_all [ForwardRule.matches]
    rw [TDN.Network.Prefix.host_contains] at sourceMatch
    exact (beq_iff_eq.mp sourceMatch).symm
  simpa [equalSource] using reachable

/-- The table is present and defaults to denial, so an unreachable source
produces a definite rejection rather than an unavailable-policy result. -/
theorem unreachable_gray_source_rejected (device : Device) (member : device ∈ devices)
    (role : coveredRole device) (port : Interface) (portMember : port ∈ device.interfaces)
    (gray : port.zone = .gray) (chain : IngressChain) (packet : RoutedPacket)
    (arrival : packet.input = port.name) (unknown : knownSource device.id port.name packet.source = false) :
    decision chain device.id packet = some false := by
  have chainMember : chain ∈ [IngressChain.input, .forward] := by cases chain <;> simp
  obtain ⟨table, _, lookup, _⟩ :=
    gray_ingress_source_certificate device member role port portMember gray chain chainMember
  cases verdict : table.accepts packet with
  | false => simp [decision, lookup, verdict]
  | true =>
    have accepted : decision chain device.id packet = some true := by simp [decision, lookup, verdict]
    have known := accepted_gray_ingress_has_reachable_source device member role port portMember gray chain packet arrival accepted
    simp [unknown] at known

theorem gray_input_filter_denies (device : Device) (member : device ∈ devices)
    (role : coveredRole device) (port : Interface) (portMember : port ∈ device.interfaces)
    (gray : port.zone = .gray) (header : TDN.Network.IPv4Header) :
    model.inputFilter device.id port.name header = false := by
  cases accepted : model.inputFilter device.id port.name header with
  | false => rfl
  | true =>
    have possible := accepted_input_has_port_signature device.id port.name header accepted
    rw [gray_local_input_impossible device member role port portMember gray] at possible
    contradiction

variable {Message : Type}

/-- A successful forwarding step on Gray is checked against the source on
the arriving wire packet. Local INPUT denial prevents pre-filter decryption
on that port, which connects the rule theorem to the actual receive operation. -/
theorem admitted_gray_forward_has_reachable_wire_source (device : Device)
    (member : device ∈ devices) (role : coveredRole device)
    (port : Interface) (portMember : port ∈ device.interfaces) (gray : port.zone = .gray)
    (packet : WirePacket Message) (result : ForwardResult Message)
    (accepted : model.forward device.id port.name packet = some result) :
    knownSource device.id port.name packet.header.source = true := by
  have evidence := forward_evidence model device.id port.name packet result accepted
  have preserved := receive_without_local_input_preserves model device.id port.name
    (gray_input_filter_denies device member role port portMember gray) packet result.body result.inputTag evidence.1
  have filtered := evidence.2.2.1
  change (decision .forward device.id
    (packetView port.name result.route.output result.body.header result.inputTag result.outputTag)).getD false = true at filtered
  have acceptedFilter : decision .forward device.id
      (packetView port.name result.route.output result.body.header result.inputTag result.outputTag) = some true := by
    cases found : decision .forward device.id
      (packetView port.name result.route.output result.body.header result.inputTag result.outputTag) <;> simp_all
  have source := accepted_gray_ingress_has_reachable_source device member role port portMember gray .forward
    (packetView port.name result.route.output result.body.header result.inputTag result.outputTag) rfl acceptedFilter
  simpa [packetView, preserved.1] using source

end TDN.MSC.SourceReachability
