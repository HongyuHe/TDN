import TDN.MSC.LocalPolicy
import TDN.MSC.Operational
import TDN.Network.LocalControl

/-!
Outer Firewalls use OSPF on declared Black adjacencies. The selected local
policy permits the adjacent peer and AllSPFRouters, with exact source and
interface bindings. Gray Firewalls have no selected local data-plane service.
Both INPUT and OUTPUT are compared with independently constructed grants.
Loopback remains explicit, and optional management is projected out upstream.

These claims complement the existing FORWARD contracts. A local OSPF event
does not bypass a gateway's IPsec requirement: the routers running OSPF and the
encryption gateways are distinct declared devices. Service placement and
forwarded Gray-control requirements are separate obligations.
-/
namespace TDN.MSC.FirewallControl
open Deployment
open TDN.Network.LocalControl (Grant)

structure Adjacency where
  owner : String
  interface : String
  localAddress : UInt32
  peer : String
  peerInterface : String
  peerAddress : UInt32
  deriving DecidableEq, BEq, Repr

def adjacency? (owner port peer peerPort : String) : Option Adjacency := do
  let device ← device? owner
  let neighbor ← device? peer
  if device.role != .firewall || (neighbor.role != .transport && neighbor.role != .firewall) then none else
  let interface ← device.interfaces.find? (fun i => i.name == port)
  let peerInterface ← neighbor.interfaces.find? (fun i => i.name == peerPort)
  if interface.zone != .black || peerInterface.zone != .black then none else
  let own ← Prefix.parse? interface.address
  let remote ← Prefix.parse? peerInterface.address
  pure ⟨owner, port, own.address, peer, peerPort, remote.address⟩

def adjacencies : List Adjacency := links.flatMap fun link =>
  (adjacency? link.a link.aPort link.b link.bPort).toList ++
  (adjacency? link.b link.bPort link.a link.aPort).toList

def allSPFRouters : UInt32 := 3758096389

def Adjacency.grants (adjacency : Adjacency) (direction : LocalDirection) : List Grant :=
  let source := match direction with
    | .input => adjacency.peerAddress
    | .output => adjacency.localAddress
  let target := match direction with
    | .input => adjacency.localAddress
    | .output => adjacency.peerAddress
  [⟨adjacency.interface, source, target, 89, []⟩,
   ⟨adjacency.interface, source, allSPFRouters, 89, []⟩]

def grants (owner : String) (direction : LocalDirection) : List Grant :=
  (adjacencies.filter (fun adjacency => adjacency.owner == owner)).flatMap (fun a => a.grants direction)

def packetView (direction : LocalDirection) (packet : RoutedPacket) : TDN.Network.LocalControl.Packet :=
  ⟨LocalContract.interface direction packet, packet.source, packet.destination,
    packet.protocol, packet.destinationPort⟩

def grantRule (direction : LocalDirection) (grant : Grant) : ForwardRule :=
  { input := if direction = .input then some grant.interface else none,
    output := if direction = .output then some grant.interface else none,
    source := some ⟨grant.source, 32⟩, destination := some ⟨grant.destination, 32⟩,
    protocol := some grant.protocol, destinationPorts := grant.destinationPorts }

def loopbackRule (direction : LocalDirection) : ForwardRule :=
  match direction with
  | .input => { input := some "lo" }
  | .output => { output := some "lo" }

def expectedTable (owner : String) (direction : LocalDirection) : ForwardTable :=
  { device := owner, defaultAccept := false,
    rules := loopbackRule direction :: (grants owner direction).map (grantRule direction) }

theorem firewall_local_tables_match : ∀ device ∈ devices,
    (device.role = .firewall ∨ device.role = .grayFirewall) →
    ∀ direction ∈ [LocalDirection.input, .output],
      ∃ table ∈ localTables direction,
        localTable? direction device.id = some table ∧ sameRules table (expectedTable device.id direction) := by decide

/-- Local OSPF sources and destinations are derived from the addressed ends of
declared Black links. Operational correspondence separately checks the actual
addresses and reciprocal veth peers in the same pinned snapshot. -/
theorem control_adjacencies_are_observed : ∀ adjacency ∈ adjacencies,
    ∃ localPort ∈ liveInterfaces adjacency.owner,
    ∃ peerPort ∈ liveInterfaces adjacency.peer,
      localPort.name = adjacency.interface ∧ peerPort.name = adjacency.peerInterface ∧
      localPort.peerIndex = some peerPort.index ∧ peerPort.peerIndex = some localPort.index ∧
      (localPort.addresses.map Prefix.address).contains adjacency.localAddress = true ∧
      (peerPort.addresses.map Prefix.address).contains adjacency.peerAddress = true := by decide

theorem firewall_has_control_adjacency : ∀ device ∈ devices, device.role = .firewall →
    ∃ adjacency ∈ adjacencies, adjacency.owner = device.id := by decide

theorem gray_firewalls_have_no_local_grants : ∀ device ∈ devices, device.role = .grayFirewall →
    ∀ direction ∈ [LocalDirection.input, .output], grants device.id direction = [] := by decide

theorem grant_rule_semantics (direction : LocalDirection) (grant : Grant) (packet : RoutedPacket) :
    (grantRule direction grant).matches packet = grant.matches (packetView direction packet) := by
  cases direction <;>
    simp [grantRule, ForwardRule.matches, optionalMatch, policyMatch, packetView,
      LocalContract.interface, TDN.Network.Prefix.host_contains, TDN.Network.LocalControl.Grant.matches]

theorem expected_table_semantics (owner : String) (direction : LocalDirection) (packet : RoutedPacket) :
    (expectedTable owner direction).accepts packet =
      TDN.Network.LocalControl.accepts "lo" (grants owner direction) (packetView direction packet) := by
  simp only [expectedTable, ForwardTable.accepts, List.any_cons, List.any_map,
    Bool.or_false, Function.comp_def]
  simp only [grant_rule_semantics]
  cases direction <;>
    simp [loopbackRule, TDN.Network.LocalControl.accepts, packetView,
      ForwardRule.matches, optionalMatch, policyMatch, LocalContract.interface]

theorem firewall_local_decision (device : Device) (member : device ∈ devices)
    (firewall : device.role = .firewall ∨ device.role = .grayFirewall)
    (direction : LocalDirection) (packet : RoutedPacket) :
    localDecision direction device.id packet = some
      (TDN.Network.LocalControl.accepts "lo" (grants device.id direction) (packetView direction packet)) := by
  have included : direction ∈ [LocalDirection.input, .output] := by cases direction <;> simp
  obtain ⟨table, _, lookup, same⟩ := firewall_local_tables_match device member firewall direction included
  simp only [localDecision, lookup, Option.map_some]
  rw [permuted_table_semantics table (expectedTable device.id direction) same packet, expected_table_semantics]

/-- Every packet matching a declared local grant is accepted. The result uses
the same observed-table equality as the negative restrictions, so missing
required controls are detected together with unintended extra allowances. -/
theorem declared_firewall_grant_allowed (device : Device) (member : device ∈ devices)
    (firewall : device.role = .firewall ∨ device.role = .grayFirewall)
    (direction : LocalDirection) (packet : RoutedPacket) (grant : Grant)
    (included : grant ∈ grants device.id direction)
    (matched : grant.matches (packetView direction packet) = true) :
    localDecision direction device.id packet = some true := by
  rw [firewall_local_decision device member firewall direction packet]
  rw [TDN.Network.LocalControl.declared_grant_is_allowed "lo" (grants device.id direction)
    (packetView direction packet) grant included matched]

def grantPacket (direction : LocalDirection) (grant : Grant) : RoutedPacket :=
  { input := if direction = .input then grant.interface else "",
    output := if direction = .output then grant.interface else "",
    source := grant.source, destination := grant.destination, protocol := grant.protocol,
    destinationPort := grant.destinationPorts.headD 0 }

/-- Each declared Black adjacency has positive unicast and multicast witnesses
in both local directions. The separate nonempty-adjacency theorem ensures that
the intended OSPF allowance is exercised on every Outer Firewall. -/
theorem every_adjacency_permits_declared_controls : ∀ adjacency ∈ adjacencies,
    ∀ direction ∈ [LocalDirection.input, .output], ∀ grant ∈ adjacency.grants direction,
      localDecision direction adjacency.owner (grantPacket direction grant) = some true := by decide

theorem accepted_external_firewall_event_has_grant (device : Device) (member : device ∈ devices)
    (firewall : device.role = .firewall ∨ device.role = .grayFirewall)
    (direction : LocalDirection) (packet : RoutedPacket)
    (external : LocalContract.interface direction packet ≠ "lo")
    (accepted : localDecision direction device.id packet = some true) :
    ∃ grant ∈ grants device.id direction, grant.matches (packetView direction packet) = true := by
  rw [firewall_local_decision device member firewall direction packet] at accepted
  exact TDN.Network.LocalControl.external_acceptance_has_grant "lo" (grants device.id direction)
    (packetView direction packet) external (Option.some.inj accepted)

theorem all_control_grants_are_ospf : ∀ device ∈ devices,
    ∀ direction ∈ [LocalDirection.input, .output],
      ∀ grant ∈ grants device.id direction, grant.protocol = 89 := by decide

theorem accepted_external_local_firewall_packet_is_ospf (device : Device) (member : device ∈ devices)
    (firewall : device.role = .firewall ∨ device.role = .grayFirewall)
    (direction : LocalDirection) (packet : RoutedPacket)
    (external : LocalContract.interface direction packet ≠ "lo")
    (accepted : localDecision direction device.id packet = some true) : packet.protocol = 89 := by
  obtain ⟨grant, included, matched⟩ := accepted_external_firewall_event_has_grant device member firewall direction packet external accepted
  have fields := TDN.Network.LocalControl.matched_grant_fixes_fields grant (packetView direction packet) matched
  have directionMember : direction ∈ [LocalDirection.input, .output] := by cases direction <;> simp
  exact fields.2.2.2.1.trans (all_control_grants_are_ospf device member direction directionMember grant included)

theorem gray_firewall_rejects_external_local_traffic (device : Device) (member : device ∈ devices)
    (gray : device.role = .grayFirewall) (direction : LocalDirection) (packet : RoutedPacket)
    (external : LocalContract.interface direction packet ≠ "lo") :
    localDecision direction device.id packet = some false := by
  rw [firewall_local_decision device member (Or.inr gray) direction packet]
  have directionMember : direction ∈ [LocalDirection.input, .output] := by cases direction <;> simp
  rw [gray_firewalls_have_no_local_grants device member gray direction directionMember]
  rw [TDN.Network.LocalControl.empty_grant_set_rejects_external "lo" (packetView direction packet) external]

inductive Chain where
  | input | output | forward
  deriving DecidableEq, BEq, Repr

def chainDecision (chain : Chain) (owner : String) (packet : RoutedPacket) : Option Bool :=
  match chain with
  | .input => localDecision .input owner packet
  | .output => localDecision .output owner packet
  | .forward => forwardDecision owner packet

def externalEvent (chain : Chain) (packet : RoutedPacket) : Prop :=
  match chain with
  | .input => packet.input ≠ "lo"
  | .output => packet.output ≠ "lo"
  | .forward => True

/-- PF-22 combines the three retained IPv4 filter chains. Local external
acceptance requires OSPF, and forwarded acceptance requires ESP or IKE/NAT-T.
The stronger local theorem above also fixes the interface and endpoint pair.
Organization approval of the chosen control set remains an external premise. -/
theorem outer_firewall_every_chain_restricts_protocols (device : Device)
    (member : device ∈ devices) (firewall : device.role = .firewall)
    (chain : Chain) (packet : RoutedPacket) (external : externalEvent chain packet)
    (accepted : chainDecision chain device.id packet = some true) :
    match chain with
    | .input | .output => packet.protocol = 89
    | .forward => ipsecClass packet = true := by
  cases chain with
  | input =>
    exact accepted_external_local_firewall_packet_is_ospf device member (Or.inl firewall)
      .input packet external accepted
  | output =>
    exact accepted_external_local_firewall_packet_is_ospf device member (Or.inl firewall)
      .output packet external accepted
  | forward =>
    obtain ⟨contract, included, owner⟩ := outer_firewall_contracts_cover device member firewall
    have acceptedContract : forwardDecision contract.device packet = some true := by
      simpa [chainDecision, owner] using accepted
    exact accepted_outer_protocol contract (List.mem_append_right _ included)
      (outer_firewall_contracts_restrict_protocols contract included) packet acceptedContract

end TDN.MSC.FirewallControl
