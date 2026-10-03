import TDN.MSC.Contracts

/-!
The same packet and ACCEPT-only rule semantics apply to local INPUT and OUTPUT.
The contract below is derived from a gateway's declared tunnel endpoints. A
finite equality check compares that contract with every retained observed rule.
General lemmas then characterize all local packets, including arbitrary source
addresses, destinations, protocols, ports, and IPv4 header lengths.

The required view projects out management interfaces. Loopback remains explicit.
An outgoing ESP header alone does not establish that a protected Red payload
was encrypted. Packet provenance is supplied separately by execution semantics.
-/
namespace TDN.MSC
open Deployment

inductive LocalDirection where
  | input | output
  deriving DecidableEq, BEq, Repr

def localTables : LocalDirection → List ForwardTable
  | .input => inputTables
  | .output => outputTables

def localTable? (direction : LocalDirection) (id : String) : Option ForwardTable :=
  (localTables direction).find? (fun table => table.device == id)

def localDecision (direction : LocalDirection) (id : String) (packet : RoutedPacket) : Option Bool :=
  (localTable? direction id).map (fun table => table.accepts packet)

structure LocalContract where
  device : String
  outside : String
  localAddress : UInt32
  peerAddress : UInt32
  noOptions : Bool
  deriving DecidableEq, BEq, Repr

def localContract? (t : Tunnel) : Option LocalContract := do
  let role ← role? t.owner
  let localAddress ← ipv4? t.localAddress
  let peerAddress ← ipv4? t.remoteAddress
  match role with
  | .inner => some ⟨t.owner, "gray", localAddress, peerAddress, false⟩
  | .outer => some ⟨t.owner, "black", localAddress, peerAddress, true⟩
  | _ => none

def localContracts : List LocalContract := tunnels.filterMap localContract?

def LocalContract.interface (direction : LocalDirection) (packet : RoutedPacket) : String :=
  match direction with
  | .input => packet.input
  | .output => packet.output

def LocalContract.peerAllows (c : LocalContract) (direction : LocalDirection)
    (packet : RoutedPacket) : Bool :=
  c.outside == LocalContract.interface direction packet &&
    (match direction with
     | .input => c.peerAddress == packet.source && c.localAddress == packet.destination
     | .output => c.localAddress == packet.source && c.peerAddress == packet.destination) &&
    ipsecClass packet

def LocalContract.allows (c : LocalContract) (direction : LocalDirection)
    (packet : RoutedPacket) : Bool :=
  (("lo" == LocalContract.interface direction packet && gatewayClass packet) ||
    c.peerAllows direction packet) && (!c.noOptions || packet.headerWords == 5)

def LocalContract.table (c : LocalContract) (direction : LocalDirection) : ForwardTable :=
  let loopback : ForwardRule :=
    match direction with
    | .input => { input := some "lo", noOptions := c.noOptions }
    | .output => { output := some "lo", noOptions := c.noOptions }
  let peer : ForwardRule :=
    match direction with
    | .input => { input := some c.outside, source := some ⟨c.peerAddress, 32⟩,
                  destination := some ⟨c.localAddress, 32⟩, noOptions := c.noOptions }
    | .output => { output := some c.outside, source := some ⟨c.localAddress, 32⟩,
                   destination := some ⟨c.peerAddress, 32⟩, noOptions := c.noOptions }
  { device := c.device, defaultAccept := false, rules :=
      [{ loopback with protocol := some 6 }, { loopback with protocol := some 17 },
       { loopback with protocol := some 50 }, { loopback with protocol := some 1 },
       { peer with protocol := some 17, destinationPorts := [500, 4500] },
       { peer with protocol := some 50 }] }

theorem local_contracts_cover : ∀ d ∈ devices,
    (d.role = .inner ∨ d.role = .outer) →
    ∃ c ∈ localContracts, c.device = d.id := by decide

theorem local_contract_tables_match : ∀ c ∈ localContracts,
    ∀ direction ∈ [LocalDirection.input, .output],
      ∃ table ∈ localTables direction,
        localTable? direction c.device = some table ∧ sameRules table (c.table direction) := by decide

theorem local_contract_external_interfaces : ∀ c ∈ localContracts, c.outside ≠ "lo" := by decide

theorem local_contract_table_semantics (c : LocalContract) (direction : LocalDirection)
    (p : RoutedPacket) : (c.table direction).accepts p = c.allows direction p := by
  cases direction <;>
    simp [LocalContract.table, ForwardTable.accepts, ForwardRule.matches, optionalMatch,
      policyMatch, LocalContract.allows, LocalContract.peerAllows, LocalContract.interface,
      ipsecClass, gatewayClass, Prefix.contains, TDN.Network.Prefix.host_contains,
      Bool.and_or_distrib_left, Bool.and_or_distrib_right] <;> ac_rfl

/-- Both implications matter: admitted controls work, and every extra local
allowance would invalidate the finite comparison with the imported chain. -/
theorem local_contract_decision (c : LocalContract) (member : c ∈ localContracts)
    (direction : LocalDirection) (p : RoutedPacket) :
    localDecision direction c.device p = some (c.allows direction p) := by
  have included : direction ∈ [LocalDirection.input, .output] := by cases direction <;> simp
  obtain ⟨table, _, lookup, same⟩ := local_contract_tables_match c member direction included
  simp only [localDecision, lookup, Option.map_some]
  rw [permuted_table_semantics table (c.table direction) same p, local_contract_table_semantics]

theorem accepted_external_local_packet_is_declared_control (c : LocalContract)
    (member : c ∈ localContracts) (direction : LocalDirection) (p : RoutedPacket)
    (external : LocalContract.interface direction p ≠ "lo")
    (accepted : localDecision direction c.device p = some true) :
    c.peerAllows direction p = true := by
  rw [local_contract_decision c member direction p] at accepted
  have different : "lo" ≠ LocalContract.interface direction p := Ne.symm external
  have allowed := Option.some.inj accepted
  simp only [LocalContract.allows, Bool.and_eq_true] at allowed
  simpa [different] using allowed.1

/-- Ordinary TCP and ICMP cannot use a VPN gateway's external local path.
IKE/ESP acceptance is separately witnessed by the complete contract above. -/
theorem undeclared_local_service_rejected (c : LocalContract) (member : c ∈ localContracts)
    (direction : LocalDirection) (p : RoutedPacket)
    (external : LocalContract.interface direction p ≠ "lo")
    (service : ipsecClass p = false) : localDecision direction c.device p = some false := by
  rw [local_contract_decision c member direction p]
  have different : "lo" ≠ LocalContract.interface direction p := Ne.symm external
  simp [LocalContract.allows, LocalContract.peerAllows, service, different]

theorem accepted_gateway_local_protocol (c : LocalContract) (member : c ∈ localContracts)
    (direction : LocalDirection) (p : RoutedPacket)
    (accepted : localDecision direction c.device p = some true) : gatewayClass p = true := by
  rw [local_contract_decision c member direction p] at accepted
  by_cases supported : gatewayClass p = true
  · exact supported
  · simp_all [LocalContract.allows, LocalContract.peerAllows, gatewayClass, ipsecClass]

theorem accepted_external_output_has_intended_destination (c : LocalContract)
    (member : c ∈ localContracts) (p : RoutedPacket) (external : p.output ≠ "lo")
    (accepted : localDecision .output c.device p = some true) :
    p.destination = c.peerAddress ∧ p.source = c.localAddress ∧ p.output = c.outside := by
  have control := accepted_external_local_packet_is_declared_control c member .output p external accepted
  simp only [LocalContract.peerAllows, LocalContract.interface, Bool.and_eq_true, beq_iff_eq] at control
  exact ⟨control.1.2.2.symm, control.1.2.1.symm, control.1.1.symm⟩

def localControlPacket (c : LocalContract) (direction : LocalDirection)
    (protocol port : Nat) : RoutedPacket :=
  match direction with
  | .input =>
    { input := c.outside, output := "", source := c.peerAddress,
      destination := c.localAddress, protocol := protocol, destinationPort := port }
  | .output =>
    { input := "", output := c.outside, source := c.localAddress,
      destination := c.peerAddress, protocol := protocol, destinationPort := port }

/-- The selected service policy has positive witnesses for every gateway,
both local directions, IKE on UDP 500/4500, and native ESP. -/
theorem every_gateway_permits_declared_local_controls : ∀ c ∈ localContracts,
    ∀ direction ∈ [LocalDirection.input, .output],
    ∀ service ∈ [(17, 500), (17, 4500), (50, 0)],
      localDecision direction c.device (localControlPacket c direction service.1 service.2) = some true := by decide

theorem outer_local_contracts_require_no_options : ∀ c ∈ localContracts,
    role? c.device = some .outer → c.noOptions = true := by decide

theorem outer_local_packets_with_options_rejected (c : LocalContract)
    (member : c ∈ localContracts) (outer : role? c.device = some .outer)
    (direction : LocalDirection) (p : RoutedPacket) (options : p.headerWords ≠ 5) :
    localDecision direction c.device p = some false := by
  rw [local_contract_decision c member direction p]
  simp [LocalContract.allows, outer_local_contracts_require_no_options c member outer, options]

end TDN.MSC
