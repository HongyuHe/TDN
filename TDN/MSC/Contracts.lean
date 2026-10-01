import TDN.MSC.Policy

/-!
# Forwarding contracts derived from tunnel intent

The observed tables and the expected contracts have independent inputs. Tables
come from exported iptables rules. Contracts come from the declared tunnels,
device roles, and cables. Finite equality checks tie the two inputs together;
general theorems then describe every `RoutedPacket`, not a sample of addresses.

These contracts cover the IPv4 FORWARD chain. They do not add INPUT/OUTPUT,
anti-spoofing, or a refinement proof for Linux. ESP and UDP ports 500/4500 form
the supported encrypted-data/IKE class at outer devices. Inner contracts permit
only TCP, UDP, ESP, and ICMP. Outer encryptors also require an IPv4 header without
options. The guards support bounded FORWARD contributions to PF-10 and PF-11.
-/
namespace TDN.MSC
open Deployment

/-- `inside` and `outside` name the two data interfaces in one direction.
Selectors describe authorized addresses. A policy ID requires outbound XFRM
evidence on egress and inbound XFRM evidence on ingress. Outer Firewalls use
`none` because encryption occurs at the adjacent outer encryptor. -/
structure TrafficContract where
  device : String
  inside : String
  outside : String
  localNet : Prefix
  remoteNet : Prefix
  policy : Option Nat
  restrictToIPsec : Bool
  noOptions : Bool
  deriving DecidableEq, BEq, Repr

def ipsecClass (packet : RoutedPacket) : Bool :=
  50 == packet.protocol ||
    (17 == packet.protocol && [500, 4500].contains packet.destinationPort)

def gatewayClass (packet : RoutedPacket) : Bool :=
  6 == packet.protocol || 17 == packet.protocol ||
    50 == packet.protocol || 1 == packet.protocol

def TrafficContract.outbound (c : TrafficContract) (p : RoutedPacket) : Bool :=
  c.inside == p.input && c.outside == p.output &&
    c.localNet.contains p.source && c.remoteNet.contains p.destination &&
    policyMatch c.policy p.outPolicy

def TrafficContract.inbound (c : TrafficContract) (p : RoutedPacket) : Bool :=
  c.outside == p.input && c.inside == p.output &&
    c.remoteNet.contains p.source && c.localNet.contains p.destination &&
    policyMatch c.policy p.inPolicy

def TrafficContract.allows (c : TrafficContract) (p : RoutedPacket) : Bool :=
  (c.outbound p || c.inbound p) &&
    (if c.restrictToIPsec then ipsecClass p else gatewayClass p) &&
    (!c.noOptions || p.headerWords == 5)

/-- Construct expected rules from a contract, independently of observed rules.
Equality with the imported table rules out extra ACCEPT rules and missing
positive allowances. Rule order is immaterial only in our ACCEPT-only subset. -/
def TrafficContract.table (c : TrafficContract) : ForwardTable := Id.run do
  let outgoing : ForwardRule :=
    { input := some c.inside, output := some c.outside,
      source := some c.localNet, destination := some c.remoteNet, outPolicy := c.policy,
      noOptions := c.noOptions }
  let incoming : ForwardRule :=
    { input := some c.outside, output := some c.inside,
      source := some c.remoteNet, destination := some c.localNet, inPolicy := c.policy,
      noOptions := c.noOptions }
  let rules := if c.restrictToIPsec then
    [{ outgoing with protocol := some 50 }, { incoming with protocol := some 50 },
     { outgoing with protocol := some 17, destinationPorts := [500, 4500] },
     { incoming with protocol := some 17, destinationPorts := [500, 4500] }]
    else [{ outgoing with protocol := some 6 }, { incoming with protocol := some 6 },
          { outgoing with protocol := some 17 }, { incoming with protocol := some 17 },
          { outgoing with protocol := some 50 }, { incoming with protocol := some 50 },
          { outgoing with protocol := some 1 }, { incoming with protocol := some 1 }]
  return { device := c.device, defaultAccept := false, rules }

/-- Normalize the ACCEPT-only rules before comparison. No rule is dropped;
permutation is allowed because every matching rule has the same target. -/
def sameRules (a b : ForwardTable) : Prop :=
  a.device = b.device ∧ a.defaultAccept = b.defaultAccept ∧ a.rules.Perm b.rules

instance (a b : ForwardTable) : Decidable (sameRules a b) :=
  inferInstanceAs (Decidable (a.device = b.device ∧ a.defaultAccept = b.defaultAccept ∧ a.rules.Perm b.rules))

def tunnel? (owner : String) : Option Tunnel :=
  tunnels.find? (fun t => t.owner == owner)

def encryptorContract? (t : Tunnel) : Option TrafficContract := do
  let role ← role? t.owner
  let localNet ← Prefix.parse? t.localSelector
  let remoteNet ← Prefix.parse? t.remoteSelector
  match role with
  | .inner => some ⟨t.owner, "red", "gray", localNet, remoteNet, some t.reqid, false, false⟩
  | .outer => some ⟨t.owner, "gray", "black", localNet, remoteNet, some t.reqid, true, true⟩
  | _ => none

def encryptorContracts : List TrafficContract := tunnels.filterMap encryptorContract?

/-- The current profile has one addressed Red interface per host and inner.
Normalize its host address to the subnet base while retaining the prefix length.
Missing, multiple, or malformed Red interfaces return `none`, rather than
silently selecting one interface or dropping an invalid address. -/
def redPrefix? (id : String) : Option Prefix := do
  let device ← device? id
  let [interface] := device.interfaces.filter (fun i => i.zone == .red) | none
  let cidr ← Prefix.parse? interface.address
  let size := 2 ^ (32 - cidr.length)
  pure ⟨UInt32.ofNat (cidr.address.toNat / size * size), cidr.length⟩

/-- Every representative Red host and its dedicated inner declare the same
subnet. Parsing success is explicit, so two missing values cannot count as an
address match. Ownership and label checks are proved in Topology.lean. -/
theorem red_prefixes_match_owners : ∀ host ∈ devices, host.role = .host →
    ∃ inner ∈ devices, inner.role = .inner ∧ inner.id ∈ redNeighbors host.id ∧
      (redPrefix? host.id).isSome = true ∧ redPrefix? host.id = redPrefix? inner.id := by decide

/-- A selector must equal the whole declared Red subnet, not merely contain
one sampled host address. Both a widened /16 and a narrowed /25 violate the
current /24 contract. The remote selector uses the peer's own Red interface. -/
theorem inner_selectors_match_red_prefixes : ∀ t ∈ tunnels,
    role? t.owner = some .inner →
      (redPrefix? t.owner).isSome = true ∧ (redPrefix? t.peer).isSome = true ∧
      Prefix.parse? t.localSelector = redPrefix? t.owner ∧
      Prefix.parse? t.remoteSelector = redPrefix? t.peer := by decide

/-- Connect each actual inner contract to the independently declared Red
interfaces. The general packet corollaries below reuse this finite bridge. -/
theorem inner_contracts_match_red_prefixes : ∀ c ∈ encryptorContracts,
    role? c.device = some .inner → ∃ t ∈ tunnels, t.owner = c.device ∧
      redPrefix? t.owner = some c.localNet ∧ redPrefix? t.peer = some c.remoteNet := by decide

def attachedOuters (id : String) : List String :=
  links.filterMap fun l =>
    if l.zone != .black then none
    else if l.a == id && role? l.b == some .outer then some l.b
    else if l.b == id && role? l.a == some .outer then some l.a
    else none

def outerFirewallContract? (d : Device) : Option TrafficContract := do
  if d.role != .firewall then none else
  let [outer] := attachedOuters d.id | none
  let t ← tunnel? outer
  let localAddress ← ipv4? t.localAddress
  let remoteAddress ← ipv4? t.remoteAddress
  some ⟨d.id, "inside", "outside", ⟨localAddress, 32⟩, ⟨remoteAddress, 32⟩, none, true, false⟩

def outerFirewallContracts : List TrafficContract := devices.filterMap outerFirewallContract?

/-- Every encryptor and Outer Firewall has a contract. An empty contract list
cannot make the following universal policy results pass vacuously. -/
theorem encryptor_contracts_cover : ∀ d ∈ devices,
    (d.role = .inner ∨ d.role = .outer) →
    ∃ c ∈ encryptorContracts, c.device = d.id := by decide

theorem outer_firewall_contracts_cover : ∀ d ∈ devices,
    d.role = .firewall → ∃ c ∈ outerFirewallContracts, c.device = d.id := by decide

theorem encryptor_contracts_match : ∀ c ∈ encryptorContracts,
    ∃ table ∈ forwardTables, table.device = c.device ∧ sameRules table c.table := by decide

theorem outer_firewall_contracts_match : ∀ c ∈ outerFirewallContracts,
    ∃ table ∈ forwardTables, table.device = c.device ∧ sameRules table c.table := by decide

/-- Lookup agrees with the unique contract. We check the exact table returned
by lookup so duplicate tables cannot hide behind an existential witness. -/
theorem contract_lookup_matches : ∀ c ∈ encryptorContracts ++ outerFirewallContracts,
    ∃ table ∈ forwardTables, forwardingTable? c.device = some table ∧ sameRules table c.table := by
  decide

/-- The general Boolean identity connects the normalized rule representation
to explicit address, direction, request-ID, and protocol requirements. -/
theorem contract_table_semantics (c : TrafficContract) (p : RoutedPacket) :
    c.table.accepts p = c.allows p := by
  cases h : c.restrictToIPsec <;>
    simp [TrafficContract.table, ForwardTable.accepts, ForwardRule.matches,
      optionalMatch, TrafficContract.allows, TrafficContract.outbound,
      TrafficContract.inbound, ipsecClass, gatewayClass, policyMatch, h,
      Bool.and_or_distrib_left, Bool.and_or_distrib_right] <;> ac_rfl

theorem permuted_table_semantics (a b : ForwardTable) (same : sameRules a b)
    (p : RoutedPacket) : a.accepts p = b.accepts p := by
  obtain ⟨_, policy, rules⟩ := same
  simp only [ForwardTable.accepts, policy]
  congr 1
  exact List.Perm.any_eq rules

/-- Accepted traffic satisfies the complete declared contract, and every
packet satisfying that contract is accepted. The reverse implication is the
positive allowance missing from a deny-all or rejection-only argument. -/
theorem declared_contract_decision (c : TrafficContract)
    (member : c ∈ encryptorContracts ++ outerFirewallContracts) (p : RoutedPacket) :
    forwardDecision c.device p = some (c.allows p) := by
  obtain ⟨table, _, lookup, same⟩ := contract_lookup_matches c member
  simp only [forwardDecision, lookup, Option.map_some]
  rw [permuted_table_semantics table c.table same p, contract_table_semantics]

theorem declared_contract_accepts_iff (c : TrafficContract)
    (member : c ∈ encryptorContracts ++ outerFirewallContracts) (p : RoutedPacket) :
    forwardDecision c.device p = some true ↔ c.allows p = true := by
  rw [declared_contract_decision c member p]
  simp

theorem encryptor_contract_directions : ∀ c ∈ encryptorContracts,
    c.inside ≠ c.outside ∧ c.policy.isSome = true := by decide

theorem accepted_outbound_requires_declared_policy (c : TrafficContract)
    (member : c ∈ encryptorContracts) (p : RoutedPacket) (id : Nat)
    (policy : c.policy = some id) (direction : p.input = c.inside)
    (accepted : forwardDecision c.device p = some true) :
    p.outPolicy = some id ∧ c.localNet.contains p.source = true ∧
      c.remoteNet.contains p.destination = true := by
  have h := (declared_contract_accepts_iff c (List.mem_append_left _ member) p).mp accepted
  have different := (encryptor_contract_directions c member).1
  have reverseDifferent : c.outside ≠ c.inside := Ne.symm different
  simp_all [TrafficContract.allows, TrafficContract.outbound, TrafficContract.inbound, policyMatch]

theorem accepted_inbound_requires_declared_policy (c : TrafficContract)
    (member : c ∈ encryptorContracts) (p : RoutedPacket) (id : Nat)
    (policy : c.policy = some id) (direction : p.input = c.outside)
    (accepted : forwardDecision c.device p = some true) :
    p.inPolicy = some id ∧ c.remoteNet.contains p.source = true ∧
      c.localNet.contains p.destination = true := by
  have h := (declared_contract_accepts_iff c (List.mem_append_left _ member) p).mp accepted
  have different := (encryptor_contract_directions c member).1
  have reverseDifferent : c.outside ≠ c.inside := Ne.symm different
  simp_all [TrafficContract.allows, TrafficContract.outbound, TrafficContract.inbound, policyMatch]

/-- Every accepted outbound inner packet has source and destination addresses
inside the attached local and peer Red subnets. Actual attribution of a packet
to its claimed source remains external; no anti-spoofing claim is inferred. -/
theorem accepted_inner_outbound_in_red_prefixes (c : TrafficContract)
    (member : c ∈ encryptorContracts) (inner : role? c.device = some .inner)
    (p : RoutedPacket) (direction : p.input = c.inside)
    (accepted : forwardDecision c.device p = some true) :
    ∃ t ∈ tunnels, t.owner = c.device ∧
      redPrefix? t.owner = some c.localNet ∧ redPrefix? t.peer = some c.remoteNet ∧
      c.localNet.contains p.source = true ∧ c.remoteNet.contains p.destination = true := by
  obtain ⟨t, tunnel, owner, localNet, remoteNet⟩ := inner_contracts_match_red_prefixes c member inner
  have present := (encryptor_contract_directions c member).2
  cases policy : c.policy with
  | none => simp [policy] at present
  | some id =>
    have bounds := accepted_outbound_requires_declared_policy c member p id policy direction accepted
    exact ⟨t, tunnel, owner, localNet, remoteNet, bounds.2⟩

/-- The reverse direction exchanges the local and peer subnet roles. -/
theorem accepted_inner_inbound_in_red_prefixes (c : TrafficContract)
    (member : c ∈ encryptorContracts) (inner : role? c.device = some .inner)
    (p : RoutedPacket) (direction : p.input = c.outside)
    (accepted : forwardDecision c.device p = some true) :
    ∃ t ∈ tunnels, t.owner = c.device ∧
      redPrefix? t.owner = some c.localNet ∧ redPrefix? t.peer = some c.remoteNet ∧
      c.remoteNet.contains p.source = true ∧ c.localNet.contains p.destination = true := by
  obtain ⟨t, tunnel, owner, localNet, remoteNet⟩ := inner_contracts_match_red_prefixes c member inner
  have present := (encryptor_contract_directions c member).2
  cases policy : c.policy with
  | none => simp [policy] at present
  | some id =>
    have bounds := accepted_inbound_requires_declared_policy c member p id policy direction accepted
    exact ⟨t, tunnel, owner, localNet, remoteNet, bounds.2⟩

/-- Each outer selector names the inner peer pair at the same site and level.
The statement uses imported tunnel addresses and labels, not packet-supplied
security labels. Correct attribution of real addresses remains external. -/
theorem outer_selectors_bind_inner_peers : ∀ outer ∈ tunnels,
    role? outer.owner = some .outer → ∃ inner ∈ tunnels,
      role? inner.owner = some .inner ∧
      grayLabel outer.owner = grayLabel inner.owner ∧
      grayLabel outer.peer = grayLabel inner.peer ∧
      outer.localSelector = inner.localAddress ++ "/32" ∧
      outer.remoteSelector = inner.remoteAddress ++ "/32" := by decide

/-- A peer's tunnel address is also its declared external interface address.
The parser retains the host bits of an interface CIDR here; subnet membership
alone would be too weak to identify that interface. -/
theorem tunnel_addresses_match_interfaces : ∀ t ∈ tunnels,
    ∃ d ∈ devices, d.id = t.owner ∧ ∃ i ∈ d.interfaces,
      ((d.role = .inner ∧ i.zone = .gray) ∨ (d.role = .outer ∧ i.zone = .black)) ∧
      (Prefix.parse? i.address).map Prefix.address = ipv4? t.localAddress ∧
      (ipv4? t.localAddress).isSome = true := by decide

theorem outer_contracts_restrict_protocols : ∀ c ∈ encryptorContracts,
    role? c.device = some .outer → c.restrictToIPsec = true := by decide

theorem outer_firewall_contracts_restrict_protocols : ∀ c ∈ outerFirewallContracts,
    c.restrictToIPsec = true := by decide

theorem accepted_outer_protocol (c : TrafficContract)
    (member : c ∈ encryptorContracts ++ outerFirewallContracts)
    (restricted : c.restrictToIPsec = true) (p : RoutedPacket)
    (accepted : forwardDecision c.device p = some true) : ipsecClass p = true := by
  have h := (declared_contract_accepts_iff c member p).mp accepted
  simp_all [TrafficContract.allows]

/-- Every accepted packet at any modeled VPN gateway belongs to PF-11's
four-protocol set. The proof covers arbitrary packet fields in either direction.
The table equality above connects the generic contract to every actual gateway. -/
theorem accepted_gateway_protocol (c : TrafficContract)
    (member : c ∈ encryptorContracts) (p : RoutedPacket)
    (accepted : forwardDecision c.device p = some true) :
    p.protocol = 6 ∨ p.protocol = 17 ∨ p.protocol = 50 ∨ p.protocol = 1 := by
  have h := (declared_contract_accepts_iff c (List.mem_append_left _ member) p).mp accepted
  cases restricted : c.restrictToIPsec <;>
    simp_all [TrafficContract.allows, ipsecClass, gatewayClass] <;> omega

/-- All four imported outer gateway contracts require the IPv4 header length
to be five words. The obligation does not apply to the separate Outer Firewalls. -/
theorem outer_contracts_require_no_options : ∀ c ∈ encryptorContracts,
    role? c.device = some .outer → c.noOptions = true := by decide

/-- PF-10's objective has a bounded FORWARD consequence: a packet accepted by
an outer gateway has no IPv4 options. INPUT/OUTPUT and real kernel interpretation
remain outside this packet model, although the deployed guard covers those chains. -/
theorem accepted_outer_has_no_options (c : TrafficContract)
    (member : c ∈ encryptorContracts) (outer : role? c.device = some .outer)
    (p : RoutedPacket) (accepted : forwardDecision c.device p = some true) :
    p.headerWords = 5 := by
  have h := (declared_contract_accepts_iff c (List.mem_append_left _ member) p).mp accepted
  have guard := outer_contracts_require_no_options c member outer
  simp_all [TrafficContract.allows]

end TDN.MSC
