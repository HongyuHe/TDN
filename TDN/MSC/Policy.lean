import TDN.MSC.Topology
import TDN.Network.Filter

/-!
# A deliberately restricted model of exported FORWARD rules

The importer accepts only rules whose semantics are represented here. The same
matcher is reused for INPUT and OUTPUT contracts. Supported connection-state
tags are explicit inputs. NAT, fragments, IPv6, and dynamic rule updates are
separate boundaries; OVS switching is modeled in the execution module.
The current forwarding chains contain ACCEPT rules followed
by a chain policy, so acceptance is the disjunction of rule matches and that
policy. Kernel fidelity remains an assumption even when observed and intended
rules agree byte-for-byte after supported normalization.
-/
namespace TDN.MSC
open Deployment

def optionalMatch {α : Type} [BEq α] (wanted : Option α) (actual : α) : Bool :=
  wanted.all (fun value => value == actual)

/-- A rule with no policy requirement imposes no policy restriction. A rule
with a request ID requires the kernel-derived tag to contain exactly that ID. -/
def policyMatch (wanted actual : Option Nat) : Bool :=
  match wanted with
  | none => true
  | some id => actual == some id

def ForwardRule.matches (rule : ForwardRule) (packet : RoutedPacket) : Bool :=
  optionalMatch rule.input packet.input &&
  optionalMatch rule.output packet.output &&
  rule.source.all (fun cidr => cidr.contains packet.source) &&
  rule.destination.all (fun cidr => cidr.contains packet.destination) &&
  optionalMatch rule.protocol packet.protocol &&
  (rule.destinationPorts.isEmpty || rule.destinationPorts.contains packet.destinationPort) &&
  (rule.connectionStates.isEmpty || rule.connectionStates.contains packet.connectionState) &&
  policyMatch rule.inPolicy packet.inPolicy &&
  policyMatch rule.outPolicy packet.outPolicy &&
  (!rule.noOptions || packet.headerWords == 5)

def ForwardRule.requiresPolicy (rule : ForwardRule) : Bool :=
  rule.inPolicy.isSome || rule.outPolicy.isSome

def ForwardTable.accepts (table : ForwardTable) (packet : RoutedPacket) : Bool :=
  table.rules.any (fun rule => rule.matches packet) || table.defaultAccept

def forwardingTable? (id : String) : Option ForwardTable :=
  forwardTables.find? (fun table => table.device == id)

/-- Missing configuration is an error for model evaluation, not an inferred
DROP. The `Option` result preserves that distinction for later TDN tooling. -/
def forwardDecision (id : String) (packet : RoutedPacket) : Option Bool :=
  (forwardingTable? id).map (fun table => table.accepts packet)

/-- A policy-dependent rule cannot accept a packet with neither policy tag.
The proof splits the optional inbound/outbound policy fields into their possible
constructors. `simp_all` then evaluates the impossible tag comparisons. -/
theorem protected_rule_blocks_untagged (rule : ForwardRule) (packet : RoutedPacket)
    (required : rule.requiresPolicy = true)
    (hin : packet.inPolicy = none) (hout : packet.outPolicy = none) :
    rule.matches packet = false := by
  cases hi : rule.inPolicy <;> cases ho : rule.outPolicy <;>
    simp_all [ForwardRule.requiresPolicy, ForwardRule.matches, policyMatch]

/-- Local rule reasoning lifts to a whole default-deny table. The quantified
packet can have any addresses, ports, protocol, and interface names. -/
theorem protected_table_blocks_untagged (table : ForwardTable) (packet : RoutedPacket)
    (deny : table.defaultAccept = false)
    (guarded : ∀ rule ∈ table.rules, rule.requiresPolicy = true)
    (hin : packet.inPolicy = none) (hout : packet.outPolicy = none) :
    table.accepts packet = false := by
  change TDN.Network.Filter.accepts ForwardRule.matches table.rules table.defaultAccept packet = false
  rw [deny]
  exact TDN.Network.Filter.all_rules_reject _ _ _
    (fun rule member => protected_rule_blocks_untagged rule packet (guarded rule member) hin hout)

def encryptorTables : List ForwardTable :=
  forwardTables.filter (fun table =>
    role? table.device == some .inner || role? table.device == some .outer)

/-- This finite premise comes from the imported rules, rather than an axiom
about how an encryptor ought to behave. Removing a guard breaks the proof. -/
theorem encryptor_tables_guarded : ∀ table ∈ encryptorTables,
    table.defaultAccept = false ∧
    (∀ rule ∈ table.rules, rule.requiresPolicy = true) := by decide

theorem encryptor_without_policy_drops (table : ForwardTable)
    (member : table ∈ encryptorTables) (packet : RoutedPacket)
    (hin : packet.inPolicy = none) (hout : packet.outPolicy = none) :
    table.accepts packet = false := by
  obtain ⟨deny, guarded⟩ := encryptor_tables_guarded table member
  exact protected_table_blocks_untagged table packet deny guarded hin hout

/-- In the deployed dedicated-Gray layout the firewall has no forwarding
allowlist at all. The theorem covers every modeled packet, not just ICMP. -/
theorem gray_firewall_denies_all (packet : RoutedPacket) :
    forwardDecision "GF_A" packet = some false ∧
    forwardDecision "GF_B" packet = some false := by
  constructor <;> rfl

def outerFirewallExample : RoutedPacket :=
  { input := "inside", output := "outside", source := 2886994689,
    destination := 2886997249, protocol := 50 }

/-- Concrete tests exercise imported CIDRs, protocol matching, and interfaces.
The addresses are 172.20.11.1 and 172.20.21.1 in unsigned IPv4 notation. -/
theorem outer_firewall_accepts_declared_esp :
    forwardDecision "OF_A1" outerFirewallExample = some true := by decide

theorem outer_firewall_rejects_icmp :
    forwardDecision "OF_A1" { outerFirewallExample with protocol := 1 } = some false := by
  decide

theorem outer_firewall_rejects_wrong_peer :
    forwardDecision "OF_A1" { outerFirewallExample with destination := 2886997505 } = some false := by
  decide

end TDN.MSC
