import TDN.MSC.Execution

/-!
PF-9 restricts multicast arriving at an Outer Encryption Component's Black
interface. The closed certificate inspects every relevant INPUT and FORWARD
allowance. Each allowed destination is a unicast /32, and the default denies.
The reusable filter lemma lifts those facts to arbitrary IPv4 group addresses.
A receive-preservation lemma connects the original arrival header to both
forwarding rejection and failed local delivery. The proof covers complete
IPv4 datagrams under the selected sampled processing model.

Outer Firewalls are a distinct role. Their required Black-underlay OSPF grants
remain governed by FirewallControl and can include multicast control traffic.
-/

namespace TDN.MSC.Multicast
open TDN.MSC
open TDN.MSC.Deployment
open TDN.MSC.Execution
open TDN.Network.Execution

open TDN.Network (ipv4Multicast)

theorem outer_black_rules_have_unicast_destinations :
    ∀ table ∈ forwardTables ++ inputTables, role? table.device = some .outer →
      table.defaultAccept = false ∧
      ∀ rule ∈ table.rules, optionalMatch rule.input "black" = true →
        rule.destination.isSome = true ∧
          ∀ destination ∈ rule.destination.toList, destination.length = 32 ∧ ipv4Multicast destination.address = false := by decide

theorem outer_black_multicast_is_rejected
    (table : ForwardTable) (included : table ∈ forwardTables ++ inputTables)
    (outer : role? table.device = some .outer) (packet : RoutedPacket)
    (black : packet.input = "black") (group : ipv4Multicast packet.destination = true) :
    table.accepts packet = false := by
  obtain ⟨deny, rules⟩ := outer_black_rules_have_unicast_destinations table included outer
  change TDN.Network.Filter.accepts ForwardRule.matches table.rules table.defaultAccept packet = false
  rw [deny]
  apply TDN.Network.Filter.all_rules_reject
  intro rule member
  apply Bool.eq_false_iff.mpr
  intro matched
  have input : optionalMatch rule.input "black" = true := by
    simp_all [ForwardRule.matches]
  obtain ⟨present, destinations⟩ := rules rule member input
  cases fixed : rule.destination with
  | none => simp [fixed] at present
  | some cidr =>
    obtain ⟨width, unicast⟩ := destinations cidr (by simp [fixed])
    have contained : cidr.contains packet.destination = true := by
      simp_all [ForwardRule.matches]
    have host : cidr = ⟨cidr.address, 32⟩ := by cases cidr; simp_all [Prefix.length, Prefix.address]
    rw [host] at contained
    have same : cidr.address = packet.destination := by
      simpa only [TDN.Network.Prefix.host_contains, beq_iff_eq] using contained
    rw [same, group] at unicast
    contradiction

/-- The concrete INPUT table gives a definite denial for every multicast
arrival header on an outer encryptor's Black interface. -/
theorem outer_black_multicast_input_rejected (node : String)
    (outer : role? node = some .outer) (header : TDN.Network.IPv4Header)
    (group : ipv4Multicast header.destination = true) :
    model.inputFilter node "black" header = false := by
  cases found : localTable? .input node with
  | none => simp [model, localDecision, found]
  | some table =>
    have member : table ∈ inputTables := List.mem_of_find?_eq_some found
    have identity : table.device = node := by simpa using List.find?_some found
    have rejected := outer_black_multicast_is_rejected table
      (List.mem_append_right forwardTables member) (by simpa [identity] using outer)
      (packetView "black" "" header none none) rfl group
    simpa [model, localDecision, found] using rejected

theorem outer_black_multicast_forward_filter_rejected (node : String)
    (outer : role? node = some .outer) (header : TDN.Network.IPv4Header)
    (group : ipv4Multicast header.destination = true) (output : String)
    (inputTag outputTag : Option Nat) :
    model.forwardFilter node "black" output header inputTag outputTag = false := by
  cases found : forwardingTable? node with
  | none => simp [model, forwardDecision, found]
  | some table =>
    have member : table ∈ forwardTables := List.mem_of_find?_eq_some found
    have identity : table.device = node := by simpa using List.find?_some found
    have rejected := outer_black_multicast_is_rejected table
      (List.mem_append_left inputTables member) (by simpa [identity] using outer)
      (packetView "black" output header inputTag outputTag) rfl group
    simpa [model, forwardDecision, found] using rejected

/-- PF-9's processing consequence applies to the destination on the arriving
wire packet. INPUT denial prevents hidden local decryption before the transit
filter is checked against that destination. -/
theorem outer_black_multicast_forward_rejected {Message : Type} (node : String)
    (outer : role? node = some .outer) (packet : TDN.Network.WirePacket Message)
    (group : ipv4Multicast packet.header.destination = true) :
    model.forward node "black" packet = none := by
  apply forward_rejects_denied_ingress model node "black" packet
  · exact outer_black_multicast_input_rejected node outer packet.header group
  · exact outer_black_multicast_forward_filter_rejected node outer packet.header group

/-- Local delivery also rejects the original multicast destination, for
both clear arrivals and ciphertext presented to the receive operation. -/
theorem outer_black_multicast_delivery_rejected {Message : Type} (node : String)
    (outer : role? node = some .outer) (packet : TDN.Network.WirePacket Message)
    (group : ipv4Multicast packet.header.destination = true) :
    model.deliver node "black" packet = none :=
  deliver_rejects_denied_input model node "black" packet
    (outer_black_multicast_input_rejected node outer packet.header group)

end TDN.MSC.Multicast
