import Std

/-!
A local service grant names an interface, source, destination, protocol, and
optional destination-port set. A selected loopback interface is explicit.
The definitions describe either incoming or outgoing local events; the caller
chooses which physical interface field to project into the packet view.
No MSC device, role, address, protocol number, or snapshot is imported.
-/
namespace TDN.Network.LocalControl

structure Packet where
  interface : String
  source : UInt32
  destination : UInt32
  protocol : Nat
  destinationPort : Nat := 0
  deriving DecidableEq, BEq, Repr

structure Grant where
  interface : String
  source : UInt32
  destination : UInt32
  protocol : Nat
  destinationPorts : List Nat := []
  deriving DecidableEq, BEq, Repr

def Grant.matches (grant : Grant) (packet : Packet) : Bool :=
  grant.interface == packet.interface && grant.source == packet.source &&
    grant.destination == packet.destination && grant.protocol == packet.protocol &&
    (grant.destinationPorts.isEmpty || grant.destinationPorts.contains packet.destinationPort)

def accepts (loopback : String) (grants : List Grant) (packet : Packet) : Bool :=
  loopback == packet.interface || grants.any (fun grant => grant.matches packet)

theorem external_acceptance_has_grant (loopback : String) (grants : List Grant) (packet : Packet)
    (external : packet.interface ≠ loopback) (accepted : accepts loopback grants packet = true) :
    ∃ grant ∈ grants, grant.matches packet = true := by
  simpa [accepts, Ne.symm external] using accepted

theorem matched_grant_fixes_fields (grant : Grant) (packet : Packet)
    (matched : grant.matches packet = true) :
    packet.interface = grant.interface ∧ packet.source = grant.source ∧
    packet.destination = grant.destination ∧ packet.protocol = grant.protocol ∧
    (grant.destinationPorts = [] ∨ packet.destinationPort ∈ grant.destinationPorts) := by
  simp only [Grant.matches, Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq,
    List.isEmpty_iff, List.contains_iff_mem] at matched
  exact ⟨matched.1.1.1.1.symm, matched.1.1.1.2.symm,
    matched.1.1.2.symm, matched.1.2.symm, matched.2⟩

theorem declared_grant_is_allowed (loopback : String) (grants : List Grant) (packet : Packet)
    (grant : Grant) (member : grant ∈ grants) (matched : grant.matches packet = true) :
    accepts loopback grants packet = true := by
  have someMatch : grants.any (fun g => g.matches packet) = true :=
    List.any_eq_true.mpr ⟨grant, member, matched⟩
  simp [accepts, someMatch]

theorem accepted_external_protocol_is_declared (loopback : String) (grants : List Grant)
    (protocol : Nat) (common : ∀ grant ∈ grants, grant.protocol = protocol)
    (packet : Packet) (external : packet.interface ≠ loopback)
    (accepted : accepts loopback grants packet = true) : packet.protocol = protocol := by
  obtain ⟨grant, member, matched⟩ := external_acceptance_has_grant loopback grants packet external accepted
  exact (matched_grant_fixes_fields grant packet matched).2.2.2.1.trans (common grant member)

theorem empty_grant_set_rejects_external (loopback : String) (packet : Packet)
    (external : packet.interface ≠ loopback) : accepts loopback [] packet = false := by
  simp [accepts, Ne.symm external]

end TDN.Network.LocalControl
