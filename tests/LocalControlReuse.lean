import TDN.Network.LocalControl

/-!
The reusable local-control model supports different interfaces, endpoint pairs,
and service protocols without importing the MSC deployment. Three services
exercise both port-specific and protocol-only grants. The proofs below use
the same generic acceptance theorem as the deployed firewall instance.
-/
namespace LocalControlReuse
open TDN.Network.LocalControl

def services : List Grant :=
  [⟨"wan-west", 1, 2, 17, [123]⟩,
   ⟨"wan-east", 3, 4, 6, [443]⟩,
   ⟨"peer-link", 5, 6, 112, []⟩]

example : accepts "loop" services ⟨"wan-west", 1, 2, 17, 123⟩ = true := by decide
example : accepts "loop" services ⟨"wan-east", 3, 4, 6, 443⟩ = true := by decide
example : accepts "loop" services ⟨"peer-link", 5, 6, 112, 0⟩ = true := by decide
example : accepts "loop" services ⟨"wan-west", 1, 2, 17, 53⟩ = false := by decide
example : accepts "loop" services ⟨"wan-east", 1, 2, 17, 123⟩ = false := by decide
example : accepts "loop" services ⟨"wan-west", 99, 2, 17, 123⟩ = false := by decide
example : accepts "loop" services ⟨"wan-west", 1, 99, 17, 123⟩ = false := by decide

example (packet : Packet) (external : packet.interface ≠ "loop")
    (accepted : accepts "loop" services packet = true) :
    ∃ grant ∈ services, packet.interface = grant.interface ∧
      packet.source = grant.source ∧ packet.destination = grant.destination ∧
      packet.protocol = grant.protocol ∧
      (grant.destinationPorts = [] ∨ packet.destinationPort ∈ grant.destinationPorts) := by
  obtain ⟨grant, included, matched⟩ := external_acceptance_has_grant "loop" services packet external accepted
  exact ⟨grant, included, matched_grant_fixes_fields grant packet matched⟩

end LocalControlReuse
