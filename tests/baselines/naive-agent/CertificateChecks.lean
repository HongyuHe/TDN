import TDN.Import.SnapshotLoader
import TDN.Models.IpHeaderAclGuards
import TDN.Models.DataPlaneForwarding

/-! Kernel-checked certificates replay the experiment's selected packet witnesses. -/
namespace TDN.BaselineCertificates
open PacketPolicy DataPlaneForwarding

instance (inside outside : String) (packet : Packet) :
    Decidable (ProtectedForward inside outside packet) := by
  have finite (values : List Nat) : (∃ value, value ∈ values) ↔ values ≠ [] := by
    cases values <;> simp
  exact decidable_of_iff
    ((packet.ingress = inside ∧ packet.egress = outside ∧ packet.matchedOutboundPolicyIds ≠ []) ∨
      (packet.ingress = outside ∧ packet.egress = inside ∧ packet.matchedInboundPolicyIds ≠ []))
    (by simp only [ProtectedForward, finite])

structure Sample where
  id : String
  network : String
  device : String
  chain : String
  requirement : String
  kind : String
  rules : List PacketAclRule
  fallback : Filter.Verdict
  packet : Packet
  inside : String
  outside : String
  egressPolicies : List IpsecPolicy

def violation (sample : Sample) : Bool :=
  decide (Filter.evaluate (sample.rules.map PacketAclRule.toFilter) sample.fallback sample.packet = .allow) &&
  match sample.kind with
  | "unprotected_forward" =>
      !decide (ProtectedForward sample.inside sample.outside sample.packet) &&
      !(sample.egressPolicies.any (fun policy => decide (policy.matches sample.packet)))
  | "ipv4_protocol" => !decide (sample.packet.protocol ∈ ["tcp", "udp", "esp", "icmp"])
  | "external_multicast" => decide (3758096384 ≤ sample.packet.destination ∧
      sample.packet.destination ≤ 4026531839)
  | _ => false

load_network_records witnesses : List Sample from ".runtime/tdn-certificates.json" ["witnesses"]

theorem recorded_packet_witnesses_violate_the_checked_clause :
    ∀ sample ∈ witnesses, violation sample = true := by native_decide

end TDN.BaselineCertificates
