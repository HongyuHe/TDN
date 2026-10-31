import TDN.Import.Command
import TDN.Targets.Operations

namespace TDN.Imported.FreshDNSHardening
open PacketPolicy

structure DNSDevice where
  name : String
  family : Nat
  earlierRules : List Rule
  guards : List Rule

tdn_data devices : List DNSDevice from "../../evidence/lean/FreshDNSHardening.json" ["TDN.Imported.FreshDNSHardening.devices"]

lemma all_prefixes : ∀ device ∈ devices, device.guards =
    [{ atoms := [.protocol "tcp", .destinationPorts [53]], verdict := .deny },
     { atoms := [.protocol "udp", .destinationPorts [53]], verdict := .deny }] := by
  unfold devices
  decide

lemma earlier_state_guards : ∀ device ∈ devices, ∀ rule ∈ device.earlierRules,
    .connectionStates ["ESTABLISHED"] ∈ rule.atoms := by
  unfold devices
  decide

lemma ipv6_has_no_earlier_rules : ∀ device ∈ devices, device.family = 6 → device.earlierRules = [] := by
  unfold devices
  decide

lemma guarded_dns_is_denied (device : DNSDevice) (member : device ∈ devices)
    (suffix : List (Filter.Rule Packet)) (fallback : Filter.Verdict)
    (packet : Packet) (dns : Targets.ConventionalDNS packet) :
    Filter.evaluate (device.guards.map Rule.toFilter ++ suffix) fallback packet = .deny := by
  apply Targets.dns_egress_disabled_of_deny_prefix
  · rw [all_prefixes device member]
    simp
  · intro candidate request
    rw [all_prefixes device member]
    rcases request with ⟨port, protocol | protocol⟩
    · refine ⟨{ atoms := [.protocol "tcp", .destinationPorts [53]], verdict := .deny }, by simp, ?_⟩
      simp [Rule.toFilter, Atom.holds, port, protocol]
    · refine ⟨{ atoms := [.protocol "udp", .destinationPorts [53]], verdict := .deny }, by simp, ?_⟩
      simp [Rule.toFilter, Atom.holds, port, protocol]
  · exact dns

theorem every_new_conventional_dns_request_is_denied (device : DNSDevice)
    (member : device ∈ devices) (suffix : List (Filter.Rule Packet))
    (fallback : Filter.Verdict) (packet : Packet) (dns : Targets.ConventionalDNS packet)
    (newRequest : packet.connectionState = "NEW") :
    Filter.evaluate (device.earlierRules.map Rule.toFilter ++
      (device.guards.map Rule.toFilter ++ suffix)) fallback packet = .deny := by
  rw [Filter.evaluate_skips_nonmatching_prefix]
  · exact guarded_dns_is_denied device member suffix fallback packet dns
  · intro rule present
    obtain ⟨original, listed, rfl⟩ := List.mem_map.mp present
    cases equal : original.toFilter.accepts packet with
    | false => rfl
    | true =>
      have state := PacketPolicy.matching_atom equal (earlier_state_guards device member original listed)
      simp [Atom.holds, newRequest] at state

theorem every_ipv6_conventional_dns_packet_is_denied (device : DNSDevice)
    (member : device ∈ devices) (ipv6 : device.family = 6)
    (suffix : List (Filter.Rule Packet)) (fallback : Filter.Verdict)
    (packet : Packet) (dns : Targets.ConventionalDNS packet) :
    Filter.evaluate (device.earlierRules.map Rule.toFilter ++
      (device.guards.map Rule.toFilter ++ suffix)) fallback packet = .deny := by
  rw [ipv6_has_no_earlier_rules device member ipv6]
  exact guarded_dns_is_denied device member suffix fallback packet dns

end TDN.Imported.FreshDNSHardening
