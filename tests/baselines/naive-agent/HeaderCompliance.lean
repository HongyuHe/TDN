import TDN.Import.SnapshotLoader
import TDN.Models.TableDrivenDataPlane
import TDN.Models.IpHeaderAclGuards

/-! Apply the existing per-hook protocol and multicast theorems to captured rules. -/
namespace TDN.BlindHeaders
open DataPlaneForwarding PacketPolicy
load_network_records devices : List DeviceData from "input.json" ["devices"]
load_network_records vpnIndices : List Nat from "input.json" ["vpnIndices"]
load_network_records outerIndices : List Nat from "input.json" ["outerIndices"]

def hooks (i : Nat) : List (List PacketAclRule) :=
  let d := deviceAt devices i
  [d.inputRules, d.forwardRules, d.outputRules]
def incomingHooks (i : Nat) : List (List PacketAclRule) :=
  let d := deviceAt devices i
  [d.inputRules, d.forwardRules]

lemma captured_defaults_deny : ∀ i ∈ vpnIndices,
    (deviceAt devices i).inputFallback = .deny ∧
    (deviceAt devices i).forwardFallback = .deny ∧
    (deviceAt devices i).outputFallback = .deny := by native_decide

lemma protocol_rules_checked : ∀ i ∈ vpnIndices, ∀ rules ∈ hooks i,
    ∀ rule ∈ rules, rule.verdict = .allow → ProtocolGuard ["tcp", "udp", "esp", "icmp"] rule := by native_decide

theorem accepted_IPv4_protocol_is_allowed (i : Nat) (member : i ∈ vpnIndices)
    (rules : List PacketAclRule) (hook : rules ∈ hooks i) (packet : Packet)
    (accepted : DefaultDenyAllows rules packet) : packet.protocol ∈ ["tcp", "udp", "esp", "icmp"] :=
  accepted_protocol rules _ (protocol_rules_checked i member rules hook) packet accepted

lemma external_multicast_rules_checked : ∀ i ∈ outerIndices, ∀ rules ∈ incomingHooks i,
    ∀ rule ∈ rules, rule.verdict = .allow → UnicastGuard "black" 3758096384 4026531839 rule := by native_decide

theorem accepted_external_packet_is_not_multicast (i : Nat) (member : i ∈ outerIndices)
    (rules : List PacketAclRule) (hook : rules ∈ incomingHooks i) (packet : Packet)
    (accepted : DefaultDenyAllows rules packet) (external : packet.ingress = "black") :
    ¬ (3758096384 ≤ packet.destination ∧ packet.destination ≤ 4026531839) :=
  accepted_external_unicast rules "black" 3758096384 4026531839
    (external_multicast_rules_checked i member rules hook) packet accepted external
end TDN.BlindHeaders
