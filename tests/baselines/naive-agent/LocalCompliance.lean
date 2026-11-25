import TDN.Import.SnapshotLoader
import TDN.Requirements.DoubleEncryptionOnBlackLinks
import TDN.Models.IpHeaderAclGuards

/-! Positive local proof attempts use the existing TDN conditions and captured
records. A failed native decision is retained as a typecheck error. -/
namespace TDN.BlindLocal
open DataPlaneForwarding PacketPolicy
structure Input where
  kind : String
  rule : PacketAclRule
  ifaces : List IfaceData
  device : DeviceData
  owner : Nat
  external : String

load_network_records observation : Input from "input.json" ["observation"]

def ComplianceClaim : Prop :=
  match observation.kind with
  | "forward" => ∀ entry ∈ ({} : IfaceData) :: observation.ifaces,
      ∀ output ∈ ({} : IfaceData) :: observation.ifaces,
      entry.owner = observation.owner → output.owner = observation.owner →
      ∀ auth ∈ possibleAuthentications observation.device entry,
        observation.rule.verdict = .allow → RecordRuleCheck entry output observation.device auth observation.rule
  | "protocol" => observation.rule.verdict = .allow →
      ProtocolGuard ["tcp", "udp", "esp", "icmp"] observation.rule
  | "unicast" => observation.rule.verdict = .allow →
      UnicastGuard observation.external 3758096384 4026531839 observation.rule
  | _ => False

instance : Decidable ComplianceClaim := by
  unfold ComplianceClaim
  split <;> infer_instance

theorem captured_rule_satisfies_the_theory_condition : ComplianceClaim := by native_decide
end TDN.BlindLocal
