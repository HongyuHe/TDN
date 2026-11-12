import TDN.Import.SnapshotLoader
import TDN.Models.IpHeaderAclGuards

namespace TDN.Deployments.SnapshotFamilyImmediateHeaders
open PacketPolicy

load_network_records gates : List (String × List Nat) from "../../data/evidence/SnapshotFamilyImmediateHeaders.json" ["TDN.Deployments.SnapshotFamilyImmediateHeaders.gates"]

load_network_records gatePriorities : List (String × Int) from "../../data/evidence/SnapshotFamilyImmediateHeaders.json" ["TDN.Deployments.SnapshotFamilyImmediateHeaders.gatePriorities"]

def rules (values : List Nat) : List Rule := [⟨[.ipv6NextHeaders values], .allow⟩]

lemma gate_values_checked : ∀ gate ∈ gates, gate.2 = [6, 17, 50, 58] := by
  unfold gates
  native_decide
lemma every_gate_precedes_defragmentation : ∀ gate ∈ gatePriorities, gate.2 < (-400 : Int) := by
  unfold gatePriorities
  native_decide
theorem admitted_header_before_defragmentation_is_permitted (gate : String × List Nat)
    (member : gate ∈ gates) (packet : Packet) (accepted : Accepts (rules gate.2) packet) :
    packet.ipv6NextHeader ∈ [6, 17, 50, 58] := by
  apply accepted_immediate_header (rules gate.2) [6, 17, 50, 58] ?_ packet accepted
  intro rule inRules allow
  have same : rule = ⟨[.ipv6NextHeaders gate.2], .allow⟩ := by simpa [rules] using inRules
  subst rule
  simp [ImmediateHeaderGuard, gate_values_checked gate member]

end TDN.Deployments.SnapshotFamilyImmediateHeaders
