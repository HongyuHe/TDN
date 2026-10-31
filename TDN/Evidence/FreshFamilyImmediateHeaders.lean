import TDN.Import.Command
import TDN.Semantics.HeaderPolicy

namespace TDN.Imported.FreshFamilyImmediateHeaders
open PacketPolicy

tdn_data gates : List (String × List Nat) from "../../evidence/lean/FreshFamilyImmediateHeaders.json" ["TDN.Imported.FreshFamilyImmediateHeaders.gates"]

tdn_data gatePriorities : List (String × Int) from "../../evidence/lean/FreshFamilyImmediateHeaders.json" ["TDN.Imported.FreshFamilyImmediateHeaders.gatePriorities"]

def rules (values : List Nat) : List Rule := [⟨[.ipv6NextHeaders values], .allow⟩]

lemma gate_values_checked : ∀ gate ∈ gates, gate.2 = [6, 17, 50, 58] := by
  unfold gates
  decide

lemma every_gate_precedes_defragmentation : ∀ gate ∈ gatePriorities, gate.2 < (-400 : Int) := by
  unfold gatePriorities
  decide

/-- The literal header is checked by the imported nft hook at priority -450.
Its connection to the original wire header uses the separately recorded kernel hook-order contract. -/
theorem admitted_header_before_defragmentation_is_permitted (gate : String × List Nat)
    (member : gate ∈ gates) (packet : Packet) (accepted : Accepts (rules gate.2) packet) :
    packet.ipv6NextHeader ∈ [6, 17, 50, 58] := by
  apply accepted_immediate_header (rules gate.2) [6, 17, 50, 58] ?_ packet accepted
  intro rule inRules allow
  have same : rule = ⟨[.ipv6NextHeaders gate.2], .allow⟩ := by simpa [rules] using inRules
  subst rule
  simp [ImmediateHeaderGuard, gate_values_checked gate member]

end TDN.Imported.FreshFamilyImmediateHeaders
