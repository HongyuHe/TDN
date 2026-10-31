import TDN.Semantics.HeaderPolicy

namespace TDN.Imported.FreshFamilyImmediateHeaders
open PacketPolicy

def gates : List (String × List Nat) := [("444/IA/prerouting", [6, 17, 50, 58]), ("444/IA/output", [6, 17, 50, 58]), ("444/OA/prerouting", [6, 17, 50, 58]), ("444/OA/output", [6, 17, 50, 58]), ("444/OB/prerouting", [6, 17, 50, 58]), ("444/OB/output", [6, 17, 50, 58]), ("444/IB/prerouting", [6, 17, 50, 58]), ("444/IB/output", [6, 17, 50, 58]), ("446/IA/prerouting", [6, 17, 50, 58]), ("446/IA/output", [6, 17, 50, 58]), ("446/OA/prerouting", [6, 17, 50, 58]), ("446/OA/output", [6, 17, 50, 58]), ("446/OB/prerouting", [6, 17, 50, 58]), ("446/OB/output", [6, 17, 50, 58]), ("446/IB/prerouting", [6, 17, 50, 58]), ("446/IB/output", [6, 17, 50, 58]), ("464/IA/prerouting", [6, 17, 50, 58]), ("464/IA/output", [6, 17, 50, 58]), ("464/OA/prerouting", [6, 17, 50, 58]), ("464/OA/output", [6, 17, 50, 58]), ("464/OB/prerouting", [6, 17, 50, 58]), ("464/OB/output", [6, 17, 50, 58]), ("464/IB/prerouting", [6, 17, 50, 58]), ("464/IB/output", [6, 17, 50, 58]), ("466/IA/prerouting", [6, 17, 50, 58]), ("466/IA/output", [6, 17, 50, 58]), ("466/OA/prerouting", [6, 17, 50, 58]), ("466/OA/output", [6, 17, 50, 58]), ("466/OB/prerouting", [6, 17, 50, 58]), ("466/OB/output", [6, 17, 50, 58]), ("466/IB/prerouting", [6, 17, 50, 58]), ("466/IB/output", [6, 17, 50, 58]), ("644/IA/prerouting", [6, 17, 50, 58]), ("644/IA/output", [6, 17, 50, 58]), ("644/OA/prerouting", [6, 17, 50, 58]), ("644/OA/output", [6, 17, 50, 58]), ("644/OB/prerouting", [6, 17, 50, 58]), ("644/OB/output", [6, 17, 50, 58]), ("644/IB/prerouting", [6, 17, 50, 58]), ("644/IB/output", [6, 17, 50, 58]), ("646/IA/prerouting", [6, 17, 50, 58]), ("646/IA/output", [6, 17, 50, 58]), ("646/OA/prerouting", [6, 17, 50, 58]), ("646/OA/output", [6, 17, 50, 58]), ("646/OB/prerouting", [6, 17, 50, 58]), ("646/OB/output", [6, 17, 50, 58]), ("646/IB/prerouting", [6, 17, 50, 58]), ("646/IB/output", [6, 17, 50, 58]), ("664/IA/prerouting", [6, 17, 50, 58]), ("664/IA/output", [6, 17, 50, 58]), ("664/OA/prerouting", [6, 17, 50, 58]), ("664/OA/output", [6, 17, 50, 58]), ("664/OB/prerouting", [6, 17, 50, 58]), ("664/OB/output", [6, 17, 50, 58]), ("664/IB/prerouting", [6, 17, 50, 58]), ("664/IB/output", [6, 17, 50, 58]), ("666/IA/prerouting", [6, 17, 50, 58]), ("666/IA/output", [6, 17, 50, 58]), ("666/OA/prerouting", [6, 17, 50, 58]), ("666/OA/output", [6, 17, 50, 58]), ("666/OB/prerouting", [6, 17, 50, 58]), ("666/OB/output", [6, 17, 50, 58]), ("666/IB/prerouting", [6, 17, 50, 58]), ("666/IB/output", [6, 17, 50, 58])]
def gatePriorities : List (String × Int) := [("444/IA/prerouting", (-450 : Int)), ("444/IA/output", (-450 : Int)), ("444/OA/prerouting", (-450 : Int)), ("444/OA/output", (-450 : Int)), ("444/OB/prerouting", (-450 : Int)), ("444/OB/output", (-450 : Int)), ("444/IB/prerouting", (-450 : Int)), ("444/IB/output", (-450 : Int)), ("446/IA/prerouting", (-450 : Int)), ("446/IA/output", (-450 : Int)), ("446/OA/prerouting", (-450 : Int)), ("446/OA/output", (-450 : Int)), ("446/OB/prerouting", (-450 : Int)), ("446/OB/output", (-450 : Int)), ("446/IB/prerouting", (-450 : Int)), ("446/IB/output", (-450 : Int)), ("464/IA/prerouting", (-450 : Int)), ("464/IA/output", (-450 : Int)), ("464/OA/prerouting", (-450 : Int)), ("464/OA/output", (-450 : Int)), ("464/OB/prerouting", (-450 : Int)), ("464/OB/output", (-450 : Int)), ("464/IB/prerouting", (-450 : Int)), ("464/IB/output", (-450 : Int)), ("466/IA/prerouting", (-450 : Int)), ("466/IA/output", (-450 : Int)), ("466/OA/prerouting", (-450 : Int)), ("466/OA/output", (-450 : Int)), ("466/OB/prerouting", (-450 : Int)), ("466/OB/output", (-450 : Int)), ("466/IB/prerouting", (-450 : Int)), ("466/IB/output", (-450 : Int)), ("644/IA/prerouting", (-450 : Int)), ("644/IA/output", (-450 : Int)), ("644/OA/prerouting", (-450 : Int)), ("644/OA/output", (-450 : Int)), ("644/OB/prerouting", (-450 : Int)), ("644/OB/output", (-450 : Int)), ("644/IB/prerouting", (-450 : Int)), ("644/IB/output", (-450 : Int)), ("646/IA/prerouting", (-450 : Int)), ("646/IA/output", (-450 : Int)), ("646/OA/prerouting", (-450 : Int)), ("646/OA/output", (-450 : Int)), ("646/OB/prerouting", (-450 : Int)), ("646/OB/output", (-450 : Int)), ("646/IB/prerouting", (-450 : Int)), ("646/IB/output", (-450 : Int)), ("664/IA/prerouting", (-450 : Int)), ("664/IA/output", (-450 : Int)), ("664/OA/prerouting", (-450 : Int)), ("664/OA/output", (-450 : Int)), ("664/OB/prerouting", (-450 : Int)), ("664/OB/output", (-450 : Int)), ("664/IB/prerouting", (-450 : Int)), ("664/IB/output", (-450 : Int)), ("666/IA/prerouting", (-450 : Int)), ("666/IA/output", (-450 : Int)), ("666/OA/prerouting", (-450 : Int)), ("666/OA/output", (-450 : Int)), ("666/OB/prerouting", (-450 : Int)), ("666/OB/output", (-450 : Int)), ("666/IB/prerouting", (-450 : Int)), ("666/IB/output", (-450 : Int))]

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
