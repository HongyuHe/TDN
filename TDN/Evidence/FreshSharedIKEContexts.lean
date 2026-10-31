import TDN.Import.Command
import TDN.Semantics.IKEContexts

namespace TDN.Imported.FreshSharedIKEContexts
open IKEContexts

tdn_data endpoints : List Endpoint from "../../evidence/lean/FreshSharedIKEContexts.json" ["TDN.Imported.FreshSharedIKEContexts.endpoints"]

tdn_data pairs : List (Nat × Nat) from "../../evidence/lean/FreshSharedIKEContexts.json" ["TDN.Imported.FreshSharedIKEContexts.pairs"]

def endpoint (index : Nat) : Endpoint :=
  endpoints[index]?.getD ⟨0, "", "", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, false⟩

lemma all_context_pairs_checked : ∀ pair ∈ pairs, Peer (endpoint pair.1) (endpoint pair.2) := by decide
lemma complete_gateway_count : endpoints.length = 10 := by decide

theorem recorded_directional_contexts_agree : ∀ pair ∈ pairs,
    sendName (endpoint pair.1) = receiveName (endpoint pair.2) := by
  intro pair member
  exact reciprocal_peers_agree_on_directional_record _ _ (all_context_pairs_checked pair member)

end TDN.Imported.FreshSharedIKEContexts
