import TDN.Import.SnapshotLoader
import TDN.Models.IkePeerSessionAgreement

namespace TDN.Deployments.ProfileShared_IkeSessions
open IKEContexts

load_network_records endpoints : List Endpoint from "../../data/evidence/ProfileShared_IkeSessions.json" ["TDN.Deployments.ProfileShared_IkeSessions.endpoints"]

load_network_records pairs : List (Nat × Nat) from "../../data/evidence/ProfileShared_IkeSessions.json" ["TDN.Deployments.ProfileShared_IkeSessions.pairs"]

def endpoint (index : Nat) : Endpoint :=
  endpoints[index]?.getD ⟨0, "", "", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, false⟩

lemma all_context_pairs_checked : ∀ pair ∈ pairs, Peer (endpoint pair.1) (endpoint pair.2) := by native_decide
lemma complete_gateway_count : endpoints.length = 10 := by native_decide

theorem recorded_directional_contexts_agree : ∀ pair ∈ pairs,
    sendName (endpoint pair.1) = receiveName (endpoint pair.2) := by
  intro pair member
  exact reciprocal_peers_agree_on_directional_record _ _ (all_context_pairs_checked pair member)

end TDN.Deployments.ProfileShared_IkeSessions
