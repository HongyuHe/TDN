import TDN.Semantics.IKEContexts

namespace TDN.Imported.FreshSharedIKEContexts
open IKEContexts

def endpoints : List Endpoint := [
  ⟨0, "NF_I_A1.msc.test", "NF_I_B1.msc.test", 174326018, 180879618, 5018351087995434592, 12938898099090383243, 3489353763, 3423243482, 167837952, 167838207, 167903488, 167903743, false, true⟩,
  ⟨1, "NF_I_A2.msc.test", "NF_I_B2.msc.test", 174326274, 180879874, 544550600578889677, 4085114442531150538, 3349471194, 3448300034, 167838208, 167838463, 167903744, 167903999, false, true⟩,
  ⟨2, "NF_I_A3.msc.test", "NF_I_B3.msc.test", 174326530, 180880130, 5999040999203723449, 1516566113559008694, 3303538228, 3349201953, 167838464, 167838719, 167904000, 167904255, false, false⟩,
  ⟨3, "NF_I_A4.msc.test", "NF_I_B4.msc.test", 174326786, 180880386, 5082369848009024059, 5250423242124085882, 3360074457, 3357648904, 167838720, 167838975, 167904256, 167904511, true, true⟩,
  ⟨4, "NF_I_B1.msc.test", "NF_I_A1.msc.test", 180879618, 174326018, 5018351087995434592, 12938898099090383243, 3423243482, 3489353763, 167903488, 167903743, 167837952, 167838207, true, true⟩,
  ⟨5, "NF_I_B2.msc.test", "NF_I_A2.msc.test", 180879874, 174326274, 544550600578889677, 4085114442531150538, 3448300034, 3349471194, 167903744, 167903999, 167838208, 167838463, true, true⟩,
  ⟨6, "NF_I_B3.msc.test", "NF_I_A3.msc.test", 180880130, 174326530, 5999040999203723449, 1516566113559008694, 3349201953, 3303538228, 167904000, 167904255, 167838464, 167838719, true, false⟩,
  ⟨7, "NF_I_B4.msc.test", "NF_I_A4.msc.test", 180880386, 174326786, 5082369848009024059, 5250423242124085882, 3357648904, 3360074457, 167904256, 167904511, 167838720, 167838975, false, true⟩,
  ⟨8, "NF_O_A1.msc.test", "NF_O_B1.msc.test", 2886994689, 2886997249, 9439823428899755865, 14589060278618543039, 3448372810, 3259174079, 174325760, 174391295, 180879360, 180944895, false, true⟩,
  ⟨9, "NF_O_B1.msc.test", "NF_O_A1.msc.test", 2886997249, 2886994689, 9439823428899755865, 14589060278618543039, 3259174079, 3448372810, 180879360, 180944895, 174325760, 174391295, true, true⟩]
def pairs : List (Nat × Nat) := [(0, 4), (1, 5), (2, 6), (3, 7), (4, 0), (5, 1), (6, 2), (7, 3), (8, 9), (9, 8)]

def endpoint (index : Nat) : Endpoint :=
  endpoints[index]?.getD ⟨0, "", "", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, false⟩

lemma all_context_pairs_checked : ∀ pair ∈ pairs, Peer (endpoint pair.1) (endpoint pair.2) := by decide
lemma complete_gateway_count : endpoints.length = 10 := by decide

theorem recorded_directional_contexts_agree : ∀ pair ∈ pairs,
    sendName (endpoint pair.1) = receiveName (endpoint pair.2) := by
  intro pair member
  exact reciprocal_peers_agree_on_directional_record _ _ (all_context_pairs_checked pair member)

end TDN.Imported.FreshSharedIKEContexts
