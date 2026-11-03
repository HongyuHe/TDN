import TDN.Evidence.FreshBaselineTrust
import TDN.Evidence.FreshSharedTrust
import TDN.Targets.CompleteAuthenticationIsolation

namespace TDN.Imported.CompleteAuthenticationIsolation
open Targets Targets.Complete

def baselinePairs : List (String × String) :=
  [("NB_I_A1", "NB_I_B1"), ("NB_I_B1", "NB_I_A1"),
    ("NB_I_A2", "NB_I_B2"), ("NB_I_B2", "NB_I_A2")]

lemma baseline_pair_credentials :
    ∀ pair ∈ baselinePairs, ∃ a ∈ FreshBaselineTrust.peers,
      ∃ b ∈ FreshBaselineTrust.peers, a.component = pair.1 ∧
        b.component = pair.2 ∧ InnerCanAuthenticate a b := by decide

theorem baseline_configured_pair_model_RG012 :
    Targets.Complete.msc_security_level_key_and_management_separation false
      FreshBaselineTrust.peers (EstablishedInnerPair baselinePairs) := by
  apply key_and_management_separation_from_scoped_inventory false FreshBaselineTrust.peers
    FreshBaselineTrust.authorityLevel FreshBaselineTrust.authorityLevel
    FreshBaselineTrust.authorityLevel baselinePairs FreshBaselineTrust.credential_scopes
  · simp
  · simp
  · decide
  · exact baseline_pair_credentials

def sharedPairs : List (String × String) :=
  [("NF_I_A1", "NF_I_B1"), ("NF_I_B1", "NF_I_A1"),
    ("NF_I_A2", "NF_I_B2"), ("NF_I_B2", "NF_I_A2"),
    ("NF_I_A3", "NF_I_B3"), ("NF_I_B3", "NF_I_A3"),
    ("NF_I_A4", "NF_I_B4"), ("NF_I_B4", "NF_I_A4")]

lemma shared_pair_credentials :
    ∀ pair ∈ sharedPairs, ∃ a ∈ FreshSharedTrust.peers,
      ∃ b ∈ FreshSharedTrust.peers, a.component = pair.1 ∧
        b.component = pair.2 ∧ InnerCanAuthenticate a b := by decide

theorem shared_configured_pair_model_RG012 :
    Targets.Complete.msc_security_level_key_and_management_separation false
      FreshSharedTrust.peers (EstablishedInnerPair sharedPairs) := by
  apply key_and_management_separation_from_scoped_inventory false FreshSharedTrust.peers
    FreshSharedTrust.authorityLevel FreshSharedTrust.authorityLevel
    FreshSharedTrust.authorityLevel sharedPairs FreshSharedTrust.credential_scopes
  · simp
  · simp
  · decide
  · exact shared_pair_credentials

def low : SecurityLevel := ⟨"SECRET", {}, {}, {}⟩
def high : SecurityLevel := ⟨"TOP_SECRET", {}, {}, {}⟩

def pskPeers : List InnerAuthentication :=
  [⟨"low.A", low, .sharedKey "low.key", {"low.manager"}⟩,
    ⟨"low.B", low, .sharedKey "low.key", {"low.manager"}⟩,
    ⟨"high.A", high, .sharedKey "high.key", {"high.manager"}⟩,
    ⟨"high.B", high, .sharedKey "high.key", {"high.manager"}⟩]

def keyLevel (key : String) : SecurityLevel :=
  if key = "low.key" then low else high

def managementLevel (manager : String) : SecurityLevel :=
  if manager = "low.manager" then low else high

def pskPairs : List (String × String) :=
  [("low.A", "low.B"), ("high.A", "high.B")]

theorem managed_psk_model_RG012 :
    Targets.Complete.msc_security_level_key_and_management_separation true
      pskPeers (EstablishedInnerPair pskPairs) := by
  apply key_and_management_separation_from_scoped_inventory true pskPeers
    keyLevel keyLevel managementLevel pskPairs
  · decide
  · decide
  · decide
  · decide
  · decide

lemma baseline_actual_pair_nonempty :
    EstablishedInnerPair baselinePairs "NB_I_A1" "NB_I_B1" := by decide

lemma cross_level_establishment_rejected :
    ¬ Targets.Complete.msc_security_level_key_and_management_separation false
      FreshBaselineTrust.peers (EstablishedInnerPair
        (("NB_I_A1", "NB_I_B2") :: baselinePairs)) := by
  intro h
  let a := FreshBaselineTrust.peers[0]'(by decide)
  let b := FreshBaselineTrust.peers[3]'(by decide)
  have memberA : a ∈ FreshBaselineTrust.peers := by decide
  have memberB : b ∈ FreshBaselineTrust.peers := by decide
  exact h.2 a memberA b memberB (by decide) (by decide)

lemma cross_level_management_reuse_rejected :
    ¬ Targets.Complete.msc_security_level_key_and_management_separation true
      [⟨"low.A", low, .sharedKey "low.key", {"shared.manager"}⟩,
       ⟨"high.A", high, .sharedKey "high.key", {"shared.manager"}⟩]
      (EstablishedInnerPair []) := by
  intro h
  have separated := (h.1.2 _ (List.mem_cons_self ..) _
    (List.mem_cons_of_mem _ (List.mem_singleton_self _)) (by decide)).2.1 rfl
  exact (Finset.disjoint_left.mp separated)
    (by decide : "shared.manager" ∈ ({"shared.manager"} : Finset String)) (by decide)

end TDN.Imported.CompleteAuthenticationIsolation
