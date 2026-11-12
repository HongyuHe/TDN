import TDN.Deployments.ProfileBaseline_PkiTrust
import TDN.Deployments.ProfileShared_PkiTrust
import TDN.Requirements.VerifiedPkiDomainIsolation

namespace TDN.Deployments.SnapshotProof_PkiIsolation
open Requirements Requirements.Msc

def baselinePairs : List (String × String) :=
  [("NB_I_A1", "NB_I_B1"), ("NB_I_B1", "NB_I_A1"),
    ("NB_I_A2", "NB_I_B2"), ("NB_I_B2", "NB_I_A2")]

lemma baseline_pair_credentials :
    ∀ pair ∈ baselinePairs, ∃ a ∈ ProfileBaseline_PkiTrust.peers,
      ∃ b ∈ ProfileBaseline_PkiTrust.peers, a.component = pair.1 ∧
        b.component = pair.2 ∧ InnerCanAuthenticate a b := by native_decide

theorem baseline_configured_pair_model_RG012 :
    Requirements.Msc.msc_security_level_key_and_management_separation false
      ProfileBaseline_PkiTrust.peers (EstablishedInnerPair baselinePairs) := by
  apply key_and_management_separation_from_scoped_inventory false ProfileBaseline_PkiTrust.peers
    ProfileBaseline_PkiTrust.authorityLevel ProfileBaseline_PkiTrust.authorityLevel
    ProfileBaseline_PkiTrust.authorityLevel baselinePairs ProfileBaseline_PkiTrust.credential_scopes
  · simp
  · simp
  · native_decide
  · exact baseline_pair_credentials

def sharedPairs : List (String × String) :=
  [("NF_I_A1", "NF_I_B1"), ("NF_I_B1", "NF_I_A1"),
    ("NF_I_A2", "NF_I_B2"), ("NF_I_B2", "NF_I_A2"),
    ("NF_I_A3", "NF_I_B3"), ("NF_I_B3", "NF_I_A3"),
    ("NF_I_A4", "NF_I_B4"), ("NF_I_B4", "NF_I_A4")]

lemma shared_pair_credentials :
    ∀ pair ∈ sharedPairs, ∃ a ∈ ProfileShared_PkiTrust.peers,
      ∃ b ∈ ProfileShared_PkiTrust.peers, a.component = pair.1 ∧
        b.component = pair.2 ∧ InnerCanAuthenticate a b := by native_decide

theorem shared_configured_pair_model_RG012 :
    Requirements.Msc.msc_security_level_key_and_management_separation false
      ProfileShared_PkiTrust.peers (EstablishedInnerPair sharedPairs) := by
  apply key_and_management_separation_from_scoped_inventory false ProfileShared_PkiTrust.peers
    ProfileShared_PkiTrust.authorityLevel ProfileShared_PkiTrust.authorityLevel
    ProfileShared_PkiTrust.authorityLevel sharedPairs ProfileShared_PkiTrust.credential_scopes
  · simp
  · simp
  · native_decide
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
    Requirements.Msc.msc_security_level_key_and_management_separation true
      pskPeers (EstablishedInnerPair pskPairs) := by
  apply key_and_management_separation_from_scoped_inventory true pskPeers
    keyLevel keyLevel managementLevel pskPairs
  · native_decide
  · native_decide
  · native_decide
  · native_decide
  · native_decide
lemma baseline_actual_pair_nonempty :
    EstablishedInnerPair baselinePairs "NB_I_A1" "NB_I_B1" := by native_decide

lemma cross_level_establishment_rejected :
    ¬ Requirements.Msc.msc_security_level_key_and_management_separation false
      ProfileBaseline_PkiTrust.peers (EstablishedInnerPair
        (("NB_I_A1", "NB_I_B2") :: baselinePairs)) := by
  intro h
  let a := ProfileBaseline_PkiTrust.peers[0]'(by native_decide)
  let b := ProfileBaseline_PkiTrust.peers[3]'(by native_decide)
  have memberA : a ∈ ProfileBaseline_PkiTrust.peers := by native_decide
  have memberB : b ∈ ProfileBaseline_PkiTrust.peers := by native_decide
  exact h.2 a memberA b memberB (by native_decide) (by native_decide)

lemma cross_level_management_reuse_rejected :
    ¬ Requirements.Msc.msc_security_level_key_and_management_separation true
      [⟨"low.A", low, .sharedKey "low.key", {"shared.manager"}⟩,
       ⟨"high.A", high, .sharedKey "high.key", {"shared.manager"}⟩]
      (EstablishedInnerPair []) := by
  intro h
  have separated := (h.1.2 _ (List.mem_cons_self ..) _
    (List.mem_cons_of_mem _ (List.mem_singleton_self _)) (by native_decide)).2.1 rfl
  exact (Finset.disjoint_left.mp separated)
    (by native_decide : "shared.manager" ∈ ({"shared.manager"} : Finset String)) (by native_decide)

end TDN.Deployments.SnapshotProof_PkiIsolation
