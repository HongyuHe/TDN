import TDN.Import.Command
import TDN.Targets.AuthenticationIsolation

namespace TDN.Imported.FreshSharedTrust

set_option maxRecDepth 100000

def authorityLevel (key : String) : SecurityLevel :=
  if key = "1ff3833cf6d196f1e1a1375caa7ca50703aa8bf11b2ea15d629440ca129edc08" then ⟨"TOP_SECRET", {}, {}, {}⟩ else
  if key = "5318c93f1e495edd4c13212034ef6b2a711b86c9e2b3a3993e0c12a71c02fea8" then ⟨"SECRET", {}, {"US_ONLY"}, {}⟩ else
  if key = "e132c8956082ed2db0e6c527d2a2241f334f8d2cf872348b23b586b817b56c5e" then ⟨"UNCLASSIFIED", {}, {}, {}⟩ else
  if key = "f2070d2573de2ce24cc4447f5634ff623c62b6083614e83f32a7f55fa883424c" then ⟨"SECRET", {}, {"COALITION"}, {}⟩ else
  ⟨"UNASSIGNED", {}, {}, {}⟩

tdn_data peers : List Targets.InnerAuthentication from "../../data/evidence/FreshSharedTrust.json" ["TDN.Imported.FreshSharedTrust.peers"]

lemma credential_scopes : ∀ peer ∈ peers, Targets.CredentialScoped authorityLevel authorityLevel peer := by
  simp [peers, authorityLevel, Targets.CredentialScoped]

theorem authority_material_separation : ∀ a ∈ peers, ∀ b ∈ peers, a.level ≠ b.level → Targets.MaterialsSeparated a b := by
  intro a ha b hb different
  exact Targets.scoped_materials_separated (credential_scopes a ha) (credential_scopes b hb) different

theorem no_cross_level_authentication : ∀ a ∈ peers, ∀ b ∈ peers, a.level ≠ b.level → ¬ Targets.InnerCanAuthenticate a b := by
  intro a ha b hb different
  exact Targets.scoped_inner_peers_cannot_cross_levels (credential_scopes a ha) (credential_scopes b hb) different

theorem snapshot_RG012_management_free :
    Targets.msc_security_level_key_and_management_separation false peers := by
  exact Targets.separate_authentication_and_management_of_scoped_material false peers
    authorityLevel authorityLevel credential_scopes (by simp) (by simp)

end TDN.Imported.FreshSharedTrust
