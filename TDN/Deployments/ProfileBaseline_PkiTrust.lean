import TDN.Import.SnapshotLoader
import TDN.Requirements.CrossEnclavePkiIsolationSpec

namespace TDN.Deployments.ProfileBaseline_PkiTrust

set_option maxRecDepth 100000

def authorityLevel (key : String) : SecurityLevel :=
  if key = "4c585fb8185f71481267d10335458eaa4b233ccff56b090d2eb803242748e361" then ⟨"SECRET", {}, {}, {}⟩ else
  if key = "677c321dd2d46d8191844c3d072d06ed4f36686b7f4b813ecf24091385bb39f7" then ⟨"TOP_SECRET", {}, {}, {}⟩ else
  ⟨"UNASSIGNED", {}, {}, {}⟩

load_network_records peers : List Requirements.InnerAuthentication from "../../data/evidence/ProfileBaseline_PkiTrust.json" ["TDN.Deployments.ProfileBaseline_PkiTrust.peers"]

lemma credential_scopes : ∀ peer ∈ peers, Requirements.CredentialScoped authorityLevel authorityLevel peer := by
  simp [peers, authorityLevel, Requirements.CredentialScoped]

theorem authority_material_separation : ∀ a ∈ peers, ∀ b ∈ peers, a.level ≠ b.level → Requirements.MaterialsSeparated a b := by
  intro a ha b hb different
  exact Requirements.scoped_materials_separated (credential_scopes a ha) (credential_scopes b hb) different

theorem no_cross_level_authentication : ∀ a ∈ peers, ∀ b ∈ peers, a.level ≠ b.level → ¬ Requirements.InnerCanAuthenticate a b := by
  intro a ha b hb different
  exact Requirements.scoped_inner_peers_cannot_cross_levels (credential_scopes a ha) (credential_scopes b hb) different

theorem snapshot_RG012_management_free :
    Requirements.msc_security_level_key_and_management_separation false peers := by
  exact Requirements.separate_authentication_and_management_of_scoped_material false peers
    authorityLevel authorityLevel credential_scopes (by simp) (by simp)

end TDN.Deployments.ProfileBaseline_PkiTrust
