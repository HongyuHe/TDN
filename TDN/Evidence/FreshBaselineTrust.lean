import TDN.Targets.AuthenticationIsolation

namespace TDN.Imported.FreshBaselineTrust

set_option maxRecDepth 100000

def authorityLevel (key : String) : SecurityLevel :=
  if key = "4c585fb8185f71481267d10335458eaa4b233ccff56b090d2eb803242748e361" then ⟨"SECRET", {}, {}, {}⟩ else
  if key = "677c321dd2d46d8191844c3d072d06ed4f36686b7f4b813ecf24091385bb39f7" then ⟨"TOP_SECRET", {}, {}, {}⟩ else
  ⟨"UNASSIGNED", {}, {}, {}⟩

def peers : List Targets.InnerAuthentication := [
  ⟨"NB_I_A1", ⟨"SECRET", {}, {}, {}⟩, .certificate "4c585fb8185f71481267d10335458eaa4b233ccff56b090d2eb803242748e361" ["4c585fb8185f71481267d10335458eaa4b233ccff56b090d2eb803242748e361"], {}⟩,
  ⟨"NB_I_A2", ⟨"TOP_SECRET", {}, {}, {}⟩, .certificate "677c321dd2d46d8191844c3d072d06ed4f36686b7f4b813ecf24091385bb39f7" ["677c321dd2d46d8191844c3d072d06ed4f36686b7f4b813ecf24091385bb39f7"], {}⟩,
  ⟨"NB_I_B1", ⟨"SECRET", {}, {}, {}⟩, .certificate "4c585fb8185f71481267d10335458eaa4b233ccff56b090d2eb803242748e361" ["4c585fb8185f71481267d10335458eaa4b233ccff56b090d2eb803242748e361"], {}⟩,
  ⟨"NB_I_B2", ⟨"TOP_SECRET", {}, {}, {}⟩, .certificate "677c321dd2d46d8191844c3d072d06ed4f36686b7f4b813ecf24091385bb39f7" ["677c321dd2d46d8191844c3d072d06ed4f36686b7f4b813ecf24091385bb39f7"], {}⟩]

/-- Management is explicitly unselected in this data-path configuration. -/
lemma credential_scopes : ∀ peer ∈ peers, Targets.CredentialScoped authorityLevel authorityLevel peer := by
  simp [peers, authorityLevel, Targets.CredentialScoped]

theorem authority_material_separation : ∀ a ∈ peers, ∀ b ∈ peers, a.level ≠ b.level → Targets.MaterialsSeparated a b := by
  intro a ha b hb different
  exact Targets.scoped_materials_separated (credential_scopes a ha) (credential_scopes b hb) different

theorem no_cross_level_authentication : ∀ a ∈ peers, ∀ b ∈ peers, a.level ≠ b.level → ¬ Targets.InnerCanAuthenticate a b := by
  intro a ha b hb different
  exact Targets.scoped_inner_peers_cannot_cross_levels (credential_scopes a ha) (credential_scopes b hb) different

/-- All applicable RG-012 clauses for the selected management-free configuration. -/
theorem snapshot_RG012_management_free :
    Targets.msc_security_level_key_and_management_separation false peers := by
  exact Targets.separate_authentication_and_management_of_scoped_material false peers
    authorityLevel authorityLevel credential_scopes (by simp) (by simp)

end TDN.Imported.FreshBaselineTrust
