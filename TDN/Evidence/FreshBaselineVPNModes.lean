import TDN.Targets.Protocol

namespace TDN.Imported.FreshBaselineVPNModes

def policies : List Targets.VPNModePolicy := [⟨"NB_I_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_O_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_I_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_O_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_I_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_O_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_I_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NB_O_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩]

lemma nonempty_gateway_inventory : policies ≠ [] := by decide

theorem complete_loaded_mode_configuration :
    Targets.msc_ike_version_and_encryption_modes policies := by
  apply Targets.vpn_mode_policies_from_complete_local_checks
  · decide
  · decide
  · decide

end TDN.Imported.FreshBaselineVPNModes
