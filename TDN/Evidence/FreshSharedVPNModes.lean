import TDN.Targets.Protocol

namespace TDN.Imported.FreshSharedVPNModes

def policies : List Targets.VPNModePolicy := [⟨"NF_I_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_O_A1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_A2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_O_B1/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_B2/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_A3/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_B3/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_A4/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩, ⟨"NF_I_B4/msc", [2], [.gcm], [⟨.gcm, false⟩]⟩]

lemma nonempty_gateway_inventory : policies ≠ [] := by decide

theorem complete_loaded_mode_configuration :
    Targets.msc_ike_version_and_encryption_modes policies := by
  apply Targets.vpn_mode_policies_from_complete_local_checks
  · decide
  · decide
  · decide

end TDN.Imported.FreshSharedVPNModes
