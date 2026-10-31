import TDN.Import.Command
import TDN.Targets.Protocol

namespace TDN.Imported.FreshSharedVPNModes

tdn_data policies : List Targets.VPNModePolicy from "../../evidence/lean/FreshSharedVPNModes.json" ["TDN.Imported.FreshSharedVPNModes.policies"]

lemma nonempty_gateway_inventory : policies ≠ [] := by decide

theorem complete_loaded_mode_configuration :
    Targets.msc_ike_version_and_encryption_modes policies := by
  apply Targets.vpn_mode_policies_from_complete_local_checks
  · decide
  · decide
  · decide

end TDN.Imported.FreshSharedVPNModes
