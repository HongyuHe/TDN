import TDN.Import.Command
import TDN.Targets.Components

namespace TDN.Imported.FreshMACsecOptions
open TDN.Targets

/-- Capability facts describe observed operational support under the recorded
Linux implementation contract, with all other protection duties kept separate. -/
tdn_data options : List MACsecOptions from "../../evidence/lean/FreshMACsecOptions.json" ["TDN.Imported.FreshMACsecOptions.options"]

lemma all_selected_ports_present : options.length = 6 := by decide

theorem selected_options_use_supported_features :
    msc_macsec_optional_clear_vlan_and_xpn options := by
  apply macsec_options_of_supported_enablement
  · decide
  · decide

end TDN.Imported.FreshMACsecOptions
