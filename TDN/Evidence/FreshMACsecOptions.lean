import TDN.Targets.Components

namespace TDN.Imported.FreshMACsecOptions
open TDN.Targets

/-- Capability facts describe observed operational support under the recorded
Linux implementation contract, with all other protection duties kept separate. -/
def options : List MACsecOptions := [⟨false, false, true, true⟩, ⟨false, false, true, true⟩, ⟨true, true, true, true⟩, ⟨true, true, true, true⟩, ⟨true, true, true, true⟩, ⟨true, true, true, true⟩]

lemma all_selected_ports_present : options.length = 6 := by decide

theorem selected_options_use_supported_features :
    msc_macsec_optional_clear_vlan_and_xpn options := by
  apply macsec_options_of_supported_enablement
  · decide
  · decide

end TDN.Imported.FreshMACsecOptions
