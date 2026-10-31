import TDN.Import.Command
import TDN.Targets.MACsecKeyServer

namespace TDN.Imported.FinalMACsecKeyServers
open Targets

/-- The two entries retain the forward and reverse EAP role arrangements. -/
tdn_data settings : List MACsecKeyServerSettings from "../../evidence/lean/FinalMACsecKeyServers.json" ["TDN.Imported.FinalMACsecKeyServers.settings"]

lemma local_settings : ∀ s ∈ settings, s.Checked := by decide

theorem configured_server_matches_central_site (s : MACsecKeyServerSettings)
    (member : s ∈ settings) (central : String) (present : s.centralSite = some central) :
    selectedKeyServer s = central :=
  checked_key_server_is_central (local_settings s member) present

theorem configured_priorities_are_distinct (s : MACsecKeyServerSettings) (member : s ∈ settings) :
    s.leftPriority ≠ s.rightPriority := checked_pair_has_distinct_priorities (local_settings s member)

lemma both_arrangements_present : settings.length = 2 := by decide

end TDN.Imported.FinalMACsecKeyServers
