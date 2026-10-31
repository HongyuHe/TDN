import TDN.Import.Command
import TDN.Evidence.NativeSameLevel

import TDN.Targets.Headers

namespace TDN.Imported.NativeSameLevelHeaders

open TDN.Imported.native_samelevel_20261017T2242Z

set_option maxRecDepth 100000

set_option maxHeartbeats 0

tdn_data gateways : List Targets.GatewayHeaderPolicy from "../../evidence/lean/NativeSameLevelHeaders.json" ["TDN.Imported.NativeSameLevelHeaders.gateways"]

lemma all_header_certificates : ∀ g ∈ gateways, Targets.HeaderCertificate g := by unfold gateways; decide

theorem snapshot_RG038 : Targets.msc_ip_header_and_multicast_filtering gateways := Targets.header_certificates_suffice gateways (by unfold gateways; decide) all_header_certificates

end TDN.Imported.NativeSameLevelHeaders
