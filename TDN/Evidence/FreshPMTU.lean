import TDN.Import.Command
import TDN.Targets.PacketSizing

namespace TDN.Imported.FreshPMTU

tdn_data initialIPLimit : Nat from "../../evidence/lean/FreshPMTU.json" ["TDN.Imported.FreshPMTU.initialIPLimit"]

tdn_data effectiveIPLimit : Nat from "../../evidence/lean/FreshPMTU.json" ["TDN.Imported.FreshPMTU.effectiveIPLimit"]

tdn_data blackMtu : Nat from "../../evidence/lean/FreshPMTU.json" ["TDN.Imported.FreshPMTU.blackMtu"]

tdn_data successfulUDPPayload : Nat from "../../evidence/lean/FreshPMTU.json" ["TDN.Imported.FreshPMTU.successfulUDPPayload"]

/-- Complete inner IP length maps to outer IPv6 ESP length under minimal padding. -/
def encodedLength := PacketLength.alignedWireLength 4 2 72

lemma discovered_limit_is_smaller : effectiveIPLimit < initialIPLimit := by decide
lemma maximum_fits : encodedLength effectiveIPLimit ≤ blackMtu := by decide

theorem every_datagram_within_discovered_limit_fits (bytes : Nat)
    (bounded : bytes ≤ effectiveIPLimit) : encodedLength bytes ≤ blackMtu :=
  PacketLength.all_sizes_fit_from_maximum 4 2 72 effectiveIPLimit blackMtu maximum_fits bytes bounded

theorem observed_useful_payload_fits :
    encodedLength (successfulUDPPayload + 40 + 8) ≤ blackMtu :=
  every_datagram_within_discovered_limit_fits _ (by decide)

end TDN.Imported.FreshPMTU
