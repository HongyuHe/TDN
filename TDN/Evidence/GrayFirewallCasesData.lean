import TDN.Evidence.GrayFirewallCasesModel

namespace TDN.Imported.GrayFirewallCases
open OuterGrayNativeModel

tdn_data reply : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["reply"]
tdn_data ordinaryIKE : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["ordinaryIKE"]
tdn_data replyWithOptions : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["replyWithOptions"]
tdn_data esp : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["esp"]
tdn_data udpESP : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["udpESP"]
tdn_data malformedIKE : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["malformedIKE"]
tdn_data baselineCross : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["baselineCross"]
tdn_data sharedCross : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["sharedCross"]

end TDN.Imported.GrayFirewallCases

namespace TDN.Imported.GrayFirewallCases
open Compliance

tdn_data baselineCrossSource : Device from "../../data/evidence/continuation/GrayFirewallCases.json" ["baselineCrossSource"]
tdn_data baselineCrossDestination : Device from "../../data/evidence/continuation/GrayFirewallCases.json" ["baselineCrossDestination"]
tdn_data sharedCrossSource : Device from "../../data/evidence/continuation/GrayFirewallCases.json" ["sharedCrossSource"]
tdn_data sharedCrossDestination : Device from "../../data/evidence/continuation/GrayFirewallCases.json" ["sharedCrossDestination"]

end TDN.Imported.GrayFirewallCases
