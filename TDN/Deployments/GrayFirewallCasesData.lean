import TDN.Deployments.GrayFirewallCasesModel

namespace TDN.Deployments.GrayFirewallCases
open OuterToGray_DeviceModel

load_network_records reply : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["reply"]
load_network_records ordinaryIKE : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["ordinaryIKE"]
load_network_records replyWithOptions : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["replyWithOptions"]
load_network_records esp : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["esp"]
load_network_records udpESP : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["udpESP"]
load_network_records malformedIKE : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["malformedIKE"]
load_network_records baselineCross : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["baselineCross"]
load_network_records sharedCross : ForwardCase from "../../data/evidence/continuation/GrayFirewallCases.json" ["sharedCross"]

end TDN.Deployments.GrayFirewallCases

namespace TDN.Deployments.GrayFirewallCases
open Compliance

load_network_records baselineCrossSource : Device from "../../data/evidence/continuation/GrayFirewallCases.json" ["baselineCrossSource"]
load_network_records baselineCrossDestination : Device from "../../data/evidence/continuation/GrayFirewallCases.json" ["baselineCrossDestination"]
load_network_records sharedCrossSource : Device from "../../data/evidence/continuation/GrayFirewallCases.json" ["sharedCrossSource"]
load_network_records sharedCrossDestination : Device from "../../data/evidence/continuation/GrayFirewallCases.json" ["sharedCrossDestination"]

end TDN.Deployments.GrayFirewallCases
