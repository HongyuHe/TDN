import TDN.Deployments.MtuSizing_BaselineData
import TDN.Deployments.MtuSizing_CapturedFrames

namespace TDN.Deployments.MtuSizing_Baseline
open Compliance Requirements OuterToGray_DeviceModel MtuSizing_Records
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records path : SizingPath from "../../data/evidence/continuation/SizingBaselineCases.json" ["path"]
load_network_records frames : List CapturedSizingFrame from "../../data/evidence/continuation/SizingBaselineCases.json" ["frames"]

end TDN.Deployments.MtuSizing_Baseline
