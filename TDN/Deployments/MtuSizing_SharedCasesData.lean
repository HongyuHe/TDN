import TDN.Deployments.MtuSizing_SharedData
import TDN.Deployments.MtuSizing_CapturedFrames

namespace TDN.Deployments.MtuSizing_Shared
open Compliance Requirements OuterToGray_DeviceModel MtuSizing_Records
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records path : SizingPath from "../../data/evidence/continuation/SizingSharedCases.json" ["path"]
load_network_records frames : List CapturedSizingFrame from "../../data/evidence/continuation/SizingSharedCases.json" ["frames"]

end TDN.Deployments.MtuSizing_Shared
