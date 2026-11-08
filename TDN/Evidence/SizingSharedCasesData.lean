import TDN.Evidence.SizingSharedData
import TDN.Evidence.PacketSizingCapturedFrames

namespace TDN.Imported.SizingShared
open Compliance Targets OuterGrayNativeModel PacketSizingRecords
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data path : SizingPath from "../../data/evidence/continuation/SizingSharedCases.json" ["path"]
tdn_data frames : List CapturedSizingFrame from "../../data/evidence/continuation/SizingSharedCases.json" ["frames"]

end TDN.Imported.SizingShared
