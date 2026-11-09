import TDN.Deployments.MtuSizing_BaselineCasesData
import TDN.Deployments.MtuSizing_DownstreamPath

namespace TDN.Deployments.MtuSizing_Baseline
open Compliance Requirements OuterToGray_DeviceModel MtuSizing_Records
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

load_network_records continuation : List SizingMove from "../../data/evidence/continuation/SizingBaselineContinuation.json" ["moves"]
load_network_records transmission : SizingMove from "../../data/evidence/continuation/SizingBaselineContinuation.json" ["transmission"]

end TDN.Deployments.MtuSizing_Baseline
