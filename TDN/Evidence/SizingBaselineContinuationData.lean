import TDN.Evidence.SizingBaselineCasesData
import TDN.Evidence.PacketSizingContinuation

namespace TDN.Imported.SizingBaseline
open Compliance Targets OuterGrayNativeModel PacketSizingRecords
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

tdn_data continuation : List SizingMove from "../../data/evidence/continuation/SizingBaselineContinuation.json" ["moves"]
tdn_data transmission : SizingMove from "../../data/evidence/continuation/SizingBaselineContinuation.json" ["transmission"]

end TDN.Imported.SizingBaseline
