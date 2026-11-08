import TDN.Evidence.SizingBaselineCasesData
import TDN.Evidence.SizingSharedCasesData

namespace TDN.Imported
open PacketSizingRecords PacketSource
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

#eval decide (SizingBaseline.path.Checks SizingBaseline.records SizingBaseline.installations)
#eval decide (SizingShared.path.Checks SizingShared.records SizingShared.installations)
#eval decide (SizingBaseline.path.SourceChecks SizingBaseline.records SizingBaseline.entries SizingBaseline.roles SizingBaseline.networks)
#eval decide (SizingShared.path.SourceChecks SizingShared.records SizingShared.entries SizingShared.roles SizingShared.networks)
#eval (SizingBaseline.frames.filter (fun frame => !decide (frame.Checked SizingBaseline.records SizingBaseline.installations SizingBaseline.roles))).map CapturedSizingFrame.id
#eval (SizingShared.frames.filter (fun frame => !decide (frame.Checked SizingShared.records SizingShared.installations SizingShared.roles))).map CapturedSizingFrame.id
#eval emittedFragmentCount (processSource 1320 (SizingBaseline.path.oversizeRequest 1321 false))
#eval emittedFragmentCount (processSource 1320 (SizingBaseline.path.oversizeRequest 4028 false))

end TDN.Imported
