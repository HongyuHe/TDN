import TDN.Deployments.MtuSizing_BaselineCasesData
import TDN.Deployments.MtuSizing_SharedCasesData

namespace TDN.Deployments
open MtuSizing_Records PacketSource
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

#eval decide (MtuSizing_Baseline.path.Checks MtuSizing_Baseline.records MtuSizing_Baseline.installations)
#eval decide (MtuSizing_Shared.path.Checks MtuSizing_Shared.records MtuSizing_Shared.installations)
#eval decide (MtuSizing_Baseline.path.SourceChecks MtuSizing_Baseline.records MtuSizing_Baseline.entries MtuSizing_Baseline.roles MtuSizing_Baseline.networks)
#eval decide (MtuSizing_Shared.path.SourceChecks MtuSizing_Shared.records MtuSizing_Shared.entries MtuSizing_Shared.roles MtuSizing_Shared.networks)
#eval (MtuSizing_Baseline.frames.filter (fun frame => !decide (frame.Checked MtuSizing_Baseline.records MtuSizing_Baseline.installations MtuSizing_Baseline.roles))).map CapturedSizingFrame.id
#eval (MtuSizing_Shared.frames.filter (fun frame => !decide (frame.Checked MtuSizing_Shared.records MtuSizing_Shared.installations MtuSizing_Shared.roles))).map CapturedSizingFrame.id
#eval emittedFragmentCount (processSource 1320 (MtuSizing_Baseline.path.oversizeRequest 1321 false))
#eval emittedFragmentCount (processSource 1320 (MtuSizing_Baseline.path.oversizeRequest 4028 false))

end TDN.Deployments
