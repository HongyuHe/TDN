import TDN.Evidence.SizingBaselineData
import TDN.Evidence.SizingSharedData
import TDN.Evidence.PacketSizingChecks

namespace TDN.Imported
open PacketSizingRecords

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

#eval decide (SizeRecordChecks SizingBaseline.records SizingBaseline.installations SizingBaseline.roles)
#eval decide (SizeRecordChecks SizingShared.records SizingShared.installations SizingShared.roles)
#eval (SizingBaseline.records.routes.filter (fun route => !decide (RouteProgramCheck SizingBaseline.records SizingBaseline.roles false route))).map
  (fun route => (SizingBaseline.records.ifaceName route.ingress, SizingBaseline.records.ifaceName route.egress, route.low, route.high))
#eval (SizingBaseline.records.routes.filter (fun route => !decide (RouteProgramCheck SizingBaseline.records SizingBaseline.roles true route))).map
  (fun route => (SizingBaseline.records.ifaceName route.ingress, SizingBaseline.records.ifaceName route.egress, route.low, route.high))
#eval (SizingShared.records.routes.filter (fun route => !decide (RouteProgramCheck SizingShared.records SizingShared.roles false route))).map
  (fun route => (SizingShared.records.ifaceName route.ingress, SizingShared.records.ifaceName route.egress, route.low, route.high))
#eval (SizingShared.records.routes.filter (fun route => !decide (RouteProgramCheck SizingShared.records SizingShared.roles true route))).map
  (fun route => (SizingShared.records.ifaceName route.ingress, SizingShared.records.ifaceName route.egress, route.low, route.high))

#eval SizingBaseline.records.links.filter (fun edge => decide (sourceMtu SizingBaseline.roles edge.2 < sourceMtu SizingBaseline.roles edge.1)) |>.map
  (fun edge => (SizingBaseline.records.ifaceName edge.1, sourceMtu SizingBaseline.roles edge.1,
    SizingBaseline.records.ifaceName edge.2, sourceMtu SizingBaseline.roles edge.2))
#eval SizingShared.records.links.filter (fun edge => decide (sourceMtu SizingShared.roles edge.2 < sourceMtu SizingShared.roles edge.1)) |>.map
  (fun edge => (SizingShared.records.ifaceName edge.1, sourceMtu SizingShared.roles edge.1,
    SizingShared.records.ifaceName edge.2, sourceMtu SizingShared.roles edge.2))
#eval SizingBaseline.records.bridges.filter (fun edge => decide (sourceMtu SizingBaseline.roles edge.2 < sourceMtu SizingBaseline.roles edge.1))
#eval decide (∀ route ∈ SizingBaseline.records.routes, ∀ policy ∈ SizingBaseline.records.configuration.ip.outbound route.ingress,
    route.low ≤ policy.receiver → policy.receiver ≤ route.high → requiredSizing SizingBaseline.roles route.egress = true →
      PacketLength.alignedWireLength 4 2 52 (plaintextLimit policy.tag) ≤ sourceMtu SizingBaseline.roles route.egress)
#eval decide (∀ device ∈ SizingBaseline.records.nativeDevices, ∀ policy ∈ device.inbound,
    plaintextLimit policy.tag ≤ authenticationLimit policy.id)
#eval decide (∀ edge ∈ SizingBaseline.records.bridges, requiredSizing SizingBaseline.roles edge.2 = false)
#eval decide (∀ route ∈ SizingBaseline.records.routes, route.high < 2^32)

end TDN.Imported
