import TDN.Deployments.MtuSizing_BaselineData
import TDN.Deployments.MtuSizing_SharedData
import TDN.Deployments.MtuSizing_Checks

namespace TDN.Deployments
open MtuSizing_Records

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

#eval decide (SizeRecordChecks MtuSizing_Baseline.records MtuSizing_Baseline.installations MtuSizing_Baseline.roles)
#eval decide (SizeRecordChecks MtuSizing_Shared.records MtuSizing_Shared.installations MtuSizing_Shared.roles)
#eval (MtuSizing_Baseline.records.routes.filter (fun route => !decide (RouteProgramCheck MtuSizing_Baseline.records MtuSizing_Baseline.roles false route))).map
  (fun route => (MtuSizing_Baseline.records.ifaceName route.ingress, MtuSizing_Baseline.records.ifaceName route.egress, route.destPrefixLow, route.destPrefixHigh))
#eval (MtuSizing_Baseline.records.routes.filter (fun route => !decide (RouteProgramCheck MtuSizing_Baseline.records MtuSizing_Baseline.roles true route))).map
  (fun route => (MtuSizing_Baseline.records.ifaceName route.ingress, MtuSizing_Baseline.records.ifaceName route.egress, route.destPrefixLow, route.destPrefixHigh))
#eval (MtuSizing_Shared.records.routes.filter (fun route => !decide (RouteProgramCheck MtuSizing_Shared.records MtuSizing_Shared.roles false route))).map
  (fun route => (MtuSizing_Shared.records.ifaceName route.ingress, MtuSizing_Shared.records.ifaceName route.egress, route.destPrefixLow, route.destPrefixHigh))
#eval (MtuSizing_Shared.records.routes.filter (fun route => !decide (RouteProgramCheck MtuSizing_Shared.records MtuSizing_Shared.roles true route))).map
  (fun route => (MtuSizing_Shared.records.ifaceName route.ingress, MtuSizing_Shared.records.ifaceName route.egress, route.destPrefixLow, route.destPrefixHigh))

#eval MtuSizing_Baseline.records.links.filter (fun edge => decide (sourceMtu MtuSizing_Baseline.roles edge.2 < sourceMtu MtuSizing_Baseline.roles edge.1)) |>.map
  (fun edge => (MtuSizing_Baseline.records.ifaceName edge.1, sourceMtu MtuSizing_Baseline.roles edge.1,
    MtuSizing_Baseline.records.ifaceName edge.2, sourceMtu MtuSizing_Baseline.roles edge.2))
#eval MtuSizing_Shared.records.links.filter (fun edge => decide (sourceMtu MtuSizing_Shared.roles edge.2 < sourceMtu MtuSizing_Shared.roles edge.1)) |>.map
  (fun edge => (MtuSizing_Shared.records.ifaceName edge.1, sourceMtu MtuSizing_Shared.roles edge.1,
    MtuSizing_Shared.records.ifaceName edge.2, sourceMtu MtuSizing_Shared.roles edge.2))
#eval MtuSizing_Baseline.records.bridges.filter (fun edge => decide (sourceMtu MtuSizing_Baseline.roles edge.2 < sourceMtu MtuSizing_Baseline.roles edge.1))
#eval decide (∀ route ∈ MtuSizing_Baseline.records.routes, ∀ policy ∈ MtuSizing_Baseline.records.configuration.ip.egressPolicies route.ingress,
    route.destPrefixLow ≤ policy.receiver → policy.receiver ≤ route.destPrefixHigh → requiredSizing MtuSizing_Baseline.roles route.egress = true →
      PacketLength.alignedWireLength 4 2 52 (plaintextLimit policy.tag) ≤ sourceMtu MtuSizing_Baseline.roles route.egress)
#eval decide (∀ device ∈ MtuSizing_Baseline.records.nativeDevices, ∀ policy ∈ device.ingressPolicies,
    plaintextLimit policy.tag ≤ authenticationLimit policy.id)
#eval decide (∀ edge ∈ MtuSizing_Baseline.records.bridges, requiredSizing MtuSizing_Baseline.roles edge.2 = false)
#eval decide (∀ route ∈ MtuSizing_Baseline.records.routes, route.destPrefixHigh < 2^32)

end TDN.Deployments
