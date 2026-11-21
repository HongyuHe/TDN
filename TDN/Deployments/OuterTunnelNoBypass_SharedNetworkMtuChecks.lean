import TDN.Import.CompiledDecide
import TDN.Deployments.OuterTunnelNoBypass_SharedNetworkData
import TDN.Deployments.MtuSizing_SourceBounds

set_option synthInstance.maxSize 16384

namespace TDN.Deployments.OuterTunnelNoBypass_SharedNetwork
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records
set_option maxRecDepth 1000000

lemma captured_size_checks : SizeRecordChecks records installations roles := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  all_goals native_decide

lemma captured_mtu_checks : RoleMtuChecks roles := by
  native_decide

lemma captured_route_egresses : ∀ route ∈ records.routes, route.egress ∈ records.inventory.ifaces := by
  native_decide

end TDN.Deployments.OuterTunnelNoBypass_SharedNetwork
