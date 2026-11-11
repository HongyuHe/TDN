import TDN.Deployments.OuterTunnelNoBypass_SharedNetworkData

namespace TDN.Deployments.OuterTunnelNoBypass_SharedNetwork
open Compliance Requirements OuterToGray_DeviceModel MtuSizing_Records

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma captured_sa_inventory_checks :
    PublicSAInventoryChecks (directionalConfiguration records installations) epoch installations := by
  decide

lemma captured_raw_state_pool_checks : CapturedStatePoolChecks installations records.nativeDevices := by
  decide

lemma captured_direction_policy_checks :
    RecordedDirectionPolicyChecks (directionalConfiguration records installations) installations := by
  decide

lemma captured_namespace_addresses :
    NamespaceAddressChecks records.interfaces records.componentName records.nativeDevices := by
  decide

end TDN.Deployments.OuterTunnelNoBypass_SharedNetwork
