import TDN.Deployments.MtuSizing_SharedDownstreamPathData

namespace TDN.Deployments.MtuSizing_Shared
open Compliance Requirements OuterToGray_DeviceModel MtuSizing_Records
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma Outer_continuation_checked :
    sizingContinuationChecked records installations linkPolicies (path.egressReady records) continuation := by
  native_decide

lemma Outer_transmission_checked :
    transmission.Check records installations (sizingFinish records (path.egressReady records) continuation) := by
  native_decide

lemma Outer_transmission_link_checked :
    transmission.LinkCheck records linkPolicies (sizingFinish records (path.egressReady records) continuation) := by
  native_decide

lemma Outer_transmission_is_wire : transmission.operation = .linkTransmit := rfl

lemma Outer_endpoint_is_mandatory : ∃ setting ∈ settings roles,
    setting.interface = (sizingFinish records (path.egressReady records) continuation).iface ∧
    setting.role = .grayFirewallOrEncryptionExternal ∧ records.ifaceName setting.interface = "V31F_O_A1:black" := by
  native_decide

end TDN.Deployments.MtuSizing_Shared
