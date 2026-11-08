import TDN.Evidence.SizingSharedContinuationData

namespace TDN.Imported.SizingShared
open Compliance Targets OuterGrayNativeModel PacketSizingRecords
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma Outer_continuation_checked :
    sizingContinuationChecked records installations linkPolicies (path.ready records) continuation := by
  exact of_decide_eq_true rfl

lemma Outer_transmission_checked :
    transmission.Check records installations (sizingFinish records (path.ready records) continuation) := by
  exact of_decide_eq_true rfl

lemma Outer_transmission_link_checked :
    transmission.LinkCheck records linkPolicies (sizingFinish records (path.ready records) continuation) := by
  exact of_decide_eq_true rfl

lemma Outer_transmission_is_wire : transmission.operation = .linkTransmit := rfl

lemma Outer_endpoint_is_mandatory : ∃ setting ∈ settings roles,
    setting.interface = (sizingFinish records (path.ready records) continuation).iface ∧
    setting.role = .grayFirewallOrEncryptionExternal ∧ records.ifaceName setting.interface = "V31F_O_A1:black" := by
  exact of_decide_eq_true rfl

end TDN.Imported.SizingShared
