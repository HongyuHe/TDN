import TDN.Deployments.MtuSizing_BaselineCasesData

namespace TDN.Deployments.MtuSizing_Baseline
open Compliance Requirements OuterToGray_DeviceModel MtuSizing_Records PacketSource
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

lemma source_attachments_are_bound : SourceAttachmentChecks records entries networks attachments := by
  native_decide

lemma positive_path_checked : path.Checks records installations := by
  native_decide

lemma positive_source_checked : path.SourceChecks records entries roles networks := by
  native_decide

lemma positive_required_interface_checked : requiredSizing roles path.routeOuterPacket.egress = true := by
  native_decide

lemma positive_before_is_routed :
    ∀ edge ∈ records.bridges, edge.1 ≠ path.routeOuterPacket.egress ∧ edge.2 ≠ path.routeOuterPacket.egress := by
  native_decide

lemma positive_receiver_program_checked :
    (∀ edge ∈ records.bridges, edge.1 ≠ path.nextIface ∧ edge.2 ≠ path.nextIface) ∨
      LinkAdmission.lookup linkPolicies path.nextIface = some openLinkPolicy := by
  native_decide

lemma captured_full_frames_checked : ∀ frame ∈ frames, frame.Checked records installations roles := by
  native_decide

lemma all_Gray_firewall_attachments_have_settings :
    ∀ interface ∈ records.interfaces, ∀ device ∈ records.components,
      interface.device = device.id → device.kind = .grayFirewall → interface.zone = .gray →
      interface.physical = true → interface.managementNetwork = false →
      ∃ setting ∈ settings roles, records.ifaceName setting.interface = interface.id ∧
        setting.role = .grayFirewallOrEncryptionExternal := by
  native_decide

lemma source_DF_1321_reports_MTU_error :
    processSource (sourceMtu roles path.flow.iface) (path.oversizeRequest 1321 true) = .error .mtuExceeded := by
  native_decide

lemma source_1321_without_DF_fragments :
    emittedFragmentCount (processSource (sourceMtu roles path.flow.iface) (path.oversizeRequest 1321 false)) = 2 := by
  native_decide

lemma source_4028_without_DF_fragments :
    emittedFragmentCount (processSource (sourceMtu roles path.flow.iface) (path.oversizeRequest 4028 false)) = 4 := by
  native_decide

lemma Inner_drops_reassembled_oversize_1321 :
    ¬ DataPlaneForwarding.accepts (records.configuration.ip.forwardRules path.route.egress)
      (records.configuration.ip.forwardFallback path.route.egress)
      (MultiProtocolForwarding.policyHeader records.configuration (path.oversizeRouted records 1321)
        (path.oversizeHeader 1321)) := by
  unfold DataPlaneForwarding.accepts
  native_decide

lemma Inner_drops_reassembled_oversize_4028 :
    ¬ DataPlaneForwarding.accepts (records.configuration.ip.forwardRules path.route.egress)
      (records.configuration.ip.forwardFallback path.route.egress)
      (MultiProtocolForwarding.policyHeader records.configuration (path.oversizeRouted records 4028)
        (path.oversizeHeader 4028)) := by
  unfold DataPlaneForwarding.accepts
  native_decide

end TDN.Deployments.MtuSizing_Baseline
