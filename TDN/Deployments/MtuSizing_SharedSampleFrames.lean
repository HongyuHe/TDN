import TDN.Deployments.MtuSizing_Shared
import TDN.Deployments.MtuSizing_SharedCasesChecks
import TDN.Deployments.MtuSizing_SharedDownstreamPathChecks

namespace TDN.Deployments.MtuSizing_Shared
open Compliance Requirements OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge

theorem nonempty_HTTP_source_reaches_required_Gray_wire
    (material : String → IPsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (parameters : DataPlaneForwarding.TunnelSAStamp → IPsecFrameEncoding.Parameters) (base : Deployment)
    (privateMaterial : PrivateMaterialAssurance installations material) :
    ∃ start actions before action after,
      (execution material primitive parameters base).initial start ∧
      (execution material primitive parameters base).system.MTr start actions before ∧
      (execution material primitive parameters base).system.Tr before action after ∧
      action.operation = .linkTransmit ∧ before.native = path.egressReady records ∧
      requiredSizing roles before.native.iface = true ∧ before.native.frame.payload ≠ 0 :=
  path.source_to_required_wire records installations entries roles linkPolicies epoch
    (codec material primitive parameters) material networks attachments services base
    (complete_recorded_packet_size_configuration material primitive parameters base privateMaterial).1
    captured_size_checks captured_mtu_checks positive_path_checked positive_source_checked
    positive_required_interface_checked positive_before_is_routed positive_receiver_program_checked

theorem nonempty_HTTP_source_reaches_mandatory_Outer_Black_wire
    (material : String → IPsecKeyMaterial) (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (parameters : DataPlaneForwarding.TunnelSAStamp → IPsecFrameEncoding.Parameters) (base : Deployment)
    (privateMaterial : PrivateMaterialAssurance installations material) :
    ∃ start actions before action after,
      (execution material primitive parameters base).initial start ∧
      (execution material primitive parameters base).system.MTr start actions before ∧
      (execution material primitive parameters base).system.Tr before action after ∧
      action.operation = .linkTransmit ∧ before.native.frame.payload ≠ 0 ∧
      ∃ setting ∈ settings roles, setting.interface = before.native.iface ∧
        setting.role = .grayFirewallOrEncryptionExternal ∧
        records.ifaceName setting.interface = "V31F_O_A1:black" := by
  obtain ⟨start, actions, first, oldAction, oldAfter, initialized, run, oldStep, oldWire, same, oldRequired, nonempty⟩ :=
    nonempty_HTTP_source_reaches_required_Gray_wire material primitive parameters base privateMaterial
  obtain ⟨steps, before, action, after, reached, step, wire, payload, required⟩ :=
    sizing_continuation_transmits records installations entries roles linkPolicies epoch
      (codec material primitive parameters) material networks attachments services base
      (complete_recorded_packet_size_configuration material primitive parameters base privateMaterial).1
      captured_size_checks captured_mtu_checks continuation transmission start first actions initialized run
      (by rw [same]; exact Outer_continuation_checked)
      (by rw [same]; exact Outer_transmission_checked)
      (by rw [same]; exact Outer_transmission_link_checked)
      Outer_transmission_is_wire "V31F_O_A1:black"
      (by rw [same]; exact Outer_endpoint_is_mandatory) nonempty
  exact ⟨start, steps, before, action, after, initialized, reached, step, wire, payload, required⟩

end TDN.Deployments.MtuSizing_Shared
