import TDN.Models.MultiStepTraceBridge
import TDN.Deployments.OuterTunnelNoBypass_BaselineForwardingSteps

namespace TDN.Deployments.OuterTunnelNoBypass_Baseline
open Compliance Requirements Requirements.Msc OuterToGray_DeviceModel MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 200000

def DeliveryMove.KeyCheck (move : DeliveryMove) (before : MultiProtocolForwarding.TunnelForwardingState) : Prop :=
  move.step.operation = .decryptIPsec → match before.frame.body with
  | .ipsec stamp _ =>
      ∃ source ∈ installations, source.installation = move.source ∧
      ∃ receiver ∈ installations, receiver.installation = move.receiver ∧
      source.materialReference = receiver.materialReference ∧
      move.source.direction = .outbound ∧
      move.source.device = capturedConfiguration.ip.owner source.localIface ∧
      move.source.association ∈ capturedConfiguration.ip.egressSAs source.localIface ∧
      (∃ policy ∈ capturedConfiguration.ip.egressPolicies source.localIface,
        DataPlaneForwarding.saMatchesPolicy move.source.association policy ∧ policy.seal move.source.association = stamp) ∧
      move.receiver.direction = .inbound ∧ move.receiver.device = capturedConfiguration.ip.owner before.iface ∧
      move.receiver.association ∈ capturedConfiguration.ip.ingressSAs before.iface ∧
      ∃ policy ∈ capturedConfiguration.ip.ingressPolicies before.iface,
        DataPlaneForwarding.saMatchesPolicy move.receiver.association policy ∧ policy.seal move.receiver.association = stamp
  | _ => False

instance deliveryMoveKeyCheckDecidable (move : DeliveryMove) (before : MultiProtocolForwarding.TunnelForwardingState) : Decidable (move.KeyCheck before) := by
  unfold DeliveryMove.KeyCheck
  cases before.frame.body <;> infer_instance

lemma material_references_consistent : MaterialReferencesConsistent installations := by
  unfold MaterialReferencesConsistent
  native_decide
lemma DeliveryMove.keys_from_check (move : DeliveryMove) (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (before : MultiProtocolForwarding.TunnelForwardingState) (checked : move.KeyCheck before) : move.Keys primitive before := by
  intro operation
  have check := checked operation
  cases shape : before.frame.body <;> simp only [shape] at check
  next stamp body =>
    obtain ⟨source, sourceMember, sourceSame, receiver, receiverMember, receiverSame, reference,
      sourceDirection, sourceOwner, sourceInstalled, sourcePolicy, receiverDirection, receiverOwner,
      receiverInstalled, receiverPolicy⟩ := check
    refine ⟨?_, ?_, stamp, body, rfl, ?_, ?_, ?_, ?_⟩
    · change move.source ∈ installations.map PublicSaRecord.installation
      exact List.mem_map.mpr ⟨source, sourceMember, sourceSame⟩
    · change move.receiver ∈ installations.map PublicSaRecord.installation
      exact List.mem_map.mpr ⟨receiver, receiverMember, receiverSame⟩
    · simp [DeliveryMove.after, operation, shape, TunnelForwardingModel.restoredFrame, Records.configuration,
        TunnelFrame.popHeader]
    · refine ⟨sourceDirection, source.localIface, ?_, sourcePolicy⟩
      change move.source.device = capturedConfiguration.ip.owner source.localIface ∧
        match move.source.direction with
        | .outbound => move.source.association ∈ capturedConfiguration.ip.egressSAs source.localIface
        | .inbound => move.source.association ∈ capturedConfiguration.ip.ingressSAs source.localIface
      rw [sourceDirection]
      exact ⟨sourceOwner, sourceInstalled⟩
    · refine ⟨receiverDirection, ?_, receiverPolicy⟩
      change move.receiver.device = capturedConfiguration.ip.owner before.iface ∧
        match move.receiver.direction with
        | .outbound => move.receiver.association ∈ capturedConfiguration.ip.egressSAs before.iface
        | .inbound => move.receiver.association ∈ capturedConfiguration.ip.ingressSAs before.iface
      rw [receiverDirection]
      exact ⟨receiverOwner, receiverInstalled⟩
    · refine ⟨material source.materialReference, (material_valid source sourceMember).1, ?_, ?_⟩
      · change publicKeyMaterial installations material move.source = _
        rw [← sourceSame]
        exact public_key_material_lookup installations material material_references_consistent source sourceMember
      · change publicKeyMaterial installations material move.receiver = _
        rw [← receiverSame, reference]
        exact public_key_material_lookup installations material material_references_consistent receiver receiverMember

def deliveryFinish := CheckedPath.finish DeliveryMove.after

def DeliveryMove.Allowed (move : DeliveryMove) (before : TunnelForwardingState) : Prop :=
  move.Check before ∧ move.KeyCheck before ∧ move.step.LinkCheck records linkPolicies before

instance (move : DeliveryMove) (before : TunnelForwardingState) : Decidable (move.Allowed before) := by
  unfold DeliveryMove.Allowed
  infer_instance

abbrev DeliveryPathChecks := CheckedPath.Checks DeliveryMove.after DeliveryMove.Allowed

lemma delivery_path_reaches (primitive : ESPWire.GCMPrimitive IpsecKeyMaterial)
    (moves : List DeliveryMove) (start first : StandardDataPlaneBridge.State records.inventory.ifaces)
    (actions : List (StandardDataPlaneBridge.Action records.inventory.ifaces))
    (initialized : (interpretedForwarding primitive).initial start)
    (run : (interpretedForwarding primitive).system.MTr start actions first)
    (checked : DeliveryPathChecks first.deviceState moves) :
    ∃ steps last, (interpretedForwarding primitive).system.MTr start steps last ∧
      last.deviceState = deliveryFinish first.deviceState moves ∧ last.deviceState.frame.payload = first.deviceState.frame.payload := by
  let model := interpretedForwarding primitive
  have budgets := size_checks_from_captured_records records installations roles linkPolicies (codec primitive)
    OuterTunnelNoBypass_BaselineNetwork.captured_size_checks
  have emissions : PacketSource.EmissionConditions (deviceBinding primitive).sourceProcessing :=
    PacketSource.source_processing_emission_conditions (sourceMtu roles)
      (source_mtu_minimum roles OuterTunnelNoBypass_BaselineNetwork.captured_mtu_checks)
  apply CheckedPath.reaches model.system (fun s => s.deviceState) (fun s => s.frame.payload)
    DeliveryMove.after DeliveryMove.Allowed start first moves actions run checked
  intro first actions move run allowed
  obtain ⟨stepChecked, keyChecked, linkChecked⟩ := allowed
  have description := StandardDataPlaneBridge.standard_reachable_link_frame_describes (deviceBinding primitive)
    records.inventory.ifaces (interpretedDeployment primitive) {} (codec primitive)
    (requiredSizing roles) (sourceMtu roles) plaintextLimit authenticationLimit budgets.1 emissions
    ⟨fun _ => 64, fun _ => 64⟩ rfl
    (by intro iface; exact ⟨by change 64 ≤ 255; native_decide, by change 64 ≤ 255; native_decide⟩) initialized run
  have accepted := move.accepted primitive first.deviceState stepChecked
    (move.keys_from_check primitive first.deviceState keyChecked) linkChecked description
  obtain ⟨action, after, tr, operation, same⟩ := (interpreted_deployment_covered primitive).deviceSteps first
    move.step.operation (move.after first.deviceState) accepted
  change after.deviceState = move.after first.deviceState at same
  exact ⟨action, after, tr, same, same ▸
    (MultiProtocolForwarding.step_preserves_payload (move.device_step primitive first.deviceState stepChecked)).1⟩

end TDN.Deployments.OuterTunnelNoBypass_Baseline
