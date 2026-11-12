import TDN.Deployments.NestedProtection_MixedTraceSteps
import TDN.Deployments.NestedProtection_MixedFrameChecks

namespace TDN.Deployments.NestedProtection_Mixed
open Compliance Requirements Requirements.Msc MtuSizing_Records StandardDataPlaneBridge MultiProtocolForwarding LayeredFrame

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

instance (material : IPsecKeyMaterial) : Decidable material.Valid := by
  unfold IPsecKeyMaterial.Valid
  cases material.transform.integrityAlgorithm <;> dsimp only <;> infer_instance

def ProtectionMove.MACsecKeyCheck (move : ProtectionMove) (before : MultiProtocolForwarding.State) : Prop :=
  move.operation = .decryptMACsec → match before.frame.body with
  | .macsec transmitted contents =>
      move.macIface ∈ configuration.macIfaces ∧ move.receiveAssociation ∈ move.macIface.receiveAssociations ∧
      before.iface = move.macIface.physicalIface ∧ (move.after before).iface = move.macIface.logicalIface ∧
      (move.after before).frame.body = contents ∧ SameMACWireIdentity transmitted move.receiveAssociation ∧
      let key := (records.macsecMaterial transmitted).getD []
      (key.length = 16 ∨ key.length = 32) ∧
        records.macsecMaterial transmitted = some key ∧
        records.macsecMaterial move.receiveAssociation = some key
  | _ => False

def ProtectionMove.IPsecKeyCheck (move : ProtectionMove) (before : MultiProtocolForwarding.State) : Prop :=
  move.operation = .decryptIPsec → match before.frame.body with
  | .ipsec stamp contents =>
      let source := move.sourceInstallation
      let receiver := move.installation
      source ∈ records.installations ∧ receiver ∈ records.installations ∧
      (move.after before).frame.body = contents ∧
      source.installation.direction = .outbound ∧
      source.installation.device = configuration.ip.owner source.localIface ∧
      source.installation.association ∈ configuration.ip.egressSAs source.localIface ∧
      (∃ policy ∈ configuration.ip.egressPolicies source.localIface,
        DataPlaneForwarding.saMatchesPolicy source.installation.association policy ∧
        policy.seal source.installation.association = stamp) ∧
      receiver.installation.direction = .inbound ∧
      receiver.installation.device = configuration.ip.owner before.iface ∧
      receiver.installation.association ∈ configuration.ip.ingressSAs before.iface ∧
      (∃ policy ∈ configuration.ip.ingressPolicies before.iface,
        DataPlaneForwarding.saMatchesPolicy receiver.installation.association policy ∧
        policy.seal receiver.installation.association = stamp) ∧
      let material := records.ipsecMaterial source.materialReference
      material.Valid ∧ deviceBinding.ipsecKeyMaterial source.installation = some material ∧
        deviceBinding.ipsecKeyMaterial receiver.installation = some material
  | _ => False

def ProtectionMove.LinkCheck (move : ProtectionMove) (before : MultiProtocolForwarding.State) : Prop :=
  let after := move.after before
  (move.operation = .linkTransmit →
    (before.iface ∈ linkIfaces → FrameAdmissionCheck before before.iface true) ∧
    (after.iface ∈ linkIfaces → FrameAdmissionCheck after after.iface false) ∧
    (before.iface ∈ linkIfaces ∨ after.iface ∈ linkIfaces →
      configuration.linkEncoding before.iface before.frame = configuration.linkEncoding after.iface after.frame)) ∧
  (move.operation = .decryptMACsec → FrameAdmissionCheck before before.iface false) ∧
  (move.operation = .bridge →
    FrameAdmissionCheck before before.iface false ∧ FrameAdmissionCheck after after.iface true) ∧
  (move.operation = .deliver → before.frame.visibleHeader = none → before.iface ∈ linkIfaces →
    FrameAdmissionCheck before before.iface false)

def ProtectionMove.HeaderCheck (move : ProtectionMove) (before : MultiProtocolForwarding.State) : Prop :=
  move.operation = .route → before.datapathStage = .ingress →
    configuration.visibleHeader before.frame = some (currentHeader before) ∧
      configuration.ForwardableHeader (currentHeader before)

instance (move : ProtectionMove) (before : MultiProtocolForwarding.State) : Decidable (move.MACsecKeyCheck before) := by
  unfold ProtectionMove.MACsecKeyCheck
  cases before.frame.body <;> dsimp only <;> infer_instance

instance (move : ProtectionMove) (before : MultiProtocolForwarding.State) : Decidable (move.IPsecKeyCheck before) := by
  unfold ProtectionMove.IPsecKeyCheck
  cases before.frame.body <;> dsimp only <;> infer_instance

instance (move : ProtectionMove) (before : MultiProtocolForwarding.State) : Decidable (move.LinkCheck before) := by
  unfold ProtectionMove.LinkCheck
  infer_instance

instance (move : ProtectionMove) (before : MultiProtocolForwarding.State) : Decidable (move.HeaderCheck before) := by
  unfold ProtectionMove.HeaderCheck Config.ForwardableHeader
  infer_instance

lemma ProtectionMove.accepted_step (move : ProtectionMove) (before : MultiProtocolForwarding.State)
    (stepChecked : move.Check before) (macKeys : move.MACsecKeyCheck before)
    (ipsecKeys : move.IPsecKeyCheck before) (links : move.LinkCheck before)
    (headers : move.HeaderCheck before) :
    deviceBinding.AcceptedStep before move.operation (move.after before) := by
  refine ⟨move.device_step before stepChecked, ?_, ?_, ?_, ?_, ?_⟩
  · intro operation
    have checked := macKeys operation
    cases shape : before.frame.body <;> simp only [shape] at checked
    next transmitted contents =>
      obtain ⟨configured, installed, physical, logical, restored, same, length, transmitKey, receiveKey⟩ := checked
      exact ⟨move.macIface, configured, move.receiveAssociation, installed, transmitted, contents,
        physical, logical, rfl, restored, same,
        (records.macsecMaterial transmitted).getD [], length, transmitKey, receiveKey⟩
  · intro operation
    have checked := ipsecKeys operation
    cases shape : before.frame.body <;> simp only [shape] at checked
    next stamp contents =>
      obtain ⟨sourceListed, receiverListed, restored, sourceDirection, sourceOwner, sourceInstalled,
        sourcePolicy, receiverDirection, receiverOwner, receiverInstalled, receiverPolicy,
        materialValid, sourceMaterial, receiverMaterial⟩ := checked
      refine ⟨move.sourceInstallation.installation, List.mem_map.mpr ⟨_, sourceListed, rfl⟩,
        move.installation.installation, List.mem_map.mpr ⟨_, receiverListed, rfl⟩,
        stamp, contents, rfl, restored, ?_, ?_,
        records.ipsecMaterial move.sourceInstallation.materialReference, materialValid, sourceMaterial, receiverMaterial⟩
      · refine ⟨sourceDirection, move.sourceInstallation.localIface, ?_, sourcePolicy⟩
        change _ ∧ match move.sourceInstallation.installation.direction with
          | .outbound => _
          | .inbound => _
        rw [sourceDirection]
        exact ⟨sourceOwner, sourceInstalled⟩
      · refine ⟨receiverDirection, ?_, receiverPolicy⟩
        change _ ∧ match move.installation.installation.direction with
          | .outbound => _
          | .inbound => _
        rw [receiverDirection]
        exact ⟨receiverOwner, receiverInstalled⟩
  · refine ⟨?_, ?_, ?_, ?_⟩
    · intro operation
      obtain ⟨outbound, inbound, encoding⟩ := links.1 operation
      exact ⟨fun path => frame_admission_from_check _ _ _ (outbound (link_path_is_recorded _ path)),
        fun path => frame_admission_from_check _ _ _ (inbound (link_path_is_recorded _ path)),
        fun path => encoding (path.elim (fun h => Or.inl (link_path_is_recorded _ h))
          (fun h => Or.inr (link_path_is_recorded _ h)))⟩
    · intro operation
      rcases operation with decrypt | validate
      · exact frame_admission_from_check _ _ _ (links.2.1 decrypt)
      · cases operation : move.operation <;> simp_all [ProtectionMove.Check]
    · intro operation
      have checked := links.2.2.1 operation
      exact ⟨frame_admission_from_check _ _ _ checked.1, frame_admission_from_check _ _ _ checked.2⟩
    · intro operation invisible path
      exact frame_admission_from_check _ _ _ (links.2.2.2 operation invisible (link_path_is_recorded _ path))
  · intro operation stage header visible
    obtain ⟨known, forwardable⟩ := headers operation stage
    have same := Option.some.inj (known.symm.trans visible)
    exact same ▸ forwardable
  · intro validate
    cases operation : move.operation <;> simp_all [ProtectionMove.Check]

def ProtectionPathChecks (before : MultiProtocolForwarding.State) : List ProtectionMove → Prop
  | [] => True
  | move :: rest => move.Check before ∧ move.MACsecKeyCheck before ∧ move.IPsecKeyCheck before ∧
      move.LinkCheck before ∧ move.HeaderCheck before ∧ ProtectionPathChecks (move.after before) rest

instance (before : MultiProtocolForwarding.State) (moves : List ProtectionMove) :
    Decidable (ProtectionPathChecks before moves) := by
  induction moves generalizing before with
  | nil => exact isTrue trivial
  | cons move rest ih =>
    change Decidable (_ ∧ _ ∧ _ ∧ _ ∧ _ ∧ ProtectionPathChecks (move.after before) rest)
    have := ih (move.after before)
    infer_instance

lemma protection_path_checks_supply_device_trace (before : MultiProtocolForwarding.State)
    (moves : List ProtectionMove) (checked : ProtectionPathChecks before moves) :
    (⟨deviceBinding.AcceptedStep⟩ : Cslib.LTS _ _).MTr before (moves.map ProtectionMove.operation)
      (moves.foldl (fun state move => move.after state) before) := by
  induction moves generalizing before with
  | nil => exact .refl
  | cons move rest ih =>
    obtain ⟨step, macKeys, ipsecKeys, links, headers, remaining⟩ := checked
    exact .stepL (move.accepted_step before step macKeys ipsecKeys links headers)
      (ih (move.after before) remaining)

lemma recorded_protection_paths_checked : ∀ path ∈ protectionPaths, ProtectionPathChecks path.start path.moves := by native_decide

lemma sample_path_0_device_trace :
    (⟨deviceBinding.AcceptedStep⟩ : Cslib.LTS _ _).MTr ((samplePath 0).state 0)
      ((samplePath 0).moves.map ProtectionMove.operation) ((samplePath 0).state 28) := by
  simpa only [ProtectionPath.state, List.take_zero, List.foldl_nil, show (samplePath 0).moves.take 28 = (samplePath 0).moves from rfl] using
    protection_path_checks_supply_device_trace (samplePath 0).start (samplePath 0).moves
      (recorded_protection_paths_checked _ List.mem_cons_self)

lemma sample_path_1_device_trace :
    (⟨deviceBinding.AcceptedStep⟩ : Cslib.LTS _ _).MTr ((samplePath 1).state 0)
      ((samplePath 1).moves.map ProtectionMove.operation) ((samplePath 1).state 28) := by
  simpa only [ProtectionPath.state, List.take_zero, List.foldl_nil, show (samplePath 1).moves.take 28 = (samplePath 1).moves from rfl] using
    protection_path_checks_supply_device_trace (samplePath 1).start (samplePath 1).moves
      (recorded_protection_paths_checked _ (List.mem_cons_of_mem _ List.mem_cons_self))

end TDN.Deployments.NestedProtection_Mixed
