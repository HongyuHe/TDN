import TDN.Evidence.PacketSizingSourceCoverage

namespace TDN.Imported.PacketSizingRecords
open Compliance Targets OuterGrayNativeModel CanonicalExecution MultiProtocolExecution


def capturedTransform : IPsecTransform :=
  { encryptionAlgorithm := "rfc4106(gcm(aes))", encryptionKeyBits := 256, saltBytes := 4,
    integrityAlgorithm := none, integrityKeyBits := 0, authenticationBits := 128 }


def PrivateMaterialAssurance (installations : List PublicSARecord)
    (material : String → IPsecKeyMaterial) : Prop :=
  ∀ record ∈ installations, (material record.materialReference).Valid ∧
    (material record.materialReference).transform = capturedTransform


def BridgePolicyChecks (records : Records) (policies : List (Nat × LinkAdmission.IfacePolicy)) : Prop :=
  (∀ iface ∈ records.inventory.ifaces,
    (∃ next ∈ records.inventory.ifaces, (iface,next) ∈ records.bridges ∨ (next,iface) ∈ records.bridges) →
    (LinkAdmission.lookup policies iface).isSome = true) ∧
  (∀ entry ∈ policies, entry.1 ∈ records.inventory.ifaces ∧
    ∃ next ∈ records.inventory.ifaces, (entry.1,next) ∈ records.bridges ∨ (next,entry.1) ∈ records.bridges) ∧
  ∀ first ∈ policies, ∀ second ∈ policies, first.1 = second.1 → first = second

instance (records : Records) (policies : List (Nat × LinkAdmission.IfacePolicy)) :
    Decidable (BridgePolicyChecks records policies) := by
  unfold BridgePolicyChecks
  infer_instance


def RecordedTunnelChecks (records : Records) (installations : List PublicSARecord) : Prop :=
  ∀ record ∈ installations, ∀ policy ∈ (match record.installation.direction with
    | .outbound => (Execution.deviceAt records.nativeDevices record.installation.device).outbound
    | .inbound => (Execution.deviceAt records.nativeDevices record.installation.device).inbound),
    Execution.StateBindsPolicy record.installation.association policy →
    ∃ tunnel ∈ records.tunnels, tunnel.id = ipsecTunnel records (policy.seal record.installation.association) ∧
      tunnel.mechanism = .ipsec ∧
      (records.interfaces.find? (fun interface => interface.address == some record.installation.association.sender)).map Interface.device = some tunnel.sender ∧
      (records.interfaces.find? (fun interface => interface.address == some record.installation.association.receiver)).map Interface.device = some tunnel.receiver

instance (records : Records) (installations : List PublicSARecord) :
    Decidable (RecordedTunnelChecks records installations) := by
  unfold RecordedTunnelChecks
  infer_instance


theorem complete_processing_coherent {Key : Type} (records : Records)
    (installations : List PublicSARecord) (policies : List (Nat × LinkAdmission.IfacePolicy))
    (codec : IPsecFrameEncoding.Codec Key) (networks : List RedNetworkIdentity)
    (attachments : List RedNetworkAttachment) (services : List ServiceRegistration) (base : Deployment)
    (structureChecked : ProcessingStructuralChecks (records.deployment base) records.inventory)
    (ifaces : ∀ interface ∈ records.interfaces,
      records.ifaceIndex interface ∈ records.inventory.ifaces ∧
        records.ifaceName (records.ifaceIndex interface) = interface.id)
    (atoms : ∀ iface ∈ records.inventory.ifaces, NativeProgramAtoms records.inventory iface) :
    (completeDeployment records installations policies codec networks attachments services base).ProcessingCoherent := by
  let inventory := completeInventory records installations policies codec
  let d := completeDeployment records installations policies codec networks attachments services base
  have checked : processingInventoryChecked d inventory = true := by
    apply native_policy_inventory_checks_from_structure d inventory records.ifaceIndex rfl
    · exact structureChecked
    · exact ifaces
    · exact atoms
    · exact records.forward_programs_are_per_owner
  exact processing_coherence_from_record_checks d inventory rfl checked rfl rfl


theorem complete_processing_bound {Key : Type} (records : Records)
    (installations : List PublicSARecord) (entries : List SourceEntry) (roles : List SizingRole)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (epoch : String)
    (codec : IPsecFrameEncoding.Codec Key) (material : String → IPsecKeyMaterial)
    (networks : List RedNetworkIdentity) (attachments : List RedNetworkAttachment)
    (services : List ServiceRegistration) (base : Deployment)
    (structureChecked : ProcessingStructuralChecks (records.deployment base) records.inventory)
    (ifaces : ∀ interface ∈ records.interfaces,
      records.ifaceIndex interface ∈ records.inventory.ifaces ∧
        records.ifaceName (records.ifaceIndex interface) = interface.id)
    (atoms : ∀ iface ∈ records.inventory.ifaces, NativeProgramAtoms records.inventory iface)
    (consistent : MaterialReferencesConsistent installations)
    (privateMaterial : PrivateMaterialAssurance installations material) :
    (prototype records installations entries roles policies epoch codec material).ProcessingBound
      (completeDeployment records installations policies codec networks attachments services base) := by
  refine ⟨complete_processing_coherent records installations policies codec networks attachments services base
    structureChecked ifaces atoms, ?_, completeInventory records installations policies codec,
    rfl, rfl, rfl, rfl, rfl, ?_, structureChecked.2.2.1, ?_, ?_⟩
  · exact ⟨by simp [completeDeployment, Records.deployment], by simp [completeDeployment, Records.deployment]⟩
  · intro carrier member
    cases member
  · intro mac member
    cases member
  · intro size sizeMember installation installed direction owner bound
    obtain ⟨record, member, rfl⟩ := List.mem_map.mp installed
    exact ⟨material record.materialReference,
      public_key_material_lookup installations material consistent record member,
      by rw [(privateMaterial record member).2]; rfl,
      by rw [(privateMaterial record member).2]; rfl,
      by rw [(privateMaterial record member).2]; rfl,
      by rw [(privateMaterial record member).2]; rfl,
      by rw [(privateMaterial record member).2]; rfl⟩


theorem captured_iface_conditions {Key : Type} (records : Records)
    (installations : List PublicSARecord) (policies : List (Nat × LinkAdmission.IfacePolicy))
    (codec : IPsecFrameEncoding.Codec Key)
    (routes : ∀ route ∈ records.routes, route.egress ∈ records.inventory.ifaces)
    (physical : ∀ edge ∈ records.links, edge.1 ∈ records.inventory.ifaces ∧ edge.2 ∈ records.inventory.ifaces)
    (bridges : ∀ edge ∈ records.bridges, edge.1 ∈ records.inventory.ifaces ∧ edge.2 ∈ records.inventory.ifaces) :
    IfaceConditions (completeConfiguration records installations policies codec) records.inventory.ifaces := by
  exact ⟨routes, fun first last member => physical (first,last) member,
    fun first last member => bridges (first,last) member,
    fun _ member => False.elim (List.not_mem_nil member),
    fun _ member => False.elim (List.not_mem_nil member)⟩


theorem captured_deployment_bindings {Key : Type} (records : Records)
    (installations : List PublicSARecord) (entries : List SourceEntry) (roles : List SizingRole)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (epoch : String)
    (codec : IPsecFrameEncoding.Codec Key) (material : String → IPsecKeyMaterial)
    (networks : List RedNetworkIdentity) (attachments : List RedNetworkAttachment)
    (services : List ServiceRegistration) (base : Deployment)
    (structureChecked : ProcessingStructuralChecks (records.deployment base) records.inventory)
    (ifaces : ∀ interface ∈ records.interfaces,
      records.ifaceIndex interface ∈ records.inventory.ifaces ∧ records.ifaceName (records.ifaceIndex interface) = interface.id)
    (atoms : ∀ iface ∈ records.inventory.ifaces, NativeProgramAtoms records.inventory iface)
    (sourceBindings : SourceBindingChecks records entries networks)
    (bridgeChecks : BridgePolicyChecks records policies)
    (ifaceChecks : IfaceConditions (completeConfiguration records installations policies codec) records.inventory.ifaces)
    (saChecks : PublicSAInventoryChecks (directionalConfiguration records installations) epoch installations)
    (tunnelChecks : RecordedTunnelChecks records installations)
    (privateMaterial : PrivateMaterialAssurance installations material)
    (nonempty : networks ≠ [])
    (devicesUnique : ∀ first ∈ records.components, ∀ second ∈ records.components, first.id = second.id → first = second)
    (interfacesUnique : InterfaceIDsUnique records.interfaces)
    (tunnelsUnique : ∀ first ∈ records.tunnels, ∀ second ∈ records.tunnels, first.id = second.id → first = second) :
    NativeDeploymentBindings (prototype records installations entries roles policies epoch codec material)
      records.inventory.ifaces
      (completeDeployment records installations policies codec networks attachments services base) := by
  let d := completeDeployment records installations policies codec networks attachments services base
  refine ⟨complete_processing_bound records installations entries roles policies epoch codec material networks
      attachments services base structureChecked ifaces atoms saChecks.1 privateMaterial,
    ?_, ?_, ?_, ?_, ?_, nonempty, ?_, devicesUnique, interfacesUnique, tunnelsUnique,
    ?_, structureChecked.2.2.1, ?_,
    source_bindings_cover_all_ifaces records entries networks sourceBindings, ?_, ?_⟩
  · intro first last linked
    obtain ⟨edge, member, firstName, lastName⟩ := linked
    have endpoints := ifaceChecks.physicalEndpoints edge.1 edge.2 member
    have firstInterface := structureChecked.2.2.1 edge.1 endpoints.1
    have lastInterface := structureChecked.2.2.1 edge.2 endpoints.2
    obtain ⟨first, firstMember, name, _⟩ := firstInterface
    obtain ⟨last, lastMember, lastId, _⟩ := lastInterface
    exact ⟨⟨first, firstMember, name.trans firstName⟩, ⟨last, lastMember, lastId.trans lastName⟩⟩
  · refine ⟨completeInventory records installations policies codec, rfl, ?_, ?_, bridgeChecks.2.2⟩
    · intro iface member path
      rcases path with ⟨mac, impossible, _⟩ | switched | ⟨carrier, impossible, _⟩
      · cases impossible
      · exact Option.isSome_iff_exists.mp (bridgeChecks.1 iface member switched)
      · cases impossible
    · intro entry member
      exact ⟨(bridgeChecks.2.1 entry member).1, Or.inr (Or.inl (bridgeChecks.2.1 entry member).2)⟩
  · exact ⟨completeInventory records installations policies codec, rfl, ⟨⟨fun _ => 64, fun _ => 64⟩,
      rfl, fun _ _ => by change 0 < 64 ∧ 64 ≤ 255 ∧ 0 < 64 ∧ 64 ≤ 255; decide⟩⟩
  · intro mac member
    cases member
  · exact public_SA_inventory_sound _ installations epoch material rfl rfl (fun _ => rfl) (fun _ => rfl)
      rfl saChecks (fun record member => (privateMaterial record member).1)
  · intro tunnel member
    exact ⟨tunnel, member, rfl, rfl⟩
  · intro interface member
    obtain ⟨iface, _, name, owner⟩ := structureChecked.2.2.2.1 interface member
    exact ⟨iface, name, owner⟩
  · intro first last member
    exact ⟨(first,last), member, rfl, rfl⟩
  · intro mac member
    cases member
  · intro iface association policy installed bound
    rcases installed with ⟨stateMember, policyMember⟩ | ⟨stateMember, policyMember⟩
    · obtain ⟨record, member, owner, direction, same⟩ := (directional_state_member ..).mp stateMember
      subst association
      have selected : policy ∈ (Execution.deviceAt records.nativeDevices record.installation.device).outbound := by
        rw [owner]
        exact policyMember
      have facts := tunnelChecks record member policy (by simpa only [direction] using selected) bound
      exact facts
    · obtain ⟨record, member, owner, direction, same⟩ := (directional_state_member ..).mp stateMember
      subst association
      have selected : policy ∈ (Execution.deviceAt records.nativeDevices record.installation.device).inbound := by
        rw [owner]
        exact policyMember
      have facts := tunnelChecks record member policy (by simpa only [direction] using selected) bound
      exact facts

end TDN.Imported.PacketSizingRecords
