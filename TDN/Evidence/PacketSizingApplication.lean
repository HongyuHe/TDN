import TDN.Evidence.PacketSizingDeploymentCoverage

namespace TDN.Imported.PacketSizingRecords
open Compliance Targets Targets.Complete OuterGrayNativeModel CanonicalExecution PacketSource


def wireMaterial (installations : List PublicSARecord) (material : String → IPsecKeyMaterial)
    (wireSeal : Execution.Seal) : IPsecKeyMaterial :=
  match installations.find? (fun record => record.installation.direction == .outbound &&
    SAWireKey record.installation.association == SealWireKey wireSeal) with
  | some record => material record.materialReference
  | none => material "unlisted-IPsec-material"


def capturedCodec (installations : List PublicSARecord) (material : String → IPsecKeyMaterial)
    (primitive : ESPWire.GCMPrimitive IPsecKeyMaterial)
    (parameters : Execution.Seal → IPsecFrameEncoding.Parameters) : IPsecFrameEncoding.Codec IPsecKeyMaterial :=
  { primitive := { primitive with salt := IPsecKeyMaterial.salt },
    key := wireMaterial installations material, parameters := parameters }


def RoleMtuChecks (roles : List SizingRole) : Prop :=
  ∀ role ∈ roles, 1280 ≤ role.mtu ∧ sourceMtu roles role.iface = role.mtu

instance (roles : List SizingRole) : Decidable (RoleMtuChecks roles) := by
  unfold RoleMtuChecks
  infer_instance


theorem source_mtu_minimum (roles : List SizingRole) (checked : RoleMtuChecks roles) :
    ∀ iface, 1280 ≤ sourceMtu roles iface := by
  intro iface
  unfold sourceMtu
  cases selected : roles.find? (fun role => role.iface == iface) with
  | none => simp
  | some role =>
    have member := List.mem_of_find?_eq_some selected
    simpa only [Option.map_some, Option.getD_some] using (checked role member).1


theorem settings_use_interface_ceilings (roles : List SizingRole) (checked : RoleMtuChecks roles) :
    SettingsUseInterfaceCeilings (settings roles) (requiredSizing roles) (sourceMtu roles) (sourceMtu roles) := by
  intro setting member
  obtain ⟨role, selected, rfl⟩ := List.mem_map.mp member
  obtain ⟨roleMember, relevant⟩ := List.mem_filter.mp selected
  have mtu := (checked role roleMember).2
  refine ⟨?_, mtu.symm, mtu.symm, by rw [mtu], ?_⟩
  · apply List.any_eq_true.mpr
    exact ⟨role, roleMember, by simpa only [beq_self_eq_true, Bool.true_and] using relevant⟩
  · intro bytes
    exact mtu.symm


theorem settings_are_IPv4_optional_inner (roles : List SizingRole) :
    ∀ setting ∈ settings roles, setting.family = .ipv4 ∧ setting.innerObjectiveSelected = false := by
  intro setting member
  obtain ⟨role, _, rfl⟩ := List.mem_map.mp member
  exact ⟨rfl, rfl⟩


theorem complete_recorded_packet_sizing {Key : Type} (records : Records)
    (installations : List PublicSARecord) (entries : List SourceEntry) (roles : List SizingRole)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (epoch : String)
    (codec : IPsecFrameEncoding.Codec Key) (material : String → IPsecKeyMaterial)
    (networks : List RedNetworkIdentity) (attachments : List RedNetworkAttachment)
    (services : List ServiceRegistration) (base : Deployment) (flows : List SourceFlow)
    (structureChecked : ProcessingStructuralChecks (records.deployment base) records.inventory)
    (ifaces : ∀ interface ∈ records.interfaces,
      records.ifaceIndex interface ∈ records.inventory.ifaces ∧ records.ifaceName (records.ifaceIndex interface) = interface.id)
    (atoms : ∀ iface ∈ records.inventory.ifaces, NativeProgramAtoms records.inventory iface)
    (sourceBindings : SourceBindingChecks records entries networks)
    (sourcesChecked : NetworkSourceChecks entries roles records.componentName networks flows)
    (bridgeChecks : BridgePolicyChecks records policies)
    (ifaceChecks : MultiProtocolExecution.IfaceConditions (completeConfiguration records installations policies codec) records.inventory.ifaces)
    (saChecks : PublicSAInventoryChecks (directionalConfiguration records installations) epoch installations)
    (tunnelChecks : RecordedTunnelChecks records installations)
    (privateMaterial : PrivateMaterialAssurance installations material)
    (nonempty : networks ≠ [])
    (devicesUnique : ∀ first ∈ records.components, ∀ second ∈ records.components, first.id = second.id → first = second)
    (interfacesUnique : InterfaceIDsUnique records.interfaces)
    (tunnelsUnique : ∀ first ∈ records.tunnels, ∀ second ∈ records.tunnels, first.id = second.id → first = second)
    (sizeChecked : SizeRecordChecks records installations roles)
    (mtuChecked : RoleMtuChecks roles)
    (inventoryChecked : SizingInventoryChecks
      (completeDeployment records installations policies codec networks attachments services base) records.ifaceName (settings roles)) :
    Targets.Complete.msc_packet_size_configuration
      (completeDeployment records installations policies codec networks attachments services base)
      (model (prototype records installations entries roles policies epoch codec material) records.inventory.ifaces
        (completeDeployment records installations policies codec networks attachments services base) {})
      (CanonicalExecution.sizedWireModel codec (sourceMtu roles) (sourceMtu roles)) (settings roles) [] := by
  have budgets := size_checks_from_captured_records records installations roles policies codec sizeChecked
  apply complete_canonical_IPsec_packet_sizing
    (prototype records installations entries roles policies epoch codec material) records.inventory.ifaces
    (completeDeployment records installations policies codec networks attachments services base) {}
    (captured_deployment_bindings records installations entries roles policies epoch codec material networks
      attachments services base structureChecked ifaces atoms sourceBindings bridgeChecks ifaceChecks saChecks tunnelChecks
      privateMaterial nonempty devicesUnique interfacesUnique tunnelsUnique)
    (by simp [ObservedHistory.Valid]) ifaceChecks codec (requiredSizing roles) (sourceMtu roles) (sourceMtu roles)
    plaintextLimit authenticationLimit budgets.1 budgets.2 ⟨fun _ => 64, fun _ => 64⟩ rfl
    (by intro iface; exact ⟨by change 64 ≤ 255; decide, by change 64 ≤ 255; decide⟩)
    (fun _ _ => rfl) rfl (source_mtu_minimum roles mtuChecked) rfl
    (allowed_source_iface_is_recorded records installations entries roles policies epoch codec material networks
      attachments services base sourceBindings)
    (every_recorded_network_has_source records installations entries roles policies epoch codec material networks
      attachments services base flows sourcesChecked)
    (settings roles) (settings_use_interface_ceilings roles mtuChecked)
    (settings_are_IPv4_optional_inner roles) inventoryChecked

end TDN.Imported.PacketSizingRecords
