import TDN.Requirements.MscComplianceSchema
import TDN.Models.TunnelSaOriginAttribution

namespace TDN.Requirements
open Compliance

structure PublicSARecord where
  installation : IPsecLocalSA
  localIface : Nat
  materialReference : String
  deriving DecidableEq


def directionalStates (records : List PublicSARecord) (owner : Nat) (direction : IPsecSADirection) :
    List DataPlaneForwarding.InstalledSA :=
  (records.filter (fun record => record.installation.device == owner && record.installation.direction == direction)).map
    (fun record => record.installation.association)

lemma directional_state_member (records : List PublicSARecord) (owner : Nat)
    (direction : IPsecSADirection) (association : DataPlaneForwarding.InstalledSA) :
    association ∈ directionalStates records owner direction ↔
      ∃ record ∈ records, record.installation.device = owner ∧ record.installation.direction = direction ∧
        record.installation.association = association := by
  simp only [directionalStates, List.mem_map, List.mem_filter, Bool.and_eq_true, beq_iff_eq]
  constructor
  · rintro ⟨record, ⟨member, owner, direction⟩, same⟩
    exact ⟨record, member, owner, direction, same⟩
  · rintro ⟨record, member, owner, direction, same⟩
    exact ⟨record, ⟨member, owner, direction⟩, same⟩


def publicKeyMaterial (records : List PublicSARecord) (material : String → IPsecKeyMaterial)
    (installation : IPsecLocalSA) : Option IPsecKeyMaterial :=
  match records with
  | [] => none
  | record :: rest =>
      if record.installation = installation then some (material record.materialReference)
      else publicKeyMaterial rest material installation


def MaterialReferencesConsistent (records : List PublicSARecord) : Prop :=
  ∀ first ∈ records, ∀ second ∈ records, first.installation = second.installation →
    first.materialReference = second.materialReference

lemma public_key_material_lookup (records : List PublicSARecord) (material : String → IPsecKeyMaterial)
    (consistent : MaterialReferencesConsistent records) (record : PublicSARecord) (member : record ∈ records) :
    publicKeyMaterial records material record.installation = some (material record.materialReference) := by
  induction records with
  | nil => cases member
  | cons first rest ih =>
    unfold publicKeyMaterial
    split
    next same =>
      rw [consistent first (by simp) record member same]
    next different =>
      apply ih
      · intro one oneMember two twoMember equal
        exact consistent one (List.mem_cons_of_mem _ oneMember) two (List.mem_cons_of_mem _ twoMember) equal
      · rcases List.mem_cons.mp member with same | inRest
        · subst record
          exact False.elim (different rfl)
        · exact inRest


def CapturedStatePoolCovered (records : List PublicSARecord) (devices : List DataPlaneForwarding.DeviceData) : Prop :=
  (∀ record ∈ records, record.installation.association ∈ (DataPlaneForwarding.deviceAt devices record.installation.device).states) ∧
  (∀ owner, ∀ association ∈ (DataPlaneForwarding.deviceAt devices owner).states,
    ∃ record ∈ records, record.installation.device = owner ∧ record.installation.association = association)


def CapturedStatePoolChecks (records : List PublicSARecord) (devices : List DataPlaneForwarding.DeviceData) : Prop :=
  (∀ record ∈ records, record.installation.association ∈
    (DataPlaneForwarding.deviceAt devices record.installation.device).states) ∧
  (∀ owner ∈ List.range devices.length,
    ∀ association ∈ (DataPlaneForwarding.deviceAt devices owner).states,
      ∃ record ∈ records, record.installation.device = owner ∧
        record.installation.association = association)

theorem checked_raw_state_pool_is_covered (records : List PublicSARecord)
    (devices : List DataPlaneForwarding.DeviceData) (checked : CapturedStatePoolChecks records devices) :
    CapturedStatePoolCovered records devices := by
  refine ⟨checked.1, ?_⟩
  intro owner association member
  by_cases present : owner < devices.length
  · exact checked.2 owner (List.mem_range.mpr present) association member
  · have absent : devices[owner]? = none := List.getElem?_eq_none (by omega)
    simp only [DataPlaneForwarding.deviceAt, absent, Option.getD_none] at member
    cases member


theorem directional_inventory_covers_exact_raw_pool (records : List PublicSARecord)
    (devices : List DataPlaneForwarding.DeviceData) (covered : CapturedStatePoolCovered records devices)
    (owner : Nat) (association : DataPlaneForwarding.InstalledSA) :
    association ∈ directionalStates records owner .outbound ∨
        association ∈ directionalStates records owner .inbound ↔
      association ∈ (DataPlaneForwarding.deviceAt devices owner).states := by
  constructor
  · intro member
    rcases member with outbound | inbound
    · obtain ⟨record, inRecords, sameOwner, _, sameAssociation⟩ :=
        (directional_state_member records owner .outbound association).mp outbound
      rw [← sameOwner, ← sameAssociation]
      exact covered.1 record inRecords
    · obtain ⟨record, inRecords, sameOwner, _, sameAssociation⟩ :=
        (directional_state_member records owner .inbound association).mp inbound
      rw [← sameOwner, ← sameAssociation]
      exact covered.1 record inRecords
  · intro member
    obtain ⟨record, inRecords, sameOwner, sameAssociation⟩ := covered.2 owner association member
    cases direction : record.installation.direction with
    | outbound =>
      exact Or.inl ((directional_state_member records owner .outbound association).mpr
        ⟨record, inRecords, sameOwner, direction, sameAssociation⟩)
    | inbound =>
      exact Or.inr ((directional_state_member records owner .inbound association).mpr
        ⟨record, inRecords, sameOwner, direction, sameAssociation⟩)

def SAWireKey (association : DataPlaneForwarding.InstalledSA) : Nat × Nat × Nat :=
  (association.spi, association.sender, association.receiver)

def SealWireKey (wireSeal : DataPlaneForwarding.TunnelSAStamp) : Nat × Nat × Nat :=
  (wireSeal.association, wireSeal.sender, wireSeal.receiver)

lemma outbound_seal_wire_key {S A : Type} (binding : DeviceExecutionBinding S A)
    (installation : IPsecLocalSA) (wireSeal : DataPlaneForwarding.TunnelSAStamp) (outbound : installation.OutboundSeal binding wireSeal) :
    SAWireKey installation.association = SealWireKey wireSeal := by
  obtain ⟨_, _, _, policy, _, bound, same⟩ := outbound
  rw [← same]
  simp only [SAWireKey, SealWireKey, DataPlaneForwarding.IpsecPolicy.seal]

lemma inbound_seal_wire_key {S A : Type} (binding : DeviceExecutionBinding S A)
    (installation : IPsecLocalSA) (iface : Nat) (wireSeal : DataPlaneForwarding.TunnelSAStamp)
    (inbound : installation.InboundSeal binding iface wireSeal) :
    SAWireKey installation.association = SealWireKey wireSeal := by
  obtain ⟨_, _, policy, _, bound, same⟩ := inbound
  rw [← same]
  simp only [SAWireKey, SealWireKey, DataPlaneForwarding.IpsecPolicy.seal]

instance (association : DataPlaneForwarding.InstalledSA) (policy : DataPlaneForwarding.IpsecPolicy) :
    Decidable (DataPlaneForwarding.saMatchesPolicy association policy) := by
  unfold DataPlaneForwarding.saMatchesPolicy
  infer_instance


def RecordedDirectionPolicyChecks (configuration : MultiProtocolForwarding.Config)
    (records : List PublicSARecord) : Prop :=
  ∀ record ∈ records,
    configuration.ip.owner record.localIface = record.installation.device ∧
    ∃ policy ∈ (match record.installation.direction with
      | .outbound => configuration.ip.egressPolicies record.localIface
      | .inbound => configuration.ip.ingressPolicies record.localIface),
      DataPlaneForwarding.saMatchesPolicy record.installation.association policy

instance (configuration : MultiProtocolForwarding.Config) (records : List PublicSARecord) :
    Decidable (RecordedDirectionPolicyChecks configuration records) := by
  unfold RecordedDirectionPolicyChecks
  infer_instance

theorem recorded_direction_has_bound_policy (configuration : MultiProtocolForwarding.Config)
    (records : List PublicSARecord) (checked : RecordedDirectionPolicyChecks configuration records)
    (record : PublicSARecord) (member : record ∈ records) :
    configuration.ip.owner record.localIface = record.installation.device ∧
    ((record.installation.direction = .outbound ∧
      ∃ policy ∈ configuration.ip.egressPolicies record.localIface,
        DataPlaneForwarding.saMatchesPolicy record.installation.association policy) ∨
     (record.installation.direction = .inbound ∧
      ∃ policy ∈ configuration.ip.ingressPolicies record.localIface,
        DataPlaneForwarding.saMatchesPolicy record.installation.association policy)) := by
  have facts := checked record member
  refine ⟨facts.1, ?_⟩
  cases direction : record.installation.direction with
  | outbound => exact Or.inl ⟨rfl, by simpa only [direction] using facts.2⟩
  | inbound => exact Or.inr ⟨rfl, by simpa only [direction] using facts.2⟩


def PublicSAInventoryChecks (configuration : MultiProtocolForwarding.Config) (epoch : String)
    (records : List PublicSARecord) : Prop :=
  MaterialReferencesConsistent records ∧
  (∀ record ∈ records, record.installation.epoch = epoch ∧ record.installation.installation ≠ "" ∧
    configuration.ip.owner record.localIface = record.installation.device) ∧
  (∀ first ∈ records, ∀ second ∈ records,
    first.installation.device = second.installation.device →
    first.installation.installation = second.installation.installation →
    first.installation = second.installation) ∧
  (∀ first ∈ records, ∀ second ∈ records,
    first.installation.direction = .outbound → second.installation.direction = .outbound →
    SAWireKey first.installation.association = SAWireKey second.installation.association →
    first.installation = second.installation) ∧
  (∀ first ∈ records, ∀ second ∈ records,
    first.installation.direction = .inbound → second.installation.direction = .inbound →
    first.installation.device = second.installation.device →
    SAWireKey first.installation.association = SAWireKey second.installation.association →
    first.installation = second.installation)

instance (configuration : MultiProtocolForwarding.Config) (epoch : String)
    (records : List PublicSARecord) : Decidable (PublicSAInventoryChecks configuration epoch records) := by
  unfold PublicSAInventoryChecks MaterialReferencesConsistent SAWireKey
  infer_instance

instance (records : List PublicSARecord) (devices : List DataPlaneForwarding.DeviceData) :
    Decidable (CapturedStatePoolChecks records devices) := by
  unfold CapturedStatePoolChecks
  infer_instance


theorem public_SA_inventory_sound {S A : Type} (binding : DeviceExecutionBinding S A)
    (records : List PublicSARecord) (epoch : String) (material : String → IPsecKeyMaterial)
    (recorded : binding.ipsecInstallations = records.map PublicSARecord.installation)
    (keys : binding.ipsecKeyMaterial = publicKeyMaterial records material)
    (outbound : ∀ iface, binding.configuration.ip.egressSAs iface =
      directionalStates records (binding.configuration.ip.owner iface) .outbound)
    (inbound : ∀ iface, binding.configuration.ip.ingressSAs iface =
      directionalStates records (binding.configuration.ip.owner iface) .inbound)
    (currentEpoch : binding.ipsecEpoch = some epoch)
    (checked : PublicSAInventoryChecks binding.configuration epoch records)
    (privateMaterial : ∀ record ∈ records, (material record.materialReference).Valid) :
    binding.IPsecKeyInventory := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro installation member
    rw [recorded] at member
    obtain ⟨record, inRecords, equal⟩ := List.mem_map.mp member
    subst installation
    have facts := checked.2.1 record inRecords
    refine ⟨epoch, currentEpoch, facts.1, facts.2.1, ?_, material record.materialReference, ?_,
      privateMaterial record inRecords⟩
    · refine ⟨record.localIface, facts.2.2.symm, ?_⟩
      cases direction : record.installation.direction with
      | outbound =>
        rw [outbound]
        exact (directional_state_member ..).mpr ⟨record, inRecords, facts.2.2.symm, direction, rfl⟩
      | inbound =>
        rw [inbound]
        exact (directional_state_member ..).mpr ⟨record, inRecords, facts.2.2.symm, direction, rfl⟩
    · rw [keys]
      exact public_key_material_lookup records material checked.1 record inRecords
  · intro iface association member
    rw [outbound] at member
    obtain ⟨record, member, owner, direction, same⟩ := (directional_state_member ..).mp member
    exact ⟨record.installation, recorded ▸ List.mem_map.mpr ⟨record, member, rfl⟩, owner, direction, same⟩
  · intro iface association member
    rw [inbound] at member
    obtain ⟨record, member, owner, direction, same⟩ := (directional_state_member ..).mp member
    exact ⟨record.installation, recorded ▸ List.mem_map.mpr ⟨record, member, rfl⟩, owner, direction, same⟩
  · intro first firstMember second secondMember owner installation
    rw [recorded] at firstMember secondMember
    obtain ⟨firstRecord, firstIn, rfl⟩ := List.mem_map.mp firstMember
    obtain ⟨secondRecord, secondIn, rfl⟩ := List.mem_map.mp secondMember
    exact checked.2.2.1 firstRecord firstIn secondRecord secondIn owner installation
  · intro first firstMember second secondMember wireSeal firstSeal secondSeal
    rw [recorded] at firstMember secondMember
    obtain ⟨firstRecord, firstIn, rfl⟩ := List.mem_map.mp firstMember
    obtain ⟨secondRecord, secondIn, rfl⟩ := List.mem_map.mp secondMember
    exact checked.2.2.2.1 firstRecord firstIn secondRecord secondIn firstSeal.1 secondSeal.1
      ((outbound_seal_wire_key binding _ wireSeal firstSeal).trans
        (outbound_seal_wire_key binding _ wireSeal secondSeal).symm)
  · intro first firstMember second secondMember iface wireSeal firstSeal secondSeal
    rw [recorded] at firstMember secondMember
    obtain ⟨firstRecord, firstIn, rfl⟩ := List.mem_map.mp firstMember
    obtain ⟨secondRecord, secondIn, rfl⟩ := List.mem_map.mp secondMember
    exact checked.2.2.2.2 firstRecord firstIn secondRecord secondIn firstSeal.1 secondSeal.1
      (firstSeal.2.1.1.trans secondSeal.2.1.1.symm)
      ((inbound_seal_wire_key binding _ iface wireSeal firstSeal).trans
        (inbound_seal_wire_key binding _ iface wireSeal secondSeal).symm)

end TDN.Requirements
