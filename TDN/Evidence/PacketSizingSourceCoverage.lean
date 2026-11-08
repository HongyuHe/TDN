import TDN.Evidence.PacketSizingChecks
import TDN.Targets.CompletePacketSizing
import TDN.Targets.FiniteInventoryNames

namespace TDN.Imported.PacketSizingRecords
open Compliance Targets OuterGrayNativeModel CanonicalExecution PacketSource


def SourceBindingChecks (records : Records) (entries : List SourceEntry) (networks : List RedNetworkIdentity) : Prop :=
  records.ifaceNames.length = records.nativeIfaces.length ∧
  (∀ interface ∈ records.interfaces, interface.id ≠ "unlisted-port") ∧
  (∀ entry ∈ entries, entry.iface < records.nativeIfaces.length ∧
    ∃ network ∈ networks, network.id = entry.network) ∧
  ∀ iface ∈ List.range records.nativeIfaces.length, ∀ network ∈ networks,
    sourceEntry entries iface = some network.id ↔
    ∃ interface ∈ records.interfaces, interface.id = records.ifaceName iface ∧ interface.zone = .red ∧
      interface.managementNetwork = false ∧ interface.device ∈ network.innerComponents

instance (records : Records) (entries : List SourceEntry) (networks : List RedNetworkIdentity) :
    Decidable (SourceBindingChecks records entries networks) := by
  unfold SourceBindingChecks
  infer_instance

lemma source_entry_is_recorded (entries : List SourceEntry) (iface : Nat) (network : String)
    (selected : sourceEntry entries iface = some network) :
    ∃ entry ∈ entries, entry.iface = iface ∧ entry.network = network := by
  unfold sourceEntry at selected
  cases found : entries.find? (fun entry => entry.iface == iface) with
  | none => simp only [found, Option.map_none] at selected; cases selected
  | some entry =>
    refine ⟨entry, List.mem_of_find?_eq_some found, ?_, ?_⟩
    · have matching : (entry.iface == iface) = true := List.find?_some (p := fun candidate : SourceEntry => candidate.iface == iface) found
      exact beq_iff_eq.mp matching
    · simpa only [found, Option.map_some, Option.some.injEq] using selected

lemma interface_name_forces_iface (records : Records) (interface : Interface)
    (namesLength : records.ifaceNames.length = records.nativeIfaces.length)
    (listed : interface.id ≠ "unlisted-port") (iface : Nat)
    (same : interface.id = records.ifaceName iface) : iface ∈ List.range records.nativeIfaces.length := by
  by_contra outside
  have absent : records.ifaceNames[iface]? = none := List.getElem?_eq_none (by
    have bound : records.nativeIfaces.length ≤ iface := by simpa only [List.mem_range, not_lt] using outside
    omega)
  exact listed (same.trans (by simp only [Records.ifaceName, absent, Option.getD_none]))


theorem source_bindings_cover_all_ifaces (records : Records) (entries : List SourceEntry)
    (networks : List RedNetworkIdentity) (checked : SourceBindingChecks records entries networks) :
    ∀ iface network, sourceEntry entries iface = some network ↔
      ∃ interface ∈ records.interfaces, interface.id = records.ifaceName iface ∧ interface.zone = .red ∧
        interface.managementNetwork = false ∧ ∃ red ∈ networks,
          red.id = network ∧ interface.device ∈ red.innerComponents := by
  intro iface network
  constructor
  · intro selected
    obtain ⟨entry, member, sameIface, sameNetwork⟩ := source_entry_is_recorded entries iface network selected
    obtain ⟨present, red, redMember, redName⟩ := checked.2.2.1 entry member
    obtain ⟨interface, interfaceMember, name, zone, management, owner⟩ :=
      (checked.2.2.2 iface (List.mem_range.mpr (by simpa only [sameIface] using present)) red redMember).mp
        (by rw [redName, sameNetwork]; exact selected)
    exact ⟨interface, interfaceMember, name, zone, management, red, redMember, redName.trans sameNetwork, owner⟩
  · rintro ⟨interface, member, name, zone, management, red, redMember, redName, owner⟩
    have present := interface_name_forces_iface records interface checked.1 (checked.2.1 interface member) iface name
    rw [← redName]
    exact (checked.2.2.2 iface present red redMember).mpr ⟨interface, member, name, zone, management, owner⟩


theorem allowed_source_iface_is_recorded {Key : Type} (records : Records)
    (installations : List PublicSARecord) (entries : List SourceEntry) (roles : List SizingRole)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (epoch : String)
    (codec : IPsecFrameEncoding.Codec Key) (material : String → IPsecKeyMaterial)
    (networks : List RedNetworkIdentity) (attachments : List RedNetworkAttachment)
    (services : List ServiceRegistration) (base : Deployment)
    (checked : SourceBindingChecks records entries networks)
    (request : Request)
    (allowed : (prototype records installations entries roles policies epoch codec material).SourceRequestAllowed
      (completeDeployment records installations policies codec networks attachments services base) request) :
    request.iface ∈ List.range records.nativeIfaces.length := by
  cases origin : sourceOrigin entries records.componentName request.originDomain with
  | red network =>
    have source := allowed.2.2
    change (match sourceOrigin entries records.componentName request.originDomain with
      | .red network => sourceEntry entries request.iface = some network ∧ _
      | .management component => _
      | .control component protocol => _) at source
    rw [origin] at source
    obtain ⟨entry, member, sameIface, sameNetwork⟩ := source_entry_is_recorded entries request.iface network source.1
    exact List.mem_range.mpr (by simpa only [sameIface] using (checked.2.2.1 entry member).1)
  | management component =>
    have source := allowed.2.2
    change (match sourceOrigin entries records.componentName request.originDomain with
      | .red network => _
      | .management component => _ ∧ _ ∧ _
      | .control component protocol => _) at source
    rw [origin] at source
    obtain ⟨interface, member, name, owner, body⟩ := source.2.2
    exact interface_name_forces_iface records interface checked.1 (checked.2.1 interface member) request.iface name
  | control component protocol =>
    have source := allowed.2.2
    change (match sourceOrigin entries records.componentName request.originDomain with
      | .red network => _
      | .management component => _
      | .control component protocol => _ ∧ _ ∧ _) at source
    rw [origin] at source
    obtain ⟨interface, member, name, owner, body⟩ := source.2.2
    exact interface_name_forces_iface records interface checked.1 (checked.2.1 interface member) request.iface name


def EmittedOutcome (outcome : Outcome) : Prop := match outcome with
  | .emitted _ => True
  | .error _ => False

instance (outcome : Outcome) : Decidable (EmittedOutcome outcome) := by
  cases outcome <;> unfold EmittedOutcome <;> infer_instance


def NetworkSourceChecks (entries : List SourceEntry) (roles : List SizingRole)
    (names : Nat → String) (networks : List RedNetworkIdentity) (flows : List SourceFlow) : Prop :=
  ∀ network ∈ networks, ∃ flow ∈ flows,
    sourceEntry entries flow.iface = some network.id ∧
    sourceOrigin entries names flow.domain = .red network.id ∧
    EmittedOutcome (processSource (sourceMtu roles flow.iface) flow.request)

instance (entries : List SourceEntry) (roles : List SizingRole) (names : Nat → String)
    (networks : List RedNetworkIdentity) (flows : List SourceFlow) :
    Decidable (NetworkSourceChecks entries roles names networks flows) := by
  unfold NetworkSourceChecks
  infer_instance


theorem every_recorded_network_has_source {Key : Type} (records : Records)
    (installations : List PublicSARecord) (entries : List SourceEntry) (roles : List SizingRole)
    (policies : List (Nat × LinkAdmission.IfacePolicy)) (epoch : String)
    (codec : IPsecFrameEncoding.Codec Key) (material : String → IPsecKeyMaterial)
    (networks : List RedNetworkIdentity) (attachments : List RedNetworkAttachment)
    (services : List ServiceRegistration) (base : Deployment) (flows : List SourceFlow)
    (checked : NetworkSourceChecks entries roles records.componentName networks flows) :
    ∀ network ∈ networks, ∃ request datagrams,
      (prototype records installations entries roles policies epoch codec material).SourceRequestAllowed
        (completeDeployment records installations policies codec networks attachments services base) request ∧
      request.application ≠ [] ∧ sourceOrigin entries records.componentName request.originDomain = .red network.id ∧
      (sourceProcessing (sourceMtu roles)).process request = .emitted datagrams := by
  intro network member
  obtain ⟨flow, flowMember, entry, origin, emitted⟩ := checked network member
  cases outcome : processSource (sourceMtu roles flow.iface) flow.request with
  | error error => simp only [outcome, EmittedOutcome] at emitted
  | emitted datagrams =>
    refine ⟨flow.request, datagrams, ?_, by simp [SourceFlow.request], origin, outcome⟩
    change _ ∧ _ ∧ match sourceOrigin entries records.componentName flow.domain with
      | .red network => sourceEntry entries flow.iface = some network ∧ _
      | .management component => _
      | .control component protocol => _
    rw [origin]
    exact ⟨Or.inl ⟨_, rfl⟩, rfl, entry, network, member, rfl⟩


def SourceAttachmentChecks (records : Records) (entries : List SourceEntry)
    (networks : List RedNetworkIdentity) (attachments : List RedNetworkAttachment) : Prop :=
  ∀ entry ∈ entries,
    entry.hostIface ∈ records.inventory.ifaces ∧ entry.iface ∈ records.inventory.ifaces ∧
    records.componentName (records.configuration.ip.owner entry.hostIface) = entry.sourceHost ∧
    entry.arrivalPath.head? = some entry.hostIface ∧ entry.arrivalPath.getLast? = some entry.iface ∧
    (∀ edge ∈ entry.arrivalPath.zip (entry.arrivalPath.drop 1), edge ∈ records.links ∨ edge ∈ records.bridges) ∧
    (∃ network ∈ networks, network.id = entry.network ∧
      records.componentName (records.configuration.ip.owner entry.iface) ∈ network.innerComponents) ∧
    (∃ attachment ∈ attachments, attachment.network = entry.network ∧
      attachment.interface = records.ifaceName entry.hostIface) ∧
    (∃ attachment ∈ attachments, attachment.network = entry.network ∧
      attachment.interface = records.ifaceName entry.iface)

instance (records : Records) (entries : List SourceEntry) (networks : List RedNetworkIdentity)
    (attachments : List RedNetworkAttachment) :
    Decidable (SourceAttachmentChecks records entries networks attachments) := by
  unfold SourceAttachmentChecks
  infer_instance

end TDN.Imported.PacketSizingRecords

