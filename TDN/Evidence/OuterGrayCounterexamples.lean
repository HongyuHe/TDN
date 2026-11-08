import TDN.Evidence.OuterGrayNativeCases
import TDN.Semantics.NativeAdmission

namespace TDN.Imported.OuterGrayNativeModel
open Compliance Targets Targets.Complete MultiProtocolExecution

def ForwardCase.SupportedChecks (sample : ForwardCase) (records : Records) (base : Deployment)
    (direction : Direction) : Prop :=
  sample.interface ∈ records.interfaces ∧ sample.interface.HookApplies .forward direction ∧
  sample.route.ingress = sample.entryIface ∧
  Execution.SelectedRoute records.routes sample.route sample.header ∧
  1 < sample.header.hopLimit ∧
  (records.deployment base).ContextLocation records.inventory sample.interface direction (sample.context records) ∧
  (sample.context records).raw.PreHookValid (sample.packet records) .forward

set_option synthInstance.maxSize 2048 in
instance (sample : ForwardCase) (records : Records) (base : Deployment) (direction : Direction) :
    Decidable (sample.SupportedChecks records base direction) := by
  unfold ForwardCase.SupportedChecks Deployment.ContextLocation ForwardCase.context
    Interface.HookApplies HookDirection Deployment.LocalSourceAddress
  cases direction <;> infer_instance

lemma checked_plain_forward_case_is_supported (sample : ForwardCase) (records : Records)
    (base : Deployment) (direction : Direction)
    (checks : sample.SupportedChecks records base direction) :
    (records.deployment base).SupportedAt sample.interface direction (sample.context records)
      ((records.deployment base).Observe (sample.packet records)) := by
  obtain ⟨member, applies, entry, selected, ttl, location, raw⟩ := checks
  have received : MultiProtocolExecution.Step records.configuration sample.entry .receive sample.entered :=
    .receive rfl rfl "new"
  have routed : MultiProtocolExecution.Step records.configuration sample.entered .route (sample.routed records) :=
    .route sample.route rfl rfl selected entry
  refine ⟨records.inventory, rfl, member, applies, ?_, location, raw, rfl,
    observed_packet_is_supported records base _ rfl⟩
  refine ⟨rfl, sample.entered, sample.route, Or.inl received, ?_, routed, rfl, rfl, ?_, entry, rfl⟩
  · intro incoming visible
    have same : incoming = sample.header := Option.some.inj visible.symm
    subst incoming
    intro _
    exact ttl
  · exact (selected_route_depends_on_destination records.routes sample.route sample.header
      (sample.context records).header rfl).mp selected

lemma datagram_cannot_be_decrypted (configuration : MultiProtocolExecution.Config)
    (before after : MultiProtocolExecution.State) (header : PacketPolicy.Packet)
    (plain : before.frame.body = .datagram header) :
    ¬ MultiProtocolExecution.Step configuration before .decryptIPsec after := by
  intro step
  cases step with
  | decryptIPsec policy association body nominal datapathStage encrypted configured installed bound visible selected tracking =>
    rw [plain] at encrypted
    cases encrypted

lemma checked_plaintext_required_arrival_is_not_positive_eligible (sample : ForwardCase)
    (records : Records) (base : Deployment)
    (required : (records.deployment base).InboundIPsecRequired records.inventory sample.entryIface
      (sample.context records).header) :
    ¬ (records.deployment base).ContextIngressEligible (sample.context records)
      ((records.deployment base).Observe (sample.packet records)) := by
  rintro ⟨inventory, present, _, _, eligibility⟩
  have same : inventory = records.inventory := Option.some.inj present.symm
  subst inventory
  rcases eligibility rfl required with ⟨entered, decrypted, _, _⟩ | ⟨_, approved, _⟩
  · exact datagram_cannot_be_decrypted records.configuration sample.entry entered sample.header rfl decrypted
  · exact approved

lemma native_arrival_iff_visible_source (d : Deployment) (inventory : PacketProcessing.Inventory)
    (state : MultiProtocolExecution.State) (header : PacketPolicy.Packet)
    (visible : state.frame.visibleHeader = some header) :
    d.NativeArrivalEligible inventory state ↔
      NativeIngressAttachment inventory state.iface ∨
        d.LocalSourceAddress (inventory.componentName (inventory.configuration.ip.owner state.iface)) header := by
  constructor
  · rintro (attachment | ⟨incoming, observed, source⟩)
    · exact Or.inl attachment
    · have same : incoming = header := Option.some.inj (observed.symm.trans visible)
      exact Or.inr (same ▸ source)
  · rintro (attachment | source)
    · exact Or.inl attachment
    · exact Or.inr ⟨header, visible, source⟩

end TDN.Imported.OuterGrayNativeModel
