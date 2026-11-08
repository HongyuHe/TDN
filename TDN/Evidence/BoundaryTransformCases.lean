import TDN.Evidence.OuterGrayNativeCases
import TDN.Targets.BoundaryProtocolDerivation

namespace TDN.Imported.BoundaryTransformCases
open Compliance Targets Targets.Complete MultiProtocolExecution OuterGrayNativeModel

structure ProtectedForwardCase where
  forward : ForwardCase
  policy : Execution.Association
  association : Execution.SecurityAssociation
  routeOuterPacket : Execution.Route
  wirePort : Nat

def ProtectedForwardCase.filtered (sample : ProtectedForwardCase) (records : Records) :
    MultiProtocolExecution.State :=
  { sample.forward.routed records with initialEntry := false, datapathStage := .filtered }

def ProtectedForwardCase.encrypted (sample : ProtectedForwardCase) (records : Records) :
    MultiProtocolExecution.State :=
  { sample.filtered records with
    initialEntry := false, datapathStage := .encapsulated,
    frame := records.configuration.ipsecFrame sample.forward.route.egress
      (sample.filtered records).frame (sample.policy.seal sample.association) }

def ProtectedForwardCase.ready (sample : ProtectedForwardCase) (records : Records) :
    MultiProtocolExecution.State :=
  { sample.encrypted records with initialEntry := false, iface := sample.routeOuterPacket.egress, datapathStage := .ready }

def ProtectedForwardCase.wired (sample : ProtectedForwardCase) (records : Records) :
    MultiProtocolExecution.State :=
  { sample.ready records with
    initialEntry := false
    iface := sample.wirePort
    datapathStage := .received
    authenticated := [] }

def ProtectedForwardCase.header (sample : ProtectedForwardCase) : PacketPolicy.Packet :=
  { LayeredFrame.outerHeader sample.policy.sender sample.policy.receiver "esp" 0 0 with hopLimit := 64 }

def ProtectedForwardCase.packet (sample : ProtectedForwardCase) (records : Records) : PacketPolicy.Packet :=
  BoundaryPacket records.configuration sample.routeOuterPacket.egress true sample.header

def ProtectedForwardCase.Checks (sample : ProtectedForwardCase) (records : Records)
    (deployment : Deployment) : Prop :=
  sample.forward.interface ∈ records.interfaces ∧
  sample.forward.interface.HookApplies .forward .outbound ∧
  sample.forward.route.ingress = sample.forward.entryIface ∧
  Execution.SelectedRoute records.routes sample.forward.route sample.forward.header ∧
  1 < sample.forward.header.hopLimit ∧ sample.forward.header.hopLimit ≤ 255 ∧
  deployment.ContextLocation records.inventory sample.forward.interface .outbound
    (sample.forward.context records) ∧
  (sample.forward.context records).raw.PreHookValid (sample.forward.packet records) .forward ∧
  Execution.accepts (records.configuration.ip.forwardRules sample.forward.route.egress)
    (records.configuration.ip.forwardFallback sample.forward.route.egress) (sample.forward.packet records) ∧
  (∀ policy ∈ records.projectedPolicies, policy.interface = sample.forward.interface.id →
    policy.direction = .outbound → policy.hook = .forward →
      policy.Accepts (deployment.Observe (sample.forward.packet records))) ∧
  sample.policy ∈ Execution.selectedAssociations
    (records.configuration.ip.outbound sample.forward.route.egress) (sample.forward.context records).header ∧
  sample.association ∈ records.configuration.ip.outboundStates sample.forward.route.egress ∧
  Execution.StateBindsPolicy sample.association sample.policy ∧
  sample.routeOuterPacket.ingress = sample.forward.route.egress ∧
  Execution.SelectedRoute records.routes sample.routeOuterPacket sample.header ∧
  records.configuration.physicalLink sample.routeOuterPacket.egress sample.wirePort ∧
  sample.routeOuterPacket.egress ∈ records.inventory.ifaces ∧
  records.ifaceName sample.routeOuterPacket.egress = sample.forward.interface.id

set_option synthInstance.maxSize 2048 in
instance (sample : ProtectedForwardCase) (records : Records) (deployment : Deployment) :
    Decidable (sample.Checks records deployment) := by
  letI : DecidableRel records.configuration.physicalLink := by
    intro first second
    change Decidable ((first, second) ∈ records.links)
    infer_instance
  unfold ProtectedForwardCase.Checks Deployment.ContextLocation Interface.HookApplies HookDirection
    InterfacePolicy.Accepts Execution.accepts Execution.StateBindsPolicy
  dsimp only [ForwardCase.context]
  infer_instance

lemma encrypted_header_is_visible (sample : ProtectedForwardCase) (records : Records)
    (bound : Execution.StateBindsPolicy sample.association sample.policy) :
    records.configuration.visibleHeader (sample.encrypted records).frame = some sample.header := by
  simp [ProtectedForwardCase.encrypted, ProtectedForwardCase.header, Records.configuration,
    Config.visibleHeader, Config.ipsecFrame, LayeredFrame.Frame.visibleHeader,
    LayeredFrame.Frame.pushHeader, LayeredFrame.Body.visibleHeader, Execution.Association.seal,
    bound.2.1, bound.2.2.1]

lemma fresh_observed_packet_is_supported (deployment : Deployment) (packet : PacketPolicy.Packet)
    (fresh : packet.connectionState = "new") :
    deployment.Supported (deployment.Observe packet) := by
  refine ⟨rfl, ?_⟩
  intro _ established
  change packet.connectionState = "established" at established
  rw [fresh] at established
  exact False.elim ((by decide : ("new" : String) ≠ "established") established)

theorem checked_case_reaches_configured_wire_header (sample : ProtectedForwardCase)
    (records : Records) (deployment : Deployment) (present : deployment.processing = some records.inventory)
    (interfaces : deployment.interfaces = records.interfaces)
    (policies : deployment.policies = records.projectedPolicies)
    (unique : InterfaceIDsUnique records.interfaces)
    (checks : sample.Checks records deployment) :
    MultiProtocolExecution.Step records.configuration (sample.forward.routed records)
        .forwardFilter (sample.filtered records) ∧
      MultiProtocolExecution.Step records.configuration (sample.filtered records)
        .encryptIPsec (sample.encrypted records) ∧
      MultiProtocolExecution.Step records.configuration (sample.encrypted records)
        .route (sample.ready records) ∧
      MultiProtocolExecution.Step records.configuration (sample.ready records)
        .linkTransmit (sample.wired records) ∧
      deployment.NativeBoundaryAccepts sample.forward.interface.id .outbound
        (deployment.Observe (sample.packet records)) := by
  obtain ⟨member, applies, entry, selected, ttl, bounded, location, raw, nativeAllow, permits,
    policySelected, installed, bound, outerEntry, outerSelected, linked, finalIface, finalName⟩ := checks
  have received : MultiProtocolExecution.Step records.configuration sample.forward.entry
      .receive sample.forward.entered := .receive rfl rfl "new"
  have routed : MultiProtocolExecution.Step records.configuration sample.forward.entered
      .route (sample.forward.routed records) := .route sample.forward.route rfl rfl selected entry
  have supported : deployment.SupportedAt sample.forward.interface .outbound
      (sample.forward.context records)
      (deployment.Observe (sample.forward.packet records)) := by
    refine ⟨records.inventory, present, interfaces.symm ▸ member, applies, ?_, location, raw, rfl,
      fresh_observed_packet_is_supported deployment _ rfl⟩
    refine ⟨rfl, sample.forward.entered, sample.forward.route, Or.inl received, ?_,
      routed, rfl, rfl, ?_, entry, rfl⟩
    · intro incoming visible
      have same : incoming = sample.forward.header := Option.some.inj visible.symm
      subst incoming
      intro _
      exact ttl
    · exact (selected_route_depends_on_destination records.routes sample.forward.route
        sample.forward.header (sample.forward.context records).header rfl).mp selected
  have admitted : deployment.AcceptsAt sample.forward.interface.id .outbound .forward
      (deployment.Observe (sample.forward.packet records)) := by
    refine ⟨fresh_observed_packet_is_supported deployment _ rfl,
      eligible_routed_packet_has_hook_context _ _ _ _ _ supported, ?_⟩
    obtain ⟨policy, policyMember, name, direction, hook, only⟩ :=
      native_policies_cover_hooks records.inventory records.interfaces records.ifaceIndex unique
        sample.forward.interface member .outbound .forward applies
    refine ⟨policy, policies.symm ▸ policyMember, name, direction, hook, ?_,
      permits policy policyMember name direction hook⟩
    intro other otherMember otherName otherDirection otherHook
    apply only other
    · change other ∈ records.projectedPolicies
      rw [← policies]
      exact otherMember
    · exact otherName
    · exact otherDirection
    · exact otherHook
  have filtered : MultiProtocolExecution.Step records.configuration (sample.forward.routed records)
      .forwardFilter (sample.filtered records) :=
    .forwardFilter rfl rfl nativeAllow
  have encrypted : MultiProtocolExecution.Step records.configuration (sample.filtered records)
      .encryptIPsec (sample.encrypted records) :=
    .encryptIPsec sample.policy sample.association rfl rfl policySelected installed bound
  have outerRouted : MultiProtocolExecution.Step records.configuration (sample.encrypted records)
      .route (sample.ready records) :=
    .routeOuterPacket sample.routeOuterPacket rfl (encrypted_header_is_visible sample records bound)
      outerSelected outerEntry
  have wired : MultiProtocolExecution.Step records.configuration (sample.ready records)
      .linkTransmit (sample.wired records) := .linkTransmit sample.wirePort rfl linked
  refine ⟨filtered, encrypted, outerRouted, wired, records.inventory, present,
    sample.forward.interface, interfaces.symm ▸ member, sample.forward.context records, supported, admitted,
    ?_, sample.routeOuterPacket.egress, finalIface, finalName, ?_,
    ?_⟩
  · exact ⟨⟨rfl, bounded⟩, rfl⟩
  · exact .outbound (sample.filtered records) (sample.ready records) (sample.wired records)
      (Or.inl ⟨rfl, filtered⟩)
      (.next (by simp [ProtectedForwardCase.filtered]) encrypted
        (.next (by simp [ProtectedForwardCase.encrypted]) outerRouted (.ready rfl)))
      wired sample.header (encrypted_header_is_visible sample records bound)
  · refine ⟨rfl, ?_⟩
    intro management established
    exact False.elim (IPsec_service_is_not_management (sample.packet records) (Or.inl rfl) management)

end TDN.Imported.BoundaryTransformCases
