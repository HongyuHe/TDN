import TDN.Requirements.VerifiedMacsecProtectionParameters
import TDN.Requirements.NetworkEventTraceOrder

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding LayeredFrame

def MACsecTunnelNamesSeparate {S A : Type} (d : Deployment)
    (binding : DeviceExecutionBinding S A) : Prop :=
  ∀ configured ∈ d.tunnels, configured.mechanism = .macsec →
    ∀ authentication, binding.ipsecTunnel authentication ≠ configured.id

lemma source_events_have_no_encrypt {S A : Type} (binding : DeviceExecutionBinding S A)
    (before : S) (payload : PayloadId) (tunnel : String) :
    NetworkEvent.encrypt payload tunnel ∉ binding.SourceEvents before := by
  dsimp only [DeviceExecutionBinding.SourceEvents]
  split
  · split
    · split <;> simp
    · simp
  · simp

lemma macsec_encrypt_output {configuration : Config} {before after : MultiProtocolForwarding.State}
    (step : MultiProtocolForwarding.Step configuration before .encryptMACsec after) :
    ∃ iface ∈ configuration.macIfaces, ∃ association,
      iface.transmitAssociation = some association ∧ after.frame.body = .macsec association before.frame.body := by
  cases step with
  | encryptMACsec iface association member stage logical emits =>
    exact ⟨iface, member, association, emits.1, Config.macsecFrame_body _ _ _⟩

lemma operation_encrypt_has_macsec_sa {S A : Type} {d : Deployment}
    (binding : DeviceExecutionBinding S A) (separate : MACsecTunnelNamesSeparate d binding)
    (before after : S) (action : MultiProtocolForwarding.Action)
    (step : MultiProtocolForwarding.Step binding.configuration (binding.state before) action (binding.state after))
    (payload : PayloadId) (configured : Tunnel) (member : configured ∈ d.tunnels)
    (mechanism : configured.mechanism = .macsec)
    (encrypted : NetworkEvent.encrypt payload configured.id ∈ binding.OperationEvents before action after) :
    ∃ iface ∈ binding.configuration.macIfaces, ∃ association,
      iface.transmitAssociation = some association ∧
      binding.macsecTunnel association = configured.id ∧
      binding.OperationEvents before action after =
        [.useSAK payload configured.id (binding.keyName association.keyGeneration),
          .protect payload configured.id (.macsec association), .encrypt payload configured.id] := by
  cases action <;> simp only [DeviceExecutionBinding.OperationEvents] at encrypted
  all_goals try contradiction
  case encryptIPsec =>
    split at encrypted
    next authentication body same =>
      simp at encrypted
      exact False.elim (separate configured member mechanism authentication encrypted.2.symm)
    next other => simp at encrypted
  case encryptMACsec =>
    obtain ⟨iface, present, association, installed, body⟩ := macsec_encrypt_output step
    rw [body] at encrypted
    simp at encrypted
    obtain ⟨samePayload, sameTunnel⟩ := encrypted
    exact ⟨iface, present, association, installed, sameTunnel.symm, by
      simp only [DeviceExecutionBinding.OperationEvents, body, samePayload, sameTunnel]⟩
  all_goals { split at encrypted <;> simp_all }

lemma macsec_use_precedes_operation_encrypt {association : MACsecAssociation} {payload : PayloadId}
    {tunnel key : String} {earlier later : List NetworkEvent}
    (split : [.useSAK payload tunnel key, .protect payload tunnel (.macsec association),
      .encrypt payload tunnel] = earlier ++ [.encrypt payload tunnel] ++ later) :
    .useSAK payload tunnel key ∈ earlier := by
  cases earlier with
  | nil => simp at split
  | cons head rest =>
    have same := (List.cons.inj split).1
    exact List.mem_cons.mpr (Or.inl same)

lemma step_encrypt_has_prior_sak_use {S A : Type} {d : Deployment} (model : ForwardingModel S A)
    (faithful : model.Faithful) (separate : MACsecTunnelNamesSeparate d model.native)
    {before after : S} {action : A} (step : model.system.Tr before action after)
    {earlier later : List NetworkEvent} {payload : PayloadId} (configured : Tunnel)
    (member : configured ∈ d.tunnels) (mechanism : configured.mechanism = .macsec)
    (split : model.events action = earlier ++ [.encrypt payload configured.id] ++ later) :
    ∃ iface ∈ model.native.configuration.macIfaces, ∃ association,
      iface.transmitAssociation = some association ∧ model.native.macsecTunnel association = configured.id ∧
      .useSAK payload configured.id (model.native.keyName association.keyGeneration) ∈ earlier := by
  have observed := faithful before action after step
  have filtered := congrArg (List.filter NetworkEvent.NetworkOperation) split
  simp only [List.filter_append, List.filter_cons, NetworkEvent.NetworkOperation,
    ↓reduceIte, List.filter_nil] at filtered
  cases operation : model.native.action action with
  | none =>
    rw [operation] at observed
    rw [observed.2] at filtered
    have encrypted : .encrypt payload configured.id ∈
        earlier.filter NetworkEvent.NetworkOperation ++ [.encrypt payload configured.id] ++
          later.filter NetworkEvent.NetworkOperation := by simp
    rw [← filtered] at encrypted
    simp at encrypted
  | some operationName =>
    rw [operation] at observed
    rw [observed.2, DeviceExecutionBinding.RequiredEvents] at filtered
    rcases event_split_append _ _ _ _ _ filtered with
      ⟨leading, trailing, sourceSplit, equal⟩ | ⟨leading, trailing, operationSplit, equal⟩
    · have encrypted : .encrypt payload configured.id ∈ model.native.SourceEvents before := by
        rw [sourceSplit]; simp
      exact False.elim (source_events_have_no_encrypt model.native before payload configured.id encrypted)
    · have encrypted : .encrypt payload configured.id ∈ model.native.OperationEvents before operationName after := by
        rw [operationSplit]; simp
      obtain ⟨iface, present, association, installed, tunnel, layout⟩ :=
        operation_encrypt_has_macsec_sa model.native separate before after operationName observed.1.1
          payload configured member mechanism encrypted
      rw [layout] at operationSplit
      have used := macsec_use_precedes_operation_encrypt operationSplit
      have inFiltered : .useSAK payload configured.id (model.native.keyName association.keyGeneration) ∈
          earlier.filter NetworkEvent.NetworkOperation := by
        rw [equal]
        exact List.mem_append_right _ used
      exact ⟨iface, present, association, installed, tunnel, (List.mem_filter.mp inFiltered).1⟩

theorem forwarding_encrypt_has_prior_sak_use {S A : Type} {d : Deployment}
    (model : ForwardingModel S A) (faithful : model.Faithful)
    (separate : MACsecTunnelNamesSeparate d model.native)
    {before after : S} {actions : List A} (run : model.system.MTr before actions after)
    {earlier later : List NetworkEvent} {payload : PayloadId} (configured : Tunnel)
    (member : configured ∈ d.tunnels) (mechanism : configured.mechanism = .macsec)
    (split : actions.flatMap model.events = earlier ++ [.encrypt payload configured.id] ++ later) :
    ∃ iface ∈ model.native.configuration.macIfaces, ∃ association,
      iface.transmitAssociation = some association ∧ model.native.macsecTunnel association = configured.id ∧
      .useSAK payload configured.id (model.native.keyName association.keyGeneration) ∈ earlier := by
  induction run generalizing earlier later with
  | refl => simp at split
  | @stepL first action next rest last step tail ih =>
    simp only [List.flatMap_cons] at split
    rcases event_split_append _ _ _ _ _ split with
      ⟨leading, trailing, actionSplit, equal⟩ | ⟨leading, trailing, restSplit, equal⟩
    · obtain ⟨iface, present, association, installed, tunnel, used⟩ :=
        step_encrypt_has_prior_sak_use model faithful separate step configured member mechanism actionSplit
      exact ⟨iface, present, association, installed, tunnel, equal ▸ used⟩
    · obtain ⟨iface, present, association, installed, tunnel, used⟩ := ih restSplit
      refine ⟨iface, present, association, installed, tunnel, ?_⟩
      rw [equal]
      exact List.mem_append_right _ used

end TDN.Requirements.Msc
