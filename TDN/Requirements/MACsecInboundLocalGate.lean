import TDN.Requirements.IPsecInboundLocalGate
import TDN.Models.MacsecExternalOutputProtection

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding LayeredFrame

structure MACsecPendingGuard {S A : Type} (binding : DeviceExecutionBinding S A)
    (target : PayloadId → String → Option String) (pending : PendingInboundProtection)
    (state : MultiProtocolForwarding.State) : Prop where
  layers : binding.LayerIds state.frame.body = pending.layers
  stage : state.datapathStage = .received ∨ state.datapathStage = .dropped
  target : target ⟨state.frame.originDomain, state.frame.payload⟩ (binding.ifaceName state.iface) = some pending.component

structure MACsecIngressGateChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : Layer) (target : PayloadId → String → Option String) : Prop where
  wire : MACsecWireChecks binding.configuration
  noBridges : ∀ first last, ¬ binding.configuration.bridge first last
  strict : ∀ iface ∈ binding.configuration.macIfaces, iface.validateStrict = true
  sourceTargets : ∀ payload iface network, binding.sourceEntry iface = some network →
    target payload (binding.ifaceName iface) = none
  physicalTargets : ∀ payload iface component, target payload (binding.ifaceName iface) = some component →
    ∃ mac ∈ binding.configuration.macIfaces, iface = mac.physicalIface
  initial : ∀ state, binding.SourceInitial d state →
    MACsecOutputProtected binding.configuration state ∧ PhysicalMACsecFrames binding.configuration state
  decryption : ∀ payload iface component sender transmitted receiver association,
    target payload (binding.ifaceName iface) = some component →
    sender ∈ binding.configuration.macIfaces → sender.transmitAssociation = some transmitted →
    receiver ∈ binding.configuration.macIfaces → iface = receiver.physicalIface →
    association ∈ receiver.receiveAssociations → SameMACWireIdentity transmitted association →
    ∃ tunnel ∈ d.tunnels, tunnel.id = binding.macsecTunnel transmitted ∧
      tunnel.layer = layer ∧ tunnel.receiver = component

lemma macsec_pending_preserved_without_decryption {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : Layer) (target : PayloadId → String → Option String)
    (checks : MACsecIngressGateChecks binding d layer target) {pending : PendingInboundProtection}
    {before after : MultiProtocolForwarding.State} {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before operation after)
    (framed : PhysicalMACsecFrames binding.configuration before)
    (other : operation ≠ .decryptMACsec) (guard : MACsecPendingGuard binding target pending before) :
    MACsecPendingGuard binding target pending after := by
  obtain ⟨receiver, configuredReceiver, physical⟩ := checks.physicalTargets _ _ _ guard.target
  obtain ⟨sender, configuredSender, transmitted, contents, installedSender, encryptedBody⟩ :=
    framed receiver configuredReceiver physical
  have pendingStage := guard.stage
  have invisible : binding.configuration.visibleHeader before.frame = none := by
    cases mode : binding.configuration.headerProcessing <;>
      simp [Config.visibleHeader, mode, Frame.visibleHeader, encryptedBody, Body.visibleHeader]
  cases step with
  | drop => exact ⟨guard.layers, Or.inr rfl, guard.target⟩
  | receive stage visible tracking => simp [invisible] at visible
  | route route stage visible selected entry => simp [invisible] at visible
  | routeLocalOutput route stage visible selected entry => simp [invisible] at visible
  | forwardFilter stage visible accepted => simp [invisible] at visible
  | outputFilter stage visible accepted => simp [invisible] at visible
  | encryptIPsec policy association stage visible selected installed bound => simp [invisible] at visible
  | routeOuterPacket route stage visible selected entry => simp [invisible] at visible
  | forwardWithoutEncap stage visible noPolicy => simp [invisible] at visible
  | inputFilter stage visible addressed accepted => simp [invisible] at visible
  | decryptIPsec policy association body header stage encrypted => rw [encryptedBody] at encrypted; cases encrypted
  | deliver domain stage plain recipient | deliverEthernet header domain stage plain recipient =>
    rw [encryptedBody] at plain
    cases plain
  | bridge next stage connected | bridgeOutput next stage connected =>
    exact False.elim (checks.noBridges _ _ connected)
  | decryptMACsec => exact False.elim (other rfl)
  | validateMACsec iface association transmitted encryptFrames confidentialityOffset body configured stage physical framed =>
    rw [encryptedBody] at framed
    cases framed
  | uncheckedMACsec iface configured stage physical unchecked =>
    simp [checks.strict iface configured] at unchecked
  | encapsulate iface configured | decapsulate iface body configured =>
    simp [checks.wire.noCarriers] at configured
  | encryptMACsec iface association configured stage logical emits => simp [stage] at pendingStage
  | unprotectedMACsec iface configured stage logical enabled unprotected => simp [stage] at pendingStage
  | protectMACsec iface association configured stage logical enabled protection installed limited => simp [stage] at pendingStage
  | linkTransmit next stage connected => simp [stage] at pendingStage

def macsecIngressDeviceGate {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : Layer) (target : PayloadId → String → Option String)
    (checks : MACsecIngressGateChecks binding d layer target) : DeviceInboundGateChecks binding d layer target := by
  refine ⟨MACsecPendingGuard binding target,
    fun state => MACsecOutputProtected binding.configuration state ∧ PhysicalMACsecFrames binding.configuration state,
    checks.initial, ?_, ?_⟩
  · intro before operation after step safe
    exact ⟨step_preserves_macsec_output_protection checks.wire.output step safe.1,
      step_preserves_physical_macsec_frames checks.wire step safe.1 safe.2⟩
  · intro before operation after step safe pending consistent
    let view := binding.withProjection (id : MultiProtocolForwarding.State → MultiProtocolForwarding.State)
      (fun action : MultiProtocolForwarding.Action => some action)
    have sourceRun := ipsec_source_events_preserve_pending view d layer target checks.sourceTargets before pending
    have names : ∀ body, view.LayerIds body = binding.LayerIds body := layer_ids_with_tunnel_names binding _ _
    have operationRun : ∃ next,
        (inboundProtectionGate d layer target ⟨before.frame.originDomain, before.frame.payload⟩).MTr
          pending (view.OperationEvents before operation after) next ∧
        InboundGateConsistent (MACsecPendingGuard binding target) next after := by
      cases pending with
      | none =>
        by_cases transmitting : operation = .linkTransmit
        · subst operation
          cases step with
          | linkTransmit next ready linked =>
            dsimp only [DeviceExecutionBinding.OperationEvents, view, DeviceExecutionBinding.withProjection, id_eq]
            dsimp only [view, DeviceExecutionBinding.withProjection] at names
            simp only [names]
            cases selected : target ⟨before.frame.originDomain, before.frame.payload⟩ (binding.ifaceName next) with
            | none =>
              refine ⟨none, ?_, trivial⟩
              exact .stepL (InboundProtectionGateStep.neutral _ _ trivial)
                (.stepL (InboundProtectionGateStep.transmit _ _ _)
                  (.stepL (InboundProtectionGateStep.receiveOther _ _ _ _ selected)
                    (.stepL (InboundProtectionGateStep.neutral _ _ trivial) .refl)))
            | some component =>
              refine ⟨some ⟨component, binding.LayerIds before.frame.body⟩, ?_, ?_⟩
              · exact .stepL (InboundProtectionGateStep.neutral _ _ trivial)
                  (.stepL (InboundProtectionGateStep.transmit _ _ _)
                    (.stepL (InboundProtectionGateStep.receiveProtected _ _ _ _ selected)
                      (.stepL (InboundProtectionGateStep.neutral _ _ trivial) .refl)))
              · exact ⟨rfl, Or.inl rfl, selected⟩
        · exact ⟨none, neutral_gate_events_preserve_pending none _
            (nontransmit_operation_events_are_gate_neutral view before after operation transmitting), trivial⟩
      | some received =>
        change MACsecPendingGuard binding target received before at consistent
        by_cases decrypted : operation = .decryptMACsec
        · subst operation
          cases step with
          | decryptMACsec receiver association transmitted body configured stage physical encrypted installed wire =>
            obtain ⟨sender, senderMember, actual, contents, senderInstalled, sameBody⟩ := safe.2 receiver configured physical
            have same : actual = transmitted := by
              exact (Body.macsec.inj (sameBody.symm.trans encrypted)).1
            subst actual
            obtain ⟨tunnel, member, same, selectedLayer, boundReceiver⟩ :=
              checks.decryption _ _ _ sender transmitted receiver association consistent.target senderMember senderInstalled
                configured physical installed wire
            have present : binding.macsecTunnel transmitted ∈ received.layers := by
              rw [← consistent.layers, encrypted]
              simp only [DeviceExecutionBinding.LayerIds, List.mem_cons, true_or]
            have matched : MatchingInboundDecryption d layer received (binding.macsecTunnel transmitted) :=
              ⟨tunnel, member, same, selectedLayer, boundReceiver, present⟩
            refine ⟨none, ?_, trivial⟩
            dsimp only [DeviceExecutionBinding.OperationEvents, view, DeviceExecutionBinding.withProjection, id_eq]
            rw [encrypted]
            exact .stepL (InboundProtectionGateStep.neutral _ _ trivial)
              (.stepL (InboundProtectionGateStep.decrypt received _ matched) .refl)
        · have retained := macsec_pending_preserved_without_decryption binding d layer target checks step safe.2 decrypted consistent
          have noTransmit : operation ≠ .linkTransmit := by
            intro same
            subst operation
            cases step with
            | linkTransmit next ready linked => simpa [ready] using consistent.stage
          exact ⟨some received, neutral_gate_events_preserve_pending _ _
            (nontransmit_operation_events_are_gate_neutral view before after operation noTransmit), retained⟩
    obtain ⟨next, emitted, retained⟩ := operationRun
    exact ⟨next, (Cslib.LTS.MTr.append_iff _).mpr ⟨pending, sourceRun, emitted⟩, retained⟩

end TDN.Requirements.Msc
