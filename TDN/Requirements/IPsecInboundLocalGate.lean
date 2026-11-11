import TDN.Requirements.DeviceInboundProtectionGate

namespace TDN.Requirements.Msc
open Compliance MultiProtocolForwarding LayeredFrame

def ipsecPendingStages : List DataPlaneForwarding.DatapathStage :=
  [.received, .ingress, .routed, .localInput, .delivered, .dropped]

structure IPsecPendingGuard {S A : Type} (binding : DeviceExecutionBinding S A)
    (target : PayloadId → String → Option String) (pending : PendingInboundProtection)
    (state : MultiProtocolForwarding.State) : Prop where
  owner : binding.componentName (binding.configuration.ip.owner state.iface) = pending.component
  layers : binding.LayerIds state.frame.body = pending.layers
  unauthenticated : state.authenticated = []
  stage : state.datapathStage ∈ ipsecPendingStages
  received : state.datapathStage = .received →
    target ⟨state.frame.originDomain, state.frame.payload⟩ (binding.ifaceName state.iface) = some pending.component
  entered : (state.datapathStage = .ingress ∨ state.datapathStage = .routed ∨ state.datapathStage = .localInput) →
    target ⟨state.frame.originDomain, state.frame.payload⟩ (binding.ifaceName state.enteredIface) = some pending.component

structure IPsecIngressGateChecks {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : Layer) (target : PayloadId → String → Option String) : Prop where
  noMACsec : binding.configuration.macIfaces = []
  noCarriers : binding.configuration.carriers = []
  targetOwner : ∀ payload iface component, target payload (binding.ifaceName iface) = some component →
    binding.componentName (binding.configuration.ip.owner iface) = component
  sourceTargets : ∀ payload iface network, binding.sourceEntry iface = some network →
    target payload (binding.ifaceName iface) = none
  routeOwners : ∀ route ∈ binding.configuration.ip.routes,
    binding.configuration.ip.owner route.egress = binding.configuration.ip.owner route.ingress
  bridgeIngress : ∀ payload first last, binding.configuration.bridge first last →
    target payload (binding.ifaceName first) = none
  authenticatedForward : ∀ state header component,
    binding.componentName (binding.configuration.ip.owner state.iface) = component →
    target ⟨state.frame.originDomain, state.frame.payload⟩ (binding.ifaceName state.enteredIface) = some component →
    state.authenticated = [] →
    ¬ DataPlaneForwarding.accepts (binding.configuration.ip.forwardRules state.iface)
      (binding.configuration.ip.forwardFallback state.iface) (policyHeader binding.configuration state header)
  decryption : ∀ payload iface component policy association,
    target payload (binding.ifaceName iface) = some component →
    policy ∈ binding.configuration.ip.ingressPolicies iface →
    association ∈ binding.configuration.ip.ingressSAs iface →
    DataPlaneForwarding.saMatchesPolicy association policy →
    ∃ tunnel ∈ d.tunnels, tunnel.id = binding.ipsecTunnel (policy.seal association) ∧
      tunnel.layer = layer ∧ tunnel.receiver = component

lemma nontransmit_operation_events_are_gate_neutral {S A : Type} (binding : DeviceExecutionBinding S A)
    (before after : S) (operation : MultiProtocolForwarding.Action) (other : operation ≠ .linkTransmit) :
    ∀ event ∈ binding.OperationEvents before operation after, InboundGateNeutral event := by
  cases operation <;> simp_all only [DeviceExecutionBinding.OperationEvents]
  all_goals repeat' first
    | split
    | simp_all [InboundGateNeutral]

lemma ipsec_source_events_preserve_pending {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : Layer) (target : PayloadId → String → Option String)
    (sourceTargets : ∀ payload iface network, binding.sourceEntry iface = some network →
      target payload (binding.ifaceName iface) = none) (before : S)
    (pending : Option PendingInboundProtection) :
    (inboundProtectionGate d layer target
      ⟨(binding.state before).frame.originDomain, (binding.state before).frame.payload⟩).MTr
      pending (binding.SourceEvents before) pending := by
  dsimp only [DeviceExecutionBinding.SourceEvents]
  split
  next initial =>
    cases origin : binding.origin (binding.state before).frame.originDomain with
    | red network =>
      dsimp only
      split
      next checked =>
        exact .stepL (InboundProtectionGateStep.neutral _ _ trivial)
          (.stepL (InboundProtectionGateStep.receiveOther _ _ _ _ (sourceTargets _ _ _ checked.1)) .refl)
      next missing => exact .refl
    | management component => exact .refl
    | control component protocol => exact .refl
  next other => exact .refl

lemma ipsec_pending_cannot_transmit {S A : Type} (binding : DeviceExecutionBinding S A)
    (target : PayloadId → String → Option String) {pending : PendingInboundProtection}
    {before after : MultiProtocolForwarding.State}
    (guard : IPsecPendingGuard binding target pending before)
    (step : MultiProtocolForwarding.Step binding.configuration before .linkTransmit after) : False := by
  cases step with
  | linkTransmit next ready linked => simpa [ipsecPendingStages, ready] using guard.stage

lemma ipsec_pending_preserved_without_decryption {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : Layer) (target : PayloadId → String → Option String)
    (checks : IPsecIngressGateChecks binding d layer target) {pending : PendingInboundProtection}
    {before after : MultiProtocolForwarding.State} {operation : MultiProtocolForwarding.Action}
    (step : MultiProtocolForwarding.Step binding.configuration before operation after)
    (other : operation ≠ .decryptIPsec) (guard : IPsecPendingGuard binding target pending before) :
    IPsecPendingGuard binding target pending after := by
  have pendingStage := guard.stage
  cases step with
  | receive stage visible tracking =>
    exact ⟨guard.owner, guard.layers, rfl, by simp [ipsecPendingStages], by simp,
      fun _ => guard.received stage⟩
  | route route stage visible selected entry =>
    refine ⟨?_, ?_, guard.unauthenticated, by simp [ipsecPendingStages], by simp, ?_⟩
    · rw [checks.routeOwners route selected.1, entry]
      exact guard.owner
    · simpa only [Config.forwardedFrame_body] using guard.layers
    · intro _
      have entered := guard.entered (Or.inl stage)
      cases mode : binding.configuration.headerProcessing
      · simpa [Config.forwardedFrame, mode] using entered
      · cases shown : before.frame.visibleHeader <;>
          simpa [Config.forwardedFrame, mode, Frame.forwarded, shown] using entered
  | forwardFilter stage visible accepted =>
    exact False.elim (checks.authenticatedForward before _ pending.component guard.owner
      (guard.entered (Or.inr (Or.inl stage))) guard.unauthenticated accepted)
  | inputFilter stage visible addressed accepted =>
    exact ⟨guard.owner, guard.layers, guard.unauthenticated, by simp [ipsecPendingStages], by simp,
      fun _ => guard.entered (Or.inl stage)⟩
  | deliver stage plain recipient | deliverEthernet header domain stage plain recipient =>
    exact ⟨guard.owner, guard.layers, guard.unauthenticated, by simp [ipsecPendingStages], by simp, by simp⟩
  | drop =>
    exact ⟨guard.owner, guard.layers, guard.unauthenticated, by simp [ipsecPendingStages], by simp, by simp⟩
  | bridge next stage member =>
    have selected := guard.received stage
    rw [checks.bridgeIngress _ _ _ member] at selected
    cases selected
  | encryptMACsec iface association configured
  | unprotectedMACsec iface configured
  | protectMACsec iface association configured
  | decryptMACsec iface association transmitted body configured
  | validateMACsec iface association transmitted encryptFrames confidentialityOffset body configured
  | uncheckedMACsec iface configured => simp [checks.noMACsec] at configured
  | encapsulate iface configured | decapsulate iface body configured => simp [checks.noCarriers] at configured
  | decryptIPsec => exact False.elim (other rfl)
  | routeLocalOutput route stage visible chosen entry
  | outputFilter stage visible accepted
  | encryptIPsec policy association stage visible selected installed bound
  | routeOuterPacket route stage visible selected entry
  | forwardWithoutEncap stage visible noPolicy
  | linkTransmit next stage linked
  | bridgeOutput next stage member =>
    simp [ipsecPendingStages, stage] at pendingStage

def ipsecIngressDeviceGate {S A : Type} (binding : DeviceExecutionBinding S A)
    (d : Deployment) (layer : Layer) (target : PayloadId → String → Option String)
    (checks : IPsecIngressGateChecks binding d layer target) : DeviceInboundGateChecks binding d layer target := by
  refine ⟨IPsecPendingGuard binding target, fun _ => True, fun _ _ => trivial, fun _ _ _ _ _ => trivial, ?_⟩
  intro before operation after step safe pending consistent
  let view := binding.withProjection (id : MultiProtocolForwarding.State → MultiProtocolForwarding.State)
    (fun action : MultiProtocolForwarding.Action => some action)
  have sourceRun := ipsec_source_events_preserve_pending view d layer target checks.sourceTargets before pending
  have names : ∀ body, view.LayerIds body = binding.LayerIds body := layer_ids_with_tunnel_names binding _ _
  have operationRun : ∃ next,
      (inboundProtectionGate d layer target ⟨before.frame.originDomain, before.frame.payload⟩).MTr
        pending (view.OperationEvents before operation after) next ∧
      InboundGateConsistent (IPsecPendingGuard binding target) next after := by
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
            · exact ⟨checks.targetOwner _ _ _ selected, rfl, rfl,
                by simp [ipsecPendingStages], fun _ => selected, by simp⟩
      · exact ⟨none, neutral_gate_events_preserve_pending none _
          (nontransmit_operation_events_are_gate_neutral view before after operation transmitting), trivial⟩
    | some received =>
      change IPsecPendingGuard binding target received before at consistent
      by_cases decrypted : operation = .decryptIPsec
      · subst operation
        cases step with
        | decryptIPsec policy association body header stage encrypted configured installed bound visible selected tracking =>
          obtain ⟨tunnel, member, same, selectedLayer, receiver⟩ :=
            checks.decryption _ _ _ policy association (consistent.received stage) configured installed bound
          have present : binding.ipsecTunnel (policy.seal association) ∈ received.layers := by
            rw [← consistent.layers, encrypted]
            simp only [DeviceExecutionBinding.LayerIds, List.mem_cons, true_or]
          have matched : MatchingInboundDecryption d layer received (binding.ipsecTunnel (policy.seal association)) :=
            ⟨tunnel, member, same, selectedLayer, receiver, present⟩
          refine ⟨none, ?_, trivial⟩
          dsimp only [DeviceExecutionBinding.OperationEvents, view, DeviceExecutionBinding.withProjection, id_eq]
          rw [encrypted]
          exact .stepL (InboundProtectionGateStep.neutral _ _ trivial)
            (.stepL (InboundProtectionGateStep.decrypt received _ matched) .refl)
      · have retained := ipsec_pending_preserved_without_decryption binding d layer target checks step decrypted consistent
        have noTransmit : operation ≠ .linkTransmit := by
          intro same
          subst operation
          exact ipsec_pending_cannot_transmit binding target consistent step
        exact ⟨some received, neutral_gate_events_preserve_pending _ _
          (nontransmit_operation_events_are_gate_neutral view before after operation noTransmit), retained⟩
  obtain ⟨next, emitted, retained⟩ := operationRun
  exact ⟨next, (Cslib.LTS.MTr.append_iff _).mpr ⟨pending, sourceRun, emitted⟩, retained⟩

end TDN.Requirements.Msc
