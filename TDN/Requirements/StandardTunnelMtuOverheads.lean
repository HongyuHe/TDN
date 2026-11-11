import TDN.Requirements.StandardIpsecWireBridge
import TDN.Models.PerStageMtuInvariants

namespace TDN.Requirements.StandardDataPlaneBridge
open Compliance LayeredFrame PacketSource MultiProtocolForwarding

lemma standard_initial_size_budget {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (required : Nat → Bool) (mtu plaintextLimit authenticationLimit : Nat → Nat)
    (emissions : EmissionConditions prototype.sourceProcessing)
    (lengthDefinition : ∀ body payload, prototype.configuration.networkBytes body payload =
      IPsecFrameEncoding.networkLength body)
    (start : State ifaces) (initialized : (model prototype ifaces d history).initial start) :
    SizeInvariant prototype.configuration required mtu plaintextLimit authenticationLimit start.native := by
  obtain ⟨request, datagrams, datagram, recorded, allowed, emitted, member, same⟩ := initialized.2
  have decoded := (emitted_datagram_valid emissions emitted member).1
  rw [same]
  refine ⟨decoded_source_body_budget datagram decoded plaintextLimit, ?_⟩
  cases origin : prototype.origin request.originDomain with
  | red network =>
    simp only [DeviceExecutionBinding.SourceState, binding, DeviceExecutionBinding.withProjection, origin]
  | management component =>
    cases body : datagram.body with
    | datagram header =>
      simp only [DeviceExecutionBinding.SourceState, binding, DeviceExecutionBinding.withProjection,
        origin, body, SourceOutputPhase]
      exact ⟨⟨header, by
          cases mode : prototype.configuration.headerProcessing <;>
            simp [Config.visibleHeader, mode, Frame.visibleHeader, Body.visibleHeader]⟩,
        authentication_bound_empty _ _ _ rfl, True.intro⟩
    | ethernet header =>
      simp only [DeviceExecutionBinding.SourceState, binding, DeviceExecutionBinding.withProjection,
        origin, body, SourceOutputPhase]
      intro needed bytes length
      rw [lengthDefinition] at length
      cases length
    | ipsec association contents => simp [Datagram.Decoded, body] at decoded
    | macsec association contents => simp [Datagram.Decoded, body] at decoded
    | macsecPdu association encryptFrames confidentialityOffset contents => simp [Datagram.Decoded, body] at decoded
    | carrier endpoint contents => simp [Datagram.Decoded, body] at decoded
  | control component protocol =>
    cases body : datagram.body with
    | datagram header =>
      simp only [DeviceExecutionBinding.SourceState, binding, DeviceExecutionBinding.withProjection,
        origin, body, SourceOutputPhase]
      exact ⟨⟨header, by
          cases mode : prototype.configuration.headerProcessing <;>
            simp [Config.visibleHeader, mode, Frame.visibleHeader, Body.visibleHeader]⟩,
        authentication_bound_empty _ _ _ rfl, True.intro⟩
    | ethernet header =>
      simp only [DeviceExecutionBinding.SourceState, binding, DeviceExecutionBinding.withProjection,
        origin, body, SourceOutputPhase]
      intro needed bytes length
      rw [lengthDefinition] at length
      cases length
    | ipsec association contents => simp [Datagram.Decoded, body] at decoded
    | macsec association contents => simp [Datagram.Decoded, body] at decoded
    | macsecPdu association encryptFrames confidentialityOffset contents => simp [Datagram.Decoded, body] at decoded
    | carrier endpoint contents => simp [Datagram.Decoded, body] at decoded


theorem standard_reachable_size_budget {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (required : Nat → Bool) (mtu plaintextLimit authenticationLimit : Nat → Nat)
    (checks : SizeChecks prototype.configuration required mtu plaintextLimit authenticationLimit)
    (emissions : EmissionConditions prototype.sourceProcessing)
    (processing : HeaderProcessing) (mode : prototype.configuration.headerProcessing = some processing)
    (headerBounds : HeaderBounds processing)
    {start finish : State ifaces} {actions : List (Action ifaces)}
    (initialized : (model prototype ifaces d history).initial start)
    (run : (model prototype ifaces d history).system.MTr start actions finish) :
    SizeInvariant prototype.configuration required mtu plaintextLimit authenticationLimit finish.native := by
  have preserved : (model prototype ifaces d history).system.TrInv (fun state =>
      state.native.frame.HeadersCoherent ∧
      SizeInvariant prototype.configuration required mtu plaintextLimit authenticationLimit state.native) := by
    intro before action after step invariant
    exact ⟨step_preserves_headers processing mode headerBounds step.2.2.2.1 invariant.1,
      device_step_preserves_size_budget checks processing mode step.2.2.2.1 invariant.1 invariant.2⟩
  have coherent := standard_reachable_headers prototype ifaces d history processing mode headerBounds
    start start [] initialized Cslib.LTS.MTr.refl
  exact (Cslib.LTS.mtrInv_of_trInv preserved start actions finish run
    ⟨coherent, standard_initial_size_budget prototype ifaces d history required mtu plaintextLimit
      authenticationLimit emissions checks.networkDefinition start initialized⟩).2


theorem standard_admitted_IP_wire_fits {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) (d : Deployment) (history : ObservedHistory)
    (required : Nat → Bool) (mtu plaintextLimit authenticationLimit : Nat → Nat)
    (checks : SizeChecks prototype.configuration required mtu plaintextLimit authenticationLimit)
    (emissions : EmissionConditions prototype.sourceProcessing)
    (processing : HeaderProcessing) (mode : prototype.configuration.headerProcessing = some processing)
    (headerBounds : HeaderBounds processing)
    {start before after : State ifaces} {actions : List (Action ifaces)} {action : Action ifaces}
    (initialized : (model prototype ifaces d history).initial start)
    (run : (model prototype ifaces d history).system.MTr start actions before)
    (step : (model prototype ifaces d history).system.Tr before action after)
    (wire : (model prototype ifaces d history).native.action action = some .linkTransmit)
    (needed : required before.native.iface = true) (bytes : Nat)
    (length : prototype.configuration.networkBytes before.native.frame.body before.native.frame.payload = some bytes) :
    bytes ≤ mtu before.native.iface := by
  have operation : action.operation = .linkTransmit := Option.some.inj wire
  have nativeStep := step.2.2.2.1
  rw [operation] at nativeStep
  have wirePhase : ∀ (first last : MultiProtocolForwarding.State),
      MultiProtocolForwarding.Step prototype.configuration first .linkTransmit last → first.datapathStage = .egressReady := by
    intro first last transition
    cases transition
    assumption
  have datapathStage : before.native.datapathStage = .egressReady := wirePhase _ _ nativeStep
  have invariant := standard_reachable_size_budget prototype ifaces d history required mtu plaintextLimit
    authenticationLimit checks emissions processing mode headerBounds initialized run
  rw [SizeInvariant, datapathStage] at invariant
  exact invariant.2 needed bytes length

end TDN.Requirements.StandardDataPlaneBridge
