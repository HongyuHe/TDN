import TDN.Targets.ComplianceModel
import TDN.Semantics.MultiProtocolPorts

namespace TDN.Compliance

def NativeExecutionBinding.withProjection {S A T B : Type}
    (binding : NativeExecutionBinding S A)
    (state : T → MultiProtocolExecution.State)
    (action : B → Option MultiProtocolExecution.Action) : NativeExecutionBinding T B :=
  { configuration := binding.configuration
    state := state
    action := action
    portName := binding.portName
    ipsecTunnel := binding.ipsecTunnel
    ipsecEpoch := binding.ipsecEpoch
    ipsecInstallations := binding.ipsecInstallations
    ipsecKeyMaterial := binding.ipsecKeyMaterial
    macsecEpoch := binding.macsecEpoch
    macsecTunnel := binding.macsecTunnel
    macsecKeyMaterial := binding.macsecKeyMaterial
    componentName := binding.componentName
    sourceEntry := binding.sourceEntry
    sourceProcessing := binding.sourceProcessing
    keyName := binding.keyName
    domainName := binding.domainName
    origin := binding.origin }

lemma NativeExecutionBinding.source_events_are_network {S A : Type}
    (binding : NativeExecutionBinding S A) (before : S) :
    (binding.SourceEvents before).filter ProcessingEvent.NetworkOperation =
      binding.SourceEvents before := by
  dsimp only [NativeExecutionBinding.SourceEvents]
  split
  · split
    · split <;> rfl
    · rfl
  · rfl

lemma NativeExecutionBinding.operation_events_are_network {S A : Type}
    (binding : NativeExecutionBinding S A) (before : S)
    (action : MultiProtocolExecution.Action) (after : S) :
    (binding.OperationEvents before action after).filter ProcessingEvent.NetworkOperation =
      binding.OperationEvents before action after := by
  cases action
  case encryptIPsec =>
    dsimp only [NativeExecutionBinding.OperationEvents]
    split <;> rfl
  case decryptIPsec =>
    dsimp only [NativeExecutionBinding.OperationEvents]
    split <;> rfl
  case encryptMACsec =>
    dsimp only [NativeExecutionBinding.OperationEvents]
    split <;> rfl
  case decryptMACsec =>
    dsimp only [NativeExecutionBinding.OperationEvents]
    split <;> rfl
  case encapsulate =>
    dsimp only [NativeExecutionBinding.OperationEvents]
    split <;> rfl
  case decapsulate =>
    dsimp only [NativeExecutionBinding.OperationEvents]
    split <;> rfl
  case deliver =>
    dsimp only [NativeExecutionBinding.OperationEvents]
    split <;> rfl
  all_goals rfl

lemma NativeExecutionBinding.required_events_are_network {S A : Type}
    (binding : NativeExecutionBinding S A) (before : S)
    (action : MultiProtocolExecution.Action) (after : S) :
    (binding.RequiredEvents before action after).filter ProcessingEvent.NetworkOperation =
      binding.RequiredEvents before action after := by
  rw [NativeExecutionBinding.RequiredEvents, List.filter_append,
    binding.source_events_are_network, binding.operation_events_are_network]

end TDN.Compliance

namespace TDN.Targets.CanonicalExecution
open Compliance

structure State (ports : List Nat) where
  native : MultiProtocolExecution.State
  portPresent : native.port ∈ ports
  source : Option (PacketSource.Request × PacketSource.Datagram)

structure Action (ports : List Nat) where
  before : State ports
  operation : MultiProtocolExecution.Action
  after : State ports

def binding {S A : Type} (prototype : NativeExecutionBinding S A) (ports : List Nat) :
    NativeExecutionBinding (State ports) (Action ports) :=
  prototype.withProjection State.native (fun action => some action.operation)

def system {S A : Type} (prototype : NativeExecutionBinding S A) (ports : List Nat) :
    Cslib.LTS (State ports) (Action ports) :=
  ⟨fun before action after =>
    action.before = before ∧ action.after = after ∧ before.source = after.source ∧
    (binding prototype ports).AcceptedStep before.native action.operation after.native⟩

def initial {S A : Type} (prototype : NativeExecutionBinding S A) (ports : List Nat)
    (d : Deployment) (state : State ports) : Prop :=
  (binding prototype ports).SourceInitial d state.native ∧
  ∃ request datagrams datagram,
    state.source = some (request, datagram) ∧
    (binding prototype ports).SourceRequestAllowed d request ∧
    prototype.sourceProcessing.process request = .emitted datagrams ∧ datagram ∈ datagrams ∧
    state.native = (binding prototype ports).SourceState request datagram

def model {S A : Type} (prototype : NativeExecutionBinding S A) (ports : List Nat)
    (d : Deployment) (history : ObservedHistory) : ExecutionModel (State ports) (Action ports) :=
  { system := system prototype ports
    initial := initial prototype ports d
    events := fun action =>
      (binding prototype ports).RequiredEvents action.before action.operation action.after
    native := binding prototype ports
    sourceRecord := State.source
    history := history }

theorem canonical_model_faithful {S A : Type} (prototype : NativeExecutionBinding S A)
    (ports : List Nat) (d : Deployment) (history : ObservedHistory) :
    (model prototype ports d history).Faithful := by
  intro before action after step
  obtain ⟨sameBefore, sameAfter, _, accepted⟩ := step
  subst before
  subst after
  exact ⟨accepted, (binding prototype ports).required_events_are_network ..⟩

theorem canonical_model_covers_every_native_step {S A : Type}
    (prototype : NativeExecutionBinding S A) (ports : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (conditions : MultiProtocolExecution.PortConditions prototype.configuration ports) :
    (model prototype ports d history).NativeStepCoverage := by
  intro before operation nativeAfter accepted
  let after : State ports :=
    ⟨nativeAfter,
      MultiProtocolExecution.step_preserves_port_inventory conditions accepted.1 before.portPresent,
      before.source⟩
  refine ⟨⟨before, operation, after⟩, after, ?_, rfl, rfl⟩
  exact ⟨rfl, rfl, rfl, accepted⟩

end TDN.Targets.CanonicalExecution
