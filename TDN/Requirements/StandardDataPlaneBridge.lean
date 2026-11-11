import TDN.Requirements.MscComplianceSchema
import TDN.Models.InterfaceInventoryClosure

namespace TDN.Compliance

def DeviceExecutionBinding.withProjection {S A T B : Type}
    (binding : DeviceExecutionBinding S A)
    (state : T → MultiProtocolForwarding.State)
    (action : B → Option MultiProtocolForwarding.Action) : DeviceExecutionBinding T B :=
  { configuration := binding.configuration
    state := state
    action := action
    ifaceName := binding.ifaceName
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

lemma DeviceExecutionBinding.source_events_are_network {S A : Type}
    (binding : DeviceExecutionBinding S A) (before : S) :
    (binding.SourceEvents before).filter NetworkEvent.NetworkOperation =
      binding.SourceEvents before := by
  dsimp only [DeviceExecutionBinding.SourceEvents]
  split
  · split
    · split <;> rfl
    · rfl
  · rfl

lemma DeviceExecutionBinding.operation_events_are_network {S A : Type}
    (binding : DeviceExecutionBinding S A) (before : S)
    (action : MultiProtocolForwarding.Action) (after : S) :
    (binding.OperationEvents before action after).filter NetworkEvent.NetworkOperation =
      binding.OperationEvents before action after := by
  cases action
  case encryptIPsec =>
    dsimp only [DeviceExecutionBinding.OperationEvents]
    split <;> rfl
  case decryptIPsec =>
    dsimp only [DeviceExecutionBinding.OperationEvents]
    split <;> rfl
  case encryptMACsec =>
    dsimp only [DeviceExecutionBinding.OperationEvents]
    split <;> rfl
  case decryptMACsec =>
    dsimp only [DeviceExecutionBinding.OperationEvents]
    split <;> rfl
  case protectMACsec =>
    dsimp only [DeviceExecutionBinding.OperationEvents]
    split <;> rfl
  case validateMACsec =>
    dsimp only [DeviceExecutionBinding.OperationEvents]
    split <;> rfl
  case encapsulate =>
    dsimp only [DeviceExecutionBinding.OperationEvents]
    split <;> rfl
  case decapsulate =>
    dsimp only [DeviceExecutionBinding.OperationEvents]
    split <;> rfl
  case deliver =>
    dsimp only [DeviceExecutionBinding.OperationEvents]
    split <;> rfl
  all_goals rfl

lemma DeviceExecutionBinding.required_events_are_network {S A : Type}
    (binding : DeviceExecutionBinding S A) (before : S)
    (action : MultiProtocolForwarding.Action) (after : S) :
    (binding.RequiredEvents before action after).filter NetworkEvent.NetworkOperation =
      binding.RequiredEvents before action after := by
  rw [DeviceExecutionBinding.RequiredEvents, List.filter_append,
    binding.source_events_are_network, binding.operation_events_are_network]

end TDN.Compliance

namespace TDN.Requirements.StandardDataPlaneBridge
open Compliance

structure State (ifaces : List Nat) where
  native : MultiProtocolForwarding.State
  ifacePresent : native.iface ∈ ifaces
  source : Option (PacketSource.Request × PacketSource.Datagram)

structure Action (ifaces : List Nat) where
  before : State ifaces
  operation : MultiProtocolForwarding.Action
  after : State ifaces

def binding {S A : Type} (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) :
    DeviceExecutionBinding (State ifaces) (Action ifaces) :=
  prototype.withProjection State.native (fun action => some action.operation)

def system {S A : Type} (prototype : DeviceExecutionBinding S A) (ifaces : List Nat) :
    Cslib.LTS (State ifaces) (Action ifaces) :=
  ⟨fun before action after =>
    action.before = before ∧ action.after = after ∧ before.source = after.source ∧
    (binding prototype ifaces).AcceptedStep before.native action.operation after.native⟩

def initial {S A : Type} (prototype : DeviceExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (state : State ifaces) : Prop :=
  (binding prototype ifaces).SourceInitial d state.native ∧
  ∃ request datagrams datagram,
    state.source = some (request, datagram) ∧
    (binding prototype ifaces).SourceRequestAllowed d request ∧
    prototype.sourceProcessing.process request = .emitted datagrams ∧ datagram ∈ datagrams ∧
    state.native = (binding prototype ifaces).SourceState request datagram

def model {S A : Type} (prototype : DeviceExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory) : ForwardingModel (State ifaces) (Action ifaces) :=
  { system := system prototype ifaces
    initial := initial prototype ifaces d
    events := fun action =>
      (binding prototype ifaces).RequiredEvents action.before action.operation action.after
    native := binding prototype ifaces
    sourceRecord := State.source
    history := history }

theorem standard_model_faithful {S A : Type} (prototype : DeviceExecutionBinding S A)
    (ifaces : List Nat) (d : Deployment) (history : ObservedHistory) :
    (model prototype ifaces d history).Faithful := by
  intro before action after step
  obtain ⟨sameBefore, sameAfter, _, accepted⟩ := step
  subst before
  subst after
  exact ⟨accepted, (binding prototype ifaces).required_events_are_network ..⟩

theorem standard_model_covers_every_native_step {S A : Type}
    (prototype : DeviceExecutionBinding S A) (ifaces : List Nat)
    (d : Deployment) (history : ObservedHistory)
    (conditions : MultiProtocolForwarding.IfaceConditions prototype.configuration ifaces) :
    (model prototype ifaces d history).DeviceStepCoverage := by
  intro before operation nativeAfter accepted
  let after : State ifaces :=
    ⟨nativeAfter,
      MultiProtocolForwarding.step_preserves_iface_inventory conditions accepted.1 before.ifacePresent,
      before.source⟩
  refine ⟨⟨before, operation, after⟩, after, ?_, rfl, rfl⟩
  exact ⟨rfl, rfl, rfl, accepted⟩

end TDN.Requirements.StandardDataPlaneBridge
