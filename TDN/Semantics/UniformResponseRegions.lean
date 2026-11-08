import TDN.Semantics.EncryptedResponseGuards

namespace TDN.UniformResponseRegions
open Execution

def Uniform (c : Execution.Environment) (expectedEncapStack : Nat → List Nat) (owner : Nat) : Prop :=
  (∀ input, c.owner input = owner → c.inbound input = []) ∧
  ∀ input output, c.owner input = owner → c.owner output = owner →
    expectedEncapStack input = expectedEncapStack output

lemma processing_stack_at_iface {c : Execution.Environment} {expectedEncapStack : Nat → List Nat}
    {state : Execution.State}
    (uniform : Uniform c expectedEncapStack (c.owner state.iface))
    (processing : ProcessingInvariant c expectedEncapStack state) :
    state.frame.tags = expectedEncapStack state.iface := by
  have emptyInbound := uniform.1 state.frame.enteredIface processing.2.2.2.symm
  have empty : state.authenticated = [] := by
    rcases processing.2.2.1 with empty | ⟨a, member, rest⟩
    · exact empty
    · rw [emptyInbound] at member
      contradiction
  have stack := processing.1
  simp only [encapStackAfterIngress, empty, ite_true] at stack
  exact stack.trans (uniform.2 state.frame.enteredIface state.iface processing.2.2.2.symm rfl)

theorem all_active_phases_have_uniform_stack
    {c : Execution.Environment} {expectedEncapStack : Nat → List Nat} {state : Execution.State}
    (uniform : Uniform c expectedEncapStack (c.owner state.iface))
    (valid : StackInvariant c expectedEncapStack state) (active : state.datapathStage ≠ .dropped) :
    state.frame.tags = expectedEncapStack state.iface := by
  cases datapathStage : state.datapathStage <;> simp only [StackInvariant, datapathStage] at valid
  · exact valid
  · exact processing_stack_at_iface uniform valid.1
  · exact processing_stack_at_iface uniform valid.1.1
  · exact processing_stack_at_iface uniform valid.1
  · exact processing_stack_at_iface uniform valid.1.1
  · exact processing_stack_at_iface uniform valid.1
  · exact valid.1
  · exact valid
  · exact processing_stack_at_iface uniform valid
  · exact processing_stack_at_iface uniform valid
  · exact False.elim (active datapathStage)

def FiniteUniform (devices : List DeviceData) (ifaces : List IfaceData) (owners : List Nat) : Prop :=
  ∀ entry ∈ ({} : IfaceData) :: ifaces, entry.owner ∈ owners →
    (deviceAt devices entry.owner).inbound = [] ∧
    ∀ output ∈ ({} : IfaceData) :: ifaces, output.owner = entry.owner → entry.stack = output.stack

instance (devices : List DeviceData) (ifaces : List IfaceData) (owners : List Nat) :
    Decidable (FiniteUniform devices ifaces owners) := by
  unfold FiniteUniform
  infer_instance

theorem finite_uniform_sound (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List Route) (links switches : List (Nat × Nat)) (owners : List Nat)
    (checked : FiniteUniform devices ifaces owners) (owner : Nat) (member : owner ∈ owners) :
    Uniform (dataPlaneConfigFromRecords devices ifaces routes links switches) (expectedEncapStackFromRecords ifaces) owner := by
  constructor
  · intro input same
    exact (checked (ifaceAt ifaces input) (iface_at_member_or_default ifaces input)
      (by change (ifaceAt ifaces input).owner = owner at same; rw [same]; exact member)).1
  · intro input output first second
    exact (checked (ifaceAt ifaces input) (iface_at_member_or_default ifaces input)
      (by change (ifaceAt ifaces input).owner = owner at first; rw [first]; exact member)).2 (ifaceAt ifaces output) (iface_at_member_or_default ifaces output)
        (second.trans first.symm)

def responseConfig (data : GuardedResponseNetwork.Data) (owners : List Nat) :
    KernelResponses.Config Execution.State :=
  { EncryptedResponseGuards.combinedConfig data with
    generates := fun state =>
      (EncryptedResponseGuards.combinedConfig data).generates state ∨
        state.datapathStage ≠ .dropped ∧ data.config.owner state.iface ∈ owners }

lemma reply_preserves_safe (data : GuardedResponseNetwork.Data) (owners : List Nat)
    (conditions : LocalStackConditions data.config data.expectedEncapStack)
    (pairs : SourceResponseGuards.FiniteReplyChecks data.devices data.ifaces data.sourceGuards)
    (coverage : SourceResponseGuards.FiniteGuardCoverage data.ifaces data.sourceGuards)
    (defaults : ∀ guard ∈ data.sourceGuards,
      (deviceAt data.devices guard.1).outputFallback = .deny)
    (encryptedChecks : EncryptedResponseGuards.LocalDeny data.config)
    (uniformChecks : FiniteUniform data.devices data.ifaces owners)
    (source : Execution.State) (header : PacketPolicy.Packet) (output : Nat)
    (valid : GuardedResponseNetwork.Safe data source)
    (enabled : (responseConfig data owners).generates source)
    (protocol : KernelResponses.ResponseProtocol header.protocol)
    (selected : (responseConfig data owners).selectedRoute source header output)
    (accepted : Filter.evaluate
      (((responseConfig data owners).outputRules source output).map PacketPolicy.Rule.toFilter)
      ((responseConfig data owners).outputFallback source output)
      (KernelResponses.outputPacket (responseConfig data owners) header output) = .allow)
    (external : (responseConfig data owners).interfaceName output ≠ "lo") :
    GuardedResponseNetwork.Safe data ((responseConfig data owners).emit source header output) := by
  rcases enabled with prior | ⟨active, member⟩
  · exact EncryptedResponseGuards.combined_reply_preserves_safe data conditions pairs coverage
      defaults encryptedChecks source header output valid prior protocol selected accepted external
  · obtain ⟨⟨route, chosen, atSource, atOutput⟩, outputMember, returns⟩ := selected
    have uniform := finite_uniform_sound data.devices data.ifaces data.routes data.links data.switches
      owners uniformChecks (data.config.owner source.iface) member
    have owner := conditions.routeOwner route chosen.1
    rw [atSource, atOutput] at owner
    have stack := all_active_phases_have_uniform_stack uniform valid.1 active
    refine ⟨?_, trivial, ?_⟩
    · change source.frame.tags = data.expectedEncapStack output
      exact stack.trans (uniform.2 source.iface output rfl owner)
    · intro impossible
      simp [responseConfig, EncryptedResponseGuards.combinedConfig,
        GuardedResponseNetwork.responseConfig, GuardedResponseNetwork.ActivePhase] at impossible

theorem all_component_response_executions_preserve_stack
    (data : GuardedResponseNetwork.Data) (owners : List Nat)
    (conditions : LocalStackConditions data.config data.expectedEncapStack)
    (pairs : SourceResponseGuards.FiniteReplyChecks data.devices data.ifaces data.sourceGuards)
    (coverage : SourceResponseGuards.FiniteGuardCoverage data.ifaces data.sourceGuards)
    (defaults : ∀ guard ∈ data.sourceGuards,
      (deviceAt data.devices guard.1).outputFallback = .deny)
    (encryptedChecks : EncryptedResponseGuards.LocalDeny data.config)
    (uniformChecks : FiniteUniform data.devices data.ifaces owners)
    {before after : Execution.State} {actions : List (KernelResponses.Action Execution.Action)}
    (run : (KernelResponses.lts (GuardedResponseNetwork.network data)
      (responseConfig data owners)).MTr (.network before) actions (.network after))
    (initial : GuardedResponseNetwork.Safe data before) :
    StackInvariant data.config data.expectedEncapStack after :=
  (KernelResponses.copied_response_executions_remain_safe
    (GuardedResponseNetwork.network data) (responseConfig data owners)
    (GuardedResponseNetwork.Safe data)
    (GuardedResponseNetwork.network_preserves_safe data conditions)
    (reply_preserves_safe data owners conditions pairs coverage defaults encryptedChecks uniformChecks)
    run initial).1

end TDN.UniformResponseRegions
