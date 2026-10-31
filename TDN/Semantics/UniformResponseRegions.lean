import TDN.Semantics.EncryptedResponseGuards

namespace TDN.UniformResponseRegions
open Execution

/-- A component whose interfaces share one protection region cannot expose copied
bytes to a less protected interface. Its lack of inbound policies also prevents
an unmodeled local decryption from removing a layer. -/
def Uniform (c : Execution.Config) (layout : Nat → List Nat) (owner : Nat) : Prop :=
  (∀ input, c.owner input = owner → c.inbound input = []) ∧
  ∀ input output, c.owner input = owner → c.owner output = owner →
    layout input = layout output

lemma processing_stack_at_port {c : Execution.Config} {layout : Nat → List Nat}
    {state : Execution.State}
    (uniform : Uniform c layout (c.owner state.port))
    (processing : ProcessingInvariant c layout state) :
    state.frame.tags = layout state.port := by
  have emptyInbound := uniform.1 state.frame.enteredPort processing.2.2.2.symm
  have empty : state.authenticated = [] := by
    rcases processing.2.2.1 with empty | ⟨a, member, rest⟩
    · exact empty
    · rw [emptyInbound] at member
      contradiction
  have stack := processing.1
  simp only [processingStack, empty, ite_true] at stack
  exact stack.trans (uniform.2 state.frame.enteredPort state.port processing.2.2.2.symm rfl)

theorem all_active_phases_have_uniform_stack
    {c : Execution.Config} {layout : Nat → List Nat} {state : Execution.State}
    (uniform : Uniform c layout (c.owner state.port))
    (valid : StackInvariant c layout state) (active : state.phase ≠ .dropped) :
    state.frame.tags = layout state.port := by
  cases phase : state.phase <;> simp only [StackInvariant, phase] at valid
  · exact valid
  · exact processing_stack_at_port uniform valid.1
  · exact processing_stack_at_port uniform valid.1.1
  · exact processing_stack_at_port uniform valid.1
  · exact processing_stack_at_port uniform valid.1.1
  · exact processing_stack_at_port uniform valid.1
  · exact valid.1
  · exact valid
  · exact processing_stack_at_port uniform valid
  · exact processing_stack_at_port uniform valid
  · exact False.elim (active phase)

def FiniteUniform (devices : List DeviceData) (ports : List PortData) (owners : List Nat) : Prop :=
  ∀ entry ∈ ({} : PortData) :: ports, entry.owner ∈ owners →
    (deviceAt devices entry.owner).inbound = [] ∧
    ∀ output ∈ ({} : PortData) :: ports, output.owner = entry.owner → entry.stack = output.stack

instance (devices : List DeviceData) (ports : List PortData) (owners : List Nat) :
    Decidable (FiniteUniform devices ports owners) := by
  unfold FiniteUniform
  infer_instance

theorem finite_uniform_sound (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (links switches : List (Nat × Nat)) (owners : List Nat)
    (checked : FiniteUniform devices ports owners) (owner : Nat) (member : owner ∈ owners) :
    Uniform (finiteConfig devices ports routes links switches) (finiteLayout ports) owner := by
  constructor
  · intro input same
    exact (checked (portAt ports input) (port_at_member_or_default ports input)
      (by change (portAt ports input).owner = owner at same; rw [same]; exact member)).1
  · intro input output first second
    exact (checked (portAt ports input) (port_at_member_or_default ports input)
      (by change (portAt ports input).owner = owner at first; rw [first]; exact member)).2 (portAt ports output) (port_at_member_or_default ports output)
        (second.trans first.symm)

def responseConfig (data : GuardedResponseNetwork.Data) (owners : List Nat) :
    KernelResponses.Config Execution.State :=
  { EncryptedResponseGuards.combinedConfig data with
    generates := fun state =>
      (EncryptedResponseGuards.combinedConfig data).generates state ∨
        state.phase ≠ .dropped ∧ data.config.owner state.port ∈ owners }

lemma reply_preserves_safe (data : GuardedResponseNetwork.Data) (owners : List Nat)
    (conditions : LocalStackConditions data.config data.layout)
    (pairs : SourceResponseGuards.FiniteReplyChecks data.devices data.ports data.sourceGuards)
    (coverage : SourceResponseGuards.FiniteGuardCoverage data.ports data.sourceGuards)
    (defaults : ∀ guard ∈ data.sourceGuards,
      (deviceAt data.devices guard.1).outputFallback = .deny)
    (encryptedChecks : EncryptedResponseGuards.LocalDeny data.config)
    (uniformChecks : FiniteUniform data.devices data.ports owners)
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
    have uniform := finite_uniform_sound data.devices data.ports data.routes data.links data.switches
      owners uniformChecks (data.config.owner source.port) member
    have owner := conditions.routeOwner route chosen.1
    rw [atSource, atOutput] at owner
    have stack := all_active_phases_have_uniform_stack uniform valid.1 active
    refine ⟨?_, trivial, ?_⟩
    · change source.frame.tags = data.layout output
      exact stack.trans (uniform.2 source.port output rfl owner)
    · intro impossible
      simp [responseConfig, EncryptedResponseGuards.combinedConfig,
        GuardedResponseNetwork.responseConfig, GuardedResponseNetwork.ActivePhase] at impossible

theorem all_component_response_executions_preserve_stack
    (data : GuardedResponseNetwork.Data) (owners : List Nat)
    (conditions : LocalStackConditions data.config data.layout)
    (pairs : SourceResponseGuards.FiniteReplyChecks data.devices data.ports data.sourceGuards)
    (coverage : SourceResponseGuards.FiniteGuardCoverage data.ports data.sourceGuards)
    (defaults : ∀ guard ∈ data.sourceGuards,
      (deviceAt data.devices guard.1).outputFallback = .deny)
    (encryptedChecks : EncryptedResponseGuards.LocalDeny data.config)
    (uniformChecks : FiniteUniform data.devices data.ports owners)
    {before after : Execution.State} {actions : List (KernelResponses.Action Execution.Action)}
    (run : (KernelResponses.lts (GuardedResponseNetwork.network data)
      (responseConfig data owners)).MTr (.network before) actions (.network after))
    (initial : GuardedResponseNetwork.Safe data before) :
    StackInvariant data.config data.layout after :=
  (KernelResponses.copied_response_executions_remain_safe
    (GuardedResponseNetwork.network data) (responseConfig data owners)
    (GuardedResponseNetwork.Safe data)
    (GuardedResponseNetwork.network_preserves_safe data conditions)
    (reply_preserves_safe data owners conditions pairs coverage defaults encryptedChecks uniformChecks)
    run initial).1

end TDN.UniformResponseRegions
