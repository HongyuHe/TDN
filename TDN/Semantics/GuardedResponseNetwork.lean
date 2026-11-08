import TDN.Semantics.SourceResponseGuards

namespace TDN.GuardedResponseNetwork
open Execution

def ActivePhase (datapathStage : DatapathStage) : Prop :=
  datapathStage ∈ [.ingress, .routed, .filtered, .localInput, .delivered]

instance (datapathStage : DatapathStage) : Decidable (ActivePhase datapathStage) := by
  unfold ActivePhase
  infer_instance

structure Data where
  devices : List DeviceData
  ifaces : List IfaceData
  routes : List Route
  links : List (Nat × Nat)
  switches : List (Nat × Nat)
  sourceGuards : List (Nat × List PacketPolicy.Rule)

def Data.config (data : Data) : Execution.Environment :=
  dataPlaneConfigFromRecords data.devices data.ifaces data.routes data.links data.switches

def Data.expectedEncapStack (data : Data) : Nat → List Nat := expectedEncapStackFromRecords data.ifaces

def sourcePacket (data : Data) (state : Execution.State) : PacketPolicy.Packet :=
  policyPacket data.config state.frame.enteredIface state.frame state.authenticated

def Guarded (data : Data) (state : Execution.State) : Prop :=
  ActivePhase state.datapathStage →
    ∀ guard ∈ data.sourceGuards, data.config.owner state.frame.enteredIface = guard.1 →
      Filter.evaluate (guard.2.map PacketPolicy.Rule.toFilter) .allow (sourcePacket data state) = .allow

instance (data : Data) (state : Execution.State) : Decidable (Guarded data state) := by
  unfold Guarded
  infer_instance

def network (data : Data) : Cslib.LTS Execution.State Execution.Action where
  Tr before action after := Execution.Step data.config before action after ∧ Guarded data after

def Safe (data : Data) (state : Execution.State) : Prop :=
  StackInvariant data.config data.expectedEncapStack state ∧
    ProcessingAuthenticationMatches data.config state ∧ Guarded data state

def responseConfig (data : Data) : KernelResponses.Config Execution.State where
  generates state := ActivePhase state.datapathStage ∧
    ∃ guard ∈ data.sourceGuards,
      (ifaceAt data.ifaces state.frame.enteredIface).owner = guard.1 ∧
      ifaceAt data.ifaces state.frame.enteredIface ∈ data.ifaces ∧
      (ifaceAt data.ifaces state.frame.enteredIface).name ≠ "lo" ∧
      SourceResponseGuards.ValidSourceAddress state.frame.packet.source
  selectedRoute state reply output :=
    (∃ route, SelectedRoute data.routes route reply ∧
      route.ingress = state.iface ∧ route.egress = output) ∧
    ifaceAt data.ifaces output ∈ data.ifaces ∧ reply.destination = state.frame.packet.source
  outputRules _ output := data.config.outputRules output
  outputFallback _ output := data.config.outputFallback output
  interfaceName := data.config.interfaceName
  emit state header output :=
    { iface := output, datapathStage := .ready, frame := { state.frame with packet := header }, authenticated := [] }

lemma processing_of_active (data : Data) {state : Execution.State}
    (active : ActivePhase state.datapathStage) (valid : StackInvariant data.config data.expectedEncapStack state) :
    ProcessingInvariant data.config data.expectedEncapStack state := by
  cases datapathStage : state.datapathStage <;> simp_all [ActivePhase, StackInvariant]

lemma selectors_of_active (data : Data) {state : Execution.State}
    (active : ActivePhase state.datapathStage)
    (valid : ProcessingAuthenticationMatches data.config state) :
    AuthenticationMatches data.config state := by
  cases datapathStage : state.datapathStage <;> simp_all [ActivePhase, ProcessingAuthenticationMatches]

lemma network_preserves_safe (data : Data)
    (conditions : LocalStackConditions data.config data.expectedEncapStack) :
    (network data).TrInv (Safe data) := by
  intro before action after step initial
  exact ⟨step_preserves_stack_invariant conditions step.1 initial.1,
    step_preserves_authentication_selectors data.config before action after step.1 initial.2.1, step.2⟩

lemma reply_emission_preserves_safe (data : Data)
    (conditions : LocalStackConditions data.config data.expectedEncapStack)
    (pairs : SourceResponseGuards.FiniteReplyChecks data.devices data.ifaces data.sourceGuards)
    (coverage : SourceResponseGuards.FiniteGuardCoverage data.ifaces data.sourceGuards)
    (defaults : ∀ guard ∈ data.sourceGuards,
      (deviceAt data.devices guard.1).outputFallback = .deny)
    (source : Execution.State) (header : PacketPolicy.Packet) (output : Nat)
    (valid : Safe data source) (enabled : (responseConfig data).generates source)
    (protocol : KernelResponses.ResponseProtocol header.protocol)
    (selected : (responseConfig data).selectedRoute source header output)
    (accepted : Filter.evaluate
      (((responseConfig data).outputRules source output).map PacketPolicy.Rule.toFilter)
      ((responseConfig data).outputFallback source output)
      (KernelResponses.outputPacket (responseConfig data) header output) = .allow)
    (external : (responseConfig data).interfaceName output ≠ "lo") :
    Safe data ((responseConfig data).emit source header output) := by
  obtain ⟨active, guard, guardMember, entryOwner, entryMember, inputExternal, address⟩ := enabled
  obtain ⟨⟨route, selectedRoute, atSource, atOutput⟩, outputMember, returns⟩ := selected
  have processing := processing_of_active data active valid.1
  have selectors := selectors_of_active data active valid.2.1
  have owner : (ifaceAt data.ifaces output).owner =
      (ifaceAt data.ifaces source.frame.enteredIface).owner := by
    have same := conditions.routeOwner route selectedRoute.1
    rw [atSource, atOutput] at same
    exact same.trans processing.2.2.2
  have fallback : (responseConfig data).outputFallback source output = .deny := by
    change (deviceAt data.devices (ifaceAt data.ifaces output).owner).outputFallback = .deny
    rw [owner, entryOwner]
    exact defaults guard guardMember
  rw [fallback] at accepted
  have covered := SourceResponseGuards.finite_guard_coverage_excludes_fallback
    data.ifaces data.sourceGuards coverage guardMember entryMember entryOwner inputExternal
    (sourcePacket data source) processing.2.1 address
  have authenticated := valid_authentication_in_finite_list data.devices data.ifaces data.routes
    data.links data.switches source.frame.enteredIface source.authenticated processing.2.2.1
  have sameLayers := SourceResponseGuards.finite_reply_checks_preserve_layers
    data.devices data.ifaces data.sourceGuards pairs
    guardMember entryMember entryOwner inputExternal outputMember owner external authenticated
    (sourcePacket data source) (KernelResponses.outputPacket (responseConfig data) header output)
    processing.2.1 rfl rfl
    (by intro id member
        obtain ⟨association, configured, same, matched⟩ := selectors id member
        exact ⟨association, configured, same, matched⟩)
    covered (valid.2.2 active guard guardMember entryOwner) accepted returns protocol
  refine ⟨?_, trivial, ?_⟩
  · change source.frame.tags = data.expectedEncapStack output
    exact processing.1.trans sameLayers
  · intro impossible
    simp [responseConfig, ActivePhase] at impossible

theorem all_guarded_response_executions_preserve_stack (data : Data)
    (conditions : LocalStackConditions data.config data.expectedEncapStack)
    (pairs : SourceResponseGuards.FiniteReplyChecks data.devices data.ifaces data.sourceGuards)
    (coverage : SourceResponseGuards.FiniteGuardCoverage data.ifaces data.sourceGuards)
    (defaults : ∀ guard ∈ data.sourceGuards,
      (deviceAt data.devices guard.1).outputFallback = .deny)
    {before after : Execution.State} {actions : List (KernelResponses.Action Execution.Action)}
    (run : (KernelResponses.lts (network data) (responseConfig data)).MTr
      (.network before) actions (.network after))
    (initial : Safe data before) : StackInvariant data.config data.expectedEncapStack after :=
  (KernelResponses.copied_response_executions_remain_safe
    (network data) (responseConfig data) (Safe data)
    (network_preserves_safe data conditions)
    (reply_emission_preserves_safe data conditions pairs coverage defaults) run initial).1

end TDN.GuardedResponseNetwork
