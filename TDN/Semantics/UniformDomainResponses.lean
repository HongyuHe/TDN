import TDN.Semantics.UniformResponseRegions
import TDN.Semantics.ExecutionDomains

namespace TDN.UniformDomainResponses
open Execution

def Uniform (c : Execution.Environment) (expectedEncapStack : Nat → List Nat)
    (allowed : Nat → Prop) (owner : Nat) : Prop :=
  UniformResponseRegions.Uniform c expectedEncapStack owner ∧
    ∀ input output, c.owner input = owner → c.owner output = owner →
      allowed input → allowed output

lemma processing_at_iface {c : Execution.Environment} {expectedEncapStack : Nat → List Nat}
    {allowed : Nat → Prop} {state : Execution.State}
    (uniform : Uniform c expectedEncapStack allowed (c.owner state.iface))
    (processing : DomainProcessing c expectedEncapStack allowed state) :
    state.frame.tags = expectedEncapStack state.iface ∧ allowed state.iface :=
  ⟨UniformResponseRegions.processing_stack_at_iface uniform.1 processing.1,
    uniform.2 state.frame.enteredIface state.iface processing.1.2.2.2.symm rfl processing.2⟩

lemma active_domain_at_iface {c : Execution.Environment} {expectedEncapStack : Nat → List Nat}
    {allowed : Nat → Prop} {state : Execution.State}
    (uniform : Uniform c expectedEncapStack allowed (c.owner state.iface))
    (valid : DomainInvariant c expectedEncapStack allowed state) (active : state.datapathStage ≠ .dropped) :
    state.frame.tags = expectedEncapStack state.iface ∧ allowed state.iface := by
  cases datapathStage : state.datapathStage <;> simp only [DomainInvariant, datapathStage] at valid
  · exact valid
  · exact processing_at_iface uniform valid.1
  · exact processing_at_iface uniform valid.1
  · exact processing_at_iface uniform valid
  · exact processing_at_iface uniform valid.1
  · exact processing_at_iface uniform valid.1
  · exact valid.1
  · exact valid
  · exact processing_at_iface uniform valid.1
  · exact processing_at_iface uniform valid.1
  · exact False.elim (active datapathStage)

def responseConfig (c : Execution.Environment) (strict uniformOwners : List Nat) :
    KernelResponses.Config Execution.State where
  generates state := state.datapathStage ≠ .dropped ∧
    (c.owner state.iface ∈ strict ∨ c.owner state.iface ∈ uniformOwners)
  selectedRoute state header iface := ∃ route,
    SelectedRoute c.routes route header ∧ route.ingress = state.iface ∧ route.egress = iface
  outputRules state _ := c.outputRules state.iface
  outputFallback state _ := c.outputFallback state.iface
  interfaceName := c.interfaceName
  emit state header iface :=
    { iface := iface, datapathStage := .ready, frame := { state.frame with packet := header }, authenticated := [] }

lemma reply_preserves_domain (c : Execution.Environment) (expectedEncapStack : Nat → List Nat)
    (allowed : Nat → Prop) (strict uniformOwners : List Nat)
    (conditions : LocalDomainConditions c expectedEncapStack allowed)
    (guards : ∀ iface, c.owner iface ∈ strict →
      c.outputFallback iface = .deny ∧ ∀ rule ∈ c.outputRules iface,
        rule.verdict = .allow → KernelResponses.SafeResponseRule rule)
    (uniform : ∀ owner ∈ uniformOwners, Uniform c expectedEncapStack allowed owner)
    (source : Execution.State) (header : PacketPolicy.Packet) (output : Nat)
    (valid : DomainInvariant c expectedEncapStack allowed source)
    (enabled : (responseConfig c strict uniformOwners).generates source)
    (protocol : KernelResponses.ResponseProtocol header.protocol)
    (selected : (responseConfig c strict uniformOwners).selectedRoute source header output)
    (accepted : Filter.evaluate
      (((responseConfig c strict uniformOwners).outputRules source output).map PacketPolicy.Rule.toFilter)
      ((responseConfig c strict uniformOwners).outputFallback source output)
      (KernelResponses.outputPacket (responseConfig c strict uniformOwners) header output) = .allow)
    (external : (responseConfig c strict uniformOwners).interfaceName output ≠ "lo") :
    DomainInvariant c expectedEncapStack allowed ((responseConfig c strict uniformOwners).emit source header output) := by
  rcases enabled with ⟨active, strictMember | uniformMember⟩
  · obtain ⟨fallback, rules⟩ := guards source.iface strictMember
    change Filter.evaluate _ (c.outputFallback source.iface) _ = .allow at accepted
    rw [fallback] at accepted
    exact False.elim (external (KernelResponses.accepted_response_is_loopback
      (c.outputRules source.iface) rules
      (KernelResponses.outputPacket (responseConfig c strict uniformOwners) header output)
      protocol accepted))
  · obtain ⟨route, chosen, atSource, atOutput⟩ := selected
    have sameOwner := conditions.routeOwner route chosen.1
    rw [atSource, atOutput] at sameOwner
    have localUniform := uniform (c.owner source.iface) uniformMember
    have atIface := active_domain_at_iface localUniform valid active
    exact ⟨atIface.1.trans (localUniform.1.2 source.iface output rfl sameOwner),
      localUniform.2 source.iface output rfl sameOwner atIface.2⟩

def FiniteUniform (devices : List DeviceData) (ifaces : List IfaceData)
    (allowed : IfaceData → Bool) (owners : List Nat) : Prop :=
  UniformResponseRegions.FiniteUniform devices ifaces owners ∧
    ∀ input ∈ ({} : IfaceData) :: ifaces, input.owner ∈ owners →
      ∀ output ∈ ({} : IfaceData) :: ifaces, input.owner = output.owner →
        allowed input = true → allowed output = true

instance (devices : List DeviceData) (ifaces : List IfaceData)
    (allowed : IfaceData → Bool) (owners : List Nat) :
    Decidable (FiniteUniform devices ifaces allowed owners) := by
  unfold FiniteUniform
  infer_instance

theorem finite_uniform_sound (devices : List DeviceData) (ifaces : List IfaceData)
    (routes : List Route) (links switches : List (Nat × Nat))
    (allowed : IfaceData → Bool) (owners : List Nat)
    (checked : FiniteUniform devices ifaces allowed owners) (owner : Nat) (member : owner ∈ owners) :
    Uniform (dataPlaneConfigFromRecords devices ifaces routes links switches) (expectedEncapStackFromRecords ifaces)
      (fun iface => allowed (ifaceAt ifaces iface) = true) owner := by
  refine ⟨UniformResponseRegions.finite_uniform_sound devices ifaces routes links switches
    owners checked.1 owner member, ?_⟩
  intro input output atInput atOutput permitted
  apply checked.2 (ifaceAt ifaces input) (iface_at_member_or_default ifaces input)
    (by change (ifaceAt ifaces input).owner = owner at atInput; rw [atInput]; exact member)
    (ifaceAt ifaces output) (iface_at_member_or_default ifaces output)
    (atInput.trans atOutput.symm) permitted

end TDN.UniformDomainResponses
