import TDN.Semantics.UniformResponseRegions
import TDN.Semantics.ExecutionDomains

namespace TDN.UniformDomainResponses
open Execution

/-- Interfaces on one component retain both the protection stack and the
permitted plaintext domain. The condition is checked separately for every
source domain and allows shared encrypted transit interfaces. -/
def Uniform (c : Execution.Config) (layout : Nat → List Nat)
    (allowed : Nat → Prop) (owner : Nat) : Prop :=
  UniformResponseRegions.Uniform c layout owner ∧
    ∀ input output, c.owner input = owner → c.owner output = owner →
      allowed input → allowed output

lemma processing_at_port {c : Execution.Config} {layout : Nat → List Nat}
    {allowed : Nat → Prop} {state : Execution.State}
    (uniform : Uniform c layout allowed (c.owner state.port))
    (processing : DomainProcessing c layout allowed state) :
    state.frame.tags = layout state.port ∧ allowed state.port :=
  ⟨UniformResponseRegions.processing_stack_at_port uniform.1 processing.1,
    uniform.2 state.frame.enteredPort state.port processing.1.2.2.2.symm rfl processing.2⟩

lemma active_domain_at_port {c : Execution.Config} {layout : Nat → List Nat}
    {allowed : Nat → Prop} {state : Execution.State}
    (uniform : Uniform c layout allowed (c.owner state.port))
    (valid : DomainInvariant c layout allowed state) (active : state.phase ≠ .dropped) :
    state.frame.tags = layout state.port ∧ allowed state.port := by
  cases phase : state.phase <;> simp only [DomainInvariant, phase] at valid
  · exact valid
  · exact processing_at_port uniform valid.1
  · exact processing_at_port uniform valid.1
  · exact processing_at_port uniform valid
  · exact processing_at_port uniform valid.1
  · exact processing_at_port uniform valid.1
  · exact valid.1
  · exact valid
  · exact processing_at_port uniform valid.1
  · exact processing_at_port uniform valid.1
  · exact False.elim (active phase)

/-- Every actual component may generate a response before or after local
filtering. Strict devices cannot emit externally. Other devices must have a
uniform protection region and permitted-domain relation across their ports. -/
def responseConfig (c : Execution.Config) (strict uniformOwners : List Nat) :
    KernelResponses.Config Execution.State where
  generates state := state.phase ≠ .dropped ∧
    (c.owner state.port ∈ strict ∨ c.owner state.port ∈ uniformOwners)
  selectedRoute state header port := ∃ route,
    SelectedRoute c.routes route header ∧ route.ingress = state.port ∧ route.egress = port
  outputRules state _ := c.outputRules state.port
  outputFallback state _ := c.outputFallback state.port
  interfaceName := c.interfaceName
  emit state header port :=
    { port := port, phase := .ready, frame := { state.frame with packet := header }, authenticated := [] }

lemma reply_preserves_domain (c : Execution.Config) (layout : Nat → List Nat)
    (allowed : Nat → Prop) (strict uniformOwners : List Nat)
    (conditions : LocalDomainConditions c layout allowed)
    (guards : ∀ port, c.owner port ∈ strict →
      c.outputFallback port = .deny ∧ ∀ rule ∈ c.outputRules port,
        rule.verdict = .allow → KernelResponses.SafeResponseRule rule)
    (uniform : ∀ owner ∈ uniformOwners, Uniform c layout allowed owner)
    (source : Execution.State) (header : PacketPolicy.Packet) (output : Nat)
    (valid : DomainInvariant c layout allowed source)
    (enabled : (responseConfig c strict uniformOwners).generates source)
    (protocol : KernelResponses.ResponseProtocol header.protocol)
    (selected : (responseConfig c strict uniformOwners).selectedRoute source header output)
    (accepted : Filter.evaluate
      (((responseConfig c strict uniformOwners).outputRules source output).map PacketPolicy.Rule.toFilter)
      ((responseConfig c strict uniformOwners).outputFallback source output)
      (KernelResponses.outputPacket (responseConfig c strict uniformOwners) header output) = .allow)
    (external : (responseConfig c strict uniformOwners).interfaceName output ≠ "lo") :
    DomainInvariant c layout allowed ((responseConfig c strict uniformOwners).emit source header output) := by
  rcases enabled with ⟨active, strictMember | uniformMember⟩
  · obtain ⟨fallback, rules⟩ := guards source.port strictMember
    change Filter.evaluate _ (c.outputFallback source.port) _ = .allow at accepted
    rw [fallback] at accepted
    exact False.elim (external (KernelResponses.accepted_response_is_loopback
      (c.outputRules source.port) rules
      (KernelResponses.outputPacket (responseConfig c strict uniformOwners) header output)
      protocol accepted))
  · obtain ⟨route, chosen, atSource, atOutput⟩ := selected
    have sameOwner := conditions.routeOwner route chosen.1
    rw [atSource, atOutput] at sameOwner
    have localUniform := uniform (c.owner source.port) uniformMember
    have atPort := active_domain_at_port localUniform valid active
    exact ⟨atPort.1.trans (localUniform.1.2 source.port output rfl sameOwner),
      localUniform.2 source.port output rfl sameOwner atPort.2⟩

def FiniteUniform (devices : List DeviceData) (ports : List PortData)
    (allowed : PortData → Bool) (owners : List Nat) : Prop :=
  UniformResponseRegions.FiniteUniform devices ports owners ∧
    ∀ input ∈ ({} : PortData) :: ports, input.owner ∈ owners →
      ∀ output ∈ ({} : PortData) :: ports, input.owner = output.owner →
        allowed input = true → allowed output = true

instance (devices : List DeviceData) (ports : List PortData)
    (allowed : PortData → Bool) (owners : List Nat) :
    Decidable (FiniteUniform devices ports allowed owners) := by
  unfold FiniteUniform
  infer_instance

theorem finite_uniform_sound (devices : List DeviceData) (ports : List PortData)
    (routes : List Route) (links switches : List (Nat × Nat))
    (allowed : PortData → Bool) (owners : List Nat)
    (checked : FiniteUniform devices ports allowed owners) (owner : Nat) (member : owner ∈ owners) :
    Uniform (finiteConfig devices ports routes links switches) (finiteLayout ports)
      (fun port => allowed (portAt ports port) = true) owner := by
  refine ⟨UniformResponseRegions.finite_uniform_sound devices ports routes links switches
    owners checked.1 owner member, ?_⟩
  intro input output atInput atOutput permitted
  apply checked.2 (portAt ports input) (port_at_member_or_default ports input)
    (by change (portAt ports input).owner = owner at atInput; rw [atInput]; exact member)
    (portAt ports output) (port_at_member_or_default ports output)
    (atInput.trans atOutput.symm) permitted

end TDN.UniformDomainResponses
