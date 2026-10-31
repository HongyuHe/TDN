import Mathlib.Data.List.Basic

namespace TDN.Targets

inductive RequirementStrength where
  | threshold | objectiveAlternative | mandatory | optionalObjective | recommendation | context
  deriving DecidableEq, Repr

structure ApplicableRequirement (Implementation : Type) where
  id : String
  strength : RequirementStrength
  applies : Implementation → Prop
  threshold : Implementation → Prop
  objectives : List (Implementation → Prop)
  objectiveSelected : Implementation → Bool

def RequirementSatisfied {Implementation : Type}
    (requirement : ApplicableRequirement Implementation) (implementation : Implementation) : Prop :=
  match requirement.strength with
  | .threshold | .objectiveAlternative =>
      requirement.threshold implementation ∨
        ∃ objective ∈ requirement.objectives, objective implementation
  | .mandatory => requirement.threshold implementation
  | .optionalObjective =>
      requirement.objectiveSelected implementation = true →
        ∃ objective ∈ requirement.objectives, objective implementation
  | .recommendation | .context => True

/-- Policy resolution records a decision for the same action. A CP decision overrides a
conflicting local decision. CNSS obligations are separately required, not discarded. -/
def resolveCPAndLocal {Action : Type} (cp localPolicy : Action → Option Bool)
    (action : Action) : Option Bool :=
  match cp action with
  | some decision => some decision
  | none => localPolicy action

def msc_applicable_requirements_and_policy {Implementation Action Capability : Type}
    (implementation : Implementation) (requirements : List (ApplicableRequirement Implementation))
    (selectedCapabilities : List Capability) (provides : Implementation → Capability → Prop)
    (cnssRequirements : List (Implementation → Prop))
    (cp localPolicy effective : Action → Option Bool) : Prop :=
  (∀ capability ∈ selectedCapabilities, provides implementation capability) ∧
  (∀ requirement ∈ requirements, requirement.applies implementation →
    RequirementSatisfied requirement implementation) ∧
  (∀ obligation ∈ cnssRequirements, obligation implementation) ∧
  (∀ action decision, cp action = some decision → effective action = some decision) ∧
  ∀ action, cp action = none → effective action = localPolicy action

theorem cp_local_resolution_preserves_precedence {Action : Type}
    (cp localPolicy : Action → Option Bool) :
    (∀ action decision, cp action = some decision →
      resolveCPAndLocal cp localPolicy action = some decision) ∧
    (∀ action, cp action = none →
      resolveCPAndLocal cp localPolicy action = localPolicy action) := by
  constructor
  · intro action decision present
    simp [resolveCPAndLocal, present]
  · intro action absent
    simp [resolveCPAndLocal, absent]

/-- Source context and recommendations do not create invented mandatory requirements. -/
lemma contextual_passage_has_no_mandatory_branch {Implementation : Type}
    (requirement : ApplicableRequirement Implementation) (implementation : Implementation)
    (contextual : requirement.strength = .context ∨ requirement.strength = .recommendation) :
    RequirementSatisfied requirement implementation := by
  rcases contextual with contextKind | recommendationKind
  · simp [RequirementSatisfied, contextKind]
  · simp [RequirementSatisfied, recommendationKind]

end TDN.Targets
