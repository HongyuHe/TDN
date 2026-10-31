import TDN.Semantics.RecordCoverage

namespace TDN.Targets

inductive TestMethod where
  | blackBox | grayBox
  deriving DecidableEq, Repr

inductive TestPurpose where
  | securityFeature | operationalCapability | annex | aoAdditional | aoNoninterference
  deriving DecidableEq, Repr

structure TestObligation where
  id : Nat
  component : Nat
  purpose : TestPurpose
  deriving DecidableEq, Repr

structure TestExecution where
  obligation : Nat
  method : TestMethod
  resultArtifact : String
  securityDiscrepancies : List String
  otherDiscrepancies : List String
  testers : List Nat
  deriving DecidableEq, Repr

structure TestBaseline where
  component : Nat
  model : String
  serial : String
  softwareVersion : String
  configuration : String
  deriving DecidableEq, Repr

structure FinalTestReport where
  testArtifactIds : List String
  comments : List String
  vulnerabilities : List String
  possibleCountermeasures : List String
  deliveredToAO : Bool
  deriving DecidableEq, Repr

/-- AO-specific requirements introduce a separate noninterference test obligation. -/
def AdditionalAOTestCovered (obligations : List TestObligation) : Prop :=
  ∀ obligation ∈ obligations, obligation.purpose = .aoAdditional →
    ∃ companion ∈ obligations, companion.component = obligation.component ∧
      companion.purpose = .aoNoninterference

/-- The obligation inventory includes the actual Testing Annex version and AO requirements.
Its completeness is an explicit source/import boundary, not inferred from executed tests.
Two-person testing is a recommendation and is tracked only when selected. -/
def msc_solution_testing_and_evidence (components : List Nat)
    (obligations : List TestObligation) (baselines : List TestBaseline)
    (plan : List Nat) (executions : List TestExecution) (report : FinalTestReport)
    (annexTestIds aoTestIds : List Nat)
    (observedSecurityDiscrepancies observedOtherDiscrepancies : List String)
    (observedComments observedVulnerabilities proposedCountermeasures : List String)
    (twoPersonRecommendationSelected : Bool) : Prop :=
  (∀ component ∈ components,
    (∃ test ∈ obligations, test.component = component ∧ test.purpose = .securityFeature) ∧
    (∃ test ∈ obligations, test.component = component ∧ test.purpose = .operationalCapability)) ∧
  (∀ id ∈ annexTestIds, ∃ test ∈ obligations, test.id = id ∧ test.purpose = .annex) ∧
  (∀ id ∈ aoTestIds, ∃ test ∈ obligations, test.id = id ∧ test.purpose = .aoAdditional) ∧
  AdditionalAOTestCovered obligations ∧
  (∀ component ∈ components, ∃ baseline ∈ baselines,
    baseline.component = component ∧ baseline.model ≠ "" ∧ baseline.serial ≠ "" ∧
    baseline.softwareVersion ≠ "" ∧ baseline.configuration ≠ "") ∧
  (∀ obligation ∈ obligations, obligation.id ∈ plan ∧
    ∃ execution ∈ executions, execution.obligation = obligation.id ∧ execution.resultArtifact ≠ "") ∧
  (∃ execution ∈ executions, execution.method = .blackBox) ∧
  (∃ execution ∈ executions, execution.method = .grayBox) ∧
  (∀ execution ∈ executions, execution.resultArtifact ∈ report.testArtifactIds) ∧
  (∀ discrepancy ∈ observedSecurityDiscrepancies,
    ∃ execution ∈ executions, discrepancy ∈ execution.securityDiscrepancies) ∧
  (∀ discrepancy ∈ observedOtherDiscrepancies,
    ∃ execution ∈ executions, discrepancy ∈ execution.otherDiscrepancies) ∧
  (∀ comment ∈ observedComments, comment ∈ report.comments) ∧
  (∀ vulnerability ∈ observedVulnerabilities, vulnerability ∈ report.vulnerabilities) ∧
  (∀ countermeasure ∈ proposedCountermeasures, countermeasure ∈ report.possibleCountermeasures) ∧
  report.deliveredToAO = true ∧
  (twoPersonRecommendationSelected = true →
    ∀ execution ∈ executions, ∃ first ∈ execution.testers,
      ∃ second ∈ execution.testers, first ≠ second)

/-- Plan and result generation from the source obligation inventory cannot lose a required test.
The theorem does not infer the inventory from the executed test set. -/
theorem generated_test_plan_covers_obligations (obligations : List TestObligation)
    (execute : TestObligation → TestExecution)
    (identity : ∀ test ∈ obligations, (execute test).obligation = test.id)
    (retained : ∀ test ∈ obligations, (execute test).resultArtifact ≠ "") :
    ∀ obligation ∈ obligations, obligation.id ∈ obligations.map TestObligation.id ∧
      ∃ execution ∈ obligations.map execute,
        execution.obligation = obligation.id ∧ execution.resultArtifact ≠ "" := by
  intro obligation member
  exact ⟨List.mem_map.mpr ⟨obligation, member, rfl⟩,
    execute obligation, List.mem_map.mpr ⟨obligation, member, rfl⟩,
    identity obligation member, retained obligation member⟩

theorem generated_final_report_retains_all_results (executions : List TestExecution) :
    ∀ execution ∈ executions,
      execution.resultArtifact ∈ executions.map TestExecution.resultArtifact :=
  fun execution member => List.mem_map.mpr ⟨execution, member, rfl⟩

lemma adding_noninterference_tests (additional : List TestObligation)
    (companion : TestObligation → TestObligation)
    (kind : ∀ test ∈ additional, (companion test).purpose = .aoNoninterference)
    (sameComponent : ∀ test ∈ additional, (companion test).component = test.component) :
    AdditionalAOTestCovered (additional ++ additional.map companion) := by
  intro obligation member purpose
  rcases List.mem_append.mp member with original | generated
  · exact ⟨companion obligation,
      List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨obligation, original, rfl⟩)),
      sameComponent obligation original, kind obligation original⟩
  · obtain ⟨test, originalMember, equality⟩ := List.mem_map.mp generated
    subst obligation
    have different := kind test originalMember
    rw [purpose] at different
    cases different

end TDN.Targets
