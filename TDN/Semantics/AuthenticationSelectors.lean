import TDN.Semantics.ExecutionInvariant

namespace TDN.Execution

def AuthenticationMatches (c : Config) (s : State) : Prop :=
  ∀ id ∈ s.authenticated, ∃ association ∈ c.inbound s.frame.enteredPort,
    association.id = id ∧ association.matches s.frame.packet = true

def ProcessingAuthenticationMatches (c : Config) (s : State) : Prop :=
  match s.phase with
  | .ingress | .routed | .filtered | .localInput | .delivered => AuthenticationMatches c s
  | _ => True

lemma step_preserves_authentication_selectors (c : Config) :
    (lts c).TrInv (ProcessingAuthenticationMatches c) := by
  intro before action after step initial
  cases step <;> simp only [ProcessingAuthenticationMatches] at initial ⊢
  case receive =>
    simp [AuthenticationMatches]
  case route => exact initial
  case filter => exact initial
  case outputFilter => simp [AuthenticationMatches]
  case decrypt a sa header rest tracking configured installed bound received src dst esp selected =>
    intro id member
    have same : id = a.id := by simpa using member
    subst id
    exact ⟨a, configured, rfl, selected⟩
  case «local» => exact initial
  case deliver => exact initial

theorem execution_preserves_authentication_selectors (c : Config)
    {before after : State} {actions : List Action}
    (run : (lts c).MTr before actions after)
    (initial : ProcessingAuthenticationMatches c before) :
    ProcessingAuthenticationMatches c after :=
  Cslib.LTS.mtrInv_of_trInv (step_preserves_authentication_selectors c)
    before actions after run initial

end TDN.Execution
