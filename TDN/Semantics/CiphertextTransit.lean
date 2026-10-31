import TDN.Semantics.ExecutionDomains

namespace TDN.Execution

def TransitAction (action : Action) : Prop :=
  action ≠ .encrypt ∧ action ≠ .decrypt ∧ action ≠ .deliver

instance (action : Action) : Decidable (TransitAction action) := by
  unfold TransitAction
  infer_instance

def transit (c : Config) : Cslib.LTS State Action where
  Tr before action after := Step c before action after ∧ TransitAction action

def withHiddenContent (payload domain : Nat) (envelopes : List Envelope) (state : State) : State :=
  { state with
    frame := { state.frame with
      payload := payload
      originDomain := domain
      envelopes := envelopes } }

lemma transit_step_ignores_hidden_content (c : Config)
    (payload domain : Nat) (envelopes : List Envelope)
    {before after : State} {action : Action}
    (step : (transit c).Tr before action after) :
    Step c (withHiddenContent payload domain envelopes before) action
      (withHiddenContent payload domain envelopes after) := by
  obtain ⟨operation, allowed⟩ := step
  cases operation with
  | receive tracking => exact .receive tracking
  | route route chosen entry => exact .route route chosen entry
  | outputRoute route chosen entry => exact .outputRoute route chosen entry
  | filter accepted => exact .filter accepted
  | outputFilter accepted => exact .outputFilter accepted
  | encrypt => exact False.elim (allowed.1 rfl)
  | outerRoute route chosen entry => exact .outerRoute route chosen entry
  | switch permitted => exact .switch permitted
  | plain noPolicy => exact .plain noPolicy
  | decrypt => exact False.elim (allowed.2.1 rfl)
  | wire linked => exact .wire linked
  | «local» addressed accepted => exact .local addressed accepted
  | deliver => exact False.elim (allowed.2.2 rfl)
  | drop => exact .drop _

theorem transit_path_ignores_hidden_content (c : Config)
    (payload domain : Nat) (envelopes : List Envelope)
    {before after : State} {actions : List Action}
    (run : (transit c).MTr before actions after) :
    (lts c).MTr (withHiddenContent payload domain envelopes before) actions
      (withHiddenContent payload domain envelopes after) := by
  induction run with
  | refl => exact .refl
  | stepL step rest ih =>
    exact .stepL (transit_step_ignores_hidden_content c payload domain envelopes step) ih

theorem recovered_content_follows_checked_transit (c : Config)
    (layout : Nat → List Nat) (allowed : Nat → Prop)
    (conditions : LocalDomainConditions c layout allowed)
    (payload domain : Nat) (envelopes : List Envelope)
    {before after : State} {actions : List Action}
    (run : (transit c).MTr before actions after)
    (initial : DomainInvariant c layout allowed
      (withHiddenContent payload domain envelopes before)) :
    DomainInvariant c layout allowed
      (withHiddenContent payload domain envelopes after) :=
  execution_preserves_domain_invariant c layout allowed conditions
    (transit_path_ignores_hidden_content c payload domain envelopes run) initial

end TDN.Execution
