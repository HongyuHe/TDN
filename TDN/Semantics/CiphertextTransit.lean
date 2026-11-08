import TDN.Semantics.ExecutionDomains

namespace TDN.Execution

def TransitAction (action : Action) : Prop :=
  action ≠ .encrypt ∧ action ≠ .decrypt ∧ action ≠ .deliver

instance (action : Action) : Decidable (TransitAction action) := by
  unfold TransitAction
  infer_instance

def transit (c : Environment) : Cslib.LTS State Action where
  Tr before action after := Step c before action after ∧ TransitAction action

def withHiddenContent (payload domain : Nat) (envelopes : List Envelope) (state : State) : State :=
  { state with
    frame := { state.frame with
      payload := payload
      originDomain := domain
      envelopes := envelopes } }

lemma transit_step_ignores_hidden_content (c : Environment)
    (payload domain : Nat) (envelopes : List Envelope)
    {before after : State} {action : Action}
    (step : (transit c).Tr before action after) :
    Step c (withHiddenContent payload domain envelopes before) action
      (withHiddenContent payload domain envelopes after) := by
  obtain ⟨operation, allowed⟩ := step
  cases operation with
  | receive tracking => exact .receive tracking
  | route route chosen entry => exact .route route chosen entry
  | routeLocalOutput route chosen entry => exact .routeLocalOutput route chosen entry
  | filter accepted => exact .filter accepted
  | outputFilter accepted => exact .outputFilter accepted
  | encrypt => exact False.elim (allowed.1 rfl)
  | routeOuterPacket route chosen entry => exact .routeOuterPacket route chosen entry
  | bridge permitted => exact .bridge permitted
  | passWithoutTransform noPolicy => exact .passWithoutTransform noPolicy
  | decrypt => exact False.elim (allowed.2.1 rfl)
  | linkTransmit linked => exact .linkTransmit linked
  | «local» addressed accepted => exact .local addressed accepted
  | deliver => exact False.elim (allowed.2.2 rfl)
  | drop => exact .drop _

theorem transit_path_ignores_hidden_content (c : Environment)
    (payload domain : Nat) (envelopes : List Envelope)
    {before after : State} {actions : List Action}
    (run : (transit c).MTr before actions after) :
    (lts c).MTr (withHiddenContent payload domain envelopes before) actions
      (withHiddenContent payload domain envelopes after) := by
  induction run with
  | refl => exact .refl
  | stepL step rest ih =>
    exact .stepL (transit_step_ignores_hidden_content c payload domain envelopes step) ih

theorem recovered_content_follows_checked_transit (c : Environment)
    (expectedEncapStack : Nat → List Nat) (allowed : Nat → Prop)
    (conditions : LocalDomainConditions c expectedEncapStack allowed)
    (payload domain : Nat) (envelopes : List Envelope)
    {before after : State} {actions : List Action}
    (run : (transit c).MTr before actions after)
    (initial : DomainInvariant c expectedEncapStack allowed
      (withHiddenContent payload domain envelopes before)) :
    DomainInvariant c expectedEncapStack allowed
      (withHiddenContent payload domain envelopes after) :=
  execution_preserves_domain_invariant c expectedEncapStack allowed conditions
    (transit_path_ignores_hidden_content c payload domain envelopes run) initial

end TDN.Execution
