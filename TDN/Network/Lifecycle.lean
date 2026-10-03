import TDN.Network.Authentication
import TDN.Network.Graph

/-!
Automatic IKE renewal has two distinct paths. Reauthentication creates a new
association; each gateway checks its peer before local activation. Inline rekey can replace keys without
fresh identity checks. The model retains both paths, so excluding inline rekey
requires an independent certificate about the initiating gateways' policies.

The state is an event ledger. Requests, derivations, authentication receipts,
and activations are retained after completion. Omitting deletion and expiry
overapproximates possible future activations but does not assume authentication
order. A monotonically increasing event position distinguishes attempts and
proves strict precedence. Preliminary key derivation occurs before IKE_AUTH;
the security conclusion concerns activation of the replacement association.

The scheduled callback covers automatic requests emitted by modeled peers.
Unconstrained operator commands and requests from endpoints outside that model
are separate inputs. Disabling a local timer alone does not filter such inputs.
-/
namespace TDN.Network.Lifecycle

inductive Kind where
  | reauthentication | inlineRekey
  deriving DecidableEq, BEq, Repr

inductive Side where
  | initiator | responder
  deriving DecidableEq, BEq, Repr

structure Negotiation (Node : Type) where
  initiator : Node
  responder : Node
  kind : Kind
  attempt : Nat
  startedEpoch : Nat
  deriving DecidableEq, BEq, Repr

def Negotiation.actor {Node : Type} (n : Negotiation Node) : Side → Node
  | .initiator => n.initiator
  | .responder => n.responder

def Negotiation.peer {Node : Type} (n : Negotiation Node) : Side → Node
  | .initiator => n.responder
  | .responder => n.initiator

structure Model (Node : Type) where
  scheduled : Node → Node → Kind → Bool
  validate : Node → Node → CredentialAudit → Authentication.Request → Bool

/-- The trusted IKE authentication operation binds its possession check to the
current exchange. A receipt from an earlier attempt must fail that binding even
when its certificate and peer identity remain valid. The Boolean records the
external cryptographic result, whose correctness is an implementation premise. -/
structure ExchangeEvidence where
  attempt : Nat
  possessionBound : Bool
  audit : CredentialAudit
  request : Authentication.Request
  deriving DecidableEq, BEq, Repr

structure Receipt (Node : Type) where
  negotiation : Negotiation Node
  side : Side
  evidence : ExchangeEvidence
  position : Nat
  deriving DecidableEq, BEq, Repr

structure Activation (Node : Type) where
  negotiation : Negotiation Node
  side : Side
  receipt : Option (Receipt Node)
  position : Nat
  epoch : Nat
  deriving DecidableEq, BEq, Repr

structure State (Node : Type) where
  next : Nat := 0
  epoch : Nat := 0
  requested : List (Negotiation Node) := []
  derived : List (Negotiation Node) := []
  receipts : List (Receipt Node) := []
  activations : List (Activation Node) := []
  deriving DecidableEq, BEq, Repr

variable {Node : Type}

def advance (s : State Node) : State Node := { s with next := s.next + 1 }

def acceptsEvidence (model : Model Node) (n : Negotiation Node) (side : Side)
    (evidence : ExchangeEvidence) : Bool :=
  evidence.attempt == n.attempt && evidence.possessionBound &&
    model.validate (n.actor side) (n.peer side) evidence.audit evidence.request

/-- Both peers can originate requests. The scheduled predicate is consulted on
the actual initiating endpoint, which prevents a one-sided timer argument. -/
inductive Step (model : Model Node) : State Node → State Node → Prop where
  | request (s : State Node) (source peer : Node) (kind : Kind)
      (allowed : model.scheduled source peer kind = true) :
      Step model s { advance s with requested := ⟨source, peer, kind, s.next, s.epoch⟩ :: s.requested }
  | derive (s : State Node) (n : Negotiation Node) (present : n ∈ s.requested)
      (fresh : n ∉ s.derived) :
      Step model s { advance s with derived := n :: s.derived }
  | authenticate (s : State Node) (n : Negotiation Node) (side : Side)
      (evidence : ExchangeEvidence)
      (keys : n ∈ s.derived)
      (current : evidence.audit.atEpoch = s.epoch)
      (accepted : acceptsEvidence model n side evidence = true) :
      Step model s { advance s with receipts := ⟨n, side, evidence, s.next⟩ :: s.receipts }
  | activateAuthenticated (s : State Node) (n : Negotiation Node) (side : Side)
      (receipt : Receipt Node) (keys : n ∈ s.derived)
      (kind : n.kind = .reauthentication) (present : receipt ∈ s.receipts)
      (attempt : receipt.negotiation = n) (actor : receipt.side = side)
      (fresh : ∀ previous ∈ s.activations, (previous.negotiation, previous.side) ≠ (n, side)) :
      Step model s { advance s with activations := ⟨n, side, some receipt, s.next, s.epoch⟩ :: s.activations }
  | activateInline (s : State Node) (n : Negotiation Node) (side : Side) (keys : n ∈ s.derived)
      (kind : n.kind = .inlineRekey)
      (fresh : ∀ previous ∈ s.activations, (previous.negotiation, previous.side) ≠ (n, side)) :
      Step model s { advance s with activations := ⟨n, side, none, s.next, s.epoch⟩ :: s.activations }
  | wait (s : State Node) : Step model s (advance s)
  | tick (s : State Node) (epoch : Nat) (forward : s.epoch ≤ epoch) :
      Step model s { advance s with epoch := epoch }

def CheckedReceipt (model : Model Node) (receipt : Receipt Node) : Prop :=
  acceptsEvidence model receipt.negotiation receipt.side receipt.evidence = true

def AuthenticatedActivation (model : Model Node) (activation : Activation Node) : Prop :=
  activation.negotiation.kind = .reauthentication ∧
  ∃ receipt,
    activation.receipt = some receipt ∧ receipt.negotiation = activation.negotiation ∧
    receipt.side = activation.side ∧ CheckedReceipt model receipt ∧
    activation.negotiation.attempt < receipt.position ∧ receipt.position < activation.position ∧
    activation.negotiation.startedEpoch ≤ receipt.evidence.audit.atEpoch ∧
    receipt.evidence.audit.atEpoch ≤ activation.epoch

def NoInlineOrigins (model : Model Node) : Prop :=
  ∀ source peer, model.scheduled source peer .inlineRekey = false

/-- Every newly appended receipt uses the clock of its authentication event.
An old audit cannot be replayed after time has advanced, even if its stored
signature-verification flag remains positive. -/
theorem new_receipt_is_current_and_checked (model : Model Node)
    {before after : State Node} (receipt : Receipt Node) (step : Step model before after)
    (added : after.receipts = receipt :: before.receipts) :
    receipt.evidence.audit.atEpoch = before.epoch ∧ CheckedReceipt model receipt := by
  have unchangedImpossible : before.receipts ≠ receipt :: before.receipts := by
    intro same
    have sizes := congrArg List.length same
    simp at sizes
  cases step with
  | authenticate n side evidence keys current accepted =>
    have same := (List.cons.inj added).1
    subst receipt
    exact ⟨current, accepted⟩
  | request => exact False.elim (unchangedImpossible added)
  | derive => exact False.elim (unchangedImpossible added)
  | activateAuthenticated => exact False.elim (unchangedImpossible added)
  | activateInline => exact False.elim (unchangedImpossible added)
  | wait => exact False.elim (unchangedImpossible added)
  | tick => exact False.elim (unchangedImpossible added)

structure Invariant (model : Model Node) (s : State Node) : Prop where
  requested : ∀ n ∈ s.requested,
    n.attempt < s.next ∧ n.startedEpoch ≤ s.epoch ∧
      model.scheduled n.initiator n.responder n.kind = true
  derived : ∀ n ∈ s.derived, n ∈ s.requested
  receipts : ∀ receipt ∈ s.receipts,
    receipt.negotiation ∈ s.requested ∧ CheckedReceipt model receipt ∧
    receipt.negotiation.attempt < receipt.position ∧ receipt.position < s.next ∧
    receipt.negotiation.startedEpoch ≤ receipt.evidence.audit.atEpoch ∧
    receipt.evidence.audit.atEpoch ≤ s.epoch
  activations : ∀ activation ∈ s.activations, AuthenticatedActivation model activation
  distinct : (s.activations.map (fun a => (a.negotiation, a.side))).Nodup

theorem empty_invariant (model : Model Node) : Invariant model ({} : State Node) := by
  constructor <;> simp

theorem empty_at_time_invariant (model : Model Node) (epoch : Nat) :
    Invariant model ({ epoch := epoch } : State Node) := by
  constructor <;> simp

theorem invariant_advance (model : Model Node) (s : State Node)
    (valid : Invariant model s) : Invariant model (advance s) := by
  refine ⟨?_, valid.derived, ?_, valid.activations, valid.distinct⟩
  · intro n member
    obtain ⟨earlier, timestamp, allowed⟩ := valid.requested n member
    exact ⟨Nat.lt_succ_of_lt earlier, timestamp, allowed⟩
  · intro receipt member
    obtain ⟨origin, checked, fresh, earlier, started, timestamp⟩ := valid.receipts receipt member
    exact ⟨origin, checked, fresh, Nat.lt_succ_of_lt earlier, started, timestamp⟩

theorem invariant_tick (model : Model Node) (s : State Node) (epoch : Nat)
    (forward : s.epoch ≤ epoch) (valid : Invariant model s) :
    Invariant model { advance s with epoch := epoch } := by
  have later := invariant_advance model s valid
  refine ⟨?_, later.derived, ?_, later.activations, later.distinct⟩
  · intro n member
    obtain ⟨earlier, timestamp, allowed⟩ := later.requested n member
    exact ⟨earlier, Nat.le_trans timestamp forward, allowed⟩
  · intro receipt member
    obtain ⟨origin, checked, fresh, earlier, started, timestamp⟩ := later.receipts receipt member
    exact ⟨origin, checked, fresh, earlier, started, Nat.le_trans timestamp forward⟩

/-- The local preservation proof is the bridge from scheduler and admission
facts to an arbitrary number of interleaved renewal attempts. -/
theorem step_preserves_invariant (model : Model Node) (disabled : NoInlineOrigins model)
    {before after : State Node} (step : Step model before after)
    (valid : Invariant model before) : Invariant model after := by
  cases step with
  | request source peer kind allowed =>
    have later := invariant_advance model before valid
    refine ⟨?_, ?_, ?_, later.activations, later.distinct⟩
    · intro n member
      rcases List.mem_cons.mp member with rfl | old
      · exact ⟨Nat.lt_succ_self _, Nat.le_refl _, allowed⟩
      · exact later.requested n old
    · intro n member
      exact List.mem_cons_of_mem _ (valid.derived n member)
    · intro receipt member
      obtain ⟨origin, checked, fresh, earlier, started, timestamp⟩ := later.receipts receipt member
      exact ⟨List.mem_cons_of_mem _ origin, checked, fresh, earlier, started, timestamp⟩
  | derive n present fresh =>
    have later := invariant_advance model before valid
    refine ⟨later.requested, ?_, later.receipts, later.activations, later.distinct⟩
    intro candidate member
    rcases List.mem_cons.mp member with rfl | old
    · exact present
    · exact valid.derived candidate old
  | authenticate n side evidence keys current accepted =>
    have later := invariant_advance model before valid
    refine ⟨later.requested, later.derived, ?_, later.activations, later.distinct⟩
    intro receipt member
    rcases List.mem_cons.mp member with rfl | old
    · have origin := valid.derived n keys
      exact ⟨origin, accepted, (valid.requested n origin).1, Nat.lt_succ_self _,
        current.symm ▸ (valid.requested n origin).2.1, Nat.le_of_eq current⟩
    · exact later.receipts receipt old
  | activateAuthenticated n side receipt keys kind present attempt actor fresh =>
    have later := invariant_advance model before valid
    refine ⟨later.requested, later.derived, later.receipts, ?_, ?_⟩
    · intro activation member
      rcases List.mem_cons.mp member with rfl | old
      · obtain ⟨_, checked, recent, earlier, started, timestamp⟩ := valid.receipts receipt present
        exact ⟨kind, receipt, rfl, attempt, actor, checked, attempt ▸ recent, earlier,
          attempt ▸ started, timestamp⟩
      · exact valid.activations activation old
    · simp only [List.map_cons, List.nodup_cons]
      refine ⟨?_, valid.distinct⟩
      intro member
      obtain ⟨previous, included, same⟩ := List.mem_map.mp member
      exact fresh previous included same
  | activateInline n side keys kind fresh =>
    have allowed := (valid.requested n (valid.derived n keys)).2.2
    rw [kind, disabled n.initiator n.responder] at allowed
    cases allowed
  | wait => exact invariant_advance model before valid
  | tick epoch forward => exact invariant_tick model before epoch forward valid

theorem executions_preserve_invariant (model : Model Node) (disabled : NoInlineOrigins model)
    {before after : State Node} (path : Reach (Step model) before after)
    (valid : Invariant model before) : Invariant model after := by
  induction path with
  | refl => exact valid
  | step transition _ ih => exact ih (step_preserves_invariant model disabled transition valid)

/-- Authentication receipts belong to the exact new attempt, occur after that
attempt starts, and precede activation. Prior-generation receipts cannot satisfy
the conclusion merely because they identify the same remote gateway. -/
theorem every_automatic_activation_has_fresh_authentication
    (model : Model Node) (disabled : NoInlineOrigins model) (result : State Node)
    (path : Reach (Step model) {} result) :
    ∀ activation ∈ result.activations, AuthenticatedActivation model activation :=
  (executions_preserve_invariant model disabled path (empty_invariant model)).activations

theorem activations_after_time_start_have_fresh_authentication
    (model : Model Node) (disabled : NoInlineOrigins model) (epoch : Nat) (result : State Node)
    (path : Reach (Step model) { epoch := epoch } result) :
    ∀ activation ∈ result.activations, AuthenticatedActivation model activation :=
  (executions_preserve_invariant model disabled path (empty_at_time_invariant model epoch)).activations

theorem checked_receipt_binds_current_exchange (model : Model Node) (receipt : Receipt Node)
    (checked : CheckedReceipt model receipt) :
    receipt.evidence.attempt = receipt.negotiation.attempt ∧
    receipt.evidence.possessionBound = true ∧
    model.validate (receipt.negotiation.actor receipt.side) (receipt.negotiation.peer receipt.side)
      receipt.evidence.audit receipt.evidence.request = true := by
  simpa [CheckedReceipt, acceptsEvidence, Bool.and_eq_true, and_assoc] using checked

theorem activation_attempts_are_distinct (model : Model Node) (disabled : NoInlineOrigins model)
    (result : State Node) (path : Reach (Step model) {} result) :
    (result.activations.map (fun a => (a.negotiation, a.side))).Nodup :=
  (executions_preserve_invariant model disabled path (empty_invariant model)).distinct

theorem previous_exchange_evidence_rejected (model : Model Node) (n : Negotiation Node)
    (side : Side) (evidence : ExchangeEvidence) (old : evidence.attempt ≠ n.attempt) :
    acceptsEvidence model n side evidence = false := by
  simp [acceptsEvidence, old]

theorem unbound_possession_rejected (model : Model Node) (n : Negotiation Node)
    (side : Side) (evidence : ExchangeEvidence) (unbound : evidence.possessionBound = false) :
    acceptsEvidence model n side evidence = false := by
  simp [acceptsEvidence, unbound]

/-- Successful fresh checks provide a concrete execution witness. The model
abstracts transport and cryptographic implementation, so the caller supplies
those checks; the theorem does not infer them from an old active session. -/
theorem checked_reauthentication_can_activate (model : Model Node) (source peer : Node)
    (epoch : Nat) (left right : ExchangeEvidence)
    (scheduled : model.scheduled source peer .reauthentication = true)
    (leftCurrent : left.audit.atEpoch = epoch) (rightCurrent : right.audit.atEpoch = epoch)
    (leftAccepted : acceptsEvidence model ⟨source, peer, .reauthentication, 0, epoch⟩ .initiator left = true)
    (rightAccepted : acceptsEvidence model ⟨source, peer, .reauthentication, 0, epoch⟩ .responder right = true) :
    ∃ result, Reach (Step model) ({ epoch := epoch } : State Node) result ∧ result.activations ≠ [] := by
  let n : Negotiation Node := ⟨source, peer, .reauthentication, 0, epoch⟩
  let a : Receipt Node := ⟨n, .initiator, left, 4⟩
  let b : Receipt Node := ⟨n, .responder, right, 2⟩
  let s1 : State Node := { next := 1, epoch := epoch, requested := [n] }
  let s2 : State Node := { s1 with next := 2, derived := [n] }
  let s3 : State Node := { s2 with next := 3, receipts := [b] }
  let s4 : State Node := { s3 with next := 4, activations := [⟨n, .responder, some b, 3, epoch⟩] }
  let s5 : State Node := { s4 with next := 5, receipts := [a, b] }
  let s6 : State Node := { s5 with next := 6, activations := ⟨n, .initiator, some a, 5, epoch⟩ :: s4.activations }
  refine ⟨s6, ?_, by simp [s6]⟩
  apply Reach.step (b := s1) (Step.request _ source peer .reauthentication scheduled)
  apply Reach.step (b := s2) (Step.derive _ n (by simp [s1]) (by simp [s1]))
  apply Reach.step (b := s3) (Step.authenticate _ n .responder right
    (by simp [s2]) rightCurrent rightAccepted)
  apply Reach.step (b := s4) (Step.activateAuthenticated _ n .responder b
    (by simp [s3, s2]) rfl (by simp [s3]) rfl rfl (by simp [s3, s2, s1]))
  apply Reach.step (b := s5) (Step.authenticate _ n .initiator left
    (by simp [s4, s3, s2]) leftCurrent leftAccepted)
  apply Reach.step (b := s6) (Step.activateAuthenticated _ n .initiator a
    (by simp [s5, s4, s3, s2]) rfl (by simp [s5]) rfl rfl (by simp [s5, s4]))
  exact .refl _

end TDN.Network.Lifecycle
