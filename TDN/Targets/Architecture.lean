import Mathlib.Logic.Relation
import Mathlib.Data.Finset.Basic

namespace TDN

/-- Full declared labels retain classification and every stated control dimension. -/
structure SecurityLevel where
  classification : String
  compartments : Finset String
  dissemination : Finset String
  otherControls : Finset String
  deriving DecidableEq

/-- Two Red networks may have the same full security level and distinct Inner assignments. -/
structure RedNetworkIdentity where
  id : String
  site : String
  level : SecurityLevel
  innerComponents : Finset String
  deriving DecidableEq

/-- A configured assignment preserves network identity separately from level equality. -/
def DedicatedInnerAssignments (networks : List RedNetworkIdentity) : Prop :=
  (∀ n ∈ networks, n.innerComponents.Nonempty) ∧
  ∀ a ∈ networks, ∀ b ∈ networks, a.id ≠ b.id →
    Disjoint a.innerComponents b.innerComponents

inductive Mechanism where
  | ipsec | macsec
  deriving DecidableEq

inductive Layer where
  | inner | outer
  deriving DecidableEq

structure Seal where
  layer : Layer
  source : Nat
  destination : Nat
  mechanism : Mechanism
  deriving DecidableEq

inductive Zone where
  | red | gray | black
  deriving DecidableEq

/-- A protected payload state. Control traffic has a separate semantic domain. -/
structure State where
  zone : Zone
  location : Nat
  level : SecurityLevel
  seals : List Seal
  deriving DecidableEq

/-- Endpoint security levels are arbitrary full labels, with no fixed site/level count. -/
structure Network where
  innerLevel : Nat → SecurityLevel
  innerPeer : Nat → Nat → Prop
  outerPeer : Nat → Nat → Prop
  linked : Nat → Nat → Prop
  allowedPair : Mechanism → Mechanism → Prop

/-- Operational protected-payload semantics. Refinement from Linux is a separate obligation. -/
inductive Step (n : Network) : State → State → Prop
  | innerEncrypt (a b : Nat) (level : SecurityLevel) (m : Mechanism)
      (peer : n.innerPeer a b) (atSource : n.innerLevel a = level) :
      Step n ⟨.red, a, level, []⟩
        ⟨.gray, a, level, [⟨.inner, a, b, m⟩]⟩
  | grayTransit (a b : Nat) (level : SecurityLevel) (i : Seal)
      (link : n.linked a b) :
      Step n ⟨.gray, a, level, [i]⟩ ⟨.gray, b, level, [i]⟩
  | outerEncrypt (a b : Nat) (level : SecurityLevel) (i : Seal) (m : Mechanism)
      (peer : n.outerPeer a b) (pair : n.allowedPair i.mechanism m) :
      Step n ⟨.gray, a, level, [i]⟩
        ⟨.black, a, level, [⟨.outer, a, b, m⟩, i]⟩
  | blackTransit (a b : Nat) (level : SecurityLevel) (o i : Seal)
      (link : n.linked a b) :
      Step n ⟨.black, a, level, [o, i]⟩ ⟨.black, b, level, [o, i]⟩
  | outerDecrypt (level : SecurityLevel) (o i : Seal)
      (outer : o.layer = .outer) (peer : n.outerPeer o.source o.destination) :
      Step n ⟨.black, o.destination, level, [o, i]⟩
        ⟨.gray, o.destination, level, [i]⟩
  | innerDecrypt (level : SecurityLevel) (i : Seal)
      (inner : i.layer = .inner) (peer : n.innerPeer i.source i.destination)
      (atDestination : n.innerLevel i.destination = level) :
      Step n ⟨.gray, i.destination, level, [i]⟩
        ⟨.red, i.destination, level, []⟩

/-- Local stack invariant. It records logical layers, not implementation independence. -/
def WellLayered (s : State) : Prop :=
  match s.zone with
  | .red => s.seals = []
  | .gray => ∃ i, s.seals = [i] ∧ i.layer = .inner
  | .black => ∃ o i, s.seals = [o, i] ∧ o.layer = .outer ∧ i.layer = .inner

lemma step_preserves_layers {n : Network} {a b : State}
    (h : Step n a b) (ha : WellLayered a) : WellLayered b := by
  cases h with
  | innerEncrypt => exact ⟨_, rfl, rfl⟩
  | grayTransit => exact ha
  | outerEncrypt a b level i m peer pair =>
      obtain ⟨j, hj, hi⟩ := ha
      cases List.cons.inj hj |>.1
      exact ⟨_, _, rfl, rfl, hi⟩
  | blackTransit => exact ha
  | outerDecrypt level o i outer peer =>
      obtain ⟨o₂, i₂, hstack, ho, hi⟩ := ha
      have eqs := List.cons.inj hstack
      have ei := List.cons.inj eqs.2
      cases eqs.1
      cases ei.1
      exact ⟨_, rfl, hi⟩
  | innerDecrypt => rfl

lemma step_preserves_level {n : Network} {a b : State}
    (h : Step n a b) : b.level = a.level := by
  cases h <;> rfl

/-- Every finite execution preserves the checked local stack invariant. -/
theorem execution_preserves_layers {n : Network} {a b : State}
    (h : Relation.ReflTransGen (Step n) a b) (ha : WellLayered a) : WellLayered b := by
  induction h with
  | refl => exact ha
  | tail _ step ih => exact step_preserves_layers step ih

theorem execution_preserves_level {n : Network} {a b : State}
    (h : Relation.ReflTransGen (Step n) a b) : b.level = a.level := by
  induction h with
  | refl => rfl
  | tail _ step ih => exact (step_preserves_level step).trans ih

/-- Black payload protection follows for arbitrary finite executions of the model. -/
theorem black_has_two_layers {n : Network} {a b : State}
    (h : Relation.ReflTransGen (Step n) a b) (ha : WellLayered a)
    (black : b.zone = .black) :
    ∃ o i, b.seals = [o, i] ∧ o.layer = .outer ∧ i.layer = .inner := by
  have hb := execution_preserves_layers h ha
  simpa [WellLayered, black] using hb

/-- Inner decryption authorizes delivery only to the payloads full security level. -/
theorem inner_delivery_same_level {n : Network} {a b : State}
    (h : Step n a b) (delivered : b.zone = .red) :
    n.innerLevel b.location = a.level := by
  cases h <;> simp_all

/-- A refinement must cover every concrete step; it is never inferred from probes. -/
def Refines {Concrete : Type} (concreteStep : Concrete → Concrete → Prop)
    (abstract : Concrete → State) (n : Network) : Prop :=
  ∀ a b, concreteStep a b → Step n (abstract a) (abstract b)

theorem refinement_lifts_execution {Concrete : Type}
    {concreteStep : Concrete → Concrete → Prop} {abstract : Concrete → State}
    {n : Network} (refinement : Refines concreteStep abstract n)
    {a b : Concrete} (h : Relation.ReflTransGen concreteStep a b) :
    Relation.ReflTransGen (Step n) (abstract a) (abstract b) := by
  induction h with
  | refl => exact .refl
  | tail _ step ih => exact ih.tail (refinement _ _ step)

/-- Conditional transfer theorem with the implementation-refinement premise displayed. -/
theorem concrete_black_protection {Concrete : Type}
    {concreteStep : Concrete → Concrete → Prop} {abstract : Concrete → State}
    {n : Network} (refinement : Refines concreteStep abstract n)
    {a b : Concrete} (h : Relation.ReflTransGen concreteStep a b)
    (initial : WellLayered (abstract a)) (black : (abstract b).zone = .black) :
    ∃ o i, (abstract b).seals = [o, i] ∧ o.layer = .outer ∧ i.layer = .inner :=
  black_has_two_layers (refinement_lifts_execution refinement h) initial black

end TDN
