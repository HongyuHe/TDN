import Mathlib.Logic.Relation
import Mathlib.Data.Finset.Basic

namespace TDN

structure SecurityLevel where
  classification : String
  compartments : Finset String
  dissemination : Finset String
  otherControls : Finset String
  deriving DecidableEq

structure RedNetworkIdentity where
  id : String
  site : String
  level : SecurityLevel
  innerComponents : Finset String
  deriving DecidableEq

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
  | red | gray | black | local
  deriving DecidableEq

structure State where
  zone : Zone
  location : Nat
  level : SecurityLevel
  seals : List Seal
  deriving DecidableEq

structure Network where
  innerLevel : Nat → SecurityLevel
  innerPeer : Nat → Nat → Prop
  outerPeer : Nat → Nat → Prop
  linked : Nat → Nat → Prop
  allowedPair : Mechanism → Mechanism → Prop

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

def WellLayered (s : State) : Prop :=
  match s.zone with
  | .local => False
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

theorem black_has_two_layers {n : Network} {a b : State}
    (h : Relation.ReflTransGen (Step n) a b) (ha : WellLayered a)
    (black : b.zone = .black) :
    ∃ o i, b.seals = [o, i] ∧ o.layer = .outer ∧ i.layer = .inner := by
  have hb := execution_preserves_layers h ha
  simpa [WellLayered, black] using hb

theorem inner_delivery_same_level {n : Network} {a b : State}
    (h : Step n a b) (delivered : b.zone = .red) :
    n.innerLevel b.location = a.level := by
  cases h <;> simp_all

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

theorem concrete_black_protection {Concrete : Type}
    {concreteStep : Concrete → Concrete → Prop} {abstract : Concrete → State}
    {n : Network} (refinement : Refines concreteStep abstract n)
    {a b : Concrete} (h : Relation.ReflTransGen concreteStep a b)
    (initial : WellLayered (abstract a)) (black : (abstract b).zone = .black) :
    ∃ o i, (abstract b).seals = [o, i] ∧ o.layer = .outer ∧ i.layer = .inner :=
  black_has_two_layers (refinement_lifts_execution refinement h) initial black

end TDN
