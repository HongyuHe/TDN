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

inductive EncryptionProtocol where
  | ipsec | macsec
  deriving DecidableEq

inductive EncryptionLayer where
  | inner | outer
  deriving DecidableEq

structure TunnelHeader where
  layer : EncryptionLayer
  source : Nat
  destination : Nat
  protocol : EncryptionProtocol
  deriving DecidableEq

inductive Zone where
  | red | gray | black | hostLocal
  deriving DecidableEq

namespace TwoLayerOverlay

structure State where
  zone : Zone
  location : Nat
  level : SecurityLevel
  tunnelStack : List TunnelHeader
  deriving DecidableEq

structure Network where
  innerLevel : Nat → SecurityLevel
  innerPeer : Nat → Nat → Prop
  outerPeer : Nat → Nat → Prop
  linked : Nat → Nat → Prop
  allowedTunnelPairing : EncryptionProtocol → EncryptionProtocol → Prop

inductive Step (n : Network) : State → State → Prop
  | innerEncrypt (a b : Nat) (level : SecurityLevel) (m : EncryptionProtocol)
      (peer : n.innerPeer a b) (atSource : n.innerLevel a = level) :
      Step n ⟨.red, a, level, []⟩
        ⟨.gray, a, level, [⟨.inner, a, b, m⟩]⟩
  | grayTransit (a b : Nat) (level : SecurityLevel) (i : TunnelHeader)
      (link : n.linked a b) :
      Step n ⟨.gray, a, level, [i]⟩ ⟨.gray, b, level, [i]⟩
  | outerEncrypt (a b : Nat) (level : SecurityLevel) (i : TunnelHeader) (m : EncryptionProtocol)
      (peer : n.outerPeer a b) (pair : n.allowedTunnelPairing i.protocol m) :
      Step n ⟨.gray, a, level, [i]⟩
        ⟨.black, a, level, [⟨.outer, a, b, m⟩, i]⟩
  | blackTransit (a b : Nat) (level : SecurityLevel) (o i : TunnelHeader)
      (link : n.linked a b) :
      Step n ⟨.black, a, level, [o, i]⟩ ⟨.black, b, level, [o, i]⟩
  | outerDecrypt (level : SecurityLevel) (o i : TunnelHeader)
      (outer : o.layer = .outer) (peer : n.outerPeer o.source o.destination) :
      Step n ⟨.black, o.destination, level, [o, i]⟩
        ⟨.gray, o.destination, level, [i]⟩
  | innerDecrypt (level : SecurityLevel) (i : TunnelHeader)
      (inner : i.layer = .inner) (peer : n.innerPeer i.source i.destination)
      (atDestination : n.innerLevel i.destination = level) :
      Step n ⟨.gray, i.destination, level, [i]⟩
        ⟨.red, i.destination, level, []⟩

abbrev ForwardsAlongOverlayPath (n : Network) (start finish : State) : Prop :=
  Relation.ReflTransGen (Step n) start finish

abbrev ForwardsAlongUnderlayPath {DeviceState : Type} (step : DeviceState → DeviceState → Prop)
    (start finish : DeviceState) : Prop :=
  Relation.ReflTransGen step start finish

def MatchesZoneEncryptionPolicy (s : State) : Prop :=
  match s.zone with
  | .hostLocal => False
  | .red => s.tunnelStack = []
  | .gray => ∃ i, s.tunnelStack = [i] ∧ i.layer = .inner
  | .black => ∃ o i, s.tunnelStack = [o, i] ∧ o.layer = .outer ∧ i.layer = .inner

lemma step_preserves_layers {n : Network} {a b : State}
    (h : Step n a b) (ha : MatchesZoneEncryptionPolicy a) : MatchesZoneEncryptionPolicy b := by
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

theorem forwarding_preserves_layers {n : Network} {a b : State}
    (h : ForwardsAlongOverlayPath n a b) (ha : MatchesZoneEncryptionPolicy a) : MatchesZoneEncryptionPolicy b := by
  induction h with
  | refl => exact ha
  | tail _ step ih => exact step_preserves_layers step ih

theorem forwarding_preserves_level {n : Network} {a b : State}
    (h : ForwardsAlongOverlayPath n a b) : b.level = a.level := by
  induction h with
  | refl => rfl
  | tail _ step ih => exact (step_preserves_level step).trans ih

theorem black_has_two_layers {n : Network} {a b : State}
    (h : ForwardsAlongOverlayPath n a b) (ha : MatchesZoneEncryptionPolicy a)
    (black : b.zone = .black) :
    ∃ o i, b.tunnelStack = [o, i] ∧ o.layer = .outer ∧ i.layer = .inner := by
  have hb := forwarding_preserves_layers h ha
  simpa [MatchesZoneEncryptionPolicy, black] using hb

theorem inner_delivery_same_level {n : Network} {a b : State}
    (h : Step n a b) (delivered : b.zone = .red) :
    n.innerLevel b.location = a.level := by
  cases h <;> simp_all

def MapsToOverlayStep {Concrete : Type} (concreteStep : Concrete → Concrete → Prop)
    (toOverlayState : Concrete → State) (n : Network) : Prop :=
  ∀ a b, concreteStep a b → Step n (toOverlayState a) (toOverlayState b)

theorem underlay_path_maps_to_overlay_path {Concrete : Type}
    {concreteStep : Concrete → Concrete → Prop} {toOverlayState : Concrete → State}
    {n : Network} (stepMapping : MapsToOverlayStep concreteStep toOverlayState n)
    {a b : Concrete} (h : ForwardsAlongUnderlayPath concreteStep a b) :
    ForwardsAlongOverlayPath n (toOverlayState a) (toOverlayState b) := by
  induction h with
  | refl => exact .refl
  | tail _ step ih => exact ih.tail (stepMapping _ _ step)

theorem concrete_black_protection {Concrete : Type}
    {concreteStep : Concrete → Concrete → Prop} {toOverlayState : Concrete → State}
    {n : Network} (stepMapping : MapsToOverlayStep concreteStep toOverlayState n)
    {a b : Concrete} (h : ForwardsAlongUnderlayPath concreteStep a b)
    (initial : MatchesZoneEncryptionPolicy (toOverlayState a)) (black : (toOverlayState b).zone = .black) :
    ∃ o i, (toOverlayState b).tunnelStack = [o, i] ∧ o.layer = .outer ∧ i.layer = .inner :=
  black_has_two_layers (underlay_path_maps_to_overlay_path stepMapping h) initial black

end TwoLayerOverlay
end TDN
