import TDN.Targets.Topology

namespace TDN.Tests.Placement
abbrev Node := Fin 4

def edge (a b : Node) : Prop := (a = 0 ∧ b = 1) ∨ (a = 1 ∧ b = 2)
def gray (a b : Node) : Prop := a = 0 ∧ b = 3
def outer (a : Node) : Prop := a = 0
def firewall (a : Node) : Prop := a = 1
def black (a : Node) : Prop := a = 2
def inner (a : Node) : Prop := a = 3
def side (a : Node) : Nat := if a = 2 then 1 else 0

/-- Nonempty non-Internet model: the connection to Black passes through the firewall. -/
theorem noninternet_mediated_connection :
    Targets.msc_outer_firewall_placement true false false edge gray outer firewall black
      (fun _ => False) inner (fun _ _ => False) (fun _ _ => False)
      (Relation.ReflTransGen edge) := by
  refine ⟨by decide, ?_, ?_, ?_, ?_⟩
  · intro a b h
    exact h.elim False.elim (fun h => h.elim False.elim id)
  · intro o ho
    have h : o = 0 := ho
    subst o
    exact ⟨2, rfl, (Relation.ReflTransGen.single (show edge (0 : Node) 1 from Or.inl ⟨rfl,rfl⟩)).tail (Or.inr ⟨rfl,rfl⟩)⟩
  · intro _ o b ho hb
    exact Paths.no_firewall_free_crossing edge firewall side
      (by unfold edge firewall side; decide)
      (by unfold outer at ho; subst o; unfold firewall; decide)
      (by unfold outer at ho; unfold black at hb; subst o; subst b; unfold side; decide)
  · intro o ho
    exact ⟨3,rfl,ho,rfl⟩

/-- Trusted, non-public transport permits a direct Black connection without a firewall. -/
theorem trusted_direct_connection :
    Targets.msc_outer_firewall_placement false false false
      (fun a b : Node => a = 0 ∧ b = 2) gray outer (fun _ => False) black
      (fun _ => False) inner (fun _ _ => False) (fun _ _ => False)
      (fun a b => a = 0 ∧ b = 2) := by
  refine ⟨by decide, ?_, ?_, (by intro h; cases h), ?_⟩
  · intro a b h
    exact Relation.ReflTransGen.single (h.elim False.elim (fun h => h.elim False.elim id))
  · intro o ho
    exact ⟨2, rfl, ho, rfl⟩
  · intro o ho
    exact ⟨3, rfl, ho, rfl⟩

end TDN.Tests.Placement
