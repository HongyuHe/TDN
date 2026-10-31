import TDN.Targets.Components

namespace TDN.Targets

/-- Role-specific OS inventories can contain several families. Disjoint family
sets imply the OS separation clause for every actual Inner/Outer pair.
Manufacturer and cryptographic-library independence remain separate clauses. -/
theorem os_separation_from_role_family_sets (components : List Component)
    (innerFamilies outerFamilies : List String)
    (innerBinding : ∀ component ∈ components, component.role = .inner →
      component.osFamily ∈ innerFamilies)
    (outerBinding : ∀ component ∈ components, component.role = .outer →
      component.osFamily ∈ outerFamilies)
    (disjoint : ∀ family ∈ innerFamilies, family ∉ outerFamilies) :
    ∀ inner ∈ components, ∀ outer ∈ components,
      inner.role = .inner → outer.role = .outer →
      inner.osFamily ≠ outer.osFamily := by
  intro inner hi outer ho ri ro same
  apply disjoint inner.osFamily (innerBinding inner hi ri)
  rw [same]
  exact outerBinding outer ho ro

end TDN.Targets
