import TDN.Targets.CompleteSpecifications

namespace TDN.Targets.Complete

instance (a b : InnerAuthentication) : Decidable (InnerCanAuthenticate a b) := by
  unfold InnerCanAuthenticate
  cases a.credential <;> cases b.credential <;> infer_instance

instance (authorityLevel keyLevel : String → SecurityLevel) (peer : InnerAuthentication) :
    Decidable (CredentialScoped authorityLevel keyLevel peer) := by
  unfold CredentialScoped
  cases peer.credential <;> infer_instance

def EstablishedInnerPair (pairs : List (String × String)) (source destination : String) : Prop :=
  (source, destination) ∈ pairs

instance (pairs : List (String × String)) (source destination : String) :
    Decidable (EstablishedInnerPair pairs source destination) := by
  unfold EstablishedInnerPair
  infer_instance

lemma scoped_management_sets_disjoint
    {managementLevel : String → SecurityLevel} {a b : InnerAuthentication}
    (scopeA : ∀ manager ∈ a.managementDevices, managementLevel manager = a.level)
    (scopeB : ∀ manager ∈ b.managementDevices, managementLevel manager = b.level)
    (different : a.level ≠ b.level) :
    Disjoint a.managementDevices b.managementDevices := by
  apply Finset.disjoint_left.mpr
  intro manager inA inB
  exact different ((scopeA manager inA).symm.trans (scopeB manager inB))

theorem key_and_management_separation_from_scoped_inventory
    (managementSelected : Bool) (peers : List InnerAuthentication)
    (authorityLevel keyLevel managementLevel : String → SecurityLevel)
    (establishedPairs : List (String × String))
    (credentialScope : ∀ peer ∈ peers, CredentialScoped authorityLevel keyLevel peer)
    (managementPresent : managementSelected = true →
      ∀ peer ∈ peers, peer.managementDevices.Nonempty)
    (managementScope : managementSelected = true → ∀ peer ∈ peers,
      ∀ manager ∈ peer.managementDevices, managementLevel manager = peer.level)
    (componentUnique : ∀ a ∈ peers, ∀ b ∈ peers, a.component = b.component → a = b)
    (authenticatedPairs : ∀ pair ∈ establishedPairs,
      ∃ a ∈ peers, ∃ b ∈ peers, a.component = pair.1 ∧
        b.component = pair.2 ∧ InnerCanAuthenticate a b) :
    msc_security_level_key_and_management_separation managementSelected peers
      (EstablishedInnerPair establishedPairs) := by
  constructor
  · apply separate_authentication_and_management_of_scoped_material managementSelected peers
      authorityLevel keyLevel credentialScope managementPresent
    intro selected a inA b inB different
    exact scoped_management_sets_disjoint (managementScope selected a inA)
      (managementScope selected b inB) different
  · intro a inA b inB different installed
    obtain ⟨actualA, memberA, actualB, memberB, source, destination, authenticated⟩ :=
      authenticatedPairs (a.component, b.component) installed
    have sameA := componentUnique actualA memberA a inA source
    have sameB := componentUnique actualB memberB b inB destination
    subst actualA
    subst actualB
    exact scoped_inner_peers_cannot_cross_levels
      (credentialScope a inA) (credentialScope b inB) different authenticated

end TDN.Targets.Complete
