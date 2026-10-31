import Mathlib.Data.List.Basic

namespace TDN.Trust

/-- An authentication identity records the issuer of its credential and accepted issuers.
Successful signature and validity checks can restrict this relation further. -/
structure Identity (Domain Authority : Type) where
  domain : Domain
  issuer : Authority
  trustedIssuers : List Authority

def Admits {D A : Type} (verifier claimant : Identity D A) : Prop :=
  claimant.issuer ∈ verifier.trustedIssuers

def MutuallyAdmits {D A : Type} (a b : Identity D A) : Prop := Admits a b ∧ Admits b a

/-- Every authority used by an identity belongs to its domain. -/
def Scoped {D A : Type} (owner : A → D) (identity : Identity D A) : Prop :=
  owner identity.issuer = identity.domain ∧
  ∀ authority ∈ identity.trustedIssuers, owner authority = identity.domain

lemma admitted_domain_eq {D A : Type} {owner : A → D} {a b : Identity D A}
    (aScoped : Scoped owner a) (bScoped : Scoped owner b) (admitted : Admits a b) :
    a.domain = b.domain := by
  exact (aScoped.2 b.issuer admitted).symm.trans bScoped.1

/-- Separately scoped issuer and trust-store entries exclude every cross-domain peer. -/
theorem scoped_authorities_exclude_cross_domain {D A : Type} {owner : A → D}
    {a b : Identity D A} (aScoped : Scoped owner a) (bScoped : Scoped owner b)
    (different : a.domain ≠ b.domain) : ¬ MutuallyAdmits a b := by
  intro both
  exact different (admitted_domain_eq aScoped bScoped both.1)

/-- Shared-key authentication is possible only when both peers possess the same key. -/
structure SharedKeyIdentity (Domain Key : Type) where
  domain : Domain
  key : Key

def KeyAdmits {D K : Type} (a b : SharedKeyIdentity D K) : Prop := a.key = b.key

theorem scoped_keys_exclude_cross_domain {D K : Type} (owner : K → D)
    (a b : SharedKeyIdentity D K) (ha : owner a.key = a.domain)
    (hb : owner b.key = b.domain) (different : a.domain ≠ b.domain) : ¬ KeyAdmits a b := by
  intro same
  apply different
  rw [← ha, ← hb, same]

end TDN.Trust
