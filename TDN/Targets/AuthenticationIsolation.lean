import TDN.Semantics.Trust
import TDN.Targets.Architecture

namespace TDN.Targets

inductive InnerCredential where
  | certificate (issuer : String) (trustedIssuers : List String)
  | sharedKey (keyIdentity : String)
  deriving DecidableEq

structure InnerAuthentication where
  component : String
  level : SecurityLevel
  credential : InnerCredential
  managementDevices : Finset String
  deriving DecidableEq

def InnerCanAuthenticate (a b : InnerAuthentication) : Prop :=
  match a.credential, b.credential with
  | .certificate issuerA trustA, .certificate issuerB trustB =>
    issuerB ∈ trustA ∧ issuerA ∈ trustB
  | .sharedKey keyA, .sharedKey keyB => keyA = keyB
  | _, _ => False

def MaterialsSeparated (a b : InnerAuthentication) : Prop :=
  match a.credential, b.credential with
  | .certificate issuerA trustA, .certificate issuerB trustB =>
    issuerA ≠ issuerB ∧ (∀ root ∈ trustA, root ∈ trustB → False) ∧
    issuerA ∉ trustB ∧ issuerB ∉ trustA
  | .sharedKey keyA, .sharedKey keyB => keyA ≠ keyB
  | _, _ => True

def msc_security_level_key_and_management_separation
    (managementSelected : Bool) (peers : List InnerAuthentication) : Prop :=
  (managementSelected = true → ∀ a ∈ peers, a.managementDevices.Nonempty) ∧
  (∀ a ∈ peers, ∀ b ∈ peers, a.level ≠ b.level →
    MaterialsSeparated a b ∧
    (managementSelected = true → Disjoint a.managementDevices b.managementDevices) ∧
    ¬ InnerCanAuthenticate a b)

def CredentialScoped (authorityLevel keyLevel : String → SecurityLevel)
    (peer : InnerAuthentication) : Prop :=
  match peer.credential with
  | .certificate issuer trusted => authorityLevel issuer = peer.level ∧
    ∀ root ∈ trusted, authorityLevel root = peer.level
  | .sharedKey key => keyLevel key = peer.level

lemma scoped_inner_peers_cannot_cross_levels
    {authorityLevel keyLevel : String → SecurityLevel} {a b : InnerAuthentication}
    (ha : CredentialScoped authorityLevel keyLevel a)
    (hb : CredentialScoped authorityLevel keyLevel b) (different : a.level ≠ b.level) :
    ¬ InnerCanAuthenticate a b := by
  intro admitted
  cases ca : a.credential with
  | certificate issuerA trustA =>
    cases cb : b.credential with
    | certificate issuerB trustB =>
      simp only [CredentialScoped, ca, cb] at ha hb
      simp only [InnerCanAuthenticate, ca, cb] at admitted
      exact different ((ha.2 issuerB admitted.1).symm.trans hb.1)
    | sharedKey keyB => simp [InnerCanAuthenticate, ca, cb] at admitted
  | sharedKey keyA =>
    cases cb : b.credential with
    | certificate issuerB trustB => simp [InnerCanAuthenticate, ca, cb] at admitted
    | sharedKey keyB =>
      simp only [CredentialScoped, ca, cb] at ha hb
      simp only [InnerCanAuthenticate, ca, cb] at admitted
      exact different (ha.symm.trans ((congrArg keyLevel admitted).trans hb))

lemma scoped_materials_separated
    {authorityLevel keyLevel : String → SecurityLevel} {a b : InnerAuthentication}
    (ha : CredentialScoped authorityLevel keyLevel a)
    (hb : CredentialScoped authorityLevel keyLevel b) (different : a.level ≠ b.level) :
    MaterialsSeparated a b := by
  cases ca : a.credential with
  | certificate issuerA trustA =>
    cases cb : b.credential with
    | certificate issuerB trustB =>
      simp only [CredentialScoped, ca, cb] at ha hb
      simp only [MaterialsSeparated, ca, cb]
      refine ⟨?_, ?_, ?_, ?_⟩
      · intro same
        exact different (ha.1.symm.trans ((congrArg authorityLevel same).trans hb.1))
      · intro root inA inB
        exact different ((ha.2 root inA).symm.trans (hb.2 root inB))
      · intro inB
        exact different (ha.1.symm.trans (hb.2 issuerA inB))
      · intro inA
        exact different ((ha.2 issuerB inA).symm.trans hb.1)
    | sharedKey keyB => simp [MaterialsSeparated, ca, cb]
  | sharedKey keyA =>
    cases cb : b.credential with
    | certificate issuerB trustB => simp [MaterialsSeparated, ca, cb]
    | sharedKey keyB =>
      simp only [CredentialScoped, ca, cb] at ha hb
      simp only [MaterialsSeparated, ca, cb]
      intro same
      exact different (ha.symm.trans ((congrArg keyLevel same).trans hb))

theorem separate_authentication_and_management_of_scoped_material
    (managementSelected : Bool) (peers : List InnerAuthentication) (authorityLevel keyLevel : String → SecurityLevel)
    (scopeFacts : ∀ peer ∈ peers, CredentialScoped authorityLevel keyLevel peer)
    (present : managementSelected = true → ∀ peer ∈ peers, peer.managementDevices.Nonempty)
    (management : managementSelected = true → ∀ a ∈ peers, ∀ b ∈ peers, a.level ≠ b.level →
      Disjoint a.managementDevices b.managementDevices) :
    msc_security_level_key_and_management_separation managementSelected peers := by
  refine ⟨present, ?_⟩
  intro a ha b hb different
  exact ⟨scoped_materials_separated (scopeFacts a ha) (scopeFacts b hb) different,
    (fun selected => management selected a ha b hb different),
    scoped_inner_peers_cannot_cross_levels (scopeFacts a ha) (scopeFacts b hb) different⟩

end TDN.Targets
