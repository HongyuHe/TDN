import TDN.Models.PkiAndPskTrustDomains
import TDN.Requirements.TwoLayerOverlayArchitecture

namespace TDN.Requirements

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

end TDN.Requirements
