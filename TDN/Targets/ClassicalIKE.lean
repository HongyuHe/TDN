import TDN.Targets.Cryptography

namespace TDN.Targets

/-- The fixed certificate and complete offered IKE proposal list supply the
algorithm facts. Negotiation may choose any entry in that list. -/
theorem classical_ike_choices_from_local_checks (offered : List AlgorithmSuite)
    (encryption : ∀ suite ∈ offered, suite.aesBits = 256)
    (authentication : ∀ suite ∈ offered,
      suite.signature = .rsa3072 ∨ suite.signature = .ecdsaP384sha384)
    (establishment : ∀ suite ∈ offered, ClassicalEstablishment suite.establishment)
    (integrity : ∀ suite ∈ offered, ApprovedIntegrity suite.integrity) :
    ∀ suite ∈ offered, CNSA1 suite := by
  intro suite member
  exact ⟨encryption suite member, authentication suite member,
    establishment suite member, integrity suite member⟩

/-- The theorem preserves the algorithm property across arbitrary selections.
An implementation-to-model connection must establish that a negotiated choice
comes from the recorded complete offer list. -/
theorem negotiated_classical_ike_from_checked_offers (offered : List AlgorithmSuite)
    (checked : ∀ suite ∈ offered, CNSA1 suite)
    (negotiated : AlgorithmSuite) (selected : negotiated ∈ offered) : CNSA1 negotiated :=
  negotiated_suite_inherits_profile offered CNSA1 checked negotiated selected

end TDN.Targets
