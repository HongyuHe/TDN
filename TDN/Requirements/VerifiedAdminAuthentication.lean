import TDN.Requirements.MasterMscRequirementSpecs

namespace TDN.Requirements.Msc
open Compliance

theorem administrator_authentication_from_local_admission_and_credential_checks
    (d : Deployment) (certificateObjective nistObjective : Bool)
    (events actions : List AdminEvent) (accounts : List AdministrativeAccount)
    (sessions : List AdministrativeSession) (awAdministrators : List Nat)
    (credentialOwner : String → Nat)
    (run : (Admission.lts (fun event : AdminEvent => event.kind = .operation)
      (MatchingAdministratorAuthentication certificateObjective nistObjective
        events accounts sessions)).MTr [] actions events)
    (individual : ∀ account ∈ accounts, account.credential ≠ "" ∧
      (account.workstationAccount = true →
        account.groupAccount = false ∧ credentialOwner account.credential = account.person))
    (roster : ∀ person ∈ awAdministrators, ∃ account ∈ accounts,
      account.person = person ∧ account.workstationAccount = true)
    (certificateAssurance : certificateObjective = true → ∀ event ∈ events,
      event.kind = .authentication → d.authority.certificateCNSACompliant event.credential)
    (nistAssurance : nistObjective = true → ∀ event ∈ events,
      event.kind = .authentication → d.authority.authenticationConformsToNIST80063 event.credential) :
    msc_administrator_authentication d certificateObjective nistObjective
      events accounts sessions awAdministrators := by
  refine ⟨administrator_authentication_from_admitted_operations
    certificateObjective nistObjective events actions accounts sessions
    awAdministrators credentialOwner run individual roster, ?_⟩
  intro event present authentication
  exact ⟨fun selected => certificateAssurance selected event present authentication,
    fun selected => nistAssurance selected event present authentication⟩

end TDN.Requirements.Msc
