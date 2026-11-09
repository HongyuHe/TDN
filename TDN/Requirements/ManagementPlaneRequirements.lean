import TDN.Models.PrerequisiteEventHistory

namespace TDN.Requirements

inductive AdminEventKind where
  | authentication | operation | logout | credentialRevocation
  deriving DecidableEq, Repr

structure AdminEvent where
  kind : AdminEventKind
  person : Nat
  component : Nat
  order : Nat
  credential : String
  certificateCNSA : Bool
  nist80063 : Bool
  session : String
  deriving DecidableEq, Repr

structure AdministrativeAccount where
  person : Nat
  component : Nat
  credential : String
  groupAccount : Bool
  workstationAccount : Bool
  createdOrder : Nat
  deriving DecidableEq, Repr

structure AdministrativeSession where
  id : String
  person : Nat
  component : Nat
  authenticationOrder : Nat
  credential : String
  operationToken : String
  deriving DecidableEq, Repr

def AdministrativeSessionActive (events : List AdminEvent)
    (session : AdministrativeSession) (operation : AdminEvent) : Prop :=
  ∀ event ∈ events, event.order ≤ operation.order →
    ¬ ((event.kind = .logout ∧ event.component = session.component ∧ event.session = session.id) ∨
       (event.kind = .credentialRevocation ∧ event.credential = session.credential))

def MatchingAdministratorAuthentication (certificateObjective nistObjective : Bool)
    (events : List AdminEvent) (accounts : List AdministrativeAccount)
    (sessions : List AdministrativeSession) (before operation : AdminEvent) : Prop :=
  before.kind = .authentication ∧ before.person = operation.person ∧
  before.component = operation.component ∧ before.order < operation.order ∧
  (certificateObjective = true → before.certificateCNSA = true) ∧
  (nistObjective = true → before.nist80063 = true) ∧
  ∃ account ∈ accounts, account.person = before.person ∧ account.component = before.component ∧
    account.credential = before.credential ∧ account.createdOrder ≤ before.order ∧
    ∃ session ∈ sessions, session.id ≠ "" ∧ session.operationToken ≠ "" ∧
      session.id = before.session ∧ session.id = operation.session ∧
      session.person = before.person ∧ session.component = before.component ∧
      session.authenticationOrder = before.order ∧ session.credential = before.credential ∧
      session.operationToken = operation.credential ∧ AdministrativeSessionActive events session operation

def msc_administrator_authentication (certificateObjective nistObjective : Bool)
    (events : List AdminEvent) (accounts : List AdministrativeAccount)
    (sessions : List AdministrativeSession) (awAdministrators : List Nat) : Prop :=
  (∀ event ∈ events, event.kind = .operation →
    ∃ authentication ∈ events,
      MatchingAdministratorAuthentication certificateObjective nistObjective events accounts sessions
        authentication event) ∧
  (∀ account ∈ accounts, account.credential ≠ "" ∧
    (account.workstationAccount = true → account.groupAccount = false)) ∧
  (∀ person ∈ awAdministrators, ∃ account ∈ accounts,
    account.person = person ∧ account.workstationAccount = true) ∧
  ∀ a ∈ accounts, a.workstationAccount = true →
    ∀ b ∈ accounts, b.workstationAccount = true →
      a.person ≠ b.person → a.credential ≠ b.credential

theorem administrator_authentication_from_admitted_operations
    (certificateObjective nistObjective : Bool) (events actions : List AdminEvent)
    (accounts : List AdministrativeAccount) (sessions : List AdministrativeSession)
    (awAdministrators : List Nat) (credentialOwner : String → Nat)
    (run : (Admission.lts (fun e : AdminEvent => e.kind = .operation)
      (MatchingAdministratorAuthentication certificateObjective nistObjective events accounts sessions)).MTr
        [] actions events)
    (individual : ∀ account ∈ accounts,
      account.credential ≠ "" ∧ (account.workstationAccount = true →
        account.groupAccount = false ∧ credentialOwner account.credential = account.person))
    (roster : ∀ person ∈ awAdministrators, ∃ account ∈ accounts,
      account.person = person ∧ account.workstationAccount = true) :
    msc_administrator_authentication certificateObjective nistObjective events accounts sessions
      awAdministrators := by
  refine ⟨Admission.all_admitted_events_have_prerequisites _ _ run, ?_, roster, ?_⟩
  · intro account member
    exact ⟨(individual account member).1, fun aw => ((individual account member).2 aw).1⟩
  · intro a memberA awA b memberB awB different same
    apply different
    rw [← ((individual a memberA).2 awA).2, ← ((individual b memberB).2 awB).2, same]

end TDN.Requirements
