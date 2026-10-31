import TDN.Targets.Management
import Mathlib.Logic.Relation

namespace TDN.RecordedOperations

/-- One configured administrative assignment. The Boolean selects an Inner component;
false selects an Outer or Gray Firewall. No physical separation is encoded here. -/
structure Assignment where
  component : String
  workstation : String
  inner : Bool
  deriving DecidableEq, Repr

/-- A supplied partition numbers the workstations. Every assignment must agree with
that workstation's partition. The partition is a witness; Lean checks its use. -/
def AssignmentChecks (assignments : List Assignment) (partition : String → Bool) : Prop :=
  ∀ a ∈ assignments, partition a.workstation = a.inner

/-- RG-044 / DM-17, restricted to the configured administrative assignments.
The same workstation cannot occur in both the Inner and Outer assignments. -/
theorem administrative_assignments_do_not_share_layers
    (assignments : List Assignment) (partition : String → Bool)
    (checked : AssignmentChecks assignments partition)
    (a b : Assignment) (ha : a ∈ assignments) (hb : b ∈ assignments)
    (different : a.inner ≠ b.inner) : a.workstation ≠ b.workstation := by
  intro same
  apply different
  calc
    a.inner = partition a.workstation := (checked a ha).symm
    _ = partition b.workstation := congrArg partition same
    _ = b.inner := checked b hb

def tlsProtection (version : String) : Option Targets.ManagementProtection :=
  if version = "TLSv1.3" then some .tls13
  else if version = "TLSv1.2" then some .tls12 else none

/-- Every recognized observed TLS version meets the CP's management protocol choice.
Actual TLS protection depends on the captured implementation and negotiation record. -/
theorem recognized_tls_is_allowed (version : String) (p : Targets.ManagementProtection)
    (recognized : tlsProtection version = some p) : Targets.ApprovedManagementProtocol p := by
  unfold tlsProtection at recognized
  split_ifs at recognized with h13 h12
  · cases recognized
    simp [Targets.ApprovedManagementProtocol]
  · cases recognized
    simp [Targets.ApprovedManagementProtocol]

structure PowerState where
  inUse : Bool
  poweredOn : Bool
  deriving DecidableEq, Repr, Inhabited

def UnusedIsOff (s : PowerState) : Prop := s.inUse = false → s.poweredOn = false

/-- The experiment explicitly declares the use window. Beginning use turns the guest
on; completing use turns it off. Other observations must preserve both fields. -/
def PowerStep (before after : PowerState) : Prop :=
  after = before ∨ after = ⟨true, true⟩ ∨ after = ⟨false, false⟩

lemma power_step_preserves_unused_off {before after : PowerState}
    (step : PowerStep before after) (valid : UnusedIsOff before) : UnusedIsOff after := by
  rcases step with same | started | finished
  · simpa [same] using valid
  · subst after
    simp [UnusedIsOff]
  · subst after
    simp [UnusedIsOff]

/-- RG-045 / DM-27 for every state of a trace that obeys the declared use protocol.
An imported finite experiment supplies its states and transition checks separately. -/
theorem power_trace_keeps_unused_guest_off {first last : PowerState}
    (initial : UnusedIsOff first) (trace : Relation.ReflTransGen PowerStep first last) :
    UnusedIsOff last := by
  induction trace with
  | refl => exact initial
  | tail _ step ih => exact power_step_preserves_unused_off step ih

/-- A preserved configuration response contains the complete selected setting list.
The list can be any configuration fragment; it is not assumed to cover a whole device. -/
structure ConfigurationResponse where
  principalRole : String
  status : Nat
  settings : List String
  deriving DecidableEq, Repr

def AvailableThrough (response : ConfigurationResponse) (role : String)
    (configuration : List String) : Prop :=
  response.principalRole = role ∧ response.status = 200 ∧
  ∀ setting ∈ configuration, setting ∈ response.settings

/-- RG-058's configuration-access part and RG-068's monitoring part. Exact readback
identity supplies every selected setting to the recorded authorized role. -/
theorem successful_readback_makes_settings_available (response : ConfigurationResponse)
    (role : String) (configuration : List String)
    (authorizedRole : response.principalRole = role) (success : response.status = 200)
    (readback : response.settings = configuration) : AvailableThrough response role configuration := by
  refine ⟨authorizedRole, success, ?_⟩
  intro setting member
  simpa [readback] using member

/-- Generic indexed retention: every selected result ID has a corresponding saved
record. Content correctness and file identity are checked by the importer. -/
def ResultsRetained (selected : List String) (saved : List (String × String)) : Prop :=
  ∀ id ∈ selected, ∃ path, (id, path) ∈ saved ∧ path ≠ ""

/-- RG-072's result-preservation part for a declared test selection. A total lookup
table, checked once, covers any selected test without assuming its outcome passed. -/
theorem retained_table_covers_selected_tests (selected : List String)
    (saved : List (String × String)) (location : String → String)
    (present : ∀ id ∈ selected, (id, location id) ∈ saved)
    (nonempty : ∀ id ∈ selected, location id ≠ "") : ResultsRetained selected saved := by
  intro id member
  exact ⟨location id, present id member, nonempty id member⟩

/-- Paths here identify the recorded CSR input, signer output and installed credential.
They do not assert that a worker-generated private key was created inside a component. -/
structure Issuance where
  requestOutput : String
  signedRequest : String
  certificateOutput : String
  configuredCertificate : String
  requestOrder : Nat
  signingOrder : Nat
  useOrder : Nat
  signer : String
  trustAnchor : String
  loadedAuthorities : List String
  deriving DecidableEq, Repr

def IssuanceChecked (i : Issuance) : Prop :=
  i.requestOutput = i.signedRequest ∧ i.certificateOutput = i.configuredCertificate ∧
  i.requestOrder < i.signingOrder ∧ i.signingOrder < i.useOrder ∧
  i.signer ∈ i.loadedAuthorities ∧ i.trustAnchor ∈ i.loadedAuthorities

/-- RG-048's request/sign/install ordering subset. The external observation contract
connects successful crypto commands at these paths to their stated effects. -/
theorem issued_credential_follows_request (i : Issuance) (checked : IssuanceChecked i) :
    i.requestOutput = i.signedRequest ∧ i.certificateOutput = i.configuredCertificate ∧
    i.requestOrder < i.useOrder ∧
    i.signer ∈ i.loadedAuthorities ∧ i.trustAnchor ∈ i.loadedAuthorities := by
  exact ⟨checked.1, checked.2.1,
    Nat.lt_trans checked.2.2.1 checked.2.2.2.1, checked.2.2.2.2⟩

end TDN.RecordedOperations
