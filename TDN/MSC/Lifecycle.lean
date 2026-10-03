import TDN.MSC.Authentication
import TDN.Network.Lifecycle

/-!
VG-16 concerns reauthentication before replacement of an established IKE SA.
The selected profile disables ordinary IKE rekey timers on both endpoints and
configures periodic reauthentication. A finite certificate checks every loaded
connection. The generic lifecycle theorem then covers automatic renewal traces
with arbitrarily many attempts, interleavings, and failed/incomplete handshakes.

The model's credential callback uses the same admission theory as the snapshot
SA binding. New exchanges supply current public audits and a trusted possession
result bound to their fresh attempt. The snapshot's existing ESTABLISHED flag
is not reused as evidence that a future exchange authenticated successfully.

The conclusion covers automatic requests emitted by the retained configured
gateways. Operator-forced rekeys and arbitrary requests outside that closed
peer model are not prevented merely by setting rekey_time to zero. Correct
strongSwan execution, current cryptographic verification, and evidence collection
remain external dependencies. The theorem concerns activation of new keys;
IKE_SA_INIT derives candidate key material before the IKE_AUTH identity checks.
-/
namespace TDN.MSC.Lifecycle
open Deployment TDN.Network.Lifecycle

def scheduled (source peer : String) (kind : Kind) : Bool :=
  (Authentication.connections source).any fun connection =>
    connection.localIdentity == source ++ ".msc.test" &&
    connection.remoteIdentity == peer ++ ".msc.test" &&
    match kind with
    | .reauthentication => connection.reauthIntervalSeconds != 0
    | .inlineRekey => connection.ikeRekeyIntervalSeconds != 0

def validate (source peer : String) (audit : TDN.Network.CredentialAudit)
    (request : TDN.Network.Authentication.Request) : Bool :=
  request.localIdentity == source ++ ".msc.test" &&
    request.remoteIdentity == peer ++ ".msc.test" &&
    TDN.Network.Authentication.admits (Authentication.policy source) audit request

def model : Model String := ⟨scheduled, validate⟩

/-- This finite check covers every loaded record, including additional
connections. Positive reauthentication timers provide a nonempty alternative
to the excluded inline-rekey branch. -/
theorem loaded_renewal_policies : ∀ observation ∈ authenticationObservations,
    ∀ connection ∈ observation.connections.getD [],
      0 < connection.reauthIntervalSeconds ∧ connection.ikeRekeyIntervalSeconds = 0 := by decide

theorem every_loaded_connection_disables_inline (owner : String)
    (connection : TDN.Network.LoadedConnection)
    (member : connection ∈ Authentication.connections owner) :
    connection.ikeRekeyIntervalSeconds = 0 := by
  cases found : Authentication.observation? owner with
  | none => simp [Authentication.connections, found] at member
  | some observation =>
    have included : observation ∈ authenticationObservations := List.mem_of_find?_eq_some found
    have loaded : connection ∈ observation.connections.getD [] := by
      simpa [Authentication.connections, found] using member
    exact (loaded_renewal_policies observation included connection loaded).2

/-- The quantifiers range over arbitrary endpoint strings. Unknown sources
have no loaded connection and cannot supply an automatic origin. -/
theorem automatic_inline_requests_disabled : NoInlineOrigins model := by
  intro source peer
  change scheduled source peer .inlineRekey = false
  apply List.any_eq_false.mpr
  intro connection member
  have disabled := every_loaded_connection_disables_inline source connection member
  simp [disabled]

theorem both_peers_schedule_reauthentication : ∀ tunnel ∈ tunnels,
    scheduled tunnel.owner tunnel.peer .reauthentication = true ∧
    scheduled tunnel.peer tunnel.owner .reauthentication = true := by decide

/-- Finite loaded-policy checks, local transition preservation, and induction
combine into strict ordering for every modeled automatic activation. -/
theorem automatic_replacement_has_fresh_peer_authentication
    (epoch : Nat) (result : State String)
    (path : TDN.Network.Reach (Step model) { epoch := epoch } result) :
    ∀ activation ∈ result.activations, AuthenticatedActivation model activation :=
  activations_after_time_start_have_fresh_authentication model automatic_inline_requests_disabled epoch result path

/-- Each fresh receipt passes the full certificate/revocation admission
procedure and names the actual endpoint pair of that renewal attempt. -/
theorem renewal_receipt_uses_credential_admission (receipt : Receipt String)
    (checked : CheckedReceipt model receipt) :
    receipt.evidence.attempt = receipt.negotiation.attempt ∧
    receipt.evidence.possessionBound = true ∧
    receipt.evidence.request.localIdentity = receipt.negotiation.actor receipt.side ++ ".msc.test" ∧
    receipt.evidence.request.remoteIdentity = receipt.negotiation.peer receipt.side ++ ".msc.test" ∧
    TDN.Network.Authentication.admits (Authentication.policy (receipt.negotiation.actor receipt.side))
      receipt.evidence.audit receipt.evidence.request = true := by
  obtain ⟨attempt, bound, validated⟩ := checked_receipt_binds_current_exchange model receipt checked
  simp only [model, validate, Bool.and_eq_true, beq_iff_eq] at validated
  exact ⟨attempt, bound, validated.1.1, validated.1.2, validated.2⟩

end TDN.MSC.Lifecycle
