import TDN

/-!
The tests use captured public credentials and loaded policies. The positive
exchange supplies a synthetic successful possession check for a fresh attempt;
it is a nonvacuity witness for the model, not an observation of a future IKE_AUTH.
Expired evidence, mismatched exchange IDs, and unbound possession must fail.
-/
namespace MSCLifecycle
open TDN.MSC TDN.MSC.Deployment TDN.MSC.Lifecycle TDN.Network.Lifecycle

def witnessEpoch : Nat :=
  authenticationObservations.foldl (fun epoch observation =>
    max epoch ((observation.audit.map TDN.Network.CredentialAudit.atEpoch).getD 0)) 0 + 1

def input? (owner : String) : Option ExchangeEvidence := do
  let audit ← Authentication.audit? owner
  let session ← (Authentication.sessions owner).head?
  let request ← Authentication.sessionRequest? audit session
  pure
    { attempt := 0, possessionBound := true, audit := { audit with atEpoch := witnessEpoch },
      request := { request with possessionVerified := true } }

def n (tunnel : Tunnel) : Negotiation String :=
  ⟨tunnel.owner, tunnel.peer, .reauthentication, 0, witnessEpoch⟩

example : ∀ tunnel ∈ tunnels,
    (input? tunnel.owner).isSome = true ∧ (input? tunnel.peer).isSome = true ∧
    ∀ left ∈ (input? tunnel.owner).toList, ∀ right ∈ (input? tunnel.peer).toList,
      acceptsEvidence model (n tunnel) .initiator left = true ∧
      acceptsEvidence model (n tunnel) .responder right = true := by decide

example (tunnel : Tunnel) (member : tunnel ∈ tunnels)
    (left right : ExchangeEvidence) (leftCurrent : left.audit.atEpoch = witnessEpoch)
    (rightCurrent : right.audit.atEpoch = witnessEpoch)
    (leftAccepted : acceptsEvidence model (n tunnel) .initiator left = true)
    (rightAccepted : acceptsEvidence model (n tunnel) .responder right = true) :
    ∃ result, TDN.Network.Reach (Step model) { epoch := witnessEpoch } result ∧ result.activations ≠ [] :=
  checked_reauthentication_can_activate model tunnel.owner tunnel.peer witnessEpoch left right
    (both_peers_schedule_reauthentication tunnel member).1 leftCurrent rightCurrent leftAccepted rightAccepted

example : ∀ evidence ∈ (input? "I_A1").toList,
    acceptsEvidence model ⟨"I_A1", "I_B1", .reauthentication, 1, witnessEpoch⟩ .initiator evidence = false := by decide

example : ∀ evidence ∈ (input? "I_A1").toList,
    acceptsEvidence model ⟨"I_A1", "I_B1", .reauthentication, 0, witnessEpoch⟩ .initiator
      { evidence with possessionBound := false } = false := by decide

example : ∀ evidence ∈ (input? "I_A1").toList,
    acceptsEvidence model ⟨"I_A1", "I_B1", .reauthentication, 0, 2000000000⟩ .initiator
      { evidence with audit := { evidence.audit with atEpoch := 2000000000 } } = false := by decide

end MSCLifecycle
