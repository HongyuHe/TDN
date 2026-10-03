import TDN.Network.Lifecycle

/-!
Three independently named endpoints reuse the generic lifecycle proof. The
credential callback is synthetic in this fixture. A separate MSC fixture checks
the full admission procedure with captured public credential objects.
-/
namespace LifecycleReuse
open TDN.Network TDN.Network.Lifecycle

def automatic : Model (Fin 3) where
  scheduled source peer kind := source != peer && kind == .reauthentication
  validate _ _ _ request := request.possessionVerified

def evidence : ExchangeEvidence :=
  { attempt := 0, possessionBound := true,
    audit := { atEpoch := 100, pemSHA256 := "synthetic", anchors := [], certificates := [], crls := [] },
    request := ⟨"local", "peer", "synthetic", true⟩ }

example : NoInlineOrigins automatic := by unfold NoInlineOrigins; decide

example (source peer : Fin 3) (different : source ≠ peer) :
    ∃ result, Reach (Step automatic) ({ epoch := 100 } : State (Fin 3)) result ∧
      result.activations ≠ [] := by
  apply checked_reauthentication_can_activate automatic source peer 100 evidence evidence
  · simp [automatic, different]
    rfl
  · rfl
  · rfl
  · rfl
  · rfl

example (result : State (Fin 3)) (path : Reach (Step automatic) { epoch := 100 } result) :
    ∀ activation ∈ result.activations, AuthenticatedActivation automatic activation :=
  activations_after_time_start_have_fresh_authentication automatic (by unfold NoInlineOrigins; decide) 100 result path

def peerInline : Model (Fin 3) :=
  { automatic with scheduled := fun source peer kind =>
      automatic.scheduled source peer kind || (source == 1 && peer == 0 && kind == .inlineRekey) }

def bare : Negotiation (Fin 3) := ⟨1, 0, .inlineRekey, 0, 0⟩
def bareRequested : State (Fin 3) := { next := 1, requested := [bare] }
def bareDerived : State (Fin 3) := { bareRequested with next := 2, derived := [bare] }
def bareActivated : State (Fin 3) :=
  { bareDerived with next := 3, activations := [⟨bare, .responder, none, 2, 0⟩] }

/-- Enabling only the remote initiator's timer produces a legal inline-rekey
trace without fresh authentication. The bilateral configuration premise matters. -/
example : Reach (Step peerInline) {} bareActivated := by
  apply Reach.step (b := bareRequested) (Step.request _ 1 0 .inlineRekey (by decide))
  apply Reach.step (b := bareDerived) (Step.derive _ bare (by simp [bareRequested]) (by simp [bareRequested]))
  apply Reach.step (b := bareActivated) (Step.activateInline _ bare .responder (by simp [bareDerived]) rfl (by simp [bareDerived, bareRequested]))
  exact .refl _

example : ¬ NoInlineOrigins peerInline := by unfold NoInlineOrigins; decide
example : ¬ AuthenticatedActivation peerInline ⟨bare, .responder, none, 2, 0⟩ := by
  simp [AuthenticatedActivation, bare]

example : acceptsEvidence automatic ⟨0, 1, .reauthentication, 1, 100⟩ .initiator evidence = false := by decide
example : acceptsEvidence automatic ⟨0, 1, .reauthentication, 0, 100⟩ .initiator
    { evidence with possessionBound := false } = false := by decide

example : Step automatic ({ epoch := 100 } : State (Fin 3)) { next := 1, epoch := 200 } :=
  .tick _ 200 (by decide)

def staleReceipt : Receipt (Fin 3) :=
  ⟨⟨0, 1, .reauthentication, 0, 100⟩, .initiator, evidence, 2⟩

example : ¬ Step automatic ({ epoch := 200 } : State (Fin 3))
    { next := 1, epoch := 200, receipts := [staleReceipt] } := by
  intro step
  have current := (new_receipt_is_current_and_checked automatic staleReceipt step rfl).1
  have wrongTime : staleReceipt.evidence.audit.atEpoch ≠ 200 := by decide
  exact wrongTime current

def earlyNegotiation : Negotiation (Fin 3) := ⟨0, 1, .reauthentication, 0, 100⟩
def earlyRequested : State (Fin 3) := { next := 1, epoch := 100, requested := [earlyNegotiation] }
def earlyDerived : State (Fin 3) := { earlyRequested with next := 2, derived := [earlyNegotiation] }
def responderCheck : Receipt (Fin 3) := ⟨earlyNegotiation, .responder, evidence, 2⟩
def responderChecked : State (Fin 3) := { earlyDerived with next := 3, receipts := [responderCheck] }
def responderActivated : State (Fin 3) :=
  { responderChecked with
      next := 4
      activations := [⟨earlyNegotiation, .responder, some responderCheck, 3, 100⟩] }

/-- The responder can establish its local association before the initiator
checks the response. A global two-receipt activation guard would exclude this
ordinary IKE behavior and would overstate what the implementation guarantees. -/
example : Reach (Step automatic) { epoch := 100 } responderActivated := by
  apply Reach.step (b := earlyRequested) (Step.request _ 0 1 .reauthentication (by decide))
  apply Reach.step (b := earlyDerived) (Step.derive _ earlyNegotiation
    (by simp [earlyRequested]) (by simp [earlyRequested]))
  apply Reach.step (b := responderChecked) (Step.authenticate _ earlyNegotiation .responder evidence
    (by simp [earlyDerived]) rfl (by decide))
  apply Reach.step (b := responderActivated) (Step.activateAuthenticated _ earlyNegotiation .responder responderCheck
    (by simp [responderChecked, earlyDerived]) rfl (by simp [responderChecked]) rfl rfl
    (by simp [responderChecked, earlyDerived, earlyRequested]))
  exact .refl _

example : responderActivated.receipts.any (fun receipt => receipt.side == .initiator) = false := by decide

end LifecycleReuse
