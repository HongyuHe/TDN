import TDN.Targets.Cryptography
import Lean.Elab.Tactic.Omega

namespace TDN.Targets

/-- Public settings sufficient to identify the required pairwise key-server choice.
KGS approval and fallback behavior are separate RG-027 clauses. -/
structure MACsecKeyServerSettings where
  leftSite : String
  rightSite : String
  leftPriority : Nat
  rightPriority : Nat
  centralSite : Option String
  cknBytes : Nat
  deriving DecidableEq, Repr

def MACsecKeyServerSettings.Checked (settings : MACsecKeyServerSettings) : Prop :=
  16 ≤ settings.cknBytes ∧
  ((settings.leftPriority = 0 ∧ settings.rightPriority = 1) ∨
    (settings.leftPriority = 1 ∧ settings.rightPriority = 0)) ∧
  (match settings.centralSite with
   | none => True
   | some central =>
      (settings.leftSite = central ∧ settings.leftPriority = 0) ∨
      (settings.rightSite = central ∧ settings.rightPriority = 0))

instance (settings : MACsecKeyServerSettings) : Decidable settings.Checked := by
  unfold MACsecKeyServerSettings.Checked
  cases settings.centralSite <;> infer_instance

/-- Select the site with lower configured priority. Source configuration and the
implementation's election rule must be connected separately for operational claims. -/
def selectedKeyServer (settings : MACsecKeyServerSettings) : String :=
  if settings.leftPriority < settings.rightPriority then settings.leftSite else settings.rightSite

lemma checked_pair_has_distinct_priorities {settings : MACsecKeyServerSettings}
    (checked : settings.Checked) : settings.leftPriority ≠ settings.rightPriority := by
  rcases checked.2.1 with h | h <;> omega

/-- The exact 0/1 checks ensure a selected central site has the unique lower priority.
The argument applies unchanged when the physical devices or their roles are swapped. -/
theorem checked_key_server_is_central {settings : MACsecKeyServerSettings}
    (checked : settings.Checked) {central : String}
    (present : settings.centralSite = some central) : selectedKeyServer settings = central := by
  have centralCheck := checked.2.2
  rw [present] at centralCheck
  rcases centralCheck with left | right
  · have order : settings.leftPriority < settings.rightPriority := by
      rcases checked.2.1 with h | h <;> omega
    simp [selectedKeyServer, order, left.1]
  · have order : ¬ settings.leftPriority < settings.rightPriority := by
      rcases checked.2.1 with h | h <;> omega
    simp [selectedKeyServer, order, right.1]

/-- Combine independently checked technical settings with approval and fallback
facts to establish the encompassing requirement. Approval is an explicit premise. -/
theorem macsec_key_requirements_from_separate_checks (pairs : List MACsecKeyPair)
    (selection : ∀ p ∈ pairs,
      (MACsecKeyServerSettings.mk p.leftSite p.rightSite p.leftPriority p.rightPriority
        p.centralSite p.cknBytes).Checked)
    (approved : ∀ p ∈ pairs, p.cknGeneratedByApprovedKGS = true ∧ p.cakGeneratedByApprovedKGS = true)
    (fallback : ∀ p ∈ pairs, p.leftFallbackEnabled = false ∧ p.rightFallbackEnabled = false) :
    msc_macsec_key_generation_and_server pairs := by
  intro p member
  have settings := selection p member
  refine ⟨settings.1, (approved p member).1, (approved p member).2,
    settings.2.1, ?_, (fallback p member).1, (fallback p member).2⟩
  intro central present
  have centralCheck := settings.2.2
  change (match p.centralSite with
    | none => True
    | some site => (p.leftSite = site ∧ p.leftPriority = 0) ∨
      (p.rightSite = site ∧ p.rightPriority = 0)) at centralCheck
  simpa [present] using centralCheck

end TDN.Targets
