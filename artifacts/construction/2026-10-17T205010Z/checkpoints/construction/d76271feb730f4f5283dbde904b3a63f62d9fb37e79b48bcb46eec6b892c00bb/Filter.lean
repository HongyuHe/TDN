import Mathlib.Data.List.Basic

namespace TDN.Filter

inductive Verdict where
  | allow | deny
  deriving DecidableEq, Repr

structure Rule (Packet : Type) where
  accepts : Packet → Bool
  verdict : Verdict

/-- Ordered first-match evaluation with an explicit default. -/
def evaluate {Packet : Type} : List (Rule Packet) → Verdict → Packet → Verdict
  | [], fallback, _ => fallback
  | r :: rest, fallback, p =>
      if r.accepts p then r.verdict else evaluate rest fallback p

/-- A rule-local condition is sufficient despite earlier denying rules and arbitrary order. -/
theorem allowed_has_matching_allow {Packet : Type} (rules : List (Rule Packet))
    (p : Packet) (h : evaluate rules .deny p = .allow) :
    ∃ r ∈ rules, r.accepts p = true ∧ r.verdict = .allow := by
  induction rules with
  | nil => cases h
  | cons r rest ih =>
      simp only [evaluate] at h
      split at h
      next hm => exact ⟨r, by simp, hm, h⟩
      next hm =>
        obtain ⟨r₂, hr₂, hm₂, ha₂⟩ := ih h
        exact ⟨r₂, by simp [hr₂], hm₂, ha₂⟩

theorem default_deny_sound {Packet : Type} (rules : List (Rule Packet))
    (permitted : Packet → Prop)
    (localRule : ∀ r ∈ rules, r.verdict = .allow → ∀ p, r.accepts p = true → permitted p)
    (p : Packet) (accepted : evaluate rules .deny p = .allow) : permitted p := by
  obtain ⟨r, hr, hm, ha⟩ := allowed_has_matching_allow rules p accepted
  exact localRule r hr ha p hm

/-- Denial is established for every packet outside the allowed cases. -/
theorem rejects_outside_allowlist {Packet : Type} (rules : List (Rule Packet))
    (permitted : Packet → Prop)
    (localRule : ∀ r ∈ rules, r.verdict = .allow → ∀ p, r.accepts p = true → permitted p)
    (p : Packet) (forbidden : ¬ permitted p) : evaluate rules .deny p = .deny := by
  cases h : evaluate rules .deny p with
  | deny => rfl
  | allow => exact False.elim (forbidden (default_deny_sound rules permitted localRule p h))

/-- Exact positive traffic is a distinct obligation, never implied by safety. -/
def HasUsefulTraffic {Packet : Type} (rules : List (Rule Packet))
    (useful : Packet → Prop) : Prop :=
  ∃ p, useful p ∧ evaluate rules .deny p = .allow

end TDN.Filter
