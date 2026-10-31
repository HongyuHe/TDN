import Mathlib.Data.List.Basic

namespace TDN.Filter

inductive Verdict where
  | allow | deny
  deriving DecidableEq, Repr

structure Rule (Packet : Type) where
  accepts : Packet → Bool
  verdict : Verdict

def evaluate {Packet : Type} : List (Rule Packet) → Verdict → Packet → Verdict
  | [], fallback, _ => fallback
  | r :: rest, fallback, p =>
      if r.accepts p then r.verdict else evaluate rest fallback p

lemma allowed_has_matching_allow {Packet : Type} (rules : List (Rule Packet))
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

theorem rejects_outside_allowlist {Packet : Type} (rules : List (Rule Packet))
    (permitted : Packet → Prop)
    (localRule : ∀ r ∈ rules, r.verdict = .allow → ∀ p, r.accepts p = true → permitted p)
    (p : Packet) (forbidden : ¬ permitted p) : evaluate rules .deny p = .deny := by
  cases h : evaluate rules .deny p with
  | deny => rfl
  | allow => exact False.elim (forbidden (default_deny_sound rules permitted localRule p h))

def HasUsefulTraffic {Packet : Type} (rules : List (Rule Packet))
    (useful : Packet → Prop) : Prop :=
  ∃ p, useful p ∧ evaluate rules .deny p = .allow

lemma evaluate_skips_nonmatching_prefix {Packet : Type} (earlierRules rest : List (Rule Packet))
    (fallback : Verdict) (packet : Packet)
    (misses : ∀ rule ∈ earlierRules, rule.accepts packet = false) :
    evaluate (earlierRules ++ rest) fallback packet = evaluate rest fallback packet := by
  induction earlierRules with
  | nil => rfl
  | cons rule remaining ih =>
    have first := misses rule (by simp)
    simp only [List.cons_append, evaluate, first, Bool.false_eq_true, ↓reduceIte]
    exact ih (fun r member => misses r (List.mem_cons_of_mem _ member))

theorem accepts_at_first_matching_rule {Packet : Type}
    (earlierRules suffix : List (Rule Packet)) (rule : Rule Packet) (packet : Packet)
    (misses : ∀ earlier ∈ earlierRules, earlier.accepts packet = false)
    (matchesRule : rule.accepts packet = true) (allows : rule.verdict = .allow) :
    evaluate (earlierRules ++ rule :: suffix) .deny packet = .allow := by
  rw [evaluate_skips_nonmatching_prefix earlierRules (rule :: suffix) .deny packet misses]
  simp [evaluate, matchesRule, allows]

theorem denying_prefix_blocks {Packet : Type} (earlierRules suffix : List (Rule Packet))
    (fallback : Verdict) (packet : Packet)
    (denials : ∀ rule ∈ earlierRules, rule.verdict = .deny)
    (covered : ∃ rule ∈ earlierRules, rule.accepts packet = true) :
    evaluate (earlierRules ++ suffix) fallback packet = .deny := by
  induction earlierRules with
  | nil => simp at covered
  | cons rule remaining ih =>
    simp only [List.cons_append, evaluate]
    split
    next matched => exact denials rule (by simp)
    next missed =>
      apply ih (fun r member => denials r (by simp [member]))
      obtain ⟨chosen, member, matchesRule⟩ := covered
      rcases List.mem_cons.mp member with equal | rest
      · subst chosen
        exact False.elim (missed matchesRule)
      · exact ⟨chosen, rest, matchesRule⟩

end TDN.Filter
