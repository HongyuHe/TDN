import TDN.Evidence.FreshTransecCover
import TDN.Targets.CompleteTransec

namespace TDN.Imported.CompleteTransec
open Targets Targets.Complete CoverTraffic

lemma retained_installation_checks :
    FreshTransecCover.installations.all coverInstallationChecked = true := by decide

theorem retained_complete_RG032 :
    Targets.Complete.msc_transec_conditions FreshTransecCover.installations :=
  transec_conditions_from_checked_installations _ retained_installation_checks

def alternateInstallation : CoverInstallation :=
  { device := "alternate.sender"
    use := ⟨true, false, false, false, true⟩
    sender := ⟨1024, 32, 8, 10000000⟩
    active := true }

lemma alternate_installation_check :
    [alternateInstallation].all coverInstallationChecked = true := by decide

theorem alternate_complete_RG032 :
    Targets.Complete.msc_transec_conditions [alternateInstallation] :=
  transec_conditions_from_checked_installations _ alternate_installation_check

lemma inactive_internet_rejected :
    ¬ Targets.Complete.msc_transec_conditions
      [{ alternateInstallation with
          active := false
          use := { alternateInstallation.use with enabled := false } }] := by
  intro h
  have active := h.2.2 _ (List.mem_singleton_self _) (Or.inl rfl)
  exact Bool.noConfusion active.1

lemma short_record_rejected :
    ¬ Targets.Complete.msc_transec_conditions
      [{ alternateInstallation with sender := ⟨16, 32, 8, 10000000⟩ }] := by
  intro h
  have bound := (h.2.2 _ (List.mem_singleton_self _) (Or.inl rfl)).2.1.1
  change 32 ≤ 16 at bound
  omega

lemma real_payload_has_nonempty_execution :
    ∃ actions finish,
      (system FreshTransecCover.sender).MTr (initial 0) actions finish ∧
      actions ≠ [] ∧ finish.attempts ≠ [] := by
  let ready : CoverTraffic.State :=
    { initial 0 with queue := enqueue FreshTransecCover.sender [] [1, 2, 3] }
  let done : CoverTraffic.State :=
    { queue := ready.queue.tail
      attempts := [⟨0, paddedBytes FreshTransecCover.sender (payload ready.queue), true⟩]
      deadlineNs := nextDeadline FreshTransecCover.sender 0 0
      sequence := 1 }
  refine ⟨[.arrival [1, 2, 3], .tick 0 0 true], done, ?_, by decide, by decide⟩
  exact Cslib.LTS.MTr.stepL (Step.arrive (initial 0) [1, 2, 3])
    (Cslib.LTS.MTr.stepL
      (Step.tick ready 0 0 true (by decide) (by decide) (by decide))
      (Cslib.LTS.MTr.refl))

end TDN.Imported.CompleteTransec
