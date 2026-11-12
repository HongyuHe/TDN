import TDN.Deployments.SnapshotTfcCoverTraffic
import TDN.Requirements.VerifiedTrafficFlowConfidentiality

namespace TDN.Deployments.SnapshotProof_TrafficFlowConfidentiality
open Requirements Requirements.Msc CoverTraffic

lemma retained_installation_checks :
    SnapshotTfcCoverTraffic.installations.all coverInstallationChecked = true := by native_decide

theorem retained_complete_RG032 :
    Requirements.Msc.msc_transec_conditions SnapshotTfcCoverTraffic.installations :=
  transec_conditions_from_checked_installations _ retained_installation_checks

def alternateInstallation : CoverInstallation :=
  { device := "alternate.sender"
    use := ⟨true, false, false, false, true⟩
    sender := ⟨1024, 32, 8, 10000000⟩
    active := true }

lemma alternate_installation_check :
    [alternateInstallation].all coverInstallationChecked = true := by native_decide

theorem alternate_complete_RG032 :
    Requirements.Msc.msc_transec_conditions [alternateInstallation] :=
  transec_conditions_from_checked_installations _ alternate_installation_check

lemma inactive_internet_rejected :
    ¬ Requirements.Msc.msc_transec_conditions
      [{ alternateInstallation with
          active := false
          use := { alternateInstallation.use with enabled := false } }] := by
  intro h
  have active := h.2.2 _ (List.mem_singleton_self _) (Or.inl rfl)
  exact Bool.noConfusion active.1

lemma short_record_rejected :
    ¬ Requirements.Msc.msc_transec_conditions
      [{ alternateInstallation with sender := ⟨16, 32, 8, 10000000⟩ }] := by
  intro h
  have bound := (h.2.2 _ (List.mem_singleton_self _) (Or.inl rfl)).2.1.1
  change 32 ≤ 16 at bound
  omega

lemma real_payload_has_nonempty_forwarding :
    ∃ actions finish,
      (system SnapshotTfcCoverTraffic.sender).MTr (initial 0) actions finish ∧
      actions ≠ [] ∧ finish.attempts ≠ [] := by
  let ready : CoverTraffic.State :=
    { initial 0 with queue := enqueue SnapshotTfcCoverTraffic.sender [] [1, 2, 3] }
  let done : CoverTraffic.State :=
    { queue := ready.queue.tail
      attempts := [⟨0, paddedBytes SnapshotTfcCoverTraffic.sender (payload ready.queue), true⟩]
      deadlineNs := nextDeadline SnapshotTfcCoverTraffic.sender 0 0
      sequence := 1 }
  refine ⟨[.arrival [1, 2, 3], .tick 0 0 true], done, ?_, by native_decide, by native_decide⟩
  exact Cslib.LTS.MTr.stepL (Step.arrive (initial 0) [1, 2, 3])
    (Cslib.LTS.MTr.stepL
      (Step.tick ready 0 0 true (by native_decide) (by native_decide) (by native_decide))
      (Cslib.LTS.MTr.refl))

end TDN.Deployments.SnapshotProof_TrafficFlowConfidentiality
