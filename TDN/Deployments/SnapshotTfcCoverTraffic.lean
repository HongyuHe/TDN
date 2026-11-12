import TDN.Import.SnapshotLoader
import TDN.Requirements.TrafficFlowConfidentialitySpec

namespace TDN.Deployments.SnapshotTfcCoverTraffic
open Requirements CoverTraffic
set_option maxRecDepth 100000
set_option maxHeartbeats 0

def sender : CoverTraffic.Config := ⟨512, 24, 64, 20000000⟩
lemma valid_parameters : sender.Valid := by native_decide

load_network_records installations : List CoverInstallation from "../../data/evidence/SnapshotTfcCoverTraffic.json" ["TDN.Deployments.SnapshotTfcCoverTraffic.installations"]

theorem selected_cover_enablement :
    msc_transec_conditions (installations.map CoverInstallation.use) := by
  exact (transec_conditions_from_cover_installations installations (by native_decide) (by native_decide)).1

theorem all_sender_traces_obey_size_and_capacity : ScheduledCoverGuarantee sender :=
  scheduled_cover_guarantee_from_parameters sender valid_parameters

load_network_records attemptsOA : List (Nat × Nat × Nat) from "../../data/evidence/SnapshotTfcCoverTraffic.json" ["TDN.Deployments.SnapshotTfcCoverTraffic.attemptsOA"]

theorem recorded_attemptsOA :
    ∀ row ∈ attemptsOA, row.1 = sender.recordBytes ∧
      row.2.1 ≤ sender.queueLimit ∧ row.2.2 ≤ 142957 := by native_decide
lemma recorded_attempt_countOA : attemptsOA.length = 1411 := by native_decide

load_network_records attemptsOB : List (Nat × Nat × Nat) from "../../data/evidence/SnapshotTfcCoverTraffic.json" ["TDN.Deployments.SnapshotTfcCoverTraffic.attemptsOB"]

theorem recorded_attemptsOB :
    ∀ row ∈ attemptsOB, row.1 = sender.recordBytes ∧
      row.2.1 ≤ sender.queueLimit ∧ row.2.2 ≤ 201497 := by native_decide
lemma recorded_attempt_countOB : attemptsOB.length = 1416 := by native_decide

end TDN.Deployments.SnapshotTfcCoverTraffic
